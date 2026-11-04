# MOD-03 History rules

Status: reviewed
Epics: E4-S2
Parity rows: SD-04, SD-03, SR-07

## What it does

Every live entry keeps a list of older copies of itself, its history. A copy (a history item) is made when an edit session changes the entry. Two vault settings limit the list: a count and a total size per entry. When a limit is passed, the oldest items are dropped. The user can view, restore and delete history items in the entry editor.

This card owns the behavior: when an item is made, what it holds, the limits, how size is measured, pruning, viewing, restoring and deleting. Other cards own the rest:

- how history is stored in the file, and the item id rule: FMT-11.31, FMT-11.32;
- the two limit fields in the file, their defaults and how odd values are read: FMT-10.15;
- attachment storage shared between an entry and its history: FMT-13.14, FMT-13.16;
- the file version that history fields need: FMT-16.19;
- merging two histories: MOD-11; cloning with or without history: MOD-10;
- the entry fields themselves: MOD-01.

Words used here. **Edit session**: a set of changes to one live entry that App applies as one step (one editor commit, one command line edit, one browser-bridge update). **Stored value**: anything that is written to the file for the entry (MOD-01, FMT-11.15). **Now**: one UTC timestamp in whole seconds, taken once per action.

## Inputs and outputs

| Input | Type | Limits |
|---|---|---|
| Max items (`HistoryMaxItems`, FMT-10.15) | signed 32-bit | -1 = no limit; 0 or more = most items kept per entry. Default 10 |
| Max size (`HistoryMaxSize`, FMT-10.15) | signed 32-bit, bytes | -1 = no limit; 0 or more = most bytes of history per entry. Default 6,291,456 (6 MiB) |
| An edit session on a live entry | the entry before and after | |
| A history page action | Show, Restore, Delete, Delete all | |

Output: the entry's history list, oldest first, newest last. Each item is a full copy of the entry as it was before one edit session (MOD-03.1).

## Rules

### What a history item is

MOD-03.1 **Contents.** A history item is a copy of the live entry taken at the start of an edit session. It holds every stored value of the entry at that moment:

| Held | Not held |
|---|---|
| all string fields with their protected flags (standard and custom, MOD-01) | its own history (an item never has history, FMT-11.31) |
| attachments: names and content (MOD-05) | a group: an item sits in no group |
| custom data items (FMT-14) | |
| icon (number or custom icon id), foreground and background colors | |
| override URL, tags, report-exclusion flag | |
| auto-type settings and window associations | |
| previous-parent group id | |
| the whole times block, including its `LastModificationTime` at that moment, expiry time and the expires flag | |

The item carries the owner's id (FMT-11.32). The item's own times are the entry's times before the edit, so the item's `LastModificationTime` says when that version was made.

MOD-03.2 **Edit sessions make at most one item.** At the start of an edit session App takes the copy. At the end, if at least one stored value of the entry changed, App appends the copy at the end of the history list and then prunes (MOD-03.8). If no stored value changed, the copy is thrown away (and wiped), and the entry's times do not move. Setting a value to the value it already has is not a change. Many changes in one session still give one item.

MOD-03.3 **Times on a change.** When an edit session changes the entry, App sets the entry's `LastModificationTime` and `LastAccessTime` to now. `CreationTime`, `LocationChanged`, `UsageCount`, `ExpiryTime` and `Expires` change only when the session itself changes them. The reference never moves `LastAccessTime` or `UsageCount` for viewing, copying, opening a URL or auto-type; App does the same.

MOD-03.4 **Actions that are edit sessions** (they make one item when something changed):

| Action | Notes |
|---|---|
| Entry editor: OK, or Apply, with changes | Each Apply is its own session: OK after two Applies can give three items |
| Entry editor: Cancel, then choosing to save the changes | Same as OK |
| One-time password setup on an entry (FEA-04) | |
| Browser bridge: updating the username and password of an existing entry (INT-02) | |
| Browser bridge: adding or replacing a passkey on an existing entry (INT-04) | |
| Browser bridge: removing the bridge's stored data from entries (vault settings or browser statistics screen) | Only when the entry held such data |
| Command line: edit an entry; import an attachment; remove an attachment (INT-10) | Importing content equal to the current content is no change |
| Command line: move an entry, in the reference only | See MOD-03.5 and lead decision L03-1 |

MOD-03.5 **Actions that make no history item.** Some of them still change the entry's times, as the last column shows.

| Action | Entry times that move |
|---|---|
| Creating a new entry, by any path (editor, command line, browser bridge, import, clone) | the entry is new. A new passkey entry from the browser bridge has its history emptied after it is created |
| Viewing, Show, copying a field, copying a one-time password, opening the URL, auto-type | none |
| Editor opened, then OK or Apply with no change | none |
| Editor Cancel, then choosing to discard | none (see the edge case on missing custom icons) |
| Moving an entry inside the vault: drag and drop, move to the recycle bin, restore from it (MOD-04) | `LocationChanged` always; `LastModificationTime` and `LastAccessTime` too when the previous-parent group changes (MOD-04.5) |
| Command line move (App) | as the row above; lead decision L03-1 |
| Expire now (MOD-09) | `LastModificationTime`, `LastAccessTime` |
| Adding or removing a tag on selected entries from the main screen, or deleting a tag from the tag list (MOD-07) | `LastModificationTime`, `LastAccessTime` |
| Downloading website icons for a group's entries (MOD-06) | `LastModificationTime`, `LastAccessTime` |
| Browser bridge remembering an allow or deny decision for a site (INT-02) | `LastModificationTime`, `LastAccessTime` |
| Replacing references with values when a referenced entry is deleted for good (MOD-04.6, MOD-08.27) | the referencing entry's `LastModificationTime`, `LastAccessTime` |
| Deleting history items (MOD-03.13) | `LastModificationTime`, `LastAccessTime` |
| Moving up or down in the group's entry order | none |
| Merge (MOD-11) | per MOD-11 |

### Limits and size

MOD-03.6 **Limit values.** Max items: -1 means no limit; 0 means no history is kept (every new item is dropped at once); n ≥ 1 keeps at most n items. Max size: -1 means no limit; 0 or more is the most bytes the items of one entry may add up to. Both limits apply together. New vaults get 10 and 6,291,456 (MOD-12 creates them; FMT-10.15 reads them). A value below -1 read from a file is ignored as FMT-10.15 says, so it never reaches these rules.

MOD-03.7 **Size of an item.** The size of an entry or history item is the sum of:

| Part | Bytes counted |
|---|---|
| each string field, standard and custom | UTF-8 bytes of the field name + UTF-8 bytes of the value. The five standard fields always count, even when empty: their names alone add 29 bytes (`Title` 5, `UserName` 8, `Password` 8, `URL` 3, `Notes` 5) |
| each attachment | UTF-8 bytes of its name + its content bytes, in full, even when the content is shared with other items or entries (FMT-13.16) |
| each custom data item | UTF-8 bytes of the key + UTF-8 bytes of the value (item times not counted) |
| each auto-type window association | UTF-8 bytes of the window title + UTF-8 bytes of the sequence |
| each tag | UTF-8 bytes of the tag |

Nothing else counts: not the icon, colors, override URL, default auto-type sequence, times, flags, previous parent or ids. App computes sizes in 64-bit arithmetic. The reference uses signed 32-bit sums, which can wrap for an entry over 2 GiB; App never wraps.

MOD-03.8 **Pruning.** Pruning runs on one entry's history:

1. If max items is not -1: walk from the newest item to the oldest. Keep the first max items items. Drop every older item.
2. Then, if max size is not -1: walk from the newest remaining item to the oldest, adding each item's size (MOD-03.7) to a running total. As soon as the total is greater than max size, drop that item and every older item, even small ones. A total equal to max size is kept.

So the newest items always win, and a single item larger than max size is dropped together with everything older. Dropped items are wiped (Security notes).

MOD-03.9 **When pruning runs.** Exactly these times:

| Trigger | Entries pruned |
|---|---|
| A new history item was added (MOD-03.2) | that entry |
| The vault settings screen is applied and the new max items or the new max size differs from the stored value | every live entry in the vault, including entries in the recycle bin |
| A merge rebuilt an entry's history (MOD-11) | that entry |

Pruning does not run when a vault is opened, saved, or reloaded, when history items are deleted, or when a limit is changed back to its old value. A vault opened with more items than the limits allow keeps them until one of the triggers above.

MOD-03.10 **App ceiling.** The reader refuses an entry with more than 100,000 history items (the history row of FMT-08.12), and App never writes a vault it would refuse to read. So App prunes every entry to at most 100,000 items at each trigger, also when max items is -1, and the settings screen accepts max items from 0 to 100,000 (lead decision L03-3). The whole-file limit of 4,000,000 live entries plus history items (the entry elements row of FMT-08.12) is checked at open, where a file over it is refused, and at save, where the save fails, nothing is written and the old file stays (lead decision LD-68).

### The history page

MOD-03.11 **History page.** The entry editor has a History page. It is hidden when the entry has no history items, in a new entry, and in the read-only view of a history item. It lists the current entry and every history item, one row each:

| Column | Content |
|---|---|
| Last modified | the row's `LastModificationTime`, in local time, short date and time format |
| Age | time since that moment in plain words; the current entry's row reads "Current" with its age, and is bold |
| Difference | the fields that differ between this row and the next older row (empty on the oldest row) |
| Size | the row's size (MOD-03.7), in human units with no decimals |

Rows are sorted by `LastModificationTime`, newest first. The Difference labels, in this order, joined with ", ": Title, Username, Password, URL, Notes; "Custom attributes" only when no standard field differs but other string fields do; Icon; Color; Expiration (flag or time); one-time password; Custom data; Attachments; Auto-Type (associations, enabled flag or default sequence); Tags.

MOD-03.12 **Show and Restore.** Show (or double-click) opens the selected item in a read-only copy of the editor; closing it returns to the History page. Restore copies all stored values of the selected item (MOD-03.1) into the editor's draft: fields, attachments, custom data, icon, colors, auto-type, tags, expiry and report flag. The times, id and previous parent are not copied. Nothing changes in the vault until the user commits. The commit is a normal edit session (MOD-03.2): the current state becomes a new history item, and the restored item also stays in the list. Show, Restore and Delete are available only for history rows, never for the current row.

MOD-03.13 **Delete and Delete all.** Delete removes the selected history item from the list. Delete all removes every history item. Both only mark the items: they are removed when the user commits the editor (OK or Apply), and kept if the user cancels and discards. At commit, App removes the marked items first, then runs the edit session. Removing items alone makes no new history item; the reference moves the entry's `LastModificationTime` and `LastAccessTime` to now when items were removed, and App does the same. Deleting history items adds no deleted-object record (FMT-15.8).

### History, attachments and ids

MOD-03.14 **Attachments in history.** Each history item keeps its own attachments as they were (MOD-03.1). Removing or replacing an attachment on the entry does not touch its history items, so the old content stays in the vault until those items are pruned or deleted. App shares one copy of equal content in memory between an entry and its items, and the file stores it once (FMT-13.16). Size still counts each item's attachments in full (MOD-03.7).

MOD-03.15 **History items are not live entries.** They carry the owner's id (FMT-11.32) and are not in the id registry. They are never listed in a group, found by search (FEA-01), counted in statistics (FEA-07), checked by Health Check (FEA-05), offered to the browser bridge or auto-type, or given to the SSH agent. A clone with a new id gives its copied history items the new id (MOD-10). A history item cannot itself be edited.

## Edge cases and errors

| Case | Result |
|---|---|
| Max items 0 | Every edit leaves 0 history items |
| Max size smaller than one item | That item, and everything older, is dropped: 0 items |
| Running total exactly equal to max size | Kept |
| Vault opened with 12 items, max items 10 | Still 12 after open and save. The next edit leaves 10 (the 3 oldest dropped, the new one added) |
| Max items changed from 10 to 3 on the settings screen | Every live entry is pruned to 3 when the screen is applied |
| Max items set to 10 when it already is 10, max size changed | Every entry is pruned (both limits apply) |
| A history item newer than the current entry (another device's clock) | Shown above the current row; pruning still goes by list position, newest last |
| History item whose id differs from the owner's | Takes the owner's id on read (FMT-11.32) |
| `HistoryMaxItems` of -2 in a file | Ignored on read (FMT-10.15) |
| Editor Cancel and discard, when the entry's custom icon no longer exists in the vault | The reference sets the entry's icon to the default icon anyway, outside an edit session: no history item, times move. App does not change the entry on discard |
| Reference: attachment changes made in the editor after Apply | The reference then applies attachment changes straight to the live entry, without a history item, and reloads the form (other unsaved edits are lost). Read from the source, not run (source re-read by Verify: after Apply the editor's attachment list is linked to the live entry's attachments, so later attachment changes go straight into the entry outside an edit session, and the entry's change signal makes the editor reload its form). App never does this: every change goes through the editor's draft and one edit session |
| Reference: attachment opened from the main screen's preview panel, edited outside, and saved back (MOD-05.13) | The reference writes the new content straight into the live entry, without a history item. App makes this an edit session (one history item) |
| Reference settings screen, size limit | The screen shows the stored size rounded half up to whole MiB, and a box that is checked only when that rounded value is above 0. Applying the screen stores the shown value × 1,048,576, or -1 when the box is unchecked. So a stored size that is not a whole MiB changes on any apply (6,000,000 becomes 6,291,456), and a stored size below 524,288 bytes becomes -1 (no limit). The multiplication is signed 32-bit, and the field accepts up to 2,000,000,000 MiB: 2,048 MiB is stored as -2,147,483,648 (no limit in that session; ignored on the next read, FMT-10.15), 4,096 MiB as 0 (all history of every entry is dropped at once), 3,000 MiB as -1,149,239,296. Read from the source, not run (source re-read and arithmetic recomputed by Verify: the shown value is the stored size divided by 1,048,576, rounded half up; the number box allows 1 to 2,000,000,000 MiB; the product is a signed 32-bit multiplication, so the values above are the wrapped results the build gives in practice, the language itself leaving signed overflow undefined; a stored size of 0 removes every history item on the next prune, and any value below -1 means no limit). App: lead decision L03-2 |
| Max items field in the reference | Accepts 0 to 2,000,000,000. App: 0 to 100,000 (MOD-03.10) |

## Security notes

- History keeps old secrets: earlier passwords, removed one-time password seeds, removed attachments. They stay in the vault until pruned or deleted (MOD-03.14). The editor's Delete all is the way to remove them. The help text for history should say so.
- Every history item holds secrets in secret types (`SecretString`, `SecretBytes`; Rust rule, plan/architecture.md). Pruned, deleted and discarded copies (MOD-03.2) are wiped when dropped (SR-07; AT-C01, AT-C02).
- The history page shows field names, times and sizes only; it never puts a value on the screen. Show opens values only on request, under the same masking rules as the editor (SC-04). History content never goes to logs or error text (AT-C06).
- A hostile vault can hold up to the FMT-08.12 limits (100,000 items per entry). Pruning and size sums must stay linear in the number of items and never overflow (AT-A08, AT-A10).
- The settings screen must never drop history the user did not ask to drop (the reference's rounding and overflow quirks above). SD-04.
- Merge must keep history without loss (SD-03, MOD-11).

## Test cases

Demo vaults use the password `demo-pass`. "id(xx)" is 16 bytes of 0xxx (FMT-11). Unless a case says otherwise, limits are 10 items and 6,291,456 bytes.

| Case | Given | When | Then |
|---|---|---|---|
| 03-01 item contents (MOD-03.1, MOD-03.3) | Entry Alpha: Title "Alpha", UserName "alice", custom field "PIN"="4711" protected, attachment a.txt "hi", custom data k=v, tag "work", `LastModificationTime` 2026-01-01T00:00:00Z, no history | Editor: change UserName to "alice2", OK at 2026-02-01T00:00:00Z | One history item: UserName "alice", PIN "4711" still protected, a.txt "hi", k=v, tag "work", id = Alpha's id, `LastModificationTime` 2026-01-01T00:00:00Z, no history of its own. Entry: `LastModificationTime` and `LastAccessTime` 2026-02-01T00:00:00Z, `CreationTime` and `LocationChanged` unchanged |
| 03-02 no change, no item (MOD-03.2) | Alpha as above | Editor opened, OK with no change; separately, command line edit setting UserName to its current value | 0 history items; times unchanged (observed with the installed command line tool: the same-value edit added nothing) |
| 03-03 one item per session (MOD-03.2, MOD-03.4) | Alpha, no history | Editor: change Title, Apply; change URL, Apply; change Notes, OK | 3 history items |
| 03-04 command line sessions (MOD-03.4) | Entry E with UserName "alice", no history | Command line edit to "alice1", then "alice2", then "alice3" | History users, oldest first: alice, alice1, alice2. Current: alice3 (observed) |
| 03-05 attachment sessions (MOD-03.4) | Entry E, no attachments | Command line: import f.txt = "hello"; import f.txt again without force; import with force f.txt = "hello"; import with force f.txt = "other" | 2 history items: before the first import, and before "other". The import without force fails; the equal-content import adds nothing (observed) |
| 03-06 no item for moves and use (MOD-03.5) | Entry E in group G1, 2 history items | Drag E to group G2; copy its password; auto-type it; expire it now | Still 2 history items. `UsageCount` and `LastAccessTime` unchanged by copy and auto-type |
| 03-07 command line move (MOD-03.5, L03-1) | Entry E in the root group, 4 history items, no previous parent | Command line move E to G1 | Reference (observed): 5 history items. App: 4 (L03-1) |
| 03-08 count pruning (MOD-03.8) | Entry T with 12 history items h00 … h11 (oldest first), max items 10 | Open and save with no edit | Still 12 items (MOD-03.9) |
| 03-09 count pruning on edit (MOD-03.8, MOD-03.9) | The vault from 03-08 | Edit T's UserName from "cur" to "new" | 10 items: h03 … h11, then "cur". h00, h01, h02 dropped (observed) |
| 03-10 size formula (MOD-03.7) | Entry: Title "Mail", UserName "bob", Password "pw-1", URL "https://m.example", Notes "", custom field PIN = "4711", attachment key.txt of 10 bytes, tags home and work, custom data k = v, one association window "Mail*" with an empty sequence | Compute the size | 96 bytes (29 + 28 + 7 + 17 + 8 + 2 + 5) |
| 03-11 UTF-8 sizes (MOD-03.7) | Entry with Title "Café", other fields empty | Compute the size | 34 bytes (29 + 5) |
| 03-12 size pruning (MOD-03.8) | Max items -1, max size 100. Entry T: Title "T", Password "pw", UserName "c"; history h0 … h4, each Title "T", UserName "h0" … "h4", Password "pw" (34 bytes each) | Edit UserName to "new" | 2 items: h4 and the item for "c" (33 bytes): 33 + 34 = 67, adding h3 makes 101 > 100, so h3 and older are dropped (observed) |
| 03-13 equal total kept (MOD-03.8) | Max items -1, max size 150. Entry: Title "T", UserName "a" × 20, other fields empty (50 bytes). History h1 (UserName "b" × 20) and h2 (UserName "c" × 20), Title "T", 50 bytes each | Edit UserName to "d" × 20 | 3 items (h1, h2, the "a" item): 50 + 50 + 50 = 150, equal, all kept. The same with max size 149: 2 items (h1 dropped) |
| 03-14 large attachment (MOD-03.8) | Default limits. Entry E: Title "E", no attachments | Import big.bin of 4,000,000 bytes; edit Title to "E2"; edit Title to "E3" | After the import: 1 item. After "E2": 2 items. After "E3": 1 item, Title "E2" (4,000,038 bytes); the 4,000,037-byte item and the small first item are both dropped (observed) |
| 03-15 single item over the limit (MOD-03.8) | Default limits. Entry with an attachment of 7,340,032 bytes | Edit the Title | 0 history items |
| 03-16 zero limits (MOD-03.6) | History of 5 items. Case A: max items 0. Case B: max items -1, max size 10 | Edit once | A and B: 0 items (observed) |
| 03-17 settings trigger (MOD-03.9) | Three entries with 8, 5 and 2 items, one of them in the recycle bin | Settings screen: max items 10 → 4, apply | 4, 4 and 2 items |
| 03-18 unchanged setting, no prune (MOD-03.9) | Entry with 12 items, max items 10 | Settings screen opened and applied with no change | Still 12 items |
| 03-19 restore (MOD-03.12) | Entry with UserName "v3"; history items "v1", "v2" | History page: select "v1", Restore, OK | Entry UserName "v1". History: v1, v2, v3 (the restored item stays, the old current becomes the newest item). Entry `CreationTime` unchanged |
| 03-20 restore needs commit (MOD-03.12) | As 03-19 | Restore "v1", then Cancel and discard | Entry unchanged, history unchanged |
| 03-21 delete items (MOD-03.13) | Entry with items v1, v2, v3; `LastModificationTime` 2026-01-01T00:00:00Z | Delete v2, OK at 2026-03-01T00:00:00Z, nothing else changed | Items v1, v3. No new item. Entry `LastModificationTime` 2026-03-01T00:00:00Z. Deleted objects unchanged |
| 03-22 delete all, then cancel (MOD-03.13) | Entry with 3 items | Delete all, Cancel, discard | Still 3 items |
| 03-23 delete all (MOD-03.13) | Entry with 3 items | Delete all, change Title, OK | 1 item (the state before this session) |
| 03-24 history page (MOD-03.11) | Entry with items at 2026-01-01 (Title "A") and 2026-02-01 (Title "B", UserName "x"), current at 2026-03-01 (Title "B", UserName "y") | Open the History page | Rows, newest first: current (bold, "Current"), Difference "Username"; 2026-02-01, Difference "Title, Username"; 2026-01-01, Difference empty. Show, Restore, Delete disabled on the current row |
| 03-25 attachments stay in history (MOD-03.14) | Entry with attachment secret.pdf, no history | Remove secret.pdf, OK; save; open again | Entry has no attachment; its one history item has secret.pdf with the same content; the file still holds that content once (FMT-13.16) |
| 03-26 history not live (MOD-03.15) | Entry Alpha with an old password "hunter2" only in a history item | Search "hunter2"; run Health Check; ask the browser bridge for Alpha's site | No result from the history item in any of them |
| 03-27 new entry (MOD-03.5) | — | Create an entry in the editor, typing several fields, OK | 0 history items |
| 03-28 ceiling (MOD-03.10) | Max items -1, max size -1, an entry with 100,000 items | Edit it | 100,000 items (the oldest dropped); the vault saves and opens again |
| 03-29 settings screen exact (MOD-03.6, L03-2) | Stored max size 6,000,000; separately 100,000 | Open the settings screen, apply without touching the history fields | App: both values unchanged. Reference (from source): 6,291,456 and -1 |
| 03-30 settings screen overflow (L03-2) | — | Type 4,096 MiB into the size field | App: refused (at most 2,047 MiB), nothing pruned. Reference (from source): stored 0, all history dropped |
| 03-31 whole-file ceiling (MOD-03.10, LD-68) | (a) A file with 3,999,990 live entries plus history items; (b) a file with 4,000,001 | (a) Open, add 11 entries one by one, save; (b) open | (a) Opens; the save that would reach 4,000,001 fails, nothing is written, the old file is unchanged. (b) Refused at open with the size-limit error (FMT-08.12) |

## How this was learned

- Reference source, read only: the entry's edit-session routines (take a copy, append it when something changed, then prune), the pruning routine, the entry size routine and the size parts of strings, attachments, custom data and auto-type associations; the routine that removes history items; the clone routine's history part; the entry editor (commit, cancel, Apply, the History page, restore, delete, delete all, the reload after an outside change, and the attachment list relinking after Apply); the history list model (rows, sort, difference labels, size column); the vault settings screen's general page (history limits, its MiB rounding and multiplication); every caller of the edit-session routines (command line edit, move, attachment import and remove; browser bridge credential update, passkey, plugin data removal; one-time password setup; shared-group export; the Linux secret service); the main screen actions for tags, expiry and icons; the merge routine's history part (read only to point at MOD-11).
- Reference tests: the modification tests for history items and history size, the entry tests for history custom data, and the main screen tests for editing, adding and drag and drop.
- Installed command line tool 2.7.11, demo vaults in `/tmp/spec-mod03-04-05/` (password `demo-pass`), made with its create and XML import commands and read back through its XML export: history order and times after three edits (03-04); no item for a same-value edit (03-02); one item for a move (03-07); count pruning only on edit, not on save (03-08, 03-09); size pruning (03-12); zero limits (03-16); the large-attachment case (03-14); attachment import collisions (03-05).
- Checked by Verify (Sprint 2), source re-read; the window was not run:
  - the reference settings screen's rounding and 32-bit overflow: as in the size limit row of Edge cases;
  - attachment changes after Apply go straight to the live entry, with no history item (the editor relinks its attachment list to the live entry after Apply); an outside-edited attachment opened from the preview panel is written into the live entry with a plain set after the save-changes question, outside any edit session;
  - deleting only history items moves `LastModificationTime` and `LastAccessTime`: the removal sends the entry's change signal, which updates both times.
- Lead decisions (decided: spec/decisions.md default rule, each takes the recommended option):
  - L03-1: command line move. The reference command line makes a history item for a move (because the previous-parent value changes), the window does not. Options: (a) as the reference command line; (b) no history item for any move. Recommended: (b), one rule for all paths.
  - L03-2: settings screen for the size limit. Recommended: show the stored value exactly (MiB with up to two decimals, or bytes), write it back unchanged unless the user edits the field, accept 1 to 2,047 MiB (2,047 × 1,048,576 = 2,146,435,072 fits a signed 32-bit value), and compute in 64 bits.
  - L03-3: the 100,000-item ceiling of MOD-03.10 (the reference has none). Recommended as written, because App never writes a vault it would refuse to read (FMT-08.12).
  - The whole-file limit at save as well as at open: decided, spec/decisions.md LD-68.
