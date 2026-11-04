# MOD-10 Clone options

Status: reviewed
Epics: E4-S7
Parity rows: SD-04, SI-02, SI-05, SI-07

## What it does

Cloning makes a new entry, or a new group with everything below it, as a copy of an existing one. The copy gets its own id and fresh times, so Larsal and the reference treat it as a separate item from then on. The user clones one entry through a small options dialog, clones a group with a menu item, or copies several entries or groups at once by dragging.

This card owns:
- every clone option, with its default,
- exactly what a clone gets: id, times, fields, history, attachments, plug-in data, place,
- group cloning, and copying several items at once by drag and drop, inside one vault and between two open vaults.

MOD-08 owns the reference syntax the references option writes. MOD-03 owns history limits. MOD-11 and INT-08 use cloning internally and own those uses.

## Inputs and outputs

In: one entry (dialog), or one group (menu), or a set of entries or groups (drag), plus the options and the current time.
Out: new items added to the vault. The originals stay unchanged. The vault counts as changed (auto-save, APP-05).

Actions (APP-08 owns menus and shortcuts):

| Action ID | Menu item (in our words) | Enabled when |
|---|---|---|
| `entry.clone` | clone the entry, with options (Cmd+D) | exactly one entry is selected, and neither the current group nor that entry is in the recycle bin or below it (this also covers an entry found through search) |
| `group.clone` | clone the group | a group is selected that is neither the root nor the recycle bin |

## Rules

MOD-10.1 **Clone entry dialog.** `entry.clone` opens a modal dialog titled "Copy this entry" with three check boxes and OK and Cancel buttons. Labels are Larsal's own:

| Option ID | Larsal label (meaning) | Default |
|---|---|---|
| `clone.suffix` | "Mark the copy's title with ' - Clone'" (MOD-10.4) | on |
| `clone.refs` | "Link user name and password to the original" (both fields become references to the original, MOD-10.5) | off |
| `clone.history` | copy the history | on |

The dialog does not remember choices. Each opening shows the defaults.

MOD-10.2 **Always: a new id and fresh times.** The clone gets a new random id (16 bytes from larsal-crypto random, with version 4 id bits, CRY-03.11). Its creation, modification, last access and location-changed times are all set to now (UTC). It keeps the original's `Expires`, `ExpiryTime` and usage count (MOD-09).

MOD-10.3 **Always copied.** Every string field (standard and custom) with its value and protected flag, every attachment (MOD-05: same content, so it is stored once on save), the icon number and custom icon id, foreground and background colours, the override URL, tags, the Auto-Type settings and window associations, the one-time password settings, the "exclude from reports" flag, all custom data (plug-in settings), and the previous parent group id.

MOD-10.4 **Title suffix.** With `clone.suffix` on, the title becomes the original title followed by ` - Clone`: space, hyphen, space, the word in the UI language (English `Clone`). An empty title gives ` - Clone`. Suffixes add up: cloning `Mail - Clone` gives `Mail - Clone - Clone`.

MOD-10.5 **References.** With `clone.refs` on, the clone's UserName becomes `{REF:U@I:<id>}` and its Password becomes `{REF:P@I:<id>}`. The id is the original's, as 32 uppercase hex digits (MOD-08.30). Each field keeps the original field's protected flag. This happens even when the original field is empty. The clone then shows the original's current values (MOD-08.16) and follows later changes to them. A clone of such a clone points at its own source, which points onward. Every link resolves within the depth budget for normal chains (MOD-08.18).

MOD-10.6 **History.** With `clone.history` on, the clone gets a copy of every history item, in the same order. Each copy keeps its own content and its own times, and takes the clone's new id. With it off, the clone has no history. The copied history is not trimmed when it is copied. MOD-03 limits apply at the clone's next edit, or when the limits change. Cloning never adds a history item to the original or to the clone.

MOD-10.7 **Options also reach history items (reference).** The reference applies `clone.suffix` and `clone.refs` to every copied history item too. Each history copy's title gets ` - Clone`, and its UserName and Password become references to the original id, while its times stay unchanged. This is read from the source, not run (source, re-read by Verify in Sprint 3, V-10-1: the clone routine copies each history item with the same options minus history, new id and new times, so the suffix and both references reach every history copy, its references name the original's id, and its times stay as they were; the window was not run). Larsal applies these two options to the clone's current version only, and copies history items unchanged (lead decision D-10-1, decided: spec/decisions.md default rule).

MOD-10.8 **Placement.** The clone goes into the original's group, after the group's last entry, even when the original was found through search. The clone becomes the selected entry. An active search runs again. The original is not changed in any way, and no deleted-object item is written.

MOD-10.9 **Cancel.** Cancel, or closing the dialog, creates nothing and changes nothing. In Larsal, a lock while the dialog is open closes it the same way. The reference does the same in effect: its lock routine closes the vault's modal windows, the clone dialog included (observed in the source, Sprint 3 Verify).

MOD-10.10 **Clone group.** `group.clone` makes, with no options dialog:
- a new group: new id, all times now, every other group field copied (name, notes, icon, Auto-Type and search settings, custom data, expiry), and the name followed by ` - Clone`,
- for each entry in it: a clone as in MOD-10.2 and MOD-10.3, with history copied, no title suffix and no references,
- for each child group, recursively: a group clone with a new id, times now and ` - Clone` added to its name too (so every subgroup name gets the suffix), holding clones of its entries.

The new group then opens in the group editor as a new group. OK puts it under the original's parent, after the last child group, then selects it and expands the parent. Cancel throws the whole copy away.

MOD-10.11 **Copy by drag inside one vault.** Dragging one or more selected entries onto a group, with the copy modifier held (Option on Mac, as in the Finder; LD-119. The reference uses Control, which its toolkit maps to Command on Mac, observed in the source, Sprint 3 Verify), puts a clone of each entry in that group, after its last entry. Each clone gets a new id, times now and copied history, with no suffix and no references. Dragging a group with the copy modifier puts a group clone (MOD-10.10, without any suffix) under the target group. A group cannot be dropped onto itself or into its own subgroups. A drag without the modifier moves (MOD-02).

MOD-10.12 **Drag between two open vaults.** Dropping entries or a group into another open vault always makes clones there: new ids, times now, history copied, no suffix, no references. Custom icons the clones use are copied into the target vault when it lacks them. A move (no modifier) then deletes the originals from the source vault. The source records a deleted-object item for each original id (FMT-15, MOD-04). A copy leaves the source unchanged.

## Edge cases and errors

- Cloning while the original is open in the editor with unsaved edits: the clone copies the stored entry, not the unsaved edits (check with Verify).
- An original with `clone.refs` whose own username is a reference: the clone's username is a reference to the original, so the result resolves through two links.
- An original that is itself expired: the clone is expired too (MOD-10.2). The user must change the clone's expiry.
- A clone of an entry with 100 history items and a history limit of 10: it holds 100 until its first edit (MOD-10.6).
- Recycle bin: `entry.clone` is disabled there, even for a bin entry selected in search results. Dragging an entry out of the recycle bin with the copy modifier is allowed and makes a normal clone.
- A group that contains the recycle bin: in the copy, the bin's copy is an ordinary group. The vault's recycle bin id still points at the original bin (MOD-04).
- Drag copy of 500 entries: one change event and one auto-save (APP-05).

## Security notes

- **Clones copy trust.** Custom data travels with the clone (MOD-10.3). So the clone inherits the browser bridge's site permissions (SI-02), any passkey (SI-05: the same credential then exists in two entries) and the SSH agent settings (SI-07: the same key is offered twice). This matches the reference. Users who clone a login to make a new account should be able to see this. The entry's "browser" and "SSH" sections must show the copied settings.
- **References keep secrets in one place.** With `clone.refs`, the clone stores no copy of the password, only a reference (MOD-08). Deleting the original for good triggers the MOD-08.27 prompt.
- **New ids are random** and come from `larsal-crypto::random` only (AT-B04). A clone must never reuse the original's id inside one vault. That would break merge (MOD-11) and the id invariant (`invariants.rs`).
- **History copies are secrets too.** A clone with history duplicates old passwords. They live in secret types and are wiped when dropped (SR-07).
- **Limits.** Cloning a huge group must stay within the reading limits for groups, entries and entry elements (FMT-08.12, checked as FMT-11.48 says; copied history items count toward entry elements). Larsal refuses a clone that would exceed one, and changes nothing.

## Test cases

Demo entry "Mail" in group Work. Id `5a5a…5a` (16 bytes of 0x5a). UserName `max`. Password `pw-mail` (protected). URL `https://mail.example`. Custom field `Pin` = `1234` (protected). Attachment `a.txt` (3 bytes). Tag `work`. Expires true, ExpiryTime 2027-01-01T00:00:00Z. Usage count 4. Created 2025-01-01T00:00:00Z, modified 2025-06-01T00:00:00Z. Two history items: titles `Mail0` (modified 2025-02-01T00:00:00Z) and `Mail1` (modified 2025-03-01T00:00:00Z). Custom data holds browser site permissions. Group Work holds Mail and then Other. Now = 2026-10-25T09:00:00Z.

| Case | Given | When | Then |
|---|---|---|---|
| 10-01 dialog defaults | Mail selected | Cmd+D | the dialog shows suffix on, references off, history on (MOD-10.1) |
| 10-02 enable rules | none, one, then two entries selected; the recycle bin open with one entry selected; the root selected; the recycle bin group selected | look at the clone actions | `entry.clone` enabled only with exactly one entry outside the bin; `group.clone` disabled for the root and for the bin (MOD-10.1, MOD-10.10) |
| 10-03 defaults result | Mail | clone with the defaults | new entry, id ≠ `5a…`; title `Mail - Clone`; created, modified, accessed and location-changed all 2026-10-25T09:00:00Z; Expires true, ExpiryTime 2027-01-01T00:00:00Z, usage count 4 (MOD-10.2, MOD-10.4) |
| 10-04 copied content | the clone from 10-03 | compare with Mail | same UserName, Password (protected), URL, Pin (protected), `a.txt` with the same bytes, tag, icon, colours, Auto-Type settings, custom data (MOD-10.3) |
| 10-05 suffix off | Mail | clone with suffix off | title `Mail` (MOD-10.4) |
| 10-06 suffix twice, empty title | the clone `Mail - Clone`; an entry with an empty title | clone each with the defaults | `Mail - Clone - Clone`; ` - Clone` (MOD-10.4) |
| 10-07 references | Mail | clone with references on | clone UserName raw `{REF:U@I:5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A}`, Password raw `{REF:P@I:5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A}` and protected; copy of the clone's password gives `pw-mail` (MOD-10.5) |
| 10-08 references follow | the 10-07 clone; a second clone made from it with references on | change Mail's password to `pw-new`; copy both clones' passwords | `pw-new` and `pw-new` (MOD-10.5) |
| 10-09 references with an empty field | an entry with an empty UserName | clone with references on | clone UserName `{REF:U@I:…}`, which resolves to empty (MOD-10.5) |
| 10-10 history on | Mail | clone with the defaults | the clone holds 2 history items, `Mail0` then `Mail1`, modified 2025-02-01T00:00:00Z and 2025-03-01T00:00:00Z, each with the clone's id (MOD-10.6) |
| 10-11 history off | Mail | clone with history off | the clone has 0 history items; Mail still has 2 (MOD-10.6) |
| 10-12 no trim at clone time | Mail with 12 history items; vault history limit 10 items | clone with history on; then edit the clone's notes and save | 12 items after cloning; 10 after the edit (MOD-03 trims, plus the new item) (MOD-10.6) |
| 10-13 options and history | Mail | clone with suffix, references and history on | reference (source reading): history titles `Mail0 - Clone`, `Mail1 - Clone`, history passwords are references. Larsal: history titles `Mail0`, `Mail1`, passwords unchanged; only the current version has the suffix and the references (MOD-10.7, D-10-1) |
| 10-14 placement | search `mail` active, showing Mail | clone with the defaults | the clone is in Work, after Other; it is selected; the search results now list Mail and `Mail - Clone`; Mail is unchanged (modified still 2025-06-01T00:00:00Z) (MOD-10.8) |
| 10-15 cancel | Mail | open the dialog, press Cancel | entry count unchanged; vault not marked changed (MOD-10.9) |
| 10-16 clone group | Work holds Mail and a subgroup Sub holding entry S | `group.clone`, then OK in the group editor | under Work's parent, after its last child: group `Work - Clone` holding `Sub - Clone`; copies of Mail (title `Mail`, history kept) and S, all with new ids and times 2026-10-25T09:00:00Z (MOD-10.10) |
| 10-17 clone group cancel | Work | `group.clone`, then Cancel in the editor | nothing added (MOD-10.10) |
| 10-18 drag copy, several | Mail and Other selected; group Home | Option-drag onto Home | Home gets `Mail` and `Other` copies with new ids, times now and history kept; Work unchanged (MOD-10.11) |
| 10-19 drag copy of a group | Work; group Home | Option-drag Work onto Home | Home gets `Work` (no suffix) with copies of all entries and subgroups, all new ids (MOD-10.11) |
| 10-20 drag into own subgroup | Work and its subgroup Sub | drag Work onto Sub, with and without the modifier | refused; nothing changes (MOD-10.11) |
| 10-21 between vaults, move | vaults A (holds Mail, with custom icon K) and B (no icon K) both open | drag Mail from A into B's root, no modifier | B holds a copy with a new id, times now, history kept, icon K copied into B; A no longer holds Mail, and A's deleted objects list Mail's id (MOD-10.12) |
| 10-22 between vaults, copy | as 10-21 | Option-drag | B gets the copy; A unchanged (MOD-10.12) |
| 10-23 lock closes the dialog | Mail selected, clone dialog open | lock the vault | the dialog closes; after unlock the entry count is unchanged (MOD-10.9) |

## How this was learned

- Read in the reference source: the entry clone routine and its option flags, the group clone routine and its flags, the clone options dialog (screen definition: check boxes, defaults, title), the action that opens it and its enable rules in the main window, the group clone action and its enable rule, the group editor's handling of a new group, the group tree's drop handler (copy and move, same vault and across vaults), the entry and group destructors (deleted-object items), and the entry tests for cloning (current version, history, references, chains of references).
- Compared the clone routine and the dialog with the installed version's tag in the reference history: no difference.
- The command line tool has no clone command, so nothing here was run. The resolution in 10-07 and 10-08 follows MOD-08 rules that were observed.

### Lead decisions

Decided: spec/decisions.md default rule (the recommendation).

| ID | Question | Options | Recommendation |
|---|---|---|---|
| D-10-1 | Suffix and references on copied history items | (a) as the reference does: they also go into every history copy; (b) current version only | (b): history should show what the original really held. The reference's own test says cloning must not change history items' times, and it never tests their titles. |

### Check with Verify

- V-10-1 (closed by source re-read in Sprint 3, see MOD-10.7): in the reference app, clone with all three options on, then open the clone's history: do the items carry ` - Clone` and references (MOD-10.7)?
- V-10-2 (closed, Sprint 3 Verify): the reference copies with Control, mapped to Command on Mac; Larsal uses Option (LD-119).
- V-10-3: cloning while the original has unsaved edits in the editor.
- V-10-4 (closed, Sprint 3 Verify): the reference's lock closes the clone dialog with the vault's other modal windows; Larsal does the same (MOD-10.9).

### Not on Mac

None. Cloning is the same on every platform.
