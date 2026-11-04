# MOD-04 Recycle bin

Status: reviewed
Epics: E4-S3
Parity rows: SD-05, SD-03, SG-04, SI-02, SI-03, SI-06, SI-07

## What it does

When the recycle bin is on, deleting an entry or a group moves it into a special group, the recycle bin, instead of erasing it. Items in the bin can be restored to the group they came from, deleted for good one by one, or all at once by emptying the bin. When the bin is off, or the item is already in the bin, deleting erases it for good and adds deleted-object records (FMT-15).

This card owns the behavior: creating the bin, the delete decision, moving into the bin, deleting for good, emptying, restoring, turning the bin off, the times that change and where recycled items are left out. Other cards own the rest:

- the three file fields `RecycleBinEnabled`, `RecycleBinUUID`, `RecycleBinChanged`: FMT-10.18, FMT-10.24;
- the deleted-objects list, its record order and encoding: FMT-15 (FMT-15.7 lists every action that adds records);
- `PreviousParentGroup` in the file, and the 4.1 version it needs: FMT-11.30, FMT-16.7, FMT-16.9, FMT-16.19;
- moves in general, group order and sorting: MOD-02; references between entries: MOD-08; merge: MOD-11; the vault settings screen: MOD-12; the command line syntax and messages: INT-10.

Words used here. **In the bin**: the item is the bin group, or its group or any group above it is the bin group. **Delete for good**: remove the item and everything inside it from the vault, adding deleted-object records per FMT-15.7. **Now**: one UTC timestamp in whole seconds, taken once per action.

## Inputs and outputs

| Input | Type |
|---|---|
| `RecycleBinEnabled` | boolean, default True for new vaults (FMT-10.18) |
| `RecycleBinUUID` | the bin group's id, or none (zero id) |
| A delete, empty, restore or settings action | the selected entries or group |

Outputs: the changed group tree, `RecycleBinUUID` and `RecycleBinChanged`, item times, deleted-object records.

## Rules

### The bin group

MOD-04.1 **Which group is the bin.** The bin is the group whose id is `RecycleBinUUID`, wherever it sits in the tree. There is at most one (architecture, `invariants.rs`). A `RecycleBinUUID` that names no group means there is no bin (FMT-10.16). The bin may be moved like any group (MOD-02); it stays the bin. It may not be the root group: the root group cannot be moved or deleted.

MOD-04.2 **Creating the bin.** The bin is made only when an item is about to be moved into it (MOD-04.4) and the vault has no bin (`RecycleBinUUID` none or dangling). The new group:

| Field | Value |
|---|---|
| id | fresh random id (larsal-crypto random, version 4 id bits, CRY-03.11) |
| name | `Recycle Bin` (the reference uses its interface language at creation time; Larsal uses the Larsal interface language string, and never renames an existing bin) |
| icon | standard icon 43 |
| `EnableSearching` | false |
| `EnableAutoType` | false |
| place | appended as the last child group of the root group |
| times | all five times = now; `Expires` false; `UsageCount` 0 |
| everything else | the defaults of a new group (MOD-02): notes empty, expanded, default auto-type sequence empty (inherit) |

`RecycleBinUUID` becomes the new id and `RecycleBinChanged` becomes now. The root group's times do not change. A group that only looks like a bin (same name or icon) is not reused.

### Deleting

MOD-04.3 **Confirmations.**

| Action | Question | Buttons (default) |
|---|---|---|
| Move entries to the bin | none, unless the app setting "Ask before moving to the Recycle Bin" (APP-01 S-ENTRY-02) is on; it is off by default, as in the reference | Move, Cancel (Cancel) |
| Move a group to the bin | always: move the named group to the bin? | Move, Cancel (Cancel) |
| Delete entries for good | always: permanently delete the named entry, or N entries? | Delete, Cancel (Cancel) |
| Delete a group for good | always: permanently delete the named group? | Delete, Cancel (Cancel) |
| Empty the bin | always: permanently delete everything in the bin? | Empty, Cancel (Cancel) |
| Turn the bin off while it is not empty | MOD-04.12 | Delete, No (No) |

Names in questions are set as text, never as markup (AT-E01). The delete button's tooltip says "move to the bin" when the bin is on and the selection is outside it, else "permanently delete".

MOD-04.4 **Bin or for good.** A delete moves the item into the bin, or deletes it for good:

| Item | Deleted for good when | Else |
|---|---|---|
| Entry | the bin is off, or the entry is in the bin | moved to the bin |
| Group | the bin is off, or the group is in the bin (the bin itself included), or the group holds the bin somewhere below it | moved to the bin |

The root group cannot be deleted. Several selected entries: Larsal decides for each entry by this table, and the question of MOD-04.3 states both counts when they differ (lead decision L04-1). The reference decides for the whole selection by the first selected entry only (FMT-15.7, interface details).

MOD-04.5 **Moving into the bin.** No history item (MOD-03.5) and no deleted-object record (FMT-15.8).

| Item | Where it goes | Fields that change |
|---|---|---|
| Entry | appended after the bin's entries | `PreviousParentGroup` = the group it left. `LocationChanged` = now. `LastModificationTime` and `LastAccessTime` = now (because the previous-parent value changed). The group it left and the bin: unchanged (MOD-02.25, LD-102) |
| Group | appended as the last child group of the bin | The group: `PreviousParentGroup` = the group it left, `LocationChanged`, `LastModificationTime`, `LastAccessTime` = now. The group it left and the bin: unchanged. Entries and groups inside it: unchanged, including their own `PreviousParentGroup` |

If an entry's previous-parent value already equals the group it leaves, its `LastModificationTime` and `LastAccessTime` do not move; its `LocationChanged` still does. A moved group's `LastModificationTime` and `LastAccessTime` always move, whatever its previous-parent value was (the reference's group move always marks the group changed). An entry already directly in the bin that is "moved to the bin" again (for example by a browser-bridge delete request, MOD-04.15) does not move at all.

MOD-04.6 **Deleting entries for good, references.** Before deleting entries for good, Larsal looks for other live entries whose standard fields reference each entry (MOD-08), ignoring entries that are in the same selection. For each entry that has such references, Larsal asks: overwrite the references with the values, skip this entry, or delete anyway (default: overwrite). Overwrite replaces each referencing standard field as MOD-08.27 says (the whole field takes the deleted entry's raw value of the same field name) and makes no history item (MOD-03.5); skip keeps that entry; delete leaves the references dangling. This question is asked only for deleting entries for good. It is not asked when moving to the bin, deleting a group, or emptying the bin.

MOD-04.7 **Deleting for good.** The item and everything inside it leave the vault. Records are added per FMT-15.7: an entry gives one record; a group gives its entries, then each child group by the same rule, then itself. Their history items, attachments and custom data go with them; attachment content that nothing else uses is not written on the next save (the pool is built from what remains, FMT-13.16). Times: deleting an entry or a group does not change the times of the group it was in (MOD-02.25, LD-102).

MOD-04.8 **Deleting the bin itself.** The bin is deleted for good (MOD-04.4) with everything in it: records for its contents, then for the bin (FMT-15.7). Afterwards there is no bin, and `RecycleBinUUID` is written as the zero id. The next move into the bin makes a new bin with a new id (MOD-04.2). `RecycleBinChanged`: the reference leaves it unchanged (observed); Larsal sets it to now, because the bin group really changed (FMT-10.24; lead decision L04-6).

MOD-04.9 **Emptying the bin.** Available when the bin, a group in it, or an entry in it is selected. After the user confirms, Larsal deletes for good each entry directly in the bin, in order, then each child group of the bin, in order, with everything inside (records per FMT-15.7). The bin group stays, with its id, name, icon and flags. No reference question is asked (MOD-04.6). The bin's times do not change (MOD-02.25, LD-102). Emptying a bin that is already empty changes nothing and does not mark the vault changed.

### Restoring

MOD-04.10 **Restore entries.** The Restore action is shown when at least one selected entry is in the bin. For each selected entry that is in the bin:

1. If its `PreviousParentGroup` names a group that exists in the vault and is not in the bin, Larsal moves the entry there, appended after that group's entries. This is a move (MOD-04.5 fields): `PreviousParentGroup` becomes the group it left (the bin, or a group in the bin), `LocationChanged`, `LastModificationTime` and `LastAccessTime` become now; the times of both groups do not change (MOD-02.25, LD-102).
2. Otherwise (no previous parent, a group that no longer exists, or a group that is itself in the bin), Larsal moves the entry to the root group the same way and tells the user once, naming how many entries went to the root group (lead decision L04-2).

No history item and no deleted-object record. Entries that are not in the bin are never moved by Restore.

Reference: restore moves every selected entry whose previous parent exists, even an entry that is not in the bin, and moves an entry into a previous parent that is in the bin. When the previous parent does not exist it does nothing and says nothing (from the source, re-read by Verify; the window was not run: Restore is offered when any selected entry is in the bin, and then moves every selected entry whose previous parent resolves to a group; there is no branch for a missing parent). A version 4.0 file holds no `PreviousParentGroup` (FMT-16.13), so entries deleted in a vault last saved at 4.0 by another writer cannot be restored to their group in the reference.

MOD-04.11 **Restore groups.** The reference has no restore action for groups; the user drags a group out of the bin (a normal move, MOD-02). Larsal offers Restore for a selected group in the bin by the same rule as MOD-04.10, with the group's own `PreviousParentGroup` (lead decision L04-3). Moving a group into a group inside itself is never allowed (MOD-02).

### Turning the bin off

MOD-04.12 **Bin setting.** The vault settings screen (MOD-12) has a "use recycle bin" switch. When the user turns it off and applies, and the bin was on:

1. If a bin exists and is not empty, Larsal asks whether to delete the bin and everything in it, saying this cannot be undone (Delete, No; default No).
   - Delete: the bin is deleted for good (MOD-04.8 records).
   - No: the bin stays as a normal group. Its name gets ` (old)` added at the end (for example `Recycle Bin (old)`), and its icon becomes the default group icon, 48.
2. An empty bin stays as a normal group with name and icon unchanged.
3. `RecycleBinUUID` becomes none, `RecycleBinChanged` becomes now, `RecycleBinEnabled` becomes false.

The old bin group keeps `EnableSearching` and `EnableAutoType` false in the reference, so its contents stay hidden from search and auto-type. Larsal sets both to inherit (null) when a group stops being the bin (lead decision L04-4). Turning the bin on again changes only `RecycleBinEnabled`; no group is made until the next delete, and the old group is not reused.

MOD-04.13 **Bin off in the file, bin id still set.** A file can hold `RecycleBinEnabled` false with a `RecycleBinUUID` that names a group (another writer, or a round trip; FMT-10.18 keeps it). Then: every delete is for good (MOD-04.4); that group still counts as the bin for "in the bin" and for MOD-04.14; Larsal hides the Empty action, because emptying applies only while the bin is on (lead decision L04-5). The reference shows Empty there, asks, and then does nothing.

### Recycled items elsewhere

MOD-04.14 **Where items in the bin are left out.** Items in the bin stay in the vault, but Larsal leaves them out of:

| Feature | Rule |
|---|---|
| Search (FEA-01) | never listed by vault-wide search, whatever any group flag says, also when a group inside the bin, or the bin itself, has searching on (FEA-01.21, lead decision LD-57). Selecting the bin still lists its entries. Reference: follows only the inherited searching flag, so a group in the bin with searching on is searched |
| Auto-Type (INT-05) | entries in the bin are never Auto-Type candidates, at global, picker or entry level, whatever any group or entry flag says (LD-57; INT-05 repeats this). Reference: global Auto-Type checks only the inherited group flag and the entry flag, with no bin check, so a group in the bin with auto-type on is offered and typed |
| Browser bridge (INT-02, INT-03) | entries in the bin are never offered or filled; the bin is left out of the group list sent to the browser |
| SSH agent (INT-06) | keys from entries in the bin are not added on unlock |
| Health Check, breach check, passkey and browser reports (FEA-05, FEA-06) | entries in the bin are skipped |
| Statistics (FEA-07) | groups and entries in the bin are not counted |
| Expired-entry checks and the warning after unlock (MOD-09) | entries in the bin are skipped |
| HTML export (FEA-09) | the bin is not written |
| Vault tag list (MOD-07.5) | tags used only by entries in the bin are not listed |

MOD-04.15 **Actions inside the bin.** While the bin, or a group or entry in it, is selected: New entry, New group, Clone entry and Download website icons are off. Cloning the bin group itself is off. Drag and drop into the bin is a normal move (MOD-02) and is allowed. A browser-bridge request to delete an entry (INT-01), after the user confirms, moves it to the bin by MOD-04.4, except that an entry already in the bin stays where it is and is never deleted for good by a request (the reference moves an entry from a group inside the bin up to the bin itself); with the bin off, it is deleted for good. No caller in Larsal 1.0: Larsal's browser bridge has no delete request (INT-01.37, LD-189). The rule stays for a later caller; test 04-25 calls the core delete function directly.

MOD-04.16 **Sorting.** Sorting a group's child groups by name (MOD-02) keeps the bin as the last child, in both directions.

MOD-04.17 **Deleted objects.** Every delete for good adds records exactly as FMT-15.7 says; moving into the bin, restoring and emptying an already empty bin add none (FMT-15.8). The list is never pruned (FMT-15.9). Merge uses it as FMT-15.10 and FMT-15.11 say (MOD-11). A move into the bin made in one copy of a vault reaches the other copy in a merge through `LocationChanged` (MOD-11).

MOD-04.18 **Times, summary.**

| Action | Item | Group left | Group entered | Meta |
|---|---|---|---|---|
| Entry to bin | `LocationChanged`; `LastModificationTime`, `LastAccessTime` when previous parent changes | — | — | `RecycleBinChanged` only if the bin is made |
| Group to bin | `LocationChanged`; mod, access always | — | — | as above |
| Entry restored | as entry to bin | — | — | — |
| Entry deleted for good | (gone) | — | — | — |
| Group deleted for good | (gone) | — | — | `RecycleBinChanged` if it was the bin (Larsal, MOD-04.8) |
| Empty the bin | (gone) | — | — | — |
| Bin turned off | old bin: its switches go back to Inherit, and name and icon change if renamed; either is a group edit (MOD-02.29), so mod, access move whenever a switch or the name changes (LD-102) | — | — | `RecycleBinUUID` none, `RecycleBinChanged` now |

"mod, access" means `LastModificationTime` and `LastAccessTime` = now. Groups never move their times when entries come or go (MOD-02.25, LD-102).

## Edge cases and errors

| Case | Result |
|---|---|
| First delete in a new vault | A bin is made as the last child of the root group, then the entry moves in (observed: name `Recycle Bin`, icon 43, searching and auto-type `false`, all times equal) |
| `RecycleBinUUID` names a group that does not exist | No bin; the next delete makes a new one with a new id (observed) |
| Deleting an entry inside a group that is inside the bin | For good (observed with the command line tool) |
| Deleting a group that holds the bin (the user moved the bin into it) | For good, with all contents, the bin included (MOD-04.4). The installed command line tool instead tries to move the group into the bin, which sits inside it, and hangs; the file is left unchanged (observed: no exit after 30 seconds). Recorded as an expected difference |
| Bin turned off, then on, then an entry deleted | A new bin is made; the old group (renamed or not) stays a normal group |
| A group named `Recycle Bin` that is not the bin | Treated as a normal group |
| Selection holds one entry in the bin and one outside | Larsal: the one in the bin is deleted for good, the other goes to the bin (L04-1). Reference: decided by the first selected entry; with the bin entry first, both are deleted for good |
| Restore with the previous parent gone | Larsal: to the root group, with a notice (L04-2). Reference: nothing happens |
| Restore when the previous parent is the bin itself (the entry was moved within the bin) | Larsal: to the root group (L04-2) |
| Empty with references from outside the bin to entries in it | Deleted without asking; the references dangle (MOD-08.16 resolves them to empty text) |
| Turning the bin off while the vault has no bin | Only `RecycleBinEnabled` changes, and `RecycleBinChanged` does not move (the bin value was already none) |
| Vault read with `RecycleBinEnabled` empty | False (FMT-12.10, FMT-10) |

Not on Mac: none. The Linux secret service integration of the reference also deletes through these rules (an item already in the bin, or with the bin off, is deleted for good); Larsal has no such integration.

## Security notes

- The bin is not a secure delete. Items in the bin keep all their secrets and are saved in the file until deleted for good. The confirmation texts must not suggest otherwise.
- Deleting for good also keeps nothing in history: the entry's history items go with it. Deleted-object records hold only ids and times, never names or values (FMT-15).
- Items in the bin must never be filled, typed, searched vault-wide, or given to the SSH agent, whatever the group flags say (MOD-04.14, LD-57; SD-05, SI-02, SI-03, SI-06, SI-07; AT-F05, AT-G01, AT-H01). The reference relies on flags for search and Auto-Type, so a group in the bin with those flags on leaks deleted entries; Larsal must not. A deleted credential that still gets filled or typed is a High finding.
- Reports and statistics skip the bin (SG-04), so a weak password in the bin is not reported. That is the reference's choice; Larsal keeps it.
- Data safety (SD-05): permanent deletes always ask; a multi-selection never deletes an entry outside the bin for good just because another selected entry is in the bin (L04-1); turning the bin off never deletes a non-empty bin without asking.
- A group cycle must never be created (AT-A08). Deleting a group that holds the bin must not try to move the group into its own descendant (the reference command line hangs there).
- A merge keeps every entry of both sides, except an entry that the same vault's deleted-objects list removed after its last change (SD-03, FMT-15.10, FMT-15.11, LD-265).

## Test cases

Demo vaults use the password `demo-pass`. "id(xx)" is 16 bytes of 0xxx (FMT-11). Times are UTC.

| Case | Given | When | Then |
|---|---|---|---|
| 04-01 bin created (MOD-04.2, MOD-04.5) | New vault: root group, child groups G1 then Zed; entry E1 in G1; no bin | Delete E1 at 2026-10-24T22:47:40Z | A group `Recycle Bin` is the last child of the root (after Zed), icon 43, `EnableSearching` false, `EnableAutoType` false, all times 22:47:40. `RecycleBinUUID` = its id, `RecycleBinChanged` 22:47:40. E1 is in it with `PreviousParentGroup` = G1, `LocationChanged`, `LastModificationTime`, `LastAccessTime` 22:47:40, no history item. G1's `LastModificationTime` 22:47:40. Root group times unchanged. Deleted objects empty (observed) |
| 04-02 delete from the bin (MOD-04.4, MOD-04.7) | The vault from 04-01 | Delete E1 again at 22:47:59 | E1 is gone. Deleted objects = [E1 at 22:47:59]. Bin `LastModificationTime` 22:47:59 (observed) |
| 04-03 group to bin (MOD-04.5, MOD-04.18) | Group G1 in the root holds E2 and child group Sub (with E3); the bin exists; root `LastModificationTime` 22:47:37 | Delete G1 at 22:48:00 | G1 is the last child of the bin, `PreviousParentGroup` = root group, `LocationChanged` and `LastModificationTime` 22:48:00. Root and bin times unchanged. E2, E3, Sub unchanged. No records (observed) |
| 04-04 group for good (MOD-04.7, MOD-04.17) | The vault from 04-03 | Delete G1 (in the bin) at 22:48:07 | Records added in order: E2, E3, Sub, G1, all at 22:48:07 (observed) |
| 04-05 delete the bin (MOD-04.8) | Bin holds entry E4; `RecycleBinChanged` 22:47:40 | Delete the bin group at 22:48:09; then delete entry E5 (outside) at 22:48:11 | After the first step: records E4, then the bin; `RecycleBinUUID` written as `AAAAAAAAAAAAAAAAAAAAAA==`; `RecycleBinChanged`: Larsal 22:48:09, reference 22:47:40 (observed). After the second: a new bin with a new id holds E5, `RecycleBinChanged` 22:48:11 (observed) |
| 04-06 bin off (MOD-04.4) | `RecycleBinEnabled` False; group id(0B) named `Recycle Bin` with entry X, and `RecycleBinUUID` = id(0B); entry A in the root | Delete A | A deleted for good, record A. `RecycleBinUUID` still id(0B); X still there (observed) |
| 04-07 dangling bin id (MOD-04.1, MOD-04.2) | `RecycleBinEnabled` True, `RecycleBinUUID` = id(0E), no such group; entry A | Delete A | A new bin with a fresh id holds A; `RecycleBinUUID` = that id (observed) |
| 04-08 nested in the bin (MOD-04.1, MOD-04.4) | Bin id(0B) inside group G; the bin holds Z and group Sub with entry W | Delete W | W deleted for good, record W (observed) |
| 04-09 group holding the bin (MOD-04.4) | As 04-08: group G holds entry Y and the bin | Delete G | Larsal: asks "permanently delete"; then records Y, Z, W, Sub, bin, G; no bin remains. Installed command line tool: hangs, file unchanged (observed) |
| 04-10 multi-selection (MOD-04.4, L04-1) | Bin on. Entry P in the bin, entry Q in the root | Select P first, then Q, delete | Larsal: P deleted for good (record P), Q moved to the bin. Reference: both deleted for good (FMT-15.7) |
| 04-11 confirmations (MOD-04.3) | Bin on, setting "Ask before moving to the Recycle Bin" off | Delete an entry outside the bin; delete a group outside the bin; delete an entry in the bin | First: moved with no question. Second: asks Move/Cancel. Third: asks Delete/Cancel, Cancel leaves it in place |
| 04-12 references on delete (MOD-04.6) | Entry R in the bin; entry S outside with Password `{REF:P@I:<R's id in hex>}` and R's password "pw-r" | Delete R, choose overwrite | S's Password becomes "pw-r", S has no new history item, R deleted for good. Choosing skip: R stays in the bin, S unchanged |
| 04-13 empty (MOD-04.9) | Bin holds entries X, Y and group S with entry Z | Empty the bin | Records X, Y, Z, S. Bin still there, same id and name, empty (FMT-15 test 15-10) |
| 04-14 empty an empty bin (MOD-04.9) | The reference test vault with an empty bin; the one with the bin off; the one with no bin yet | Empty | Nothing changes; the vault is not marked changed |
| 04-15 restore (MOD-04.10, MOD-04.18) | Entry E with `PreviousParentGroup` = G1, in the bin; G1 exists | Restore E at 2026-03-01T00:00:00Z | E is the last entry of G1, `PreviousParentGroup` = the bin's id, `LocationChanged` and `LastModificationTime` 2026-03-01T00:00:00Z. No history item, no record |
| 04-16 restore, parent gone (MOD-04.10, L04-2) | Entry E in the bin, `PreviousParentGroup` = id(55), no such group | Restore E | Larsal: E in the root group, notice "1 entry restored to the root group". Reference: E stays in the bin, no message |
| 04-17 restore only from the bin (MOD-04.10) | Entry F in G2 with `PreviousParentGroup` = G1 (not in the bin); entry E in the bin with `PreviousParentGroup` = G1 | Select E and F, Restore | Larsal: E to G1; F stays in G2. Reference: both move to G1 |
| 04-18 restore a group (MOD-04.11, L04-3) | Group G in the bin with `PreviousParentGroup` = root | Restore G | Larsal: G is the last child of the root group. Reference: no such action |
| 04-19 bin off, not empty, keep (MOD-04.12) | Bin with entry X | Settings: turn the bin off, answer No | Group renamed `Recycle Bin (old)`, icon 48, still holds X. Larsal: its searching and auto-type flags become null (L04-4). `RecycleBinUUID` none, `RecycleBinChanged` now, `RecycleBinEnabled` False. No records |
| 04-20 bin off, not empty, delete (MOD-04.12) | Bin B holds entry X and group S with entry Z | Settings: turn the bin off, answer Delete | Records X, Z, S, B (FMT-15 test 15-12b). No bin |
| 04-21 bin off, empty (MOD-04.12) | Empty bin | Settings: turn the bin off | No question. The group stays as `Recycle Bin`, icon 43. Larsal: flags null (L04-4) |
| 04-22 bin off but id set (MOD-04.13, L04-5) | `RecycleBinEnabled` False, `RecycleBinUUID` names group B holding entry X with a weak password | Select B; run Health Check | Larsal: no Empty action; X not in Health Check. Reference: Empty shown, does nothing |
| 04-23 left out (MOD-04.14) | Entry X in the bin with URL https://a.example, an SSH key attachment set to load on unlock, a weak password, expired yesterday | Search "a.example"; browser bridge asks for https://a.example; unlock; Health Check; statistics; unlock warning | X is in none of the results; its key is not added; not counted; no expiry warning for X |
| 04-24 actions in the bin (MOD-04.15) | The bin selected | Look at the actions | New entry, New group, Clone entry and Download website icons are off; Empty is on |
| 04-25 browser delete request (MOD-04.15) | Bin on; entry A in the root; entry B directly in the bin | The core delete function a bridge request would call (no caller in Larsal 1.0) deletes A, then B, as confirmed | A moves to the bin; B stays in the bin, not deleted. With the bin off: A deleted for good |
| 04-26 sorting (MOD-04.16) | Root children: Zeta, bin, Alpha | Sort by name, ascending, then descending | Alpha, Zeta, bin; then Zeta, Alpha, bin |
| 04-27 round trip of restore info (MOD-04.10, FMT-16.19) | Entry moved to the bin by Larsal | Save, close, open, Restore | The entry goes back to its group (the file was written at 4.1 because the previous parent exists) |
| 04-28 tag list (MOD-04.14) | Entry A outside the bin with tag `home`; entry X in the bin with tags `home` and `old` | Look at the sidebar tag list | `home` only |
| 04-29 search flag on inside the bin (MOD-04.14, LD-57) | Bin with `EnableSearching` false holds group S with `EnableSearching` true; S holds entry X titled `Bank`. A second vault whose bin itself has `EnableSearching` true holds entry Y titled `Bank` | Search `Bank` in each vault | Larsal: neither X nor Y is listed. Reference (from source): X and Y are listed |
| 04-30 auto-type flag on inside the bin (MOD-04.14, LD-57) | Bin holds group S with `EnableAutoType` true; S holds entry X whose window match fits the active window `Bank login`; no other entry matches | Start global Auto-Type in that window; open the picker and search `Bank`; select X in the bin and choose entry-level Auto-Type | Larsal: X is not a candidate, no picker offers it, nothing is typed; entry-level Auto-Type is off for X. Reference (from source): X is offered and typed |
| 04-31 move times, entry against group (MOD-04.5, MOD-04.18) | Entry E in G1 with `PreviousParentGroup` = G1; group H in the root with `PreviousParentGroup` = root; all their times 2026-01-01T00:00:00Z; the bin exists | Delete E, then H, at 2026-03-01T00:00:00Z | E: `LocationChanged` 2026-03-01, `LastModificationTime` and `LastAccessTime` still 2026-01-01. H: `LocationChanged`, `LastModificationTime` and `LastAccessTime` all 2026-03-01 |

## How this was learned

- Reference source, read only: the vault's recycle routines (create the bin, move an entry or group to it, empty it), the group's "is recycled" check, the group and entry destructors (records), the move routines for entries and groups (previous parent, location time, which groups get modified), the main screen's delete, restore and empty routines and the shared delete helper (permanent decision, confirmations, reference handling), the main window's action enabling rules, the vault settings screen's general page (turning the bin off), group sorting, the command line remove and remove-group commands, the browser bridge's delete request and group list, and every place that checks "is recycled" (search, Health Check, breach checks, statistics, reports, SSH agent, auto-type, HTML export, browser bridge).
- Reference tests: the vault tests for emptying the bin (disabled, not yet created, empty, with data), the entry and group "is recycled" tests, and the main screen delete-entry test.
- The reference's four recycle-bin test vaults (password `123`), read only with the installed command line tool's XML export: bin off with no id; no bin yet; an empty bin; a bin holding two entries and a group.
- Installed command line tool 2.7.11, demo vaults in `/tmp/spec-mod03-04-05/` (password `demo-pass`): bin creation and its fields (04-01), deletes from the bin (04-02, 04-04, 04-08), group to bin and which times move (04-03), deleting the bin and making a new one (04-05), bin off with an id (04-06), dangling id (04-07), and the hang when removing a group that holds the bin (04-09).
- Checked by Verify (Sprint 2), source re-read; the window was not run:
  - the reference window's restore (see MOD-04.10's reference note); its multi-selection rule (only the first selected entry decides between bin and for good); its Empty on a disabled bin (the action shows whenever the bin group is selected, because that group counts as the bin while its id is set; it asks, and the vault's empty routine then does nothing because the bin is off); the bin-off dialog (Delete or No, No preselected; Delete removes the bin with its contents; No renames it with " (old)" and the default icon; an empty bin gets no question);
  - the sort rule of MOD-04.16: the comparison answers "not before" when the bin is the first operand but compares names when the bin is the second, so it is not a consistent order and the bin's final place depends on the order in which the sort routine compares.
- Lead decisions (decided: spec/decisions.md default rule, each takes the recommended option):
  - L04-1: multi-selection delete. (a) as the reference, the first entry decides; (b) per entry. Recommended (b): never delete an entry outside the bin for good by accident.
  - L04-2: restore when the previous parent is missing or in the bin. (a) as the reference, do nothing; (b) to the root group with a notice; (c) ask for a group. Recommended (b).
  - L04-3: restore for groups (the reference has none). Recommended: offer it by the MOD-04.10 rule.
  - L04-4: flags of a group that stops being the bin. (a) as the reference, keep searching and auto-type off; (b) set both to inherit. Recommended (b): otherwise its entries silently vanish from search.
  - L04-5: Empty when the bin is off but its id is set. (a) as the reference, show it and do nothing; (b) hide it; (c) make it work. Recommended (b).
  - L04-6: `RecycleBinChanged` when the bin group is deleted. (a) as the reference, unchanged; (b) now, by FMT-10.24. Recommended (b).
  - Deleting a group that holds the bin: for good, as the reference window does (the command line tool hangs). Recommended as written in MOD-04.4.
