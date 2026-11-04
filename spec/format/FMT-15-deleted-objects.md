# FMT-15 Deleted objects

Status: reviewed
Epics: E3-S6, E15-S2
Parity rows: SD-03, SD-05, SD-06, SI-09

## What it does

A vault keeps a list of things that were deleted for good: each entry is an id and the time of deletion. The list holds no names and no data. A merge can use it to tell "deleted on the other side" from "new on this side".

This card gives:
- the list's place and structure in the document,
- the read rules, including for broken lists,
- when the reference adds items,
- that the reference never prunes the list,
- how the reference's two merge modes use the list,
- where App runs the deletion pass: in every same-vault merge and in a shared-group import (FMT-15.10, FMT-15.11; decided: spec/decisions.md LD-265).

The list lives in `Root`, after the root group (FMT-10.4, FMT-10.6). Ids and times follow FMT-12. "V", "id", "id(xx)", "zero id", "fail" and "open time" mean the same as in FMT-11. App writes the V that FMT-16 chooses: 4.0 or 4.1 by content (FMT-16.18, FMT-16.19), or at least the version the file was read as while the vault holds kept unknown parts (FMT-16.24, decided: spec/decisions.md LD-09; FMT-15.13). Version 3.1 facts in this card describe the reference and what App reads. MOD-04 covers the recycle bin and MOD-11 covers merge rules; this card gives only the facts they build on.

## Inputs and outputs

Read: the `DeletedObjects` element (or elements) in `Root`. Out: an ordered list of items. Each item is an id and a time.

Write: the list plus V. Out: one `DeletedObjects` element.

Limit: the `deleted objects` limit of FMT-08.12, set in `limits.rs` (FMT-15.14; decided: spec/decisions.md LD-22). The reference has no limit.

## Rules

FMT-15.1 **Structure.** `DeletedObjects` holds one `DeletedObject` per item. `DeletedObject` holds `UUID` (id) and then `DeletionTime` (time), in that write order. Where `DeletedObjects` goes is FMT-10.4: inside `Root`, right after the root `Group`, always written, as `<DeletedObjects/>` when the list is empty. Layout is FMT-10.2.

FMT-15.2 **Encodings and versions.** The list exists in all versions. `UUID` is an id (FMT-12). `DeletionTime` is a time (FMT-12):
- App always writes the binary form (FMT-12.2): the base64 of 8 bytes, the little-endian count of seconds since 0001-01-01T00:00:00Z;
- the reference writes the text `yyyy-MM-ddTHH:mm:ssZ` in 3.1 files (FMT-12.3). App never writes it;
- on read, either form is accepted in any file version (FMT-12.4).

Times are kept to whole seconds.

FMT-15.3 **Order.** Items are written in stored order. Read order becomes stored order. New items are added at the end.

FMT-15.4 **Reading an item.** The children of `DeletedObject` may come in any order, `DeletionTime` first included. An item is kept only when it has a usable id and a `DeletionTime` element:

| Item as read | Result |
|---|---|
| No usable `UUID`: every `UUID` child is missing, empty, the zero id, or not exactly 16 bytes after decoding | Item dropped silently |
| `DeletionTime` element missing | Item dropped silently |
| `DeletionTime` empty | Kept, with time 0001-01-01T00:00:00Z |
| `DeletionTime` text not valid base64 and not a valid ISO-8601 date | Kept, with the open time |
| `DeletionTime` in the binary form with a seconds count so large or so small that the toolkit's date arithmetic overflows (for example `/////////38=`, the largest 64-bit value) | Ours: kept, and written back unchanged (FMT-12.8). The installed version (2.7.11): kept, with wrapped arithmetic: at 4.x `/////////38=` is written back as `//////////8=` (-1); at 3.1 it is written `<DeletionTime/>` (FMT-12.3). The source: the item is probably dropped silently, because its newer toolkit gives a null time when seconds × 1000 overflows a 64-bit count, and the reader keeps an item only when its time is not null (differs in installed version; reasoned from the source, not run; check with Verify) |
| Empty `<DeletedObject/>` | Dropped |

No case in this table fails the open.

**Repeated children.** When `DeletionTime` appears more than once, the last one wins. `UUID` is different: a `UUID` that is empty, the zero id or not exactly 16 bytes is ignored, even when it comes after a valid one. So an earlier valid id stays. When several `UUID` children are valid, the last valid one wins. This is unlike groups, entries and custom icons, where a later invalid `UUID` wins (FMT-11.8, FMT-11.34, FMT-14.6).

**Unknown children.** The reference skips unknown children of `DeletedObject`, and children of `DeletedObjects` other than `DeletedObject`. We keep them, with the policy of FMT-11.45 (decided: spec/decisions.md LD-27): a kept item writes its unknown children after `DeletionTime`, in read order. When an item is dropped (no usable id, or no `DeletionTime`), its unknown children are dropped with it; nothing of the item is written back. Kept unknown children count toward the kept unknown limit of FMT-11.48.

FMT-15.5 **No clean-up on read.** Items are never merged and never checked:
- Two items with the same id are both kept, in order.
- An item whose id matches a live group, a live entry or a custom icon is kept. The live object stays too.
- A time in the future is kept.

FMT-15.6 **Several blocks.** When `Root` has more than one `DeletedObjects` element, wherever they sit in `Root` (FMT-10.6), their items are added in document order. The writer writes one block.

FMT-15.7 **When the reference adds items.** Each added item carries the current UTC time.

| Action | Items added, in this order |
|---|---|
| Deleting an entry for good: the recycle bin is off, the entry is already in the recycle bin, or the user empties the bin | One item: the entry's id |
| Deleting a group for good: the bin is off, or the group is the bin, inside the bin, or holds the bin | The group's own entries, in stored order; then each child group in stored order, applying this same rule to it; then the group itself |
| Emptying the recycle bin | Each entry directly in the bin, in order; then each group directly in the bin, by the group rule above. The bin itself stays |
| Moving an entry or group into another open vault | Items in the source vault, by the same rules (one item for an entry; for a group: its entries, its child groups, then the group) |
| Turning the recycle bin off in the vault settings while the bin is not empty, and choosing to delete it | By the group rule above, for the bin: its entries, its child groups, then the bin itself. (Choosing not to delete it keeps the group, renamed as an old bin, and adds nothing. An empty bin is not deleted.) |
| Removing a custom icon (FMT-14.9) | One item: the icon's id |

Example: group G1 holds entry E1 and child group G2, and G2 holds entry E2. Deleting G1 for good adds E1, E2, G2, G1, all with the same time.

Interface details that decide "for good" (for MOD-04; the list format is the same either way):
- Main screen, several entries selected: only the first selected entry is checked. If it is in the bin, or the bin is off, all selected entries are deleted for good; otherwise all go to the bin.
- Command line tool, removing a group: only "the bin is off" and "the group is the bin or inside it" count as for good. A group that holds the bin is not deleted for good there, unlike on the main screen.

FMT-15.8 **When the reference adds no item.**
- moving to the recycle bin,
- restoring from the recycle bin,
- moving inside the vault,
- deleting history items,
- removing an attachment, a string field or a custom data item,
- replacing the root group,
- an entry or group that a merge erases. During a merge, the list is put back after each erase, so the erase adds nothing (FMT-15.11).

FMT-15.9 **No pruning.** The reference never removes items by age or by count. The maintenance setting in Meta (FMT-10) does not touch the list. Only the deletion pass of a merge rewrites the list (FMT-15.11): in the reference only in synchronize mode; in App also in a same-vault merge (FMT-15.10, LD-265). Loading and saving keep the list exactly. The list is dropped from memory when the vault is closed. We do the same: App never prunes the list (decided: spec/decisions.md, default rule: the reference behavior for L15-1).

FMT-15.10 **Merge, default mode.** The reference's normal merge uses the keep-newer mode. This covers the merge command, merging from the screen, and merging after the file changed on disk. In the reference, this mode never reads or changes either vault's list:
- the source's deletions are not applied to the target;
- the source's items are not copied into the target;
- an entry deleted in the target but still present in the source comes back from the source, and the target's item for it stays.

App (decided: spec/decisions.md LD-265, LD-267 (2), LD-269 (3); design: spec/research/sync-server.md P2): a keep-newer merge that is a **same-vault merge** runs the deletion pass of FMT-15.11 over the whole vault after the group step, with both vaults' lists. Same vault has one meaning, the one in MOD-11's Notation (LD-267 (2)); the key, or the user's own credentials, is the proof, the root group id alone is not. This covers the merge after a change on disk, a conflict copy that a cloud made (APP-05.17), an older disk version that the rollback guard merges (APP-05.26), server sync, and a merge from another copy of this vault (MOD-11.27, MOD-11.28). So an entry deleted for good on one copy stays deleted, unless the other copy changed or moved it after the deletion (FMT-15.11, LD-271 (2)). Every other keep-newer merge keeps the reference behavior above, with no pass: a vault that is not the same vault, a copy under a key this Mac retired (MOD-11.31), and the import wizard. One exception: Merge anyway, for a copy under a key this Mac retired, drops this Mac's items for the entries and groups it adds back, the recycle bin included (MOD-11.31; LD-313, LD-315). Why: only a key holder can make a copy that opens with the vault's key, so its deletions are the user's own (LD-265). This goes beyond the reference app (parity row SD-03).

FMT-15.11 **Merge, synchronize mode, and the deletion pass.** The reference uses this mode only when it imports a shared group (INT-08). After merging the groups and entries, it rebuilds the target's list with the deletion pass below. App runs the same pass in two places (decided: spec/decisions.md LD-265, LD-271):
- **In a shared-group import** (MOD-11.15, D-11-9, INT-08). It erases only inside the shared group. An item from the share's list whose id names an entry or group outside the shared group is dropped from the rebuilt list; the target's own items stay as they were. Before the pass, each item of the share's list dated later than the import time (App's clock, whole seconds) takes the import time (LD-271 (1)); the pass and the rebuilt list use that time, so every item the import keeps is dated no later than the import. A share's item whose id names nothing in the target, or an object inside the shared group that the pass erases, stays in the rebuilt list (steps 1 and 3; the round trips of FMT-15.12 need it). In this pass an object's time is its `LastModificationTime`, as in the reference: the one the target holds after the group step. Neither `LocationChanged` nor the share's own times count (D-11-9; LD-287 (2) changes the whole-vault pass only; test 15-28).
- **In every same-vault merge** (FMT-15.10), the whole-vault pass: it erases anywhere in the vault (LD-265), and an object's time is the latest `LastModificationTime` or `LocationChanged` that either side holds for it: the merged object's own, and the source copy's when the source holds it (decided: spec/decisions.md LD-287 (2)). It is read per kind: an entry's time from the source's entry, a group's from the source's group, because an entry and a group may share an id (MOD-11.22; LD-288 (1)). So a move counts as a change, on either side (LD-271 (2)). The pass only reads the source copy's times; it never writes them into the target, so reading them adds no change record of its own (MOD-11.26).

Known limit (LD-271 (3); MOD-11.15, MOD-11 T65, SI-09; spec/research/sync-server.md P2): a member of a share can delete an entry that was shared with them, and if another copy of the vault moved that entry out of the shared group earlier than that deletion, the later same-vault merge erases it. A member can only name ids it was shown, because ids are 128 random bits. A record on this Mac of the items a share import placed is not taken: it does not travel with the vault file, so another Mac would still apply the item (LD-271 (4)).

The pass:
1. Walk the target's items, then the source's items. At the first sight of an id:
   - if the target vault holds an entry with that id, mark the entry for a check;
   - otherwise, if it holds a group with that id, mark the group for a check;
   - otherwise, put the item into the new list as it is.
2. At a later sight of the same id, remember whichever of the two times is earlier, for the checks in steps 3 and 4. An item already placed in the new list in step 1 is not changed: it keeps the time of its first sight. (Quirk; source, re-read by Verify: the merge keeps its own copy of each item it places at first sight, and later sights only update the earliest time kept for the checks of steps 3 and 4.)
3. For each marked entry:
   - if the entry's time (above: in a shared-group import its `LastModificationTime`; in the whole-vault pass the latest `LastModificationTime` or `LocationChanged` that either side holds for the entry, never a same-id group's) is later than the earliest deletion time, keep the entry and drop the item. Later means strictly later: an equal time does not keep it;
   - otherwise, put the item (with the earliest time) into the new list and erase the entry.
4. For each marked group, after its child groups have been decided:
   - keep the group and drop the item if the group's time (as in step 3, read from the groups: in the whole-vault pass the latest `LastModificationTime` or `LocationChanged` that either side holds for the group, never a same-id entry's) is strictly later than the earliest deletion time, or if the group still holds any entry or group;
   - otherwise, put the item into the new list and erase the group.
5. If the new list differs from the target's old list, it replaces the old one.

So the pass removes duplicate ids and drops items for objects that were kept. Wherever App runs the pass (a same-vault merge, FMT-15.10; a shared-group import, MOD-11, INT-08), it rebuilds the list by these steps, the step 2 quirk included (decided: spec/decisions.md, default rule: the reference behavior for L15-3).

FMT-15.12 **Shared export.** When the reference writes a shared-group container (INT-08), it copies the whole list of the source vault into that container. This includes items for objects that were never in the shared group. App does the same: it copies the whole list (decided: spec/decisions.md, default rule: the reference behavior for L15-2). The list does not record where a deleted object sat, so App could not pick out the items that belong to the share anyway. INT-08 owns the export.

FMT-15.13 **No effect on version.** The list never raises V: none of the raises of FMT-16.3 to FMT-16.10 looks at it, so it changes neither App's choice of 4.0 or 4.1 by content nor the reference's choice between 3.1, 4.0 and 4.1. One exception in App: while the vault holds kept unknown children (FMT-15.4), App writes at least the version the file was read as (FMT-16.24), as for every kept unknown element (FMT-11.45; decided: spec/decisions.md LD-09). A file read as 4.1 is written as 4.1, a file read as 4.2 as 4.2.

FMT-15.14 **Limits.** The item limit is `deleted objects` in FMT-08.12, which owns its number (decided: spec/decisions.md LD-22; test row 15-20 uses the number FMT-08.12 gives today; tests must be able to lower it). It counts every `DeletedObject` element in all `DeletedObjects` blocks, including items that are then dropped (FMT-15.4). When the element that would pass the limit starts, the read stops with `TooLarge`, naming the limit, before anything is stored for it (as FMT-11.48). A list within the limit is read in full, with memory that grows with the item count only (AT-A08).

## Edge cases and errors

- The reference's broken sample (stem BrokenDeletedObjects) holds three items:
  - an item with an empty `UUID` and a time: dropped;
  - an empty `DeletedObject`: dropped;
  - an item with id `5K/bzWCSmkCv5OZxYl4N/w==` and an empty `DeletionTime`: kept, with time 0001-01-01T00:00:00Z.
  
  The open succeeds.
- An item that names a live entry: both are kept (FMT-15.5). The reference's default-mode merges, and App's merges that are not same vault, can create this on purpose (FMT-15.10). A vault made that way keeps both until the next same-vault merge: its pass erases such an entry unless either copy changed or moved it after the item's time (FMT-15.11 step 3, LD-265, LD-271 (2), LD-287 (2)). The backup of APP-05.19 holds the copy before that save.
- The same id deleted, brought back by a merge, and deleted again: two items with that id (FMT-15.5).
- A deleted custom icon's id sits in the same list as entry and group ids. A reader must not assume an item names an entry or a group.
- There is no error case: nothing in this list fails the open, except going over the limit (FMT-15.14) and XML syntax errors (FMT-11.41).

## Security notes

- **No secrets.** Items hold only ids and times. Never put a name, title or any other value into this list.
- **The list still leaks metadata:** how many things were deleted, and when. The reference copies the whole list into shared-group containers (FMT-15.12). That tells everyone the share reaches how often, and when, the owner deleted unrelated items. App does the same (FMT-15.12), so this leak is accepted; INT-08 should tell the user that a share carries the vault's deletion list.
- **The list grows without end** in the reference (FMT-15.9). A hostile file can hold millions of items. The reader must stop at the limit (FMT-15.14; AT-A08, AT-A10).
- **A hostile source vault, in synchronize mode, can delete entries in the target (SI-09).** It only needs to list their ids with a time later than their last change. In the reference the deletion pass searches the whole target vault from its root group, not only the shared group, so matching entries and empty groups anywhere in the target can be erased. App limits a share's pass to the shared group (MOD-11.15, D-11-9), drops from the rebuilt list every share item that names an object outside it on this Mac (FMT-15.11), and runs the pass only for a share the user approved (INT-08.31). A share item whose id names nothing here, or an object inside the shared group that the import erased, stays in the list, but with a time no later than the import: the import clamps a future-dated item to the import time (FMT-15.11, LD-271 (1)), so it cannot erase every later edit until its date. The whole-vault pass of a later same-vault merge keeps an object whose last change or last move is later than the item's time (LD-271 (2)), so an entry that another copy moved out of the shared group after the import stays. Known limit (LD-271 (3)): a member can delete an entry that was shared with them, and if another copy moved it out of the shared group earlier than that deletion, the later same-vault merge erases it; a member can only name ids it was shown, because ids are 128 random bits (FMT-15.11, MOD-11.15, MOD-11 T65). A share is never a same-vault merge, even when its root group id equals the vault's: it opens with the share password, not with the vault's key (MOD-11 Notation). App runs the pass over the whole vault only in a same-vault merge (FMT-15.10), because only a key holder can make a copy that opens with the vault's key, so its deletions are the user's own (LD-265; spec/research/sync-server.md P2). A copy under a key this Mac retired gives no deletions and is never merged on its own (LD-267 (2), LD-269 (3)): a password change often follows a leak, and whoever knows the old password must not delete entries.
- **No lost data on merge (SD-03, AT-I05).** A merge keeps every entry of both sides, except an entry that the same vault's deleted-objects list removed after its last change (FMT-15.11, LD-265). Only a key holder can make a copy that opens with the vault's key, so the deletions it carries are the user's own. In the reference's default mode the list is never read, so an entry deleted on one copy comes back from any other copy that still holds it; App goes further for a same-vault merge only (FMT-15.10).

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| 15-01 write at 4.0 | Items: id(77) at 2020-07-07T07:07:07Z, then id(78) at 2020-07-08T07:07:07Z | Write at 4.0 | `<DeletedObjects><DeletedObject><UUID>d3d3d3d3d3d3d3d3d3d3dw==</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime></DeletedObject><DeletedObject><UUID>eHh4eHh4eHh4eHh4eHh4eA==</UUID><DeletionTime>m2eX1g4AAAA=</DeletionTime></DeletedObject></DeletedObjects>` right after the root `Group`. FMT-15.1, 15.2, 15.3 |
| 15-02 text times read | A 3.1 file (as the reference writes it) whose list holds id(77) with `<DeletionTime>2020-07-07T07:07:07Z</DeletionTime>` and id(78) with `<DeletionTime>2020-07-08T07:07:07Z</DeletionTime>` | App reads, then writes | The same two items and times as 15-01; written in the binary form, `GxaW1g4AAAA=` and `m2eX1g4AAAA=`. App never writes the text form. FMT-15.2 |
| 15-03 empty list | No items | Write | `<DeletedObjects/>` after the root group. FMT-15.1 |
| 15-04 broken sample | Items: (`<UUID/>`, `<DeletionTime>2010-08-25T16:14:12Z</DeletionTime>`); `<DeletedObject/>`; (`<UUID>5K/bzWCSmkCv5OZxYl4N/w==</UUID>`, `<DeletionTime/>`) | Read, write at 4.0 | Opens. List = one item: `5K/bzWCSmkCv5OZxYl4N/w==` at 0001-01-01T00:00:00Z, written `<DeletionTime>AAAAAAAAAAA=</DeletionTime>`. FMT-15.4 |
| 15-05 lenient items | Items: (time `2021-01-01T00:00:00Z` before `UUID` id(31)); (`<UUID>QUJD</UUID>`, valid time); (id(32), `<DeletionTime>yesterday</DeletionTime>`); (id(33), no `DeletionTime`) | Read | List = [id(31) at 2021-01-01T00:00:00Z, id(32) at the open time]. FMT-15.4 |
| 15-06 no clean-up | Live entry id(10). Items: id(10) at 2020-01-01; id(30) at 2020-01-01; id(30) at 2021-01-01; id(40) at 2099-01-01 | Read, write | All four items kept, in order. Entry id(10) still present. FMT-15.5 |
| 15-07 two blocks | `Root` = `DeletedObjects`[id(77)], `Group` id(01), `DeletedObjects`[id(78)] | Read, write | One block written, with items id(77), id(78). FMT-15.6 |
| 15-08 delete group for good | Recycle bin off. G1 holds E1 and child G2; G2 holds E2 | Delete G1 at 2026-10-24T19:20:00Z | Four items added at the end, all at 2026-10-24T19:20:00Z: E1, E2, G2, G1. FMT-15.7 |
| 15-09 bin then delete | Bin on. Entry E3 in the root | Delete E3 (it goes to the bin), then delete E3 from the bin | No item after the first step. After the second step, one item: E3. FMT-15.7, 15.8 |
| 15-10 empty the bin | Bin holds entries X and Y and group S; S holds entry Z | Empty the bin | Items X, Y, Z, S. The bin group stays, with no item for it. FMT-15.7 |
| 15-11 other actions | Vault with custom icon id(A1) and entry E with two history items | Remove icon id(A1); delete one history item of E; move E to the bin and restore it | Exactly one item added: id(A1). FMT-15.7, 15.8 |
| 15-12 move to another vault | Vault A holds group G with entry E; vault B open | Move G into B | A's list gains E, then G. B's list is unchanged. FMT-15.7 |
| 15-12b bin turned off | Bin B holds entry X and group S; S holds entry Z | In the vault settings, turn the bin off and choose to delete it | Items X, Z, S, B, in that order, all with the same time. FMT-15.7 |
| 15-12c multi-selection | Bin on. Entry P in the bin, entry Q outside it | On the main screen select P first, then Q, and delete | Both deleted for good: items P, Q, in selection order. With Q selected first, both go to the bin and no item is added. FMT-15.7 |
| 15-13 no pruning | Vault with 3 items, the oldest from 2001 | Open and save 100 times | The same 3 items, same times, same order. FMT-15.9 |
| 15-14 default merge, not same vault | M1 holds E and F; M2 is a copy; in M2, E is deleted for good (M2's list = [E]) | Default-mode merge of M2 into M1: in the reference; in App with M2's root group id changed to another id, and again with M2 saved under a key this Mac retired and "Merge anyway" (MOD-11.31) | M1 still holds E and F. M1's list is empty (the reference: observed with the installed CLI's merge command; App the same in both runs). FMT-15.10 |
| 15-15 synchronize merge, entries | Target and source share entry X and entry Y. The source deleted X at t1, after the target changed X at t0 < t1. The target changed Y at t3, after the source deleted Y at t2 < t3 | Synchronize-mode merge | X erased, item X at t1 in the target's list. Y kept, no item for Y. FMT-15.11 |
| 15-16 synchronize merge, groups | The source deleted group G at t1. In the target, G holds entry Z, changed at t2 > t1 | Synchronize-mode merge | G and Z kept; no item for G or Z. FMT-15.11 |
| 15-17 synchronize quirk | Target item id(30) at 2021-01-01; source item id(30) at 2020-01-01; no object with id(30) anywhere | Synchronize-mode merge | The target's list holds id(30) once, at 2021-01-01, the time of its first sight (the reference, source re-read by Verify; App the same, L15-3 decided). FMT-15.11 |
| 15-18 shared export | Vault list: [id(77)]. Shared group G does not contain id(77) | Write the shared-group container per INT-08 | Reference and ours: the container's list holds id(77) (L15-2 decided: the whole list is copied). FMT-15.12 |
| 15-19 version | Vault with legacy AES-KDF and no feature of FMT-16.3 to FMT-16.10, list of 5 items | Run App's chooser and the reference's chooser (FMT-16) | App: 4.0 (LD-07: App never writes 3.1). The reference: 3.1. The same without the list gives the same versions. FMT-15.13 |
| 15-20 limit | File A: `DeletedObjects` with 1,000,000 items, each a distinct id and a valid time. File B: 1,000,001 items, split over two `DeletedObjects` blocks (500,000 and 500,001). File C: 1,000,000 valid items plus one `<DeletedObject/>` | Read | A opens with 1,000,000 items. B and C: `TooLarge`, naming the deleted-objects limit (C counts the item that would be dropped). Memory stays under the limit set for the document. FMT-15.14 |
| 15-21 repeated children | Item A: `<UUID>MDAwMDAwMDAwMDAwMDAwMA==</UUID><UUID/><DeletionTime>GxaW1g4AAAA=</DeletionTime>`. Item B: `<UUID>MDAwMDAwMDAwMDAwMDAwMA==</UUID><UUID>MTExMTExMTExMTExMTExMQ==</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime><DeletionTime>m2eX1g4AAAA=</DeletionTime>`. Item C: `<UUID>MTExMTExMTExMTExMTExMQ==</UUID><UUID>QUJD</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime>` | Read, write at 4.0 | List = [id(30) at `GxaW1g4AAAA=` (2020-07-07T07:07:07Z); id(31) at `m2eX1g4AAAA=` (2020-07-08T07:07:07Z); id(31) at `GxaW1g4AAAA=`]. In A and C the later invalid `UUID` is ignored. The installed CLI gives the same three items (observed: XML import with text times, saved at 3.1, decrypted). FMT-15.4 |
| 15-22 unknown children | Item D: `<UUID>MDAwMDAwMDAwMDAwMDAwMA==</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime><DelExtra a="1"/>`. Item E: `<DeletionTime>GxaW1g4AAAA=</DeletionTime><DelExtra2/>` (no `UUID`) | Read, write at 4.0 | One item, id(30), written `<DeletedObject><UUID>MDAwMDAwMDAwMDAwMDAwMA==</UUID><DeletionTime>GxaW1g4AAAA=</DeletionTime><DelExtra a="1"/></DeletedObject>` (ours, decided: spec/decisions.md LD-27). Item E is dropped, and `DelExtra2` with it. The reference keeps D without `DelExtra` and drops E (observed with the installed CLI in review round 2). FMT-15.4 |
| 15-22b unknown child keeps the version | File A: a 4.1 file whose only unknown part is item D of 15-22 (with `<DelExtra a="1"/>`), and nothing else in the vault needs 4.1. File B: the same document in a 4.0 file. File C: the same document in a file whose header says 4.2 | Read, let FMT-16 choose V, write | A: V is 4.1 (LD-09, FMT-16.24), and item D is written with `<DelExtra a="1"/>` after `DeletionTime`. B: V is 4.0, item D written the same way. C: V is 4.2 (header minor version `02 00`), item D written the same way. FMT-15.13, 15.4 |
| 15-23 time out of range | Item F: `<UUID>MDAwMDAwMDAwMDAwMDAwMA==</UUID><DeletionTime>/////////38=</DeletionTime>`. Item G: `<UUID>MTExMTExMTExMTExMTExMQ==</UUID><DeletionTime>2f////////8=</DeletionTime>` (-39 seconds) | Read, write at 4.1 | Ours: both items kept, written with `/////////38=` and `2f////////8=` unchanged; no panic. The installed CLI (observed in review round 3): F written `//////////8=`, G `2f////////8=`. The source: F probably dropped (check with Verify). FMT-15.4 |
| 15-24 same-vault merge (LD-265) | M1 holds E (Mod 2026-01-01) and F (Mod 2026-01-01); M2 is a copy with the same root group id, opened with M1's key; in M2, E is deleted for good at 2026-02-01 (M2's list = [E at 2026-02-01]). Second run: the same, but in M1 E was edited at 2026-03-01 | App merges M2 into M1 (same-vault merge) | First run: E erased from M1, F stays; M1's list = [E at 2026-02-01]. Second run: E stays with the 2026-03-01 edit; M1's list stays empty. The reference (15-14) keeps E in both runs. FMT-15.10, 15.11 |
| 15-25 no whole-vault pass for a share | Vault V (root id(01)) holds entry X outside shared group S. A share container whose root group id is also id(01), opened with the share password, lists X deleted at a time later than X's change | App imports the share into S; then App merges into V a copy of V from before the import (same root group id, opened with V's key) | X stays after both; V's key and settings unchanged; the import erases only inside S (MOD-11.15, D-11-9), and V's list holds no item for X, so the same-vault merge erases nothing. FMT-15.10, 15.11 |
| 15-26 a share's item is clamped (LD-271 (1)) | Vault V: shared group S holds entry X (Mod 2026-01-01); id(40) names nothing in V. The share lists X at 2099-01-01 and id(40) at 2099-01-01, and id(41) at 2026-02-01 | App imports the share into S at 2026-03-01 (test clock) | X erased; V's list = [id(40) at 2026-03-01, id(41) at 2026-02-01, X at 2026-03-01] (step 1 places id(40) and id(41) during the walk, step 3 places X's item after them); no item dated 2099. FMT-15.11 |
| 15-27 a move counts as a change in the whole-vault pass only (LD-271 (2)) | M1 holds entry E (Mod 2026-01-01, LocationChanged 2026-03-01) and empty group G (Mod 2026-01-01, LocationChanged 2026-03-01). M2 is a copy with the same root group id, opened with M1's key, whose list holds E and G at 2026-02-01. Second run: vault M3 whose shared group S holds E and G with the same times; a share lists E and G at 2026-02-01 | App merges M2 into M1 (same-vault merge); second run: App imports the share into M3's S at 2026-04-01 (test clock) | Same-vault merge: E and G stay, M1's list gains no item for them. Import: E and G erased in M3 (their `LastModificationTime` is earlier than 2026-02-01), items E and G at 2026-02-01 in the list. FMT-15.11 |
| 15-28 either side's time, read per kind, strictly after the item (LD-287 (2), LD-288 (1)) | M1 and M2 share the root group id, M2 opened with M1's key; both hold entry E and empty group G in the same place. (a) M1: E and G at `LastModificationTime` 2026-02-01, `LocationChanged` 2026-01-01; M2: E and G at `LastModificationTime` 2026-01-01, `LocationChanged` 2026-04-01; items for E and G at 2026-03-01 in M1's list (as a merge that was not same vault leaves it, FMT-15.5) or in M2's. (b) As (a), but M2 moved E and G at exactly 2026-03-01. (c) Both hold E at 2026-02-01 and 2026-01-01; a group H with E's id holds entry F, and only M2's H moved, at 2026-04-01; the item for E at 2026-03-01. (d) Vault M3: shared group S holds E (`LastModificationTime` 2026-01-01); the share holds E with `LastModificationTime` 2026-01-01 and `LocationChanged` 2026-04-01 and lists E at 2026-02-01 | (a) to (c): App merges M2 into M1 (same-vault merge), then the same M2 again; (d) App imports the share into S | (a) E and G stay after both merges, no Deleted record (M2's moves count). (b) E and G erased: an equal time does not keep. (c) E erased (a group's time never keeps an entry); H stays, as it holds F. (d) E erased: the import reads `LastModificationTime` alone. As MOD-11 T68 to T73 and their tests. FMT-15.11 |

## How this was learned

- **Reference source, read only.** These parts were studied:
  - the document reader and writer parts for this list;
  - the vault's list functions: add, replace, contains;
  - every place in the source that adds an item: the entry and group clean-up paths, the move code for an item that leaves its vault, icon removal;
  - the recycle bin functions (move to bin, empty bin);
  - the delete actions of the main screen and of the command line tool;
  - the vault general-settings save routine (turning the bin off);
  - the merge routine (deletion pass, erase helpers, merge mode lookup and its fallback);
  - the shared-group export and import code;
  - the reference tests for deleted objects and for merge deletion conflicts.
- **The installed reference CLI, 2.7.11.** Observed with demo vaults made in `/tmp/spec-fmt11-14-15/` (password `demo-pass`) and decrypted with the scratch tool described in FMT-11:
  - the broken sample read through the XML import (one item kept, at 0001-01-01);
  - duplicates and items naming live entries kept;
  - deletion order E3, E1, E2, G2, G1 after "rm" from the bin and "rmdir" from the bin;
  - the default merge leaving a deleted entry in the target and the target's list empty;
  - in review round 2 (`/tmp/spec-review-r2-fmt11-14-15/`): an item with an unknown child, a valid id and a time kept, and an item with only an unknown child and a time dropped (test 15-22);
  - repeated `UUID` and `DeletionTime` children (test 15-21), in `/tmp/spec-fmt11-14-15/r3/`. The rule that an invalid `UUID` never clears an earlier valid one was first read from the document reader's deleted-object part.
- **Installed version against the source.** One difference: a `DeletionTime` out of the toolkit's range (FMT-15.4, test 15-23), kept with wrapped arithmetic by the installed version and probably dropped by the source. No other difference was found for these rules.
- **check with Verify:**
  - FMT-15.4, the out-of-range `DeletionTime` row (test 15-23): that a build of the source drops the item. The installed version's wrap was observed in review round 3 (`/tmp/spec-review-r3-fmt11-14-15/`); the source's drop was reasoned from the deleted-object reader and the toolkit's overflow rule, not run. Needs a build of the source on toolkit version 6.
- **Checked by Verify (Sprint 2), source re-read, not run:**
  - FMT-15.11 step 2: confirmed in the merge's deletion step. An id not found in the target is copied into the new list at its first sight; a later sight only updates the earliest time kept for the entry and group checks.
  - Only shared-group import uses synchronize mode. Shared-group import is the only caller that forces the mode. No product code sets a group's own merge mode (only the reference's unit tests do), the mode is not stored in the file, and a group with no mode of its own takes its parent's, and the root falls back to keep-newer (a comment in the source says synchronize, but the code returns keep-newer). So the reference's window merge and CLI merge never read the list.
  - The bin-off row of FMT-15.7 and the interface details under it (tests 15-12b, 15-12c). Turning off a non-empty bin asks Delete or No (No preselected). Delete destroys the bin group, whose teardown records its entries, then its child groups by the same rule, then itself. No renames it with " (old)" and gives it the default icon. An empty bin gets no question and stays as it is. The main screen checks only the first selected entry ("for good" when it is in the bin or the bin is off) and then deletes or recycles every selected entry in selection order. The CLI group removal deletes for good only when the bin is off or the group is the bin or inside it, and recycles otherwise. One nuance: each record takes its own clock reading, so "all with the same time" holds when the deletions fall within one second.
- **Lead decisions (all decided, spec/decisions.md):**
  - L15-1 pruning: never prune, as the reference (default rule; FMT-15.9). Not chosen: prune items older than a set number of days.
  - L15-2 shared export: copy the whole list, as the reference (default rule; FMT-15.12). Not chosen: copy only items for the share.
  - L15-3 synchronize quirk of FMT-15.11 step 2: copy it, as the reference (default rule). Not chosen: use the earliest time.
  - L15-4 item limit: LD-22, the number of FMT-08.12 (FMT-15.14).
  - Also applied here: LD-27 (kept unknown children, FMT-15.4) and LD-09 (version, FMT-15.13).
- E15-S1 (2026-10-31): FMT-15.9, FMT-15.10, FMT-15.11 (with the share scope of the rebuilt list and its known limit, MOD-11 T65), the edge case on items that name a live entry, the security notes and tests 15-14, 15-24 and 15-25 now carry App's same-vault deletion pass (LD-265, LD-267 (2), LD-269 (3)), from spec/research/sync-server.md P2. No reference source was read for these edits; the reference facts above are unchanged. Parity note: App goes beyond the reference app here (SD-03).
- E16-S1 (2026-10-31): FMT-15.10, FMT-15.11 (a share's items clamped to the import time; the whole-vault pass counts a move as a change; the known limit that is left; the local record not taken), the edge case on items that name a live entry, the SI-09 security note and tests 15-26 and 15-27 carry LD-271 (1) to (4). No reference source was read for these edits; the share pass keeps the reference's `LastModificationTime` check, because LD-271 (2) names the whole-vault pass only.
- E15-S2 Spec run (2026-11-01, after E15-S2 signed): FMT-15.11 (the whole-vault pass reads the latest `LastModificationTime` or `LocationChanged` that either side holds, per kind, strictly after the item; steps 3 and 4; a share import still reads `LastModificationTime` alone), the edge case on items that name a live entry and test 15-28 carry LD-287 (2) and LD-288 (1), matched to E15-S2's signed code and tests in app-core, read only. No reference source was read.
- Sprint 1 close-out: the intro and FMT-15.13 now say "at least the version the file was read as (FMT-16.24)" (LD-09); test 15-22b has a 4.2 file C. FMT-15.14 and Inputs and outputs point to FMT-08.12 for the limit number.
