# MOD-02 Groups and what entries inherit from them

Status: reviewed
Epics: E4-S1
Parity rows: SD-03, SD-05, SI-04, SI-06

## What it does

Groups form a tree that holds the entries of a vault. This card says what a group holds in App's model (app-model `group.rs`), the rules for the root group, how the auto-type, search and browser switches and the auto-type sequence are inherited down the tree, how groups and entries are moved, reordered and sorted, what a new group gets, and which changes move a group's times. FMT-11 owns how groups are written in the file (FMT-11.6 table) and how the tree is read (FMT-11.33 to FMT-11.37).

Words used in this card (and as in MOD-01): **now**, **change batch**, **live entry**. **Inherit**, **On**, **Off** are the three values of a group switch; in the file they are `null`, `true` and `false` (FMT-11.9). The **subtree** of a group is the group and every group below it at any depth. **Same vault** means both groups belong to one open vault.

Neighbor cards: MOD-01 (entries), MOD-04 (recycle bin, delete, restore), MOD-06 (icons, apply icon to children), MOD-07 (tags), MOD-09 (expiry), MOD-10 (clone), MOD-11 (merge), FEA-01 (search), INT-02 (browser options), INT-05 (auto-type), INT-08 (shared groups), INT-10 (command line), APP-05 (when changes are saved), APP-07 (new vault and its root group), APP-08 (menus and shortcuts).

## Inputs and outputs

Every group property, its model type, what a new group gets, and who changes it. The last column points to the row of the FMT-11.6 table.

| # | Property | Model type | New group (App) | Changed by | FMT-11.6 row |
|---|---|---|---|---|---|
| 1 | Id | 16 bytes | random RFC 4122 version 4 UUID, unique among groups (as MOD-01.12) | nobody after creation | 1 |
| 2 | Name | text | as typed, may be empty | user | 2 |
| 3 | Notes | text, multi-line | empty | user | 3 |
| 4 | Tags | raw text | empty | nobody: carried (MOD-02.8) | 4 |
| 5 | Icon | standard number or custom icon id | 48 (MOD-06.2) | user, MOD-06 | 5, 6 |
| 6 | Times: creation, last modification, last access, location changed, expiry time; expires flag; usage count | as for entries | commit time for all five times; expires false; usage count 0 (D-01-4) | MOD-02.25, MOD-02.29 | 7 |
| 7 | Expanded | boolean | true | sidebar expand and collapse (MOD-02.5) | 8 |
| 8 | Default auto-type sequence | text, empty means inherit | empty | user | 9 |
| 9 | Auto-type switch | Inherit, On, Off | Inherit | user | 10 |
| 10 | Search switch | Inherit, On, Off | Inherit | user | 11 |
| 11 | Last top visible entry | entry id or none | none | nobody: carried (MOD-02.11) | 12 |
| 12 | Custom data | items of FMT-14 | none | plug-ins (INT-02, INT-08); the user may only delete | 13 |
| 13 | Previous parent group | group id or none | none | moves only (MOD-02.20) | 14 |
| 14 | Entries | ordered list of live entries | none | MOD-01, MOD-02.21, MOD-02.24 | 15 |
| 15 | Child groups | ordered list of groups | none | MOD-02.20, MOD-02.26 | 16 |
| 16 | Kept unknown elements | FMT-11.45 | none | nobody | none |

The reference also keeps a merge mode per group in memory only. It is never stored and is not part of App's group (MOD-11).

## Rules

### The tree

MOD-02.1 **Shape.** A vault has exactly one root group. Every other group has exactly one parent group. No group is inside itself (app-model `invariants.rs`; reading: FMT-11.36). Group ids are unique among groups; entry ids are a separate space (FMT-11.33). The order of child groups and the order of entries inside a group are stored orders: they survive open and save, and screens that show "stored order" show them.

MOD-02.2 **Root group.**
- It is made with the vault. Its name is set by APP-07 (the reference's new vault wizard uses its UI word for "Root"; vaults made by its command line tool get its UI word for "Passwords").
- It cannot be deleted, moved, cloned or put into the recycle bin. Every other property can be edited like any group's.
- Inherit on the root resolves to On for both switches (MOD-02.13, MOD-02.14); a missing browser option on the root resolves to off (MOD-02.17).
- Its previous parent group is always none. It may hold entries. The recycle bin, when one exists, is made as its child (MOD-04).

MOD-02.3 **Name and notes.** A name is any text: empty allowed, no trimming, duplicate names among siblings allowed, `/` allowed (the command line tool's paths then become ambiguous: INT-10). The group edit screen's name box is single-line: in App, each line break in typed or pasted text becomes one space, the rule of MOD-01.5 (the reference's single-line box was not run with pasted line breaks: check with Verify). Notes are multi-line text kept exactly. Names and notes from files are kept exactly.

MOD-02.4 **Icon.** A standard icon number or a custom icon (MOD-06); 48 for a new group (MOD-06.2). "Apply to children" is MOD-06.13.

MOD-02.5 **Expanded.** View state stored in the file: whether the sidebar shows the group's children. It is set when the user expands or collapses the group in the sidebar. App's sidebar opens each group as this flag says. APP-05 decides when such a view-state change is saved.

MOD-02.6 **Default auto-type sequence.** Empty means "inherit" (MOD-02.15). On the group edit screen the user picks "inherit" (the group stores empty text) or "custom", whose text box starts with the group's effective sequence (MOD-02.15); saving "custom" stores the text as typed, and an empty custom text is stored as empty, which means inherit.

MOD-02.7 **Switches.** The auto-type switch and the search switch each hold Inherit, On or Off; a new group has Inherit for both. The edit screen shows Inherit together with the value it currently resolves to from the parent (for example "Inherit (On)"). The recycle bin is made with both switches Off (MOD-04).

MOD-02.8 **Group tags.** A group carries a tags text from the file, kept raw (FMT-11.27). Nothing in the reference shows, edits, searches, lists or merges it. App does not show, edit, search or list it either: group tags are not in the vault tag list (MOD-07.5) and not matched by tag search (FEA-01). A merge copies it with the group's other own fields (MOD-11.10, lead decision D-11-3).

MOD-02.9 **Custom data.** Plug-in data (FMT-14): browser options (MOD-02.17, INT-02) and shared-group settings (INT-08). The group edit screen's properties page lists the items and lets the user delete selected items after a confirmation; the user never adds or changes one there. Deleting is a change (MOD-02.29).

MOD-02.10 **Previous parent group.** Set only by moves (MOD-02.20), by the recycle bin (MOD-04) and by merge moves (MOD-11.8). No screen edits it.

MOD-02.11 **Last top visible entry.** Carried only: the reference sets it only when reading a file, and App does the same. A reference that finds no entry resolves to none and is written as the zero id (FMT-11.37).

MOD-02.12 **Group expiry.** A group has its own expires flag and expiry time, set on the group edit screen. An expired group is shown struck through and with the expired badge (MOD-06.16, MOD-09.14). It does not make its entries expired and does not hide them.

### Inheritance

MOD-02.13 **Search switch.** A group's effective search value is its own value when that is On or Off. When it is Inherit, the value is its parent's effective value, and so on up the tree; Inherit on the root means On. A search (FEA-01) looks at every group of its scope whose effective value is On and checks that group's own entries only. So a group set On below a group set Off is searched, while a group set Inherit below it is not. The search on screen always follows the switch. The command line search and the command line copy command ignore it and look at every group (INT-10). The browser bridge ignores the search switch too (it uses MOD-02.17).

MOD-02.14 **Auto-type switch.** Resolved the same way as MOD-02.13 (Inherit on the root means On). An entry may be auto-typed only when its own auto-type flag is on (MOD-01.18) and its group's effective auto-type value is On (INT-05).

MOD-02.15 **Effective sequence of a group.** Start at the group and walk up the tree:
1. If the current group's own auto-type switch is Off, the result is empty: no sequence.
2. Take the current group's default sequence. If it is not empty, that is the result.
3. Otherwise move to the parent and repeat from step 1.
4. When the root has been passed without a result, the result is the built-in default `{USERNAME}{TAB}{PASSWORD}{ENTER}`.

The walk checks Off only on the groups it visits, and it stops at the first group with a sequence. So an Off on a group above the one that gives the sequence does not empty the result; MOD-02.14 still blocks typing in that case. INT-05 owns the sequence language.

MOD-02.16 **Effective sequence of an entry.**
1. Empty if the entry's own auto-type flag is off, if the entry sits in no group, or if its group's effective sequence (MOD-02.15) is empty.
2. Otherwise the entry's own default sequence, when that is not empty.
3. Otherwise, when the group's effective sequence is exactly the built-in default and the entry has a user name or a password (raw values, before placeholders): user name empty gives `{PASSWORD}{ENTER}`; password empty gives `{USERNAME}{ENTER}`; both set gives the built-in default.
4. Otherwise the group's effective sequence.

MOD-02.17 **Browser options.** Each browser option (FMT-14.20: hide entries, skip auto-submit, only HTTP auth, never HTTP auth, omit www) is a group custom data key. Resolution for a group: walk up from the group to the first group that has the key; the option is on when that value is exactly `true` (lowercase) and off for any other value; when no group up to the root has the key, the option is off. The restrict-to-browser key resolves to the value of the first group up the tree that has the key, even an empty value (empty means no restriction); no key anywhere means no restriction. The group edit screen writes `true` for On, `false` for Off and removes the key for Inherit. INT-02 owns what the options do and how entry-level options combine with them.

MOD-02.18 **Recycled and shared state.** An entry or group is "recycled" when it, or a group above it, is the recycle bin (MOD-04). A group is "shared" when it, or a group above it, carries the shared-group key (INT-08).

### Moving and ordering

MOD-02.19 **Move operations.** App's core offers: move a group (to a target group and a final position), move entries (to a target group), reorder an entry inside its group, sort groups, and cross-vault move or copy. Screens reach them by drag and drop and by menus (APP-08). Every move is one change batch.

MOD-02.20 **Moving a group inside the vault.**
- Refused: moving the root; a target that is the group itself or lies in its subtree. A refused move changes nothing.
- The recycle bin itself may be moved like any other group (the reference allows it). Moving a group into the recycle bin's subtree puts it in the bin (MOD-04 owns delete).
- Position: the caller gives the final index in the target's child list (0 up to the list length after removal), or "end". A drop between two rows of the sidebar maps to the index the group will have after the move (the reference counts the drop row before removal and subtracts one when the group moves down inside the same parent).
- Same parent and same final index: no change at all.
- Effects: the previous parent group becomes the old parent, only when the parent changes; location changed, last modification and last access time of the moved group become now, also for a pure reorder among siblings; the times of the old and new parent and of everything inside the moved group do not change.

MOD-02.21 **Moving entries inside the vault.**
- Target: any group of the same vault. An entry is always put at the end of the target's entries (the reference refuses a drop of entries at a row position). Several entries are moved in the order they are given.
- Moving an entry into the group it is in changes nothing.
- Effects per moved entry: previous parent group = the old group; location changed = now (MOD-01.29); last modification and last access time = now when the previous parent group changed, which is every move except one where it already named the old group (MOD-01.26, MOD-03.5). Group times: MOD-02.25.
- No history item is made by moves (MOD-01.32). The reference's command line move makes one; App's makes none (MOD-03.5, lead decision L03-1).

MOD-02.22 **Moving or copying into another open vault.** The source item is copied, not moved, into the target vault:
- A group: the group, its whole subtree and all entries with their history are copied with new ids for every group and entry; creation, modification, last access and location changed of every copied group and live entry become now (expiry time and usage count are kept; history items keep their times and take their owner's new id). The copy goes to the given position.
- An entry: copied with a new id, its history included, times reset the same way; put at the end of the target group.
- Custom icons used by the copied items are added to the target vault when it lacks that id (MOD-06.17).
- Previous parent group: every copied group and entry in the other vault has none, for a move and for a copy (decided: spec/decisions.md LD-68). The reference's copy keeps the source's value, which names a group of the other vault.
- Move (not copy): after the copy is complete, the source item is deleted permanently from the source vault, which records deleted objects (FMT-15).
- Copy inside the same vault (drag with the copy modifier, Option on Mac): the result is a copy with new ids and reset times, history included, without a name suffix (MOD-10 owns clone details).

MOD-02.23 **Delete.** Deleting a group or entry moves it into the recycle bin, or deletes it permanently (MOD-04). Moving into the bin follows MOD-02.20 and MOD-02.21.

MOD-02.24 **Reordering entries.** Move up and move down swap the selected entry with its neighbor in the stored list. They are offered only while the entry list shows stored order (not sorted by a column) and exactly one entry is selected; the first entry cannot move up, the last cannot move down. No entry time moves. In the reference the group's modification time moves (MOD-02.25). APP-05 treats this as a view-state change.

MOD-02.25 **What moves a group's modification time.** The last access time always moves with it, to the same value.

| Event | Reference (from the source; rows marked observed were seen with the installed command line tool) | App (lead decision D-02-1, recommended) |
|---|---|---|
| Own data changed (MOD-02.29) | yes | yes |
| The group itself moved to another parent, or to another position among its siblings | yes | yes |
| An entry added to or removed from the group: new entry committed, entry moved in or out, deleted, restored, deleted permanently | yes (observed for add and move) | no |
| Entries of the group reordered (MOD-02.24) | yes | no |
| Group expanded or collapsed (MOD-02.5) | yes | no |
| Sort applied (MOD-02.26): every group of the sorted subtree, even when its order did not change | yes | no |
| A child group added, moved away or deleted | no (observed for add and for move to the recycle bin) | no |
| An entry of the group edited | no | no |

Why App differs: a merge (MOD-11) lets the group with the newer modification time win the group's name, notes, icon and expiry. When a view-state change or an entry joining a group makes the group look newer, a rename made earlier on another device is lost in the merge. App moves the time only for changes to the group itself (SD-03).

MOD-02.26 **Sorting groups.** "Sort A–Z" and "Sort Z–A" act on the selected group: its child groups, and the child groups of every group in its subtree, are put in order by name. Entries are never sorted in the model; sorting the entry list by a column changes the display only.
- Comparison: compare the two names code point by code point after Unicode simple case folding; the first difference decides by the folded code point values; a name that is the start of the other comes first. There is no numeric order: `item10` comes before `item9`, `007` before `07x`. Z–A uses the reverse comparison.
- Ties (names equal after folding, for example `Alpha` and `alpha`): App keeps their current relative order in both directions (stable sort). The reference's sort is not stable, so their order there is not defined.
- Recycle bin: App puts it last among its siblings in both directions (lead decision D-02-2, recommended). The reference intends to keep it out of the name order, but its comparison only stops the bin from coming before others while still comparing other groups against the bin's name; the outcome depends on the order of comparisons (from the source, not run).
- Effects: the new orders are stored; the change is one change batch; no group's location changed time moves; modification times per MOD-02.25.

### New groups and group times

MOD-02.27 **New group.** "Add group" with a group selected opens the group edit screen for a new group that is not yet in the vault. On save it is put at the end of the selected group's child groups, with the defaults of the property table; all five times are the commit time (lead decision D-01-4 of MOD-01, recommended; the reference uses the moment the screen opened for creation and expiry time). Cancel leaves no trace (custom icons added meanwhile stay: MOD-06.10). Clone of a group is MOD-10.

MOD-02.28 **Templates group.** There is no template feature (MOD-01.33). The vault's templates-group pointer is carried only (FMT-10.16); when that group is deleted the pointer no longer resolves and is written as the zero id.

MOD-02.29 **Own data changes.** A real change of any of these sets the group's last modification and last access time to now: name, notes, icon number or custom icon, expires flag, expiry time, default sequence, either switch, a custom data item (added, changed, renamed, removed), previous parent group, id. Setting a value it already has changes nothing. The usage count never changes (as MOD-01.28). Group tags only come from files, so no action changes them.

### Not on Mac

- The Linux secret service plug-in exposes one chosen group to other programs; its key in the vault custom data is kept (FMT-14.20) but nothing acts on it on Mac.

## Edge cases and errors

| Case | Expected behavior |
|---|---|
| Drag the root group anywhere | Refused; nothing changes. |
| Drag group A onto itself or onto a group inside A | Refused; nothing changes. |
| Move a group to the place it already has | No change; no time moves. |
| Move the recycle bin under group G | Allowed; the bin stays the recycle bin (MOD-04). |
| Two sibling groups both named `Mail` | Allowed; both kept; sort keeps their relative order (App). |
| Group named `a/b` | Allowed; command line paths are ambiguous (INT-10). |
| Root group's switches Inherit | Search and auto-type resolve to On. |
| Browser option value `True` (capital T) on a group | Resolves to off: only `true` means on (MOD-02.17). |
| Entry dropped on the group it is already in | No change. |
| Cross-vault move of a group while the copy cannot be completed (for example the target is locked) | Nothing is deleted from the source; the move fails as a whole. |
| Last top visible entry names a deleted entry | Resolves to none; written as the zero id (FMT-11.37). |
| Group with the shared-group key, child with none | The child is shared too (MOD-02.18). |

## Security notes

- **No cycles (AT-A08).** The model must never hold a group inside itself. Moves check the subtree before they change anything (MOD-02.20); reading refuses such files (FMT-11.36). The reference relies on its screens for this; App's core checks it on every move command, because commands can be called with hostile arguments (AT-E03).
- **Auto-type off is inherited (SI-06).** An Off switch on a group blocks auto-type for every entry below it except under a descendant group set On (MOD-02.14). A wrong resolution would type secrets where the user turned typing off. INT-05 checks both the entry flag and this switch before typing.
- **Browser options are inherited (SI-04).** "Hide entries" and the other options must resolve exactly as MOD-02.17 says, or entries could be offered to sites the user excluded. Only the exact value `true` turns an option on.
- **Search off is not a protection.** Entries in a group with search Off still show in the tree and still reach the browser bridge; screens must not present the switch as hiding secrets.
- **Restore needs the previous parent (SD-05).** Moves keep the previous parent group up to date (MOD-02.20, MOD-02.21) so that MOD-04 can restore an item to where it was. A previous parent that names a missing group is kept and handled by MOD-04.
- **No data loss on cross-vault moves (SD-03).** The source item is deleted only after the copy is complete (MOD-02.22). The group modification time rule (MOD-02.25) avoids losing renames in merges.
- **Untrusted text (AT-E01).** Group names, notes and raw tags are shown as plain text.

## Test cases

Notation: t0 = 2026-10-25T10:00:00Z, t1 = 2026-10-25T10:05:00Z, t2 = 2026-10-25T10:10:00Z. Vault V: root R; under R the groups A and B; under A the group A1; entry E in A. All times t0 unless a case says otherwise. id(xx) as in FMT-11.

| Case | Given | When | Then |
|---|---|---|---|
| MOD-02.1 stored order | R's children in order B, A (from the file) | Open, save, open | Children still B, A. |
| MOD-02.2 root refusals | Vault V | Delete R; drag R onto A; clone R | All three refused; vault unchanged. |
| MOD-02.2 root editable | Vault V | Rename R to `Home`, set its search switch Off | Saved; R named `Home`; every group with Inherit below R resolves search Off. |
| MOD-02.3 names | Vault V | Add two groups under R named `` (empty) and `A` | Both added; R has children A, B, ``, A (stored order: A, B, then the two new ones). |
| MOD-02.3 line break | Group edit screen | Paste `Work` LF `Mail` as name, save | Name `Work Mail` (App). |
| MOD-02.4 icon | Vault V | Add group N under A without touching the icon; then pick icon 12 for N and save | N icon 48; then 12. |
| MOD-02.5 expanded stored | Group A expanded | Collapse A in the sidebar, save, reopen | A shown collapsed; A's IsExpanded false. |
| MOD-02.6 sequence inherit | A with default sequence `{PASSWORD}{ENTER}` | Choose inherit on A's edit screen, save | A's default sequence empty. |
| MOD-02.6 custom prefill | R's default sequence empty, A's empty | Open A's edit screen, choose custom | Text box shows `{USERNAME}{TAB}{PASSWORD}{ENTER}`. |
| MOD-02.7 new switches | Vault V | Add group N under A | N auto-type Inherit, search Inherit; screen shows "Inherit (On)" for both. |
| MOD-02.8 group tags | File where A's tags are `  zz ; aa,  ` | Open, view the tag list, save | Tag list has no `zz` or `aa`; A's tags written back exactly `  zz ; aa,  `. |
| MOD-02.9 custom data delete | A with custom data `BrowserHideEntry`=`true` | Delete the item on A's properties page, confirm, save | Item gone; A's modification time = now. |
| MOD-02.10 previous parent automatic | New group N committed under A | Inspect; move N to B; inspect | First none; then A. No screen field edits it. |
| MOD-02.11 carried | File where A's last top visible entry is E's id | Open, save | Same id written. Delete E permanently, save: zero id written. |
| MOD-02.12 group expiry | A expires at t1, clock t2 | Show the sidebar | A struck through with the expired badge; E not expired. |
| MOD-02.13 search resolve | R Inherit, A Off, A1 Inherit, B Inherit; entries E in A, E1 in A1, E2 in B; new group A2 under A with search On holding E3 | Search for a word all four entries contain | Results E2, E3 only. |
| MOD-02.13 command line | Same as above | Command line search for the same word (INT-10) | Results E, E1, E2, E3. |
| MOD-02.14 auto-type resolve | R Off, A On, B Inherit; E in A, E2 in B, both entry flags on | Ask whether each may be auto-typed | E yes, E2 no. |
| MOD-02.15 group walk | R sequence empty, A sequence `{USERNAME}{ENTER}`, A1 sequence empty, all switches Inherit | Effective sequence of A1 | `{USERNAME}{ENTER}`. |
| MOD-02.15 Off stops | A1 switch Off, A sequence `X` | Effective sequence of A1 | Empty. |
| MOD-02.15 Off above the giver | R switch Off, A sequence `X` (A Inherit) | Effective sequence of A; may E be auto-typed | Sequence `X`; E may not be auto-typed (MOD-02.14). |
| MOD-02.15 fallback | All sequences empty, all switches Inherit | Effective sequence of A1 | `{USERNAME}{TAB}{PASSWORD}{ENTER}`. |
| MOD-02.16 password only | All sequences empty; E has user name empty, password `pw` | Effective sequence of E | `{PASSWORD}{ENTER}`. |
| MOD-02.16 user only | Same, E user name `bob`, password empty | Effective sequence of E | `{USERNAME}{ENTER}`. |
| MOD-02.16 both empty | Same, E user name and password empty | Effective sequence of E | `{USERNAME}{TAB}{PASSWORD}{ENTER}`. |
| MOD-02.16 own sequence | E default sequence `{TITLE}`, A switch Inherit | Effective sequence of E | `{TITLE}`. |
| MOD-02.16 entry off | E auto-type flag off | Effective sequence of E | Empty. |
| MOD-02.17 browser option | R `BrowserHideEntry`=`true`, A has no key, A1 `BrowserHideEntry`=`false` | Resolve for A, A1, B | A on, A1 off, B on. |
| MOD-02.17 missing everywhere | No group has `BrowserSkipAutoSubmit` | Resolve for A1 | Off. |
| MOD-02.17 restrict key | R `BrowserRestrictKey`=`Laptop`, A `BrowserRestrictKey`=`` (empty) | Resolve for A1 and for B | A1: no restriction; B: `Laptop`. |
| MOD-02.17 editor writes | A with no browser keys | Set hide entries to On, skip auto-submit to Off, save; then set hide entries to Inherit, save | First: `BrowserHideEntry`=`true`, `BrowserSkipAutoSubmit`=`false`. Then `BrowserHideEntry` removed. |
| MOD-02.18 recycled | A moved into the recycle bin | Is E recycled? | Yes. |
| MOD-02.19 one batch | Vault V at t0, autosave on (APP-05) | At t1 drag A1 to B | One change batch: one save; A1 moved with all its effects at t1. |
| MOD-02.20 refuse cycle | Vault V | Move A into A1 | Refused; tree unchanged; no time moves. |
| MOD-02.20 move effects | Vault V at t0 | At t1 move A1 to B (end) | A1 under B; A1 previous parent A; A1 location changed, modification and last access t1; A and B times t0; E times t0. |
| MOD-02.20 reorder | R's children A, B | At t1 move B to index 0 under R | Order B, A; B previous parent unchanged (none); B location changed and modification t1. |
| MOD-02.20 same place | R's children A, B | Move A to index 0 under R | No change; A's times t0. |
| MOD-02.20 bin movable | Recycle bin under R | Move the bin under B | Allowed; the vault's recycle bin is still that group. |
| MOD-02.21 entry move | Vault V at t0, A has entries E, F; B has G1 | At t1 move E to B | B's entries G1, E; E previous parent A; E location changed, modification, last access t1; no history item. |
| MOD-02.21 same group | E in A | Move E to A | No change. |
| MOD-02.21 order of several | A has entries E, F, H | Move H, E (in that order) to B, which is empty | B's entries H, E. |
| MOD-02.22 cross-vault group move | Vault V and vault W open; A in V holds E with 2 history items and custom icon X | At t1 drag A onto W's root (move) | W has a copy of A with new ids for A, A1, E; copy times t1 except expiry; E's copy keeps 2 history items, each with E's new id; X added to W; V no longer has A, A1, E; V's deleted objects list A, A1 and E with time t1; copy's previous parent none. |
| MOD-02.22 cross-vault entry copy | Same vaults; E's previous parent group is B (moved earlier from B to A) | Copy E onto W's root | E stays in V with previous parent B; W gets a copy with a new id at the end of W's root entries; the copy's previous parent is none (LD-68). |
| MOD-02.22 copy in same vault | Vault V | Option-drag E onto B | B gets a copy with a new id, Title unchanged (no suffix), history included; E unchanged in A. |
| MOD-02.23 delete is a move | Vault V with recycle bin enabled, at t0 | At t1 delete group A1 | A1 under the recycle bin; A1 previous parent A; A1 location changed t1 (MOD-04 owns the rest). |
| MOD-02.24 reorder entries | A's entries E, F (stored order shown), all times t0 | At t1 move F up | A's entries F, E; E and F times t0; App: A's times t0 (reference: A modification t1). |
| MOD-02.24 sorted view | Entry list sorted by title | Look at the move up and move down actions | Not offered. |
| MOD-02.25 entry add | Vault V at t0 | At t1 commit a new entry in A | App: A's modification time t0. Reference: t1. |
| MOD-02.25 expand | A collapsed at t0 | At t1 expand A | App: A's modification time t0. Reference: t1. |
| MOD-02.25 child group added | Vault V at t0 | At t1 add group N under A | A's modification time t0 in both. |
| MOD-02.26 sort | Children of R named, in stored order: `beta`, `Alpha`, `item10`, `item9`, `007`, `07x`, `_misc`, `Zeta`, `alpha` | Sort A–Z on R | Order `007`, `07x`, `_misc`, `Alpha`, `alpha`, `beta`, `item10`, `item9`, `Zeta`. |
| MOD-02.26 reverse | Same start | Sort Z–A on R | Order `Zeta`, `item9`, `item10`, `beta`, `Alpha`, `alpha`, `_misc`, `07x`, `007`. |
| MOD-02.26 recursive | A's children `z`, `m`; A1 (under A) children `q`, `b` | Sort A–Z on R | A's children `m`, `z`; A1's children `b`, `q`. |
| MOD-02.26 subtree only | Sort A–Z on A | Look at R's children | R's children order unchanged. |
| MOD-02.26 recycle bin | R's children `Zeta`, the recycle bin (named `Bin`), `Alpha` | Sort A–Z, then Z–A | A–Z: `Alpha`, `Zeta`, bin. Z–A: `Zeta`, `Alpha`, bin. |
| MOD-02.26 entries untouched | A's entries Z, B, M | Sort A–Z on R | A's entries still Z, B, M. |
| MOD-02.27 new group | Vault V, A selected, clock t1 at save | Add group `New`, save | `New` is the last child of A; icon 48; expanded true; switches Inherit; sequence empty; all five times t1. |
| MOD-02.27 cancel | A selected | Add group, Cancel | A's children unchanged. |
| MOD-02.28 templates pointer | File whose templates pointer names B | Delete B permanently, save, read | Pointer written as the zero id. |
| MOD-02.29 own change | A at t0 | At t1 change A's notes; at t2 set A's notes to the same text | Modification and last access t1; still t1 after t2. |

## How this was learned

- Lead decisions D-02-1 and D-02-2 (decided: spec/decisions.md default rule, each takes the recommended option).
- The previous parent rule for copies into another vault (MOD-02.22) is decided by spec/decisions.md LD-68.

- Read the reference's group model in the core folder: defaults (icon 48, expanded, both switches inherit), the root auto-type default sequence, the walk for the effective sequence, the resolution of the two switches and of the browser options kept in group custom data, the move routine (previous parent, location time, the unconditional modification signal, cross-vault branch with icon copy and deleted-object records), the add and remove entry routines (which signal a change on the group), the entry reorder routines (a view-state change that also moves the group's time), the expand routine, the sort routine and its comparison, and the clone routine.
- Read the vault model: root group creation and its default name, recycle bin creation, and how view-state changes are flagged. Read the new vault wizard (root name) and the main vault view (add group, clone group, delete and clone guards for the root and the bin, sort actions).
- Read the sidebar's drag and drop handling (refusals, position adjustment, cross-vault copies with new ids and reset times, copy action inside one vault) and the group edit screen (tri-state choices with the inherited value, sequence choice, browser option writes, apply-icon choices, properties page).
- Read the search routine (which groups are scanned) and the auto-type checks.
- Read the reference's tests for group parenting, previous parent, child sorting and auto-type state, and used their sort facts with our own names.
- Ran the installed command line tool 2.7.11 on demo vaults in a scratch folder (password `demo`): creating a group did not move the root group's modification time; adding an entry did; moving an entry moved both groups' times and the entry's previous parent, location, modification and access times; removing a group moved it into a new recycle bin (icon 43) with previous parent set and did not move the root group's time. A crafted XML import with a group whose search switch is Off showed that the command line search still finds its entry.
