# MOD-07 Tags

Status: reviewed
Epics: E4-S5
Parity rows: none (no security parity row covers tags)

## What it does

A tag is a short label on an entry, for example `Work` or `Bank`. An entry has any number of tags. The vault keeps no tag list of its own: the list of all tags is built from the entries each time. This card says what a tag may contain, how tag text is split, cleaned and ordered, how the vault-wide tag list is built and sorted, and what the tag screens do: the tag box on the edit screen, the tag list in the sidebar, the tag menu for selected entries and "remove tag everywhere". FMT-11.26 owns how entry tags are read and written in the file and FMT-11.27 owns the raw group tags text. FEA-01 owns tag search.

Words used in this card: **live entry**, **history item**, **now**, **change batch** as in MOD-01. **White space** is the set of characters with the Unicode White_Space property listed in FMT-11.26. **Separators** are `,` (U+002C), `;` (U+003B) and TAB (U+0009).

## Inputs and outputs

- An entry's tags: in the model, a sorted list of distinct texts (MOD-07.2). In the file: the texts joined with `,` (FMT-11.26).
- Tag text from the edit screen, from files, from imports (FEA-08) and from features that add a tag by themselves (MOD-07.11).
- Outputs: the vault tag list (MOD-07.5) for the sidebar, the tag menu and the edit screen's suggestions; exact tag terms handed to FEA-01 (FEA-01.35).
- Messages and actions, with our IDs: `act.tag_remove_everywhere`, `msg.tag_remove_confirm`, `msg.no_tags` (texts are App's own).

Limits: the joined tags text of one entry is one text value and must fit the `text` limit of FMT-08.12, measured as FMT-12 says (App refuses an edit that passes it, as MOD-01.9). No other limit on the number or length of tags.

## Rules

MOD-07.1 **Where tags live.** Tags with meaning live on entries: live entries and history items. A history item keeps the tags its entry had at that time. Groups only carry a raw tags text from the file, which nothing shows, edits, lists or searches (MOD-02.8, FMT-11.27). The vault has no stored tag list.

MOD-07.2 **What an entry's tag list holds.** Every tag is a text that:
- is not empty;
- has no white space at its start or end (white space inside is allowed: `my tag`);
- contains no separator;
- appears once (exact comparison, case-sensitive: `Work` and `work` are two tags).

The list is kept sorted by UTF-16 code units, case-sensitive, so capitals come before small letters: `10`, `9`, `A`, `B`, `Z`, `_x`, `a`, `b`, `é`. Screens show an entry's tags in this stored order. Two tag lists are equal when the sorted lists are equal; setting an equal list is no change (MOD-01.26).

MOD-07.3 **Setting tags from text.** One function turns a text into a tag list. It is used for files (FMT-11.26), imports, the command line and the edit screen:
1. Split the text at every separator.
2. Trim white space from both ends of each piece.
3. Drop empty pieces.
4. Remove exact duplicates.
5. Sort by UTF-16 code units.

Example: `zeta; alpha,beta` TAB `alpha ,Alpha` gives `Alpha`, `alpha`, `beta`, `zeta`. The reference trims after it drops empty pieces, so a piece made only of spaces survives as an empty tag until the next read (FMT-11.26 note); App never keeps an empty tag.

MOD-07.4 **The tag box on the edit screen.** The entry's tags are shown as separate chips in stored order, followed by a typing area.
- Enter, Return, `,` and `;` end the tag being typed: its text is trimmed and, when not empty, becomes a chip. `,` and `;` are never typed into a tag. When the suggestion pop-up is open with a suggestion highlighted, Enter takes that suggestion instead.
- Backspace in an empty typing area moves to the previous chip for editing. A chip that becomes empty, or equal to another chip, disappears when the user leaves it.
- Paste splits the clipboard text at `,` only; each piece becomes a chip (pieces with `;` or TAB inside are split later by MOD-07.3).
- Suggestions: the vault tag list (MOD-07.5), filtered by case-insensitive prefix match on the text being typed.
- On save, the chips are joined and passed through MOD-07.3. A change of tags is part of the edit session (MOD-01.32).

MOD-07.5 **The vault tag list.** It holds every tag of every live entry that is not in the recycle bin, each text once (exact comparison). History items, entries in the recycle bin (MOD-04) and group tags are left out. The list is rebuilt after the vault is opened and after every change.

Order: natural and case-insensitive. App compares two tags this way (lead decision D-07-1, recommended):
1. Cut each text into runs: a run of ASCII digits `0` to `9`, or a run of other characters.
2. Compare the runs in order. Two digit runs: by numeric value (leading zeros ignored). A digit run against another run: the digit run comes first. Two other runs: code point by code point after Unicode simple case folding; the first difference decides by the folded code point value; a run that is the start of the other comes first.
3. When one text runs out of runs first, it comes first.
4. When everything is equal, compare the original texts by UTF-16 code units (so `Work` comes before `work`, `007` before `7`).

Example: `9`, `10`, `_x`, `A`, `a9`, `a10`, `b`, `Work`, `work`. The reference sorts with its UI toolkit's collator for the system language, in numeric and case-insensitive mode; that collator may place punctuation before digits (`_x` before `9`) and leaves the order of case variants to the language (from the source, not run: check with Verify).

MOD-07.6 **The tag list in the sidebar.** Below the fixed searches and the saved searches (FEA-01, APP cards), the sidebar shows one row per tag of the vault tag list, in its order. Choosing a row hands FEA-01 one exact tag term for T; no query text is built, so no character of T needs escaping (decided: spec/decisions.md LD-66). Choosing several rows hands one exact tag term per row, all required. FEA-01.35 owns how the term matches: T exactly, case included. The reference instead runs the text search `tag:"T"` with every `"` written as `\"`, joined by one space for several rows.

MOD-07.7 **The tag menu for selected entries.** The entries menu has a tags sub-menu (APP-08) listing every tag of the vault tag list as an item with a check mark. An item is checked when at least one selected entry has that tag. Choosing an unchecked item adds the tag to every selected entry (MOD-07.8); choosing a checked item removes it from every selected entry. When the vault has no tags, the sub-menu shows one disabled item (`msg.no_tags`). Each choice is one change batch: every entry that really changes gets a new modification time; no history items are made (MOD-01.32).

MOD-07.8 **Adding one tag.** Used by the tag menu, by imports and by features (MOD-07.11). The text is cleaned (separators removed from inside it, then white space trimmed from both ends); an empty result adds nothing (the reference would add an empty tag; only internal callers can reach that case); a tag already in the list (exact) adds nothing; otherwise the tag is added and the list stays sorted.

MOD-07.9 **Removing a tag everywhere.** On a tag row of the sidebar the user chooses `act.tag_remove_everywhere`. App asks `msg.tag_remove_confirm` (remove tag T from all entries of this vault?) with Remove and Cancel; Cancel is the default. On Remove, the tag is removed (exact comparison) from every live entry of the vault, including entries in the recycle bin. History items keep it. It is one change batch: each entry that really changes gets a new modification time; no history items are made (MOD-01.32). Afterwards the tag is gone from the vault tag list.

MOD-07.10 **No rename.** The reference offers no way to rename a tag across the vault. App offers none in E4 (lead decision D-07-2: parity recommended; a later rename would be "remove T and add U" on the same entries, as one change batch, with the effects of MOD-07.9).

MOD-07.11 **Tags App adds by itself.** Creating a passkey through the browser bridge adds the tag "Passkey" in App's UI language, and removing an entry's passkey removes that tag (INT-04). Some importers add tags such as "Favorite" and "Archived" in the UI language (FEA-08). These tags follow MOD-07.8.

MOD-07.12 **Tag changes move times.** Any real change of an entry's tag list moves its modification time (MOD-01.26). Building the vault tag list changes nothing.

## Edge cases and errors

| Case | Expected behavior |
|---|---|
| Tag text `a, ,b;;c` from a file | Tags `a`, `b`, `c` (App); no empty tag. |
| Tag typed as `  Work  ` | Stored as `Work`. |
| User types `a,b` in the tag box | Two chips: `a`, then `b` (the comma ends the first tag). |
| Paste `x;y,z` | Chips `x;y` and `z`; on save the tags become `x`, `y`, `z`. |
| Tags `Work` and `work` on one entry | Both kept; both in the vault tag list. |
| Tag only on an entry in the recycle bin | Not in the vault tag list; "remove everywhere" for a listed tag still removes it from recycled entries. |
| Tag only in a history item | Not in the list; never removed by MOD-07.9. |
| Tag containing `"` such as `say "hi"` | Sidebar search text `tag:"say \"hi\""`. |
| Vault without tags | Tag sub-menu shows one disabled item; sidebar shows no tag rows. |
| Add tag `a,b` through MOD-07.8 | Tag `ab`. |
| Remove everywhere, answer Cancel | No change. |
| Joined tags text over the `text` limit of FMT-08.12 | Edit refused (as MOD-01.9). |

## Security notes

- **Untrusted text (AT-E01).** Tags come from files, imports and other people's shared groups. They are shown as plain text in chips, rows and menus, never as HTML.
- **No search text built from tags.** The sidebar hands exact tag terms (MOD-07.6, LD-66), so a tag holding `"`, `\`, `*`, `?`, `|` or spaces cannot change the search. In the reference, a tag that ends in `\` or holds `\"` is not written exactly in its text search and can match nothing or gain an extra term. The search parser (FEA-01) must still treat typed query text as untrusted.
- **No secret in tags.** Tags are not protected fields and are written as plain text inside the vault payload (FMT-11.26). Screens must not invite users to put secrets into tags; tags appear in lists and in the tag menu.
- **Bulk changes.** Removing a tag everywhere changes many entries at once without history items (MOD-07.9), which is why it asks first.

## Test cases

Notation: t0 = 2026-10-25T10:00:00Z, t1 = 2026-10-25T10:05:00Z. Vault V: root R, group G, entries E1 and E2 in G, a recycle bin, all times t0.

| Case | Given | When | Then |
|---|---|---|---|
| MOD-07.1 group tags ignored | File with group G tags `grp` and no entry tags | Open | Vault tag list empty; G's tags text kept and written back. |
| MOD-07.1 history keeps tags | E1 tags `a` with a history item tags `old` | Remove tag `a` from E1 on the edit screen, save | E1 no tags; the earlier history item still `old`; the new history item `a`. |
| MOD-07.2 order and case | Entry tags set from `b;B, a ,A` TAB `_x;10;9;b;é;Z` | Read the tag list | `10`, `9`, `A`, `B`, `Z`, `_x`, `a`, `b`, `é` (observed with the reference's import and export). |
| MOD-07.2 equal list | E1 tags `a`, `b` at t0 | At t1 save the edit screen with tags `b`, `a` | No change: modification time t0, no history item. |
| MOD-07.3 normalize | — | Set tags from `zeta; alpha,beta` TAB `alpha ,Alpha` | `Alpha`, `alpha`, `beta`, `zeta`; written `Alpha,alpha,beta,zeta`. |
| MOD-07.3 empty pieces | — | Set tags from `a, ,b;;c` | `a`, `b`, `c`. |
| MOD-07.4 keys end a tag | Empty tag box | Type `Work`, press `,`, type `Mail`, press Enter, save | Tags `Mail`, `Work`; no comma inside any tag. |
| MOD-07.4 spaces only | Empty tag box | Type three spaces, press Enter, save | No tag added. |
| MOD-07.4 paste | Empty tag box | Paste `x;y,z`, save | Tags `x`, `y`, `z`. |
| MOD-07.4 suggestions | Vault tag list `Bank`, `banking`, `Work` | Type `ban` | Suggestions `Bank`, `banking`. |
| MOD-07.5 list contents | E1 tags `b`, `A`; E2 tags `a10`, `a9`, `Work`; entry E3 in R tags `work`, `_x`, `10`, `9`; entry in the recycle bin tags `Old`; a history item tags `Hist`; group tags `grp` | Build the vault tag list | `9`, `10`, `_x`, `A`, `a9`, `a10`, `b`, `Work`, `work`. |
| MOD-07.5 rebuilt | List `a` | Add tag `z` to E1 | List `a`, `z` right after the change. |
| MOD-07.6 sidebar search | Tag `say "hi"` on E1 | Choose its sidebar row | One exact tag term `say "hi"` sent to FEA-01; result E1. |
| MOD-07.6 backslash tag | Tag `dir\` on E1, tag `dir` on E2 | Choose the `dir\` row | One exact tag term `dir\`; result E1 only. |
| MOD-07.6 several rows | Tags `a`, `b` | Choose both rows | Two exact tag terms `a` and `b`, both required. |
| MOD-07.7 menu check marks | E1 tags `a`; E2 tags `b`; both selected | Open the tag sub-menu | Items `a` and `b`, both checked. |
| MOD-07.7 add to selection | E1 tags `a`, E2 no tags, both selected, clock t1; vault list has `x` from another entry | Choose `x` | E1 tags `a`, `x`; E2 tags `x`; both modification times t1; no history items. |
| MOD-07.7 remove from selection | E1 tags `a`, E2 no tags, both selected | Choose `a` (checked) | E1 no tags; E2 unchanged (modification time t0). |
| MOD-07.7 no tags | Vault without tags | Open the tag sub-menu | One disabled item `msg.no_tags`. |
| MOD-07.8 clean add | E1 no tags | Add tag `  a,b  ` through MOD-07.8 | E1 tags `ab`. |
| MOD-07.8 empty add | E1 no tags | Add tag ` , ` | No change. |
| MOD-07.9 remove everywhere | E1 tags `x`, E2 tags `x`, `y`; recycled entry tags `x`; E1 history item tags `x`; clock t1 | Choose `act.tag_remove_everywhere` on `x`, confirm | E1 no tags, E2 `y`, recycled entry no tags; history item still `x`; the three entries' modification times t1; no history items; list `y`. |
| MOD-07.9 cancel | Same | Choose the action, Cancel | Nothing changes. |
| MOD-07.10 no rename | Sidebar tag row | Open its menu | Only `act.tag_remove_everywhere`; no rename. |
| MOD-07.11 passkey tag | Entry without tags, UI language English | Create a passkey on it through the browser bridge (INT-04) | Entry tags `Passkey`. Remove the passkey: no tags. |
| MOD-07.12 time | E1 tags `a` at t0 | At t1 add tag `b` on the edit screen, save | Modification time t1; one history item with tags `a`. |

## How this was learned

- Lead decisions D-07-1 and D-07-2 (decided: spec/decisions.md default rule, each takes the recommended option). The sidebar's exact tag term (MOD-07.6) is decided by LD-66.

- Read the reference's entry tag routines (split at `,`, `;` and TAB, trim, remove duplicates, sort; add one tag; remove one tag) and its group tag field (raw text, carried only, written only when not empty).
- Read the vault model's tag list rebuild (live entries outside the recycle bin, unique texts, numeric case-insensitive collation) and its remove-everywhere routine; the sidebar tag model (fixed searches, saved searches, tag rows and the `tag:"…"` search with escaped quotes) and its context menu with the confirmation; the main window's tag sub-menu (check marks, the "no tags" item) and the vault view's add or remove for selected entries.
- Read the tag box widget (keys that end a tag, paste split at commas, suggestions, empty-chip handling) and how the entry edit screen saves tags (remove duplicates, join, then the split routine).
- Searched the whole source for code that adds tags by itself (passkey creation and removal, importers).
- Ran the installed command line tool 2.7.11: a crafted XML import with entry tags `b;B, a ,A` TAB `_x;10;9;b;é;Z` exported `10,9,A,B,Z,_x,a,b,é`, and group tags `  zz ; aa,  ` were exported unchanged.
