# MOD-01 Entry fields, standard and custom

Status: reviewed
Epics: E3-S1, E4-S1
Parity rows: SF-08, SF-09, SC-04, SD-04, SD-06, SG-04

## What it does

An entry is one stored login or secret. This card says what an entry holds in Larsal's model (larsal-model `entry.rs`), how its text fields are named and protected, what a new entry gets, and which changes move which of its times. It is the behavior layer. FMT-11 owns how each property is written in the file; FMT-14 owns custom data and the reserved field names; FMT-12 owns value encodings.

Words used in this card:

- **live entry**, **history item**: as in FMT-11.
- **now**: the current UTC time in whole seconds (larsal-model `times.rs`).
- **change batch**: one user action or one core edit command that changes an entry, for example saving the edit screen once, one drag and drop, one tag menu click. All changes of one batch get the same time.
- **edit session**: a change batch made by saving the entry's edit screen (or the command line edit command, INT-10). Only edit sessions make a history item (MOD-01.32, MOD-03).
- **effective protection** of a field: its own protected flag, or for a standard field the matching vault flag (FMT-11.20, MOD-12).

Neighbor cards: MOD-02 (groups, inheritance, moves), MOD-03 (history), MOD-04 (recycle bin), MOD-05 (attachments), MOD-06 (icons), MOD-07 (tags), MOD-08 (references; `_EXEC_CMD` and opening URLs: MOD-08.31), MOD-09 (expiry), MOD-10 (clone), MOD-11 (merge), MOD-12 (vault protection flags), FEA-04 (one-time password fields), FEA-05 (report exclusion), INT-02 (browser options), INT-03 (additional URLs), INT-04 (passkey fields), INT-05 (auto-type), INT-10 (command line).

## Inputs and outputs

Every entry property, its model type, what a new entry gets, and who changes it. The last column points to the row of the FMT-11.15 table that encodes it.

| # | Property | Model type | New entry (Larsal) | Changed by | FMT-11.15 row |
|---|---|---|---|---|---|
| 1 | Id | 16 bytes | random (MOD-01.12) | nobody after creation | 1 |
| 2 | Standard fields `Title`, `UserName`, `Password`, `URL`, `Notes` | 5 × (value text, own protected flag) | all empty, own flags off; `UserName` per MOD-01.22 | user | 11 |
| 3 | Custom fields | map name → (value text, own protected flag), kept sorted by name in UTF-16 code unit order, the order FMT-11.22 writes (the reference keeps them sorted the same way); screens list custom fields in this order | none | user, plug-ins (INT cards) | 11 |
| 4 | Icon | standard icon number (32-bit signed) or custom icon id | MOD-06.3 | user, MOD-06 | 2, 3 |
| 5 | Foreground color, background color | text each, empty means none | empty | user | 4, 5 |
| 6 | Override URL | text | empty | nobody: carried only (MOD-01.15) | 6 |
| 7 | Tags | sorted set of texts (MOD-07) | empty | user | 7 |
| 8 | Times: creation, last modification, last access, location changed, expiry time | timestamps | MOD-01.25 | MOD-01.26 to MOD-01.31 | 8 |
| 9 | Expires flag | boolean | false | user (MOD-09) | 8 |
| 10 | Usage count | 32-bit signed integer | 0 | nobody (MOD-01.28) | 8 |
| 11 | Report exclusion | boolean, true = left out of password reports | false | user | 9 |
| 12 | Previous parent group | group id or none | none | moves only (MOD-02.21) | 10 |
| 13 | Attachments | MOD-05 | none | user | 12 |
| 14 | Auto-type block: enabled, obfuscation, default sequence, window associations | boolean, 32-bit signed integer, text, ordered list of (window text, sequence text) | true, 0, empty, none | user (INT-05) | 13 |
| 15 | Custom data | items of FMT-14 | none | plug-ins; the user may only delete (MOD-01.20) | 14 |
| 16 | History | ordered list of history items, oldest first | none | MOD-03 | 15 |
| 17 | Kept unknown elements | FMT-11.45 | none | nobody | none |

Outputs to the screen: list and detail views hold no secret values (plan/architecture.md, larsal-desktop Must). A protected value reaches the screen only through Show, one value at a time.

Limits: MOD-01.9.

## Rules

### Fields

MOD-01.1 **Standard fields.** Every entry, live or history, has exactly five standard fields named `Title`, `UserName`, `Password`, `URL` and `Notes` (exact, case-sensitive). They always exist, may be empty, and can be neither removed nor renamed. Screens show them in this fixed order, never in file order.

MOD-01.2 **Custom fields.** An entry may hold any number of further fields (limit: MOD-01.9). Each is a name, a value and an own protected flag. Names are unique inside one entry and compared exactly: code unit by code unit, case-sensitive, no Unicode normalization, no trimming. A custom field can never carry one of the five standard names. Names that differ from a standard name in any way are allowed and are separate fields: `title`, `Username`, ` Title` (leading space) and `URL ` (trailing space) can all sit next to `Title` and `URL` in one entry.

MOD-01.3 **Adding and renaming a custom field on the edit screen.**
- Add: the new field gets the base name B, or if B is taken, B followed by a space and the first of 1, 2, 3 … that gives an unused name. B is Larsal's own UI text (recommended: `New field`). The new field's value is empty and its protected flag is off. The name cell opens for typing at once.
- Rename: the new name is refused when it is empty, is one of the five standard names, or equals the name of another field of this entry. A refused rename leaves the old name in place. The reference refuses silently; Larsal shows an inline message `msg.field_name_invalid` (our ID) naming the reason, without the field value.
- White space: the reference keeps typed names exactly, so `  ` (two spaces) is a valid name. Larsal trims leading and trailing white space (the Unicode White_Space set of FMT-11.26) from names the user types, then applies the refusal rules, so a name made only of spaces is refused (lead decision D-01-1, recommended). Names read from a file are never trimmed (MOD-01.4).
- Removing a custom field asks for confirmation (Remove / Cancel, Cancel is the default).

MOD-01.4 **Names from a file are kept.** A name read from a file is kept exactly: an empty name, leading or trailing white space, any case. Larsal never renames a field by itself. On save, characters XML cannot hold are removed from names (FMT-11.46). An entry read with an empty-named field shows that field with an empty name; the user may rename it.

MOD-01.5 **Values.** A value is any Unicode text, empty included, kept exactly (no trimming). When the edit screen is saved, every line break in `Title`, `UserName` and `URL` becomes one space; a line break is CR LF, LF or CR, and CR LF counts as one break (`a` CR LF `b` LF `c` becomes `a b c`). `Notes`, `Password` and custom field values keep their line breaks. Values set by other paths (file, import, command line, browser bridge) are not changed by this rule.

MOD-01.6 **Own protected flag.**
- Default: off for the five standard fields of a new entry and for every new custom field.
- Custom fields: the user turns the flag on or off on the edit screen. While the flag is on, the value is hidden there (a placeholder text stands in its place) until the user presses Show; turning the flag on first stores the text currently shown; turning it off keeps the stored value.
- Standard fields: no screen changes their own flag. It is set only by reading a file (FMT-11.19, FMT-11.21). Their protection on save also comes from the vault flags (FMT-11.20, MOD-12).
- Changing a value never changes the flag; renaming a custom field keeps its flag.
- The detail view hides the value of every custom field whose own flag is on, with a Show control per field (SC-04).

MOD-01.7 **Secret handling.** Every value whose effective protection is on, and the `Password` value always, lives in a secret type (`SecretString`, plan/architecture.md secret.rs) in live entries and in history items. Such a value never goes into a log line, an error text or a view other than Show (AGENTS.md rule 4). Larsal may keep other values in secret types too. Turning protection off never copies a value out into a plain string.

MOD-01.8 **Field names with a meaning.** Some custom field names mean something to Larsal (full list and protection: FMT-14.22): additional URLs (`KP2A_URL`, `KP2A_URL_1`, `KP2A_URL_2` …, INT-03), one-time password fields (FEA-04), `_EXEC_CMD` (MOD-08.31) and passkey fields, whose names start with `KPEX_PASSKEY` (INT-04).
- A user may type such a name by hand; the field takes its meaning at once (for example, a field named `otp` makes the entry show a one-time code, FEA-04).
- The edit screen's additional URL list names a new URL `KP2A_URL`, or if taken `KP2A_URL_` followed by the first unused of 1, 2, 3 … (INT-03 owns the rest of that list).
- Passkey fields are left out of every list of "custom fields" except the edit screen's field list: they are not in search over custom fields (FEA-01), the copy-field menu, the field name suggestions (MOD-01.24), the detail view, or the HTML export (FEA-09). The edit screen lists them like other custom fields.

MOD-01.9 **Limits.** The reference has no size or count limit on fields. Larsal refuses an edit, with message `msg.field_too_large` (our ID), that would make: (Decided: spec/decisions.md LD-56.)
- a field value longer than 50,331,648 bytes of UTF-8 (48 MiB). Any value can be written as base64 once it is protected (MOD-12), and the `text` limit of FMT-08.12 (67,108,864 bytes) is measured before base64 decoding, so three quarters of it is the most a value may hold;
- a field name longer than 67,108,864 bytes of UTF-8 (the `text` limit of FMT-08.12; names are never base64);
- more than 99,995 custom fields in one entry. The writer always writes the five standard fields, and the `strings` limit of FMT-08.12 is 100,000 `String` elements per entry or history item (FMT-11.48).

So Larsal never makes an entry that Larsal cannot save and read back (decided: spec/decisions.md LD-56). Reading follows FMT-11.48 only.

MOD-01.10 **URL change and the remembered command choice.** When the `URL` value changes and the field `_EXEC_CMD` holds exactly `1` or `0`, that field is removed in the same change batch. Any other `_EXEC_CMD` value stays. MOD-08.31 owns what the field means and how a URL is opened.

### Other properties

MOD-01.11 **Carried properties.** Every property of the table above survives open and save (FMT-11). Properties no screen edits (override URL, usage count, last access time, previous parent group, kept unknown elements) are only changed by the rules of this card and of the cards it names.

MOD-01.12 **Id.** 16 bytes, never the zero id, unique among the live entries of the vault (group ids are a separate space, FMT-11.33). A new entry gets a random RFC 4122 version 4 UUID drawn from larsal-crypto random; Larsal draws again if the result is already used by a live entry. The id never changes on edit. History items carry their owner's id (FMT-11.32). A clone, and an entry copied or moved into another vault, is a new entry with a new id (MOD-10, MOD-02.22).

MOD-01.13 **Icon.** An entry shows either a standard icon number or a custom icon (MOD-06). Choosing a standard number clears the custom icon. Choosing a custom icon sets the number to 0. Choosing the icon that is already set is no change.

MOD-01.14 **Colors.** Foreground and background color are texts; empty means no color.
- When the user picks a color, Larsal stores `#rrggbb` with lowercase hex digits (FMT-12.18). Turning a color off stores empty text.
- Larsal keeps the stored text of a color the user did not change, whatever it holds (`red`, `#FF0000`, `#GG0000`).
- The reference's edit screen rewrites both colors whenever the entry is saved there: any text its UI toolkit understands as a color becomes lowercase `#rrggbb` (observed in the source: `red` becomes `#ff0000`, `#F00` and `#FF0000` become `#ff0000`), and text it cannot read is removed. That rewrite counts as a change and makes a history item. Larsal does not copy it (lead decision D-01-3, recommended).
- Display uses only colors of the form `#` plus 6 hex digits (FMT-12.18); the foreground color tints the entry's row text, the background color tints the row or a color marker (screen detail: APP cards).

MOD-01.15 **Override URL.** Text, carried only. No reference screen shows or edits it and nothing in the reference uses it. Larsal does the same: it is never opened, run or used for matching (AT-E02).

MOD-01.16 **Tags.** MOD-07 owns them.

MOD-01.17 **Expiry.** The expires flag and the expiry time: MOD-09 owns their meaning and the edit screen presets. Both are data: changing either is a change (MOD-01.26).

MOD-01.18 **Auto-type block.** Enabled (default true), obfuscation (default 0, carried; no screen in the reference shows it), default sequence (default empty, which means "use the group's", MOD-02.16) and window associations (default none). INT-05 owns what they do.

MOD-01.19 **Report exclusion.** A boolean on the edit screen ("leave out of password reports"); default false. FEA-05 reads it. The older custom data flag is converted on read (FMT-14.19).

MOD-01.20 **Attachments, custom data, history.**
- Attachments: MOD-05.
- Custom data belongs to plug-ins (keys: FMT-14.20). The edit screen's properties page lists the items (key and value) and lets the user delete selected items after a confirmation; it never lets the user add or change one. Deleting is a change (MOD-01.26). FMT-14.18 says how `_LAST_MODIFIED` follows changes.
- History: MOD-03.

MOD-01.21 **Previous parent group.** Set only by moves (MOD-02.21, MOD-02.22, MOD-04) and by merge moves (MOD-11.7). No screen edits it.

### New entries

MOD-01.22 **What "Add entry" gives.** The user picks a group and chooses Add entry; the edit screen opens with a new entry that is not yet in the vault. It has the defaults of the property table, and also:
- `UserName` = the vault's default user name (FMT-10, `DefaultUserName`), when that is not empty;
- `Password` = empty, or a generated password when setting `set.entry_autogen_password` (our ID; APP-01 owns the final ID) is on; default off; the generator uses the saved generator settings, or its defaults when those are invalid (FEA-02);
- the icon of MOD-06.3.

Entries made by other paths do not take the default user name: the command line add command (INT-10), the browser bridge (INT-02), passkey creation (INT-04), imports (FEA-08).

MOD-01.23 **User name suggestions.** The edit screen's user name box offers the vault's most used user names: at most 10, counted over all live entries of the whole tree (recycle bin included), leaving out empty values, values that are field references (MOD-08), and protected values (the field's own flag, or the vault's ProtectUserName flag; LD-105); ordered by count, highest first, ties by name in code unit order. The list is rebuilt after the vault is opened and after each save. The box always shows the list as a drop-down. As-you-type completion from the same list happens only while setting `set.username_autocomplete` (our ID) is on; default on (APP-01).

MOD-01.24 **Field name suggestions.** While a custom field name is typed, the edit screen suggests names used by custom fields in other live entries: entries in the recycle bin and passkey fields (MOD-01.8) left out, each name once, minus the names this entry already has. Order: natural and case-insensitive, digit runs compared by value (the comparison of MOD-07.5). The list is rebuilt after open and after each save.

MOD-01.25 **Commit and the times of a new entry.** The new entry joins the chosen group only when the user saves the edit screen. Cancel leaves no trace in the vault (custom icons added meanwhile stay: MOD-06.10).
- Larsal: creation time, last modification time, last access time, location changed and expiry time are all set to the commit time; expires is false; usage count is 0 (lead decision D-01-4, recommended).
- Reference (from the source and observed): creation time and expiry time are the moment the add screen opened; modification and last access time are the time of the last field change before saving (usually the save); location changed is the save. So in the reference the creation time can be earlier than the save by the time the screen was open.

### Times

MOD-01.26 **Last modification time.** It is set to now whenever a stored property of the entry really changes:
- a standard or custom field value; a field's own protected flag; a custom field added, removed or renamed;
- an attachment added, removed, renamed or replaced (MOD-05);
- a custom data item added, changed, renamed or removed;
- icon number or custom icon; either color; override URL; tags; expires flag; expiry time;
- auto-type enabled, obfuscation, default sequence or associations; report exclusion;
- previous parent group, so a move to another group of the same vault (MOD-02.21), except when the previous parent already names the old group: then it does not change and no time moves (as MOD-03.5);
- history items deleted in the editor (MOD-03.13);
- id.

Setting a property to the value it already has changes nothing and moves no time. All changes of one change batch get one time. History items never get new times.

MOD-01.27 **Last access time.** It moves with the last modification time, to the same value, and at no other moment. Viewing an entry, Show, copying a field, auto-type and a browser fill do not move it. This is what the reference does (its entry list even dropped the access column); Larsal does the same (lead decision D-01-5, recommended: anything else would turn every read into a vault change that must be saved and merged).

MOD-01.28 **Usage count.** Never changed by any action. A new entry has 0; a read value is kept and written back as read (negative values included, FMT-11.13).

MOD-01.29 **Location changed.** Set to now each time the entry is put into a group: when a new entry is committed, when it moves to another group of the vault (MOD-02.21), when it goes to the recycle bin and when it is restored (MOD-04), and for the new entry made by a cross-vault move or copy (MOD-02.22). An edit never moves it. Putting an entry into the group it is already in is no move.

MOD-01.30 **Creation time.** Set once when the entry is made. Only clone with reset times (MOD-10), cross-vault copies (MOD-02.22) and merge (MOD-11) give an entry another creation time.

MOD-01.31 **Changes that move no entry time.**
- Reading a file, and anything done while reading (FMT-11, FMT-14.19).
- Merge and shared-group sync, which carry the source's times (MOD-11, INT-08).
- Removing a custom icon from history items (MOD-06.14, MOD-06.15).
- Reordering entries inside a group (MOD-02.24): only the group is touched.
- Changes to the entry's group (MOD-02.25).

MOD-01.32 **Which changes make a history item.** An edit session that changes at least one property adds exactly one history item: a copy of the entry as it was before the session (MOD-03 owns limits and details). The reference makes no history item for changes made outside an edit session: moves on screen (MOD-02.21), the tag menu and tag removal across the vault (MOD-07.7, MOD-07.9), icon "apply to children" (MOD-06.13), bulk icon download (MOD-06.11), icon removal (MOD-06.14) and expire now (MOD-09.9). These still move the entry's times by MOD-01.26. Its command line move does make one; Larsal's command line move makes none (MOD-03.5, lead decision L03-1). Otherwise Larsal does the same as the reference unless MOD-03 rules otherwise.

### Templates

MOD-01.33 **No entry templates.** The reference has no entry template feature. Its vault keeps a pointer to a templates group, which it carries and never sets (FMT-10.16). Larsal offers no templates and carries the pointer the same way.

### Not on Mac

- The Linux secret service plug-in exposes entries of one chosen group to other programs and writes entries through that service. Larsal does not build it; its vault custom data key is kept (FMT-14.20).

## Edge cases and errors

| Case | Expected behavior |
|---|---|
| Rename a custom field to `Password` | Refused (MOD-01.3); `msg.field_name_invalid`; old name stays. |
| Rename a custom field to `password` (lowercase) | Allowed: it is a custom field, not the standard field. |
| Rename to the name of another custom field of the entry | Refused; old name stays. |
| Typed name `  ` (two spaces) | Larsal: refused after trimming (D-01-1). Reference: accepted as a name of two spaces. |
| File holds a custom field with an empty name | Kept and shown with an empty name (MOD-01.4); saved back as an empty key (FMT-11.17). |
| File holds both `Title` and ` Title` | Two fields: the standard title and a custom field named ` Title`. |
| Title pasted with line breaks on the edit screen | Each break becomes one space on save (MOD-01.5). |
| Edit screen saved without any change | No change batch: no time moves, no history item. |
| Color `#GG0000` read from a file, entry saved on the Larsal edit screen without touching colors | Kept as `#GG0000` (MOD-01.14); not shown as a color. |
| A value over 50,331,648 bytes, or a name over 67,108,864 bytes, typed or pasted | Refused with `msg.field_too_large`; the entry is unchanged (MOD-01.9). |
| A 99,996th custom field added | Refused with `msg.field_too_large` (MOD-01.9). |
| `URL` changed while `_EXEC_CMD` = `0` | `_EXEC_CMD` removed in the same batch (MOD-01.10). |
| `URL` changed while `_EXEC_CMD` = `yes` | `_EXEC_CMD` kept. |
| Field named `otp` added by hand | The entry has one-time password settings from that value (FEA-04). |
| Vault default user name is empty | New entry's `UserName` is empty. |
| Add entry, then Cancel | Nothing added to the vault; no deleted-object record. |
| A new id collides with an existing live entry id | Larsal draws again (MOD-01.12). |
| Entry copied or Show used | No time moves (MOD-01.27). |

## Security notes

- **Protected values (SF-08, SF-09).** Values with effective protection, and every `Password`, are secret types in live entries and history items, and are never logged, never put in error text and never sent to the screen except by Show (AGENTS.md rule 4, MOD-01.7). A protected value must never be written as plain text inside a vault (FMT-11.20). AT-C01, AT-C02 and AT-C06 check this.
- **Masking (SC-04).** Protected custom fields are masked in the detail view and on the edit screen until Show (MOD-01.6). Show returns one value; hiding it again drops it from the screen layer (AT-E07).
- **Untrusted text (AT-E01, AT-E03).** Field names, values, colors and the override URL come from files and imports. They are shown as plain text, never as HTML or CSS; a color is used only in the `#` plus 6 hex digits form. Edit commands with huge names or values are refused by MOD-01.9 before any copy is made.
- **Nothing runs (AT-E02).** The model never opens or runs the override URL or a `cmd://` URL (MOD-01.15); opening a URL is MOD-08.31.
- **Special names.** A hostile vault can carry fields with meaning (one-time password, passkey, additional URLs). They are data; the cards that use them check them (FEA-04, INT-03, INT-04).
- **No silent writes.** Last access time and usage count do not move on reads (MOD-01.27, MOD-01.28), so viewing never makes the vault dirty and never leaks usage into the file.
- **Report exclusion (SG-04).** An excluded entry is still a normal entry everywhere else; only FEA-05 reports leave it out.

## Test cases

Notation: the clock is fixed per case; t0 = 2026-10-25T10:00:00Z, t1 = 2026-10-25T10:05:00Z, t2 = 2026-10-25T10:10:00Z. "Vault V" is a demo vault with root group R and group G under R; vault flags default (only `ProtectPassword` on). "Save the edit screen" means one edit session.

| Case | Given | When | Then |
|---|---|---|---|
| MOD-01.1 standard set | New entry | Inspect fields | Exactly `Title`, `UserName`, `Password`, `URL`, `Notes`, all empty; removing or renaming any of them is refused. |
| MOD-01.1 order | Entry read from a file whose strings come in order `URL`, `Notes`, `Title` | Open the detail view | Fields shown Title, UserName, Password, URL, Notes. |
| MOD-01.2 case-distinct names | Entry E in G with `Title`=`Bank` | Add custom fields `title`=`x`, `Username`=`y`, ` Title`=`z` | All three stored as custom fields; E has 8 fields; `Title` still `Bank`. |
| MOD-01.3 default names | Entry with no custom field | Add a field three times | Names `New field`, `New field 1`, `New field 2`; values empty; own flags off. |
| MOD-01.3 default name gap | Entry with custom fields `New field` and `New field 2` | Add a field | Name `New field 1`. |
| MOD-01.3 refused renames | Entry with custom fields `A`, `B` | Rename `A` to `` (empty), to `Notes`, to `B` | Each refused; field still named `A`; `msg.field_name_invalid` shown each time. |
| MOD-01.3 trim | Entry with custom field `A` | Rename `A` to `  PIN  ` | Larsal stores the name `PIN`. |
| MOD-01.3 spaces only | Entry with custom field `A` | Rename to two spaces | Larsal refuses (D-01-1). |
| MOD-01.3 remove confirm | Custom field `A` | Remove, answer Cancel | Field kept; no change batch. |
| MOD-01.4 file names kept | File with an entry holding custom keys `` (empty) and `x ` | Open, save without edits, open again | Both keys present, unchanged. |
| MOD-01.5 line breaks | Edit screen of E | Set Title to `a` CR LF `b` LF `c` CR `d`, Notes to `n1` LF `n2`, save | Title `a b c d`; Notes `n1` LF `n2`. |
| MOD-01.5 other paths | Command line edit sets Title to `a` LF `b` | Read the entry | Title `a` LF `b` (rule applies to the edit screen only). |
| MOD-01.6 default flags | New custom field `PIN`=`1234` | Save | `PIN` own flag off; written unprotected unless the user turned the flag on. |
| MOD-01.6 protect toggle | Custom field `PIN` unprotected, edit text box shows `9999` (typed, not yet stored) | Turn protection on | Stored value `9999`, own flag on, text box shows the placeholder. |
| MOD-01.6 unprotect keeps value | Custom field `PIN`=`1234` protected | Turn protection off | Value still `1234`, own flag off. |
| MOD-01.6 standard flag sticks | File entry whose `UserName` is read protected; vault `ProtectUserName` off | Change UserName to `bob`, save vault, read the file | `UserName` written with `Protected="True"` (FMT-11.21). |
| MOD-01.7 no secret in logs | Entry with `Password`=`DemoPass-7` and protected custom `PIN`=`4711` | Run open, edit, save at the highest log level; force an error during save | No log line or error text contains `DemoPass-7` or `4711` (AT-C06). |
| MOD-01.8 typed meaning | Entry without one-time settings | Add custom field `otp` = `otpauth://totp/demo?secret=JBSWY3DPEHPK3PXP` | The entry shows a one-time code (FEA-04). |
| MOD-01.8 additional URL names | Entry with custom field `KP2A_URL` | Add a URL in the URL list twice | New fields `KP2A_URL_1`, then `KP2A_URL_2`. |
| MOD-01.8 passkey fields hidden | Entry with custom fields `KPEX_PASSKEY_USERNAME`=`demo` and `Color`=`blue` | Open the detail view; open the field name suggestions in another entry | Detail view lists only `Color`; suggestions offer `Color`, not the passkey name; the edit screen lists both. |
| MOD-01.9 value too large | Entry E | Paste a 50,331,649-byte value into a custom field and save | Refused with `msg.field_too_large`; entry unchanged; no history item. |
| MOD-01.9 value at the cap round-trips | Entry E; the vault protects passwords (MOD-12) | Set the password to exactly 50,331,648 bytes, save, open again | Saved (no TooLarge); the value reads back the same. Its base64 text is 67,108,864 bytes, exactly the FMT-08.12 `text` limit. |
| MOD-01.9 name too large | Entry E | Add a custom field whose name is 67,108,865 bytes | Refused with `msg.field_too_large`. |
| MOD-01.9 count | Entry with 99,995 custom fields (built by a test vault builder) | Add one more | Refused with `msg.field_too_large`; saving the 99,995-field entry and opening it again works (100,000 `String` elements with the five standard ones). |
| MOD-01.10 exec choice reset | E with `URL`=`cmd://open-demo`, `_EXEC_CMD`=`1` | Set URL to `cmd://open-demo2`, save | `_EXEC_CMD` removed; one history item. |
| MOD-01.10 other value kept | E with `_EXEC_CMD`=`maybe` | Change URL | `_EXEC_CMD`=`maybe` still there. |
| MOD-01.11 carried | File entry with override URL `cmd://x`, usage count 7, kept unknown element `<Z>1</Z>` | Open, edit Title, save, read | Override URL `cmd://x`, usage count 7, `<Z>1</Z>` present. |
| MOD-01.12 new id | Vault V | Add entry, commit | Id is 16 bytes, not zero, byte 6 high nibble 4 and byte 8 top bits 10 (version 4), unique among live entries. |
| MOD-01.12 id stable | Entry id id(10) | Edit and save five times | Id still id(10); history items carry id(10). |
| MOD-01.13 icon switch | E with custom icon X | Pick standard icon 12 | Icon number 12, no custom icon. Then pick X: custom icon X, number 0. |
| MOD-01.14 pick | E without colors | Pick red for the foreground on the color picker | Foreground `#ff0000`; background empty. |
| MOD-01.14 keep unknown | File entry with foreground `#GG0000`, background `RED` | Change Title on the Larsal edit screen, save | Foreground `#GG0000`, background `RED`. (Reference: foreground removed, background `#ff0000`.) |
| MOD-01.14 off | E with background `#00ff00` | Turn the background color off, save | Background empty. |
| MOD-01.15 override URL inert | File entry with override URL `cmd://touch /tmp/x` | Open, view, copy URL, save | Nothing run; `/tmp/x` not created; value kept. |
| MOD-01.16 tags pointer | E on the edit screen, tags `b` then `a` typed in the tag box | Save, read the entry | Tags `a`, `b` (MOD-07.3 applies). |
| MOD-01.17 expiry is data | E at t0, expires false | At t1 turn expires on with expiry t2, save | Modification time t1; one history item. |
| MOD-01.18 auto-type defaults | New entry | Inspect | Enabled true, obfuscation 0, default sequence empty, no associations. |
| MOD-01.19 exclusion | New entry | Inspect; then tick the exclusion box and save | First false; then true and FEA-05 reports leave it out. |
| MOD-01.20 custom data delete | E with entry custom data item `PluginDemo`=`1` | Delete it on the properties page and confirm | Item gone; modification time = now; one history item (it was an edit session). |
| MOD-01.21 previous parent automatic | New entry committed in G | Inspect | Previous parent none. |
| MOD-01.22 default user name | Vault default user name `demo-user` | Add entry in G | Edit screen opens with UserName `demo-user`, Password empty (setting off), icon per MOD-06.3. |
| MOD-01.22 autogen | Setting `set.entry_autogen_password` on, generator length 20 | Add entry | Password box holds a 20-character generated password. |
| MOD-01.22 command line | Vault default user name `demo-user` | Command line add `E2` | E2 UserName empty. |
| MOD-01.23 user name list | Live entries with user names a ×3, b ×3, c ×1, empty ×5, `{REF:U@I:...}` ×4, and 9 other distinct names once each | Open the edit screen | Suggestions start `a`, `b` (count 3, code unit order), then count-1 names in code unit order; 10 names in all; no empty value and no reference. |
| MOD-01.24 field name list | Live entries with custom fields `PIN`, `pin`, `Code2`, `Code10`; an entry in the recycle bin with `Secret`; current entry has `PIN` | Type a new field name | Suggestions `Code2`, `Code10`, `pin` (in that order); not `PIN`, not `Secret`. |
| MOD-01.25 commit times | Vault V, clock t0 at Add entry, t1 at save | Add entry in G at t0, type Title `Mail`, save at t1 | Larsal: creation, modification, last access, location changed and expiry time all t1; expires false; usage count 0. Reference: creation and expiry t0, the others t1. |
| MOD-01.25 cancel | Vault V | Add entry, type Title, Cancel | Entry count unchanged; deleted objects unchanged. |
| MOD-01.26 change moves time | E saved at t0 | At t1 change only the protected flag of custom field `PIN`, save | Modification time t1, last access t1, one history item. |
| MOD-01.26 same value | E at t0 with Title `Mail` | At t1 set Title to `Mail` (same), save | Times still t0; no history item. |
| MOD-01.27 no access update | E at t0 | At t1 view E, Show the password, copy the user name, auto-type it | Last access and modification still t0; vault not dirty. |
| MOD-01.28 usage count | File entry with usage count -5 | Edit and save | Usage count -5 written back. |
| MOD-01.29 location changed | E committed in G at t0 | At t1 edit Notes and save | Location changed still t0. At t2 move E to R: location changed t2. |
| MOD-01.30 creation kept | E created at t0 | Edit at t1 and t2 | Creation time t0. |
| MOD-01.31 reorder | Entries E1, E2 in G, all times t0 | At t1 move E2 up | E1 and E2 times unchanged (t0). |
| MOD-01.32 move without history | E in G, 0 history items, at t0 | At t1 drag E onto R | E in R, previous parent G, modification t1, location changed t1, 0 history items. |
| MOD-01.32 edit session history | E Title `A` at t0 | At t1 set Title `B` and Notes `n`, save once | Exactly 1 history item with Title `A` and modification time t0. |
| MOD-01.33 no templates | File whose templates-group pointer names G | Open, save | Pointer still names G (FMT-10.16); no template action anywhere. |

## How this was learned

- Lead decisions D-01-1 and D-01-3 to D-01-5 (decided: spec/decisions.md default rule, each takes the recommended option). D-01-2, the edit limits, is decided by LD-56 with the numbers in MOD-01.9.

- Read the reference's entry model, its field map and its time-info type in the core folder: default values, the setter rule that only real changes count, the rule that every change moves both modification and access time, the move routine (location time, previous parent, custom icon copy and deleted-object record on cross-vault moves), the clone routine, the passkey-name filter, the additional URL prefix and the tag handling.
- Read the entry edit screen and its field list model: field defaults, the default-name counter, the rename refusals, the protect and Show controls, the line-break replacement on save, the color buttons and their rewrite, the save routine with its begin/end of the history step, and the new-entry flow in the main vault view (default user name, group icon, generated password).
- Read the vault model's rebuild of user name suggestions (top 10) and field name suggestions, and the setting defaults in the settings table.
- Read the reference's tests for modification signals, entry previous parent and moves.
- Searched the whole source for every place that sets the access time or the usage count: only the modification step, clone and importers do; nothing increments the usage count. The entry list keeps only a placeholder for a removed access column.
- Ran the installed command line tool 2.7.11 on demo vaults in a scratch folder (password `demo`): add, edit, mkdir, mv and export showed the defaults (icon 0, expires false, usage count 0, expiry time equal to creation time), that edit and command line move each add one history item, that a move sets previous parent group and moves location changed, modification and access time of the entry, and that adding an entry moves the group's modification time. A crafted XML import showed that ` Title`, `title` and an empty key are kept as separate custom fields.
