# FMT-14 Custom icons and custom data

Status: reviewed
Epics: E3-S6
Parity rows: SD-06, SF-07, SF-08, SI-01, SI-02, SI-04, SI-09

## What it does

The vault document (FMT-11) holds two kinds of extra data:

- **Custom icons.** These are images stored once in Meta. Groups and entries point to them by id (FMT-11.11).
- **Custom data.** These are lists of key and value text pairs, each with an optional change time. Custom data can sit on the vault (in Meta), on each group, and on each entry, history items included. The reference and plug-ins keep settings there.

This card gives the structure, the encodings, the version rules, the read and write behavior, and a list of the keys that the reference itself writes. It also lists the reserved string-field names the reference writes on entries, because they are often confused with custom data keys.

FMT-10 gives where these blocks sit inside Meta. Ids, times and base64 follow FMT-12. "V", "id", "id(xx)", "zero id", "fail" and "open time" mean the same as in FMT-11. Larsal writes the V that FMT-16 chooses: 4.0 or 4.1 by content (FMT-16.18, FMT-16.19), or at least the version the file was read as while the vault holds kept unknown parts, such as the kept children of FMT-14.6 and FMT-14.16 (FMT-16.24, decided: spec/decisions.md LD-09). Every gate "V ≥ 4.1" in this card holds for any 4.x minor of 1 or more. Version 3.1 facts in this card describe the reference and what Larsal reads.

Keys whose text contains a banned name are given only as hex bytes of their ASCII text, marked "stored encoded (name rule)". Builders put those exact bytes into the code as a byte string.

Custom data here is not the same as the public custom data in the outer header (FMT-02, FMT-03).

## Inputs and outputs

Read:
- In: the `CustomIcons` element of Meta, and the `CustomData` elements of Meta, groups, entries and history items.
- Out:
  - custom icons, in order: id, image bytes, optional name, optional time;
  - custom data containers: one for the vault and one for each group, entry and history item. Each holds items in order: key, value, optional time.

Write: the same model plus V, giving XML elements.

Limits: FMT-08.12 owns the numbers (decided: spec/decisions.md LD-22); FMT-14.25 says how they are counted. The reference has no such limits.

## Rules

### Custom icons

FMT-14.1 **Place and structure.** `CustomIcons` sits in Meta at the position FMT-10 gives. It is always written, as an empty element when there are no icons. It holds one `Icon` per custom icon. The children of `Icon`, in write order:

| # | Element | Content | Since | Written |
|---|---|---|---|---|
| 1 | `UUID` | id | all | always |
| 2 | `Name` | text | 4.1 | only when V ≥ 4.1 and not empty |
| 3 | `LastModificationTime` | time (FMT-12) | 4.1 | only when V ≥ 4.1 and set |
| 4 | `Data` | base64 of the image bytes | all | always; empty element when there are no bytes |

FMT-14.2 **Image data.** `Data` is the base64 of the image file's bytes (FMT-12). The reference stores PNG. On read, any bytes are accepted, including none. Images are decoded only when shown (MOD-06), never in the format layer.

FMT-14.3 **How the reference creates icons** (for MOD-06, information only). There are three ways:
- on the edit screen, the user picks an image file;
- on the edit screen, the app downloads a website's icon for the entry;
- the bulk icon download, which fetches website icons for several selected entries at once.

All three use steps 1 to 3. Steps 4 and 5 apply to the edit screen only:
1. If the image is wider or taller than 128 pixels, it is scaled to exactly 128 × 128 pixels; the aspect ratio is not kept. Smaller images keep their size.
2. The image is encoded as PNG.
3. If an icon with the same PNG bytes already exists, its id is reused and no new icon is added. The reference finds such an icon by an MD5 hash of the PNG bytes. Larsal may compare the bytes themselves.
4. `Name` becomes the image file's name up to its first dot. A downloaded icon gets an empty `Name`.
5. `LastModificationTime` becomes the time the icon was added (UTC).

So every icon added on the edit screen has a time, and that forces V 4.1 (FMT-14.4). The bulk download adds the icon with no `Name` and no time, so it does not raise V.

Copies between open vaults: dragging a group into another open vault copies the icons it uses with id, bytes, `Name` and time. Dragging an entry into another open vault copies its custom icon with id and bytes only, so the `Name` and time are lost there. Both are read from the source.

FMT-14.4 **Versions.** An `Icon` with `UUID` and `Data` exists in all versions. `Name` and `LastModificationTime` exist since 4.1. They are read in any file version, but below 4.1 they are not written, so they are lost on such a save. A vault with any icon that has a name that is not empty, or has a time set, needs V 4.1 (FMT-16).

FMT-14.5 **Order.** Icons are written in stored order. Read order becomes stored order. New icons are added at the end. Several `CustomIcons` elements add up into one list of icons, in document order. This holds both for several `CustomIcons` in one Meta and for `CustomIcons` in several Meta elements. A later block does not replace an earlier one: this is not a case of "values from the second replace those from the first" in FMT-10.13. An icon whose id an earlier icon already has follows FMT-14.7. The writer writes one `CustomIcons` element.

FMT-14.6 **Reading an icon.** The children of `Icon` may come in any order. `Name` and `LastModificationTime` are read in any file version; without `LastModificationTime` the icon has no time. The open fails, with the reason "a custom icon has no id or no data", in each of these cases:
- `UUID` is missing,
- `UUID` is empty or the zero id,
- `UUID` does not decode to exactly 16 bytes,
- `Data` is missing.

When a child appears more than once, the last one decides. So an empty, zero or wrong-length `UUID` that comes after a valid one also fails the open. An empty `Data` element is allowed. The reference skips unknown children of `Icon`, and children of `CustomIcons` other than `Icon`. We keep them, with the policy of FMT-11.45 (decided: spec/decisions.md LD-27); they count toward the kept unknown limit of FMT-11.48.

FMT-14.7 **Duplicate icon ids.** When an `Icon` carries an id that an earlier icon already has, the later icon gets a fresh random id (larsal-crypto random) and is kept. References with that id keep pointing to the first icon.

FMT-14.8 **References.** Groups and entries point to an icon with `CustomIconUUID` (FMT-11.11). Nothing checks that the icon exists. A pointer to a missing icon is kept. Icons that nothing points to are kept too; the format layer never purges them.

FMT-14.9 **Removing an icon.** When the app removes a custom icon, the icon's id is added to the deleted-objects list with the current time (FMT-15.7).

### Custom data

FMT-14.10 **Structure.** `CustomData` holds `Item` elements. The children of `Item`, in write order:

| # | Element | Content | Since | Written |
|---|---|---|---|---|
| 1 | `Key` | text | all | always |
| 2 | `Value` | text | all | always; empty element when empty |
| 3 | `LastModificationTime` | time (FMT-12) | 4.1 | per FMT-14.13 |

On write, `Key` and `Value`, like icon `Name`, lose the characters XML cannot hold, with the removal set of FMT-12.25 (as FMT-11.46).

FMT-14.11 **Where it sits, and versions.**
- **Vault custom data.** In Meta, at the position FMT-10 gives. It is written in every version: both versions Larsal writes, and 3.1 files of the reference.
- **Group custom data.** At FMT-11.6 row 13. Written only when V ≥ 4.0, which always holds for Larsal; the reference never writes it in 3.1.
- **Entry custom data**, for live entries and history items. At FMT-11.15 row 14. Written only when V ≥ 4.0, as for groups.

Custom data that is not empty on any group, live entry or history item needs V 4.0 (FMT-16). Vault custom data never raises V.

FMT-14.12 **Empty containers.** A container with no items is not written: there is no `<CustomData/>` element.

FMT-14.13 **Item time on write.** The reference writes `LastModificationTime` only when all three are true:
- the item belongs to the vault container,
- V ≥ 4.1,
- the item has a time.

It never writes item times for group or entry items. It reads them, in any file version and on every container, but they are lost at its next save.

We write the time of every item that has one, on every container, when V ≥ 4.1. The format allows this, and the reference reads it (decided: spec/decisions.md, default rule, the card's recommendation for L14-1).

FMT-14.14 **Item time on read.** An item read without `LastModificationTime` has no time. When we create or change an item, we set its time to now. (The reference instead gives such an item the current time during the read. It then writes that time back for vault items at 4.1.)

FMT-14.15 **Item order.** The reference writes items in an arbitrary order: hash-table order, which changes from run to run. We keep the read order as stored order. New keys go at the end. A changed key keeps its place. Readers must not depend on item order.

FMT-14.16 **Reading items.**
- `Item` needs both `Key` and `Value`. If either is missing, the open fails with the reason "a custom data item has no key or no value".
- An empty key and an empty value are both allowed and kept.
- A second item with the same key in the same container, with a different value, replaces the first item as a whole: its value and its time. When that later item has no `LastModificationTime`, the reference gives it the current time during the read; we give it no time (FMT-14.14). If both values are equal, the first item and its time stay, and the later item's time is ignored.
- Several `CustomData` blocks under one parent add up into one container, in document order. For the vault this also holds across several Meta elements: the vault custom data of all Meta elements adds up, and a later block does not replace an earlier one (unlike the simple values of FMT-10.13).
- The reference skips unknown children of `Item`, and children of `CustomData` other than `Item`. We keep them (FMT-11.45 policy).

FMT-14.17 **Plain text on write, honoured protection on read.**
- **Write.** The writer never writes a `Protected` attribute inside custom data, and the model has no protected flag for custom data. Writing custom data takes no keystream bytes. Only the outer encryption protects a value stored here.
- **Read.** `Key`, `Value` and `LastModificationTime` of an `Item` are value elements like any other (FMT-12.22). When one carries a true `Protected` attribute and its text is not empty, it is decrypted with the next keystream bytes, in document order (FMT-09). The decrypted text becomes the plain key, value or time. If a reader skipped them, every later protected value in the document would decrypt wrongly.
- After such a read, the item is plain text in memory and is written back without `Protected`.

FMT-14.18 **The `_LAST_MODIFIED` item.** This item records when its container (vault, group or entry) last changed. It has no `LastModificationTime` of its own.

Its value is a UTC date and time as text, in this exact form. Larsal always writes this form:
1. the day of the week as an English three-letter name: `Mon`, `Tue`, `Wed`, `Thu`, `Fri`, `Sat` or `Sun`;
2. one space (0x20);
3. the month as an English three-letter name: `Jan`, `Feb`, `Mar`, `Apr`, `May`, `Jun`, `Jul`, `Aug`, `Sep`, `Oct`, `Nov` or `Dec`;
4. one space;
5. the day of the month in decimal, with no leading zero and no padding: `1` to `31`;
6. one space;
7. `HH:MM:SS` in 24-hour time, each part two digits with a leading zero;
8. one space;
9. the year in four digits;
10. one space, then `GMT`.

Milliseconds are dropped, not rounded. Examples: 2026-10-24T19:17:16Z is `Sat Oct 24 19:17:16 2026 GMT`. 2026-10-04T19:17:16Z is `Sun Oct 4 19:17:16 2026 GMT`, the 27 bytes `53 75 6E 20 4F 63 74 20 34 20 31 39 3A 31 37 3A 31 36 20 32 30 32 36 20 47 4D 54` (one space between `Oct` and `4`). 2026-03-01T00:00:00Z is `Sun Mar 1 00:00:00 2026 GMT`.

Day and month names in other languages. The source build uses a newer major version of its UI toolkit, whose text form for dates always uses the English names above (the toolkit's documented behavior for this format; not run, check with Verify). The installed 2.7.11 uses the short day and month names of the Mac's region setting instead (differs in installed version). Observed with a scratch probe that called the installed toolkit's date-to-text routine for 2026-10-04T19:17:16Z: region en_US gives `Sun Oct 4 19:17:16 2026 GMT`, region de_DE gives `So. Okt. 4 19:17:16 2026 GMT`, region fr_FR gives `dim. oct. 4 19:17:16 2026 GMT`. The day without a leading zero, the two-digit time parts and ` GMT` were the same in every region. So files saved by the installed version on a Mac with another region can hold such values. Larsal keeps any value as read (below) and only ever writes the English form. A value that does not have the English form is a time that is not valid for merge (FMT-14.24, MOD-11).

What the reference does:
- (a) On read, every container that ends up not empty gets `_LAST_MODIFIED` set to the current time during the read (taken per container, close to the open time). This replaces any value from the file.
- (b) A container whose only item is `_LAST_MODIFIED` ends up empty, and so is not written.
- (c) Each time an item is added, changed, renamed or removed, `_LAST_MODIFIED` is set to now. When nothing else remains, it is removed.
- (d) A merge decides between the two vault custom data containers by comparing their `_LAST_MODIFIED` values (MOD-11). It never copies the key itself.

What we do (decided: spec/decisions.md, default rule, the card's recommendation for L14-2):
- keep the value read from the file;
- apply (c) when we change items in that container;
- use exactly the text form above.

FMT-14.19 **Legacy report flag.** The ASCII key `KnownBad` is an older way to exclude an entry from password reports.
- **When.** The check runs after each `CustomData` block of an entry is read, for live entries and history items.
- **Value.** If the key is present with value exactly `true` (lowercase), the entry is excluded from reports (FMT-11.29). Any other value means included.
- **Item.** The item is removed in both cases. If that leaves only `_LAST_MODIFIED`, the container becomes empty.
- **What the reference does with `_LAST_MODIFIED`.** It removes the flag as a normal item removal, so rule (c) of FMT-14.18 applies in full. With rule (a), a container that keeps other items ends up with `_LAST_MODIFIED` at the current time during the read, even when the file had none (observed).
- **What we do with `_LAST_MODIFIED`.** Removing the flag is part of reading, not a change by the user, so it never sets or refreshes `_LAST_MODIFIED`. A value read from the file stays as read, and none is added when the file had none. If the removal leaves only `_LAST_MODIFIED`, the container is emptied and not written, as the reference does (the second half of rule (c)). This is not the edge case "container whose only item is `_LAST_MODIFIED`", which covers a container that held only that item in the file.
- **Order.** Because the check runs after the block, it overrides a `QualityCheck` element read earlier in the same entry.
- The key is never written.

FMT-14.20 **Keys the reference writes.** Values are text.

| Key | Container | Value | Meaning |
|---|---|---|---|
| `_LAST_MODIFIED` | vault, group, entry | date text (FMT-14.18) | Last change of this container |
| `4B 50 58 43 5F 52 41 4E 44 4F 4D 5F 53 4C 55 47` (stored encoded, name rule) | vault | lowercase hex, 128 to 1022 digits | Random padding (FMT-14.21) |
| `4B 50 58 43 5F 42 52 4F 57 53 45 52 5F` (stored encoded, name rule) followed by an association name | vault | the browser extension's public identification key, base64 text as the extension sent it | One browser association per key (INT-02, SI-01). Merge never removes these keys |
| `_CREATED_` followed by an association name | vault | local date and time in the system locale's short date-and-time form, for example `10/24/26 8:11 PM`; depends on the locale | When that browser association was made (INT-02). Unlike the key above, merge may remove it: only the bare key `_CREATED_` counts as protected |
| `4B 50 58 43 5F 44 45 43 52 59 50 54 49 4F 4E 5F 54 49 4D 45 5F 50 52 45 46 45 52 45 4E 43 45` (stored encoded, name rule) | vault | decimal integer, milliseconds | The unlock time the user picked in the simple encryption settings (CRY-02) |
| `4B 50 58 43 5F 61 75 74 6F 73 61 76 65 44 65 6C 61 79 4D 69 6E` (stored encoded, name rule) | vault | decimal integer, minutes, 0 to 420000000 | Autosave delay (APP-05) |
| `4B 50 58 43 5F 53 61 76 65 64 53 65 61 72 63 68` (stored encoded, name rule) | vault | JSON object mapping each saved-search name to its search text (indented JSON) | Saved searches (FEA-01) |
| `FDO_SECRETS_EXPOSED_GROUP` | vault | group id as text: braces, lowercase hex with dashes, for example `{6e8f3d0a-7c2b-4f55-9a10-1c2d3e4f5a6b}` | Group shared with the Linux secret service. Not used on Mac; kept. Merge never removes it |
| `4B 50 58 43 5F 52 45 4D 4F 54 45 5F 53 59 4E 43 5F 53 45 54 54 49 4E 47 53` (stored encoded, name rule) | vault | compact JSON (no spaces or line breaks) array of objects with the keys `name`, `downloadCommand`, `downloadCommandInput`, `downloadTimeoutMsec`, `uploadCommand`, `uploadCommandInput`, `uploadTimeoutMsec` | Remote sync programs (INT-09). Holds shell commands. Merge never removes it. Seen in the source only, not checked in the installed version |
| `BrowserHideEntry`, `BrowserSkipAutoSubmit`, `BrowserOnlyHttpAuth`, `BrowserNotHttpAuth`, `BrowserOmitWww` | group | `true` or `false`; a missing key means inherit from the parent group | Browser options for the group's entries (INT-02, SI-04) |
| `BrowserRestrictKey` | group | an association name, or empty text | Limits the group's entries to one browser association. Empty means "no limit", overriding the parent group; a missing key means inherit |
| `4B 65 65 53 68 61 72 65 2F 52 65 66 65 72 65 6E 63 65` (stored encoded, name rule) | group | base64 of a UTF-8 XML text that describes the share | Shared-group settings (INT-08, SI-09) |
| `BrowserHideEntry`, `BrowserSkipAutoSubmit`, `BrowserOnlyHttpAuth`, `BrowserNotHttpAuth` | entry | `true` or `false` | Entry-level browser options; they apply when the group does not decide (INT-02, SI-04) |
| `4B 65 65 50 61 73 73 58 43 2D 42 72 6F 77 73 65 72 20 53 65 74 74 69 6E 67 73` (stored encoded, name rule) | entry | compact JSON object `{"Allow":[hosts],"Deny":[hosts],"Realm":"text"}` | Sites the user allowed or denied for this entry (INT-02, SI-02) |
| `KnownBad` | entry | `true` or other | Read only, converted, never written (FMT-14.19) |

FMT-14.21 **The random padding item: format.** This rule owns the item's format. On every save, the reference writes the item whose key is `4B 50 58 43 5F 52 41 4E 44 4F 4D 5F 53 4C 55 47` (stored encoded, name rule) into the vault custom data.
- **Value.** Lowercase hex of N random bytes, where N is from 64 to 511 (CRY-03.7 owns how N and the bytes are drawn). So the value has 128 to 1022 hex digits, always an even number. A new value is made on each save.
- **Time.** The item gets the save time as its item time. It is written as `LastModificationTime` at 4.1 only (FMT-14.13). Larsal does the same when it writes the item: setting it is a change, so FMT-14.14 gives it the save time.
- **Purpose.** It changes the payload size on every save, so the size gives away less about the content, for example to storage that deduplicates data.
- **Merge.** Never copied.
- **Side effect on `_LAST_MODIFIED`.** The reference sets this item through the normal custom data change, so rule (c) of FMT-14.18 also sets the vault container's `_LAST_MODIFIED` to the save time. Larsal does the same, because refreshing the item is a change to the vault container under FMT-14.18 (c) (CRY-03 T15). In a vault saved by either app, the vault `_LAST_MODIFIED` is therefore about the last save time. The reference itself does not compare that file value in a merge: it replaces it with the current time when it reads the file (FMT-14.18 (a)). Larsal keeps the read value (FMT-14.18), so Larsal's merge (MOD-11) compares file values, and both apps refresh them on every save.
- **Larsal writes it.** Larsal writes this item on every save to a file, with exactly the key and form of this rule and a fresh value each time (decided: spec/decisions.md LD-16). An item already present, from the reference or from an earlier save, is replaced, never kept or merged. CRY-03.7 owns how N and the bytes are drawn; FMT-10.25 places the item.

FMT-14.22 **Reserved string-field names** (entry `String` keys from FMT-11, not custom data). The reference writes these entry strings itself, except those marked "read only": it reads those but never creates them. Keep them all exactly; their meaning lives in the cards listed. (Opening URLs: MOD-08.31, decided: spec/decisions.md LD-59.)

| Field key | Protected when written by the reference | Meaning |
|---|---|---|
| `Title`, `UserName`, `Password`, `URL`, `Notes` | per the vault flags (FMT-11.20) | Standard fields (MOD-01) |
| `KP2A_URL`, and `KP2A_URL_1`, `KP2A_URL_2` and so on | no | More URLs for the entry (MOD-01, INT-03) |
| `_EXEC_CMD` | no | Remembers the user's choice for running a `cmd://` URL (MOD-08.31) |
| `otp` | yes | One-time password settings text, usually an `otpauth://` URI (FEA-04) |
| `TOTP Seed` | yes | One-time password secret, older form (FEA-04) |
| `TOTP Settings` | no | One-time password period and digits, older form (FEA-04) |
| `TimeOtp-Secret-Base32`, `TimeOtp-Algorithm`, `TimeOtp-Length`, `TimeOtp-Period` | read only | One-time password settings in another app's form: the secret in base32, the hash name, the number of digits and the period in seconds. The reference uses them only when the entry has neither `TOTP Settings` nor `otp` (in that order of preference), and only when the secret is not empty. An empty algorithm, length or period takes the FEA-04 default. It never converts or removes them (FEA-04) |
| `KPEX_PASSKEY_CREDENTIAL_ID`, `KPEX_PASSKEY_PRIVATE_KEY_PEM`, `KPEX_PASSKEY_USER_HANDLE` | yes, all three (also when the reference imports a passkey from another app: credential id and private key) | Passkey secrets and ids (INT-04) |
| `KPEX_PASSKEY_USERNAME`, `KPEX_PASSKEY_RELYING_PARTY` | no | Passkey user name and site (INT-04) |
| `KPEX_PASSKEY_FLAG_BE`, `KPEX_PASSKEY_FLAG_BS` | no; the reference writes the value `1` (it reads `1` or `true` as set) | Passkey backup flags (INT-04) |
| `KPEX_PASSKEY_GENERATED_USER_ID` | read only | An id written by other apps; when present, the reference uses it as the passkey credential id instead of `KPEX_PASSKEY_CREDENTIAL_ID` (INT-04) |
| `4B 50 58 43 5F 50 41 53 53 4B 45 59 5F 55 53 45 52 4E 41 4D 45` (stored encoded, name rule) | read only | Passkey user name in another form, written by other apps; when present, the reference uses it instead of `KPEX_PASSKEY_USERNAME` (INT-04) |

The attachment name `4B 65 65 41 67 65 6E 74 2E 73 65 74 74 69 6E 67 73` (17 ASCII bytes, stored encoded, name rule: it names an outside product) holds SSH agent settings (INT-06). It is an attachment (FMT-13), not a string field.

FMT-14.23 **Unknown keys.** Any key the app does not know is kept unchanged, with its value and time, and written back. Keys are exact and case-sensitive.

FMT-14.24 **Merge.** MOD-11 owns how merges treat custom icons and custom data. Facts from the reference:
- icons missing from the target are added with their id, bytes, name and time;
- **when the source wins.** The source's vault custom data wins when the target's vault container has no `_LAST_MODIFIED` key, or when both containers' times are valid and the target's is older than the source's. In every other case (equal times, or a time that cannot be read) the target's vault custom data stays as it is;
- **the container time.** A container's time is its `_LAST_MODIFIED` value, read in the form of FMT-14.18. When the container has no such key, its time is the newest `LastModificationTime` of its items; when no item has one, the time is not valid;
- **when the source wins, removal.** Each target key that the source does not have is removed, except the protected keys: those starting with the browser association prefix, the bare key `_CREATED_`, `FDO_SECRETS_EXPOSED_GROUP` and the remote sync key (FMT-14.20). So `_CREATED_` plus an association name, and the padding key, can be removed. Each removal and each copy refreshes the target's `_LAST_MODIFIED` (FMT-14.18 (c));
- **when the source wins, copying.** Each source key whose value differs from the target's is set in the target, except `_LAST_MODIFIED` and the random padding key, which are never copied. A key that the target lacks counts as having an empty value there, so a source key whose value is empty is not copied into a target that lacks it. A copied item gets the merge time as its item time, not the source item's time;
- two kinds of merge never touch vault custom data (icons are still added): a shared-group import (INT-08) and the import wizard's merge into a newly made vault.

### Limits

FMT-14.25 **Limits.** Checked as FMT-11.48 says: when the element that would pass a count starts, before anything is stored for it, the read stops with `TooLarge`, naming the limit. FMT-08.12 owns the numbers and the limit names (decided: spec/decisions.md LD-22); this table says only what each limit counts. Test rows 14-35 to 14-38 use the numbers FMT-08.12 gives today; if FMT-08.12 changes a number, those rows change with it. Tests must be able to lower each limit.

| Limit (FMT-08.12 name) | What is counted |
|---|---|
| Custom icons (`icons`) | `Icon` elements in the whole document, in all `CustomIcons` blocks of all `Meta` elements; icons that get a fresh id (FMT-14.7) count too. |
| Bytes per icon (`icon data`) | No own limit. The `Data` text is one text value, so the `text` limit bounds it (FMT-08.12 gives the decoded size this allows). |
| Items per container (`custom data items`) | `Item` elements read into one container, across all its `CustomData` blocks (for the vault, across all `Meta` elements), duplicate keys included. |
| Items in the whole document (`custom data items in all`) | `Item` elements of all containers together, history items included. |
| Key length, value length (`custom data key`, `custom data value`) | No own limit. Each `Key` and `Value` is one text value, bounded by the `text` limit. |

Kept unknown children of `CustomIcons`, `Icon`, `CustomData` and `Item` count toward the kept unknown limit of FMT-11.48. The element depth limit of FMT-11.48 applies here too.

## Edge cases and errors

| Case | Result |
|---|---|
| `Icon` without `UUID`, with an empty, zero or wrong-length `UUID`, or without `Data` | Fail: "a custom icon has no id or no data" |
| `Icon` with `<Data/>` | Kept, 0 bytes |
| Two icons with the same id | Second gets a fresh id; the first keeps the id |
| `CustomIconUUID` naming no icon | Kept (FMT-11.11) |
| `Item` without `Key` or without `Value` | Fail: "a custom data item has no key or no value" |
| `Item` with `<Key/>` or `<Value/>` | Kept |
| `Key`, `Value` or `LastModificationTime` of an `Item` with a true `Protected` attribute and text | Decrypted on read with the next keystream bytes; written back plain (FMT-14.17) |
| Same key twice in one container | Different values: the later item wins, value and time. Equal values: the first item and its time stay |
| Container whose only item in the file is `_LAST_MODIFIED` | The reference drops it at read time. We keep it as read (FMT-14.18; decided: spec/decisions.md, default rule) |
| Container left holding only `_LAST_MODIFIED` after the legacy report flag is removed | Emptied and not written, by the reference and by us (FMT-14.19) |
| `KnownBad` with `True` (capital T) | Entry included in reports; item removed |
| Group or entry custom data in a file whose version is below 4.0 | Read normally. The next save picks V ≥ 4.0 (FMT-16) |
| Item time on a group or entry item | Read. We write it back at 4.1; the reference drops it |

## Security notes

- **Custom data is plain text inside the payload (FMT-14.17).** Nothing secret may be put there by our app unless a card says so and accepts that only the outer encryption protects it. Browser association keys are public keys, so they are fine.
- **Protected custom data from other writers (FMT-14.17).** A value that another app wrote with `Protected` is decrypted on read and then held and written as plain text, as the reference does. It must still never reach logs or error text (AGENTS.md rule 4). Getting the keystream order wrong here breaks every later password (SF-08).
- **Remote sync settings hold shell commands.** A hostile vault can plant them. The reference runs them when the user starts a sync. Our INT-09 must show the exact command and ask the user before running anything read from a vault. The format layer never runs anything.
- **Shared-group settings and browser settings decide who gets credentials** (SI-01, SI-02, SI-04, SI-09). They come from the file, so they are untrusted, and their parsers (INT-02, INT-08) must be hardened and fuzzed (AT-A10).
- **Icon bytes are hostile input.** Size limits apply before decoding. Decoding happens only when an icon is shown, with a safe decoder. The screen layer gets the bytes, never a file path (AT-E01, AT-E04).
- **The random padding (SF-07).** Larsal writes it on every save (LD-16). Its length and bytes come from larsal-crypto random (AT-B04).
- **No data loss (SD-06).** Unknown keys, unknown children and item times survive a round trip with us (FMT-14.13, FMT-14.16, FMT-14.23). The reference loses group and entry item times and unknown children.

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| 14-01 icon at 4.1 | Icon id(A1), name "demo icon", time 2020-01-02T03:04:05Z, Data = a valid 68-byte 1 × 1 transparent PNG with hex `89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000b4944415478da636000020000050001e9fadcd80000000049454e44ae426082` | Write at 4.1 | `<Icon><UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Name>demo icon</Name><LastModificationTime>pVSf1Q4AAAA=</LastModificationTime><Data>iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNgAAIAAAUAAen63NgAAAAASUVORK5CYII=</Data></Icon>`. FMT-14.1, 14.2 |
| 14-02 icon below 4.1 | The icon of 14-01 | Write at 4.0 | `<Icon><UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Data>iVBOR…</Data></Icon>`: no `Name`, no time. The version chooser returns 4.1 for this vault. FMT-14.4 |
| 14-03 no icons | Vault without icons | Write at 4.0 | Meta contains `<CustomIcons/>`, on its own line at depth 2 (TAB TAB `<CustomIcons/>` LF, FMT-10.2). FMT-14.1 |
| 14-04 empty data | `<Icon><UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Data/></Icon>` | Read, write | Icon id(A1) with 0 bytes, written `<Data/>`. FMT-14.2, 14.6 |
| 14-05 broken icons | Five files: `Icon` with only `UUID` id(A1); `Icon` with only `<Data>QUFB</Data>`; `<UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Data>QUFB</Data>`; `<UUID>QUJD</UUID><Data>QUFB</Data>`; `<UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><UUID/><Data>QUFB</Data>` (a valid id, then an empty one) | Read | All five fail ("a custom icon has no id or no data"). FMT-14.6 |
| 14-06 duplicate icon id | Icons: id(A1) Data `QUFB` ("AAA"), then id(A1) Data `QkJC` ("BBB"). Entry `CustomIconUUID` id(A1) | Read, write | Two icons: id(A1) = "AAA"; a fresh non-zero id = "BBB", written second. The entry still points to id(A1) ("AAA"). FMT-14.7, 14.5 |
| 14-07 icon order | Icons read in this order: id(A2), id(A1) | Write | Written id(A2), then id(A1). FMT-14.5 |
| 14-08 dangling and unused | Entry `CustomIconUUID` id(EE), with no such icon; icon id(A2) that nothing uses | Read, write | Both kept and written back. FMT-14.8 |
| 14-09 remove icon | Vault with icon id(A1); deleted list empty | Remove the icon at 2026-10-24T10:00:00Z, write at 4.0 | `DeletedObjects` holds one item: `<DeletedObject><UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><DeletionTime>oHhu4g4AAAA=</DeletionTime></DeletedObject>` (63928432800 seconds). FMT-14.9 |
| 14-10 group item at 4.0 | Group custom data: Key `GroupKey`, Value `g1` | Write at 4.0 | Right after `LastTopVisibleEntry`: `<CustomData><Item><Key>GroupKey</Key><Value>g1</Value></Item></CustomData>`, then any `PreviousParentGroup`, then the entries. FMT-14.10, 14.11 |
| 14-11 vault data at 4.0 | Vault custom data `DemoMetaKey` = `m1` with item time 2021-01-01T00:00:00Z; nothing else needs 4.1 | Larsal lets FMT-16 choose V, then writes | V is 4.0 (vault custom data never raises V; Larsal never writes 3.1, LD-07). Meta holds `<CustomData><Item><Key>DemoMetaKey</Key><Value>m1</Value></Item></CustomData>`, with no item time (times are 4.1 only). The reference writes the same item in a 3.1 file when its KDF is the legacy AES-KDF (FMT-16.11). FMT-14.11, 14.13 |
| 14-12 group data raises the reference to 4.0 | Group custom data `GroupKey` = `g1`; legacy AES-KDF; nothing else needs 4.1 | Run Larsal's chooser and the reference's chooser (FMT-16) | Larsal: 4.0. The reference: 4.0 too, never 3.1 (FMT-16.5). FMT-14.11 |
| 14-13 no empty block | Group with no custom data | Write at 4.1 | No `CustomData` element in the group. FMT-14.12 |
| 14-14 item times | Vault item `DemoMetaKey`, time 2021-01-01T00:00:00Z; entry item `EntryKeyB`, time 2022-02-02T02:02:02Z | Write at 4.1; write at 4.0 | 4.1: vault item ends with `<LastModificationTime>AF2A1w4AAAA=</LastModificationTime>`, and the entry item has its time too (the reference: none on the entry item). 4.0: no item has a time. FMT-14.13 |
| 14-15 item without time | Vault item `k` = `v`, no time in the file | Read, write at 4.1 | Written without `LastModificationTime`. After the app changes `v` to `w`, it is written with a time equal to the time of the change. FMT-14.14 |
| 14-16 order kept | Entry items read in the order `EntryKeyB`, `EntryKeyA` | Write | Order `EntryKeyB`, `EntryKeyA`. FMT-14.15 |
| 14-17 item errors | Three files: `<Item><Key>k</Key></Item>`; `<Item><Value>v</Value></Item>`; `<Item><Key/><Value>v</Value></Item><Item><Key>k</Key><Value/></Item>` | Read | First fails, second fails. Third opens with items "" = `v` and `k` = "". FMT-14.16 |
| 14-18 duplicate key | Vault custom data: `<Item><Key>k</Key><Value>first</Value><LastModificationTime>AF2A1w4AAAA=</LastModificationTime></Item><Item><Key>k</Key><Value>second</Value></Item>`, then `<Item><Key>j</Key><Value>same</Value><LastModificationTime>AF2A1w4AAAA=</LastModificationTime></Item><Item><Key>j</Key><Value>same</Value><LastModificationTime>GxaW1g4AAAA=</LastModificationTime></Item>` | Read, write at 4.1 | One item `k` = `second`, written with no `LastModificationTime`: the later item's missing time replaced the earlier 2021-01-01 time (the reference writes the current time of its read instead). One item `j` = `same`, written with `<LastModificationTime>AF2A1w4AAAA=</LastModificationTime>` (the first item's time; the equal later item is ignored). FMT-14.16 |
| 14-19 two blocks | Group with two `CustomData` blocks, holding `a`=`1` and `b`=`2` | Read | One container with `a` and `b`. FMT-14.16 |
| 14-20 plain text | Entry custom data `k` = `secret-looking`, inside a vault with an inner stream | Write | `<Value>secret-looking</Value>` in plain text; no `Protected` attribute; inner-stream position unchanged. FMT-14.17 |
| 14-21 last-modified form | Group container `a`=`1` | Larsal changes `a` at 2026-10-24T19:17:16Z | Item `_LAST_MODIFIED` = `Sat Oct 24 19:17:16 2026 GMT`, with no `LastModificationTime`. FMT-14.18 |
| 14-22 last-modified only | Group `<CustomData><Item><Key>_LAST_MODIFIED</Key><Value>Mon Jan 1 00:00:00 2018 GMT</Value></Item></CustomData>` | Read, write at 4.0 | Ours (FMT-14.18, decided): the item is kept as read. The reference: the container is empty after reading and no `CustomData` is written (observed: the file stayed 3.1). FMT-14.18 |
| 14-23 last-modified kept | Group items `a`=`1` and `_LAST_MODIFIED`=`Mon Jan 1 00:00:00 2018 GMT` | Read, write without change | Ours: the value stays `Mon Jan 1 00:00:00 2018 GMT`. The reference writes the current time of its read. FMT-14.18 |
| 14-24 legacy flag | Entry A custom data `KnownBad`=`true`; entry B `KnownBad`=`True`; entry C `<QualityCheck>False</QualityCheck>` and `KnownBad`=`false` | Read, write at 4.1 | A excluded (`<QualityCheck>False</QualityCheck>`), no custom data left. B included, no custom data left. C included (the custom data block decides last). `KnownBad` is never written. FMT-14.19 |
| 14-24b legacy flag and `_LAST_MODIFIED` | Entry E custom data `X`=`1` and `KnownBad`=`true`, no `_LAST_MODIFIED`. Entry F custom data `_LAST_MODIFIED`=`Mon Jan 1 00:00:00 2018 GMT` and `KnownBad`=`true` | Read, write at 4.1 | Ours: E excluded (`<QualityCheck>False</QualityCheck>`), its `CustomData` holds only `X`=`1`, with no `_LAST_MODIFIED`. F excluded, and no `CustomData` element is written for it. The reference (observed with the installed CLI in review round 3): E has `QualityCheck` False and custom data `_LAST_MODIFIED` (the current time of the read) plus `X`; F has `QualityCheck` False and no `CustomData`. FMT-14.19 |
| 14-25 reference keys round trip | Entry custom data: key = bytes `4B 65 65 50 61 73 73 58 43 2D 42 72 6F 77 73 65 72 20 53 65 74 74 69 6E 67 73` (stored encoded, name rule), value `{"Allow":["example.com"],"Deny":[],"Realm":""}`. Group custom data `BrowserHideEntry`=`true`, `BrowserRestrictKey`="" | Read, write at 4.0 | All keys and values written back byte for byte. FMT-14.20, 14.23 |
| 14-26 padding item form | Any vault; a second vault that already holds the padding item with value `00` (written by another tool) | Save twice | Each time the vault custom data has exactly one item with key `4B 50 58 43 5F 52 41 4E 44 4F 4D 5F 53 4C 55 47` (stored encoded, name rule) with a value matching `^([0-9a-f]{2}){64,511}$`. The two values differ. At 4.1 the item has a time equal to the save time. The vault `_LAST_MODIFIED` also becomes the save time each time (FMT-14.18 (c)). In the second vault the value `00` is gone after the first save, replaced by a fresh value (LD-16). FMT-14.21 |
| 14-27 reserved strings | Entry strings `otp` (protected) = `otpauth://totp/demo?secret=JBSWY3DPEHPK3PXP`, `KP2A_URL_1`=`https://b.example`, `_EXEC_CMD`=`1` | Read, write | Same keys and values; `otp` still `Protected="True"`; the other two plain. FMT-14.22 |
| 14-27b other app's one-time password fields | Entry strings `TimeOtp-Secret-Base32`=`JBSWY3DPEHPK3PXP` and `TimeOtp-Period`=`60`; no `otp`, no `TOTP Settings` | Read, write | The four-name form is the entry's one-time password source: secret `JBSWY3DPEHPK3PXP`, period 60, other settings at the FEA-04 defaults. Both strings are written back with the same keys and values; no `otp` string is added. A second entry that also holds `otp` uses `otp` instead. FMT-14.22 |
| 14-28 unknown key | Vault item `Some.Plugin/Setting` = `x`, time 2021-01-01T00:00:00Z | Read, write at 4.1 | Written back unchanged, with `<LastModificationTime>AF2A1w4AAAA=</LastModificationTime>`. FMT-14.23 |
| 14-29 merge facts | In-memory vaults (values as held after loading). Target vault without icon id(A1); source with icon id(A1). Target vault custom data: `_LAST_MODIFIED` = `Mon Jan 1 00:00:00 2018 GMT`, `T-only` = `t`, `_CREATED_demo` = `d`, and the key made of bytes `4B 50 58 43 5F 42 52 4F 57 53 45 52 5F 64 65 6D 6F` (stored encoded, name rule) = `pk`. Source vault custom data: `_LAST_MODIFIED` = `Tue Jan 2 00:00:00 2018 GMT`, `S-only` = `s` with item time 2021-01-01T00:00:00Z, `S-empty` = "" (empty value), and the padding key | Merge of the source into the target, as the reference does it, at 2026-10-24T10:00:00Z | Target gains icon id(A1) with the same bytes, name and time. Target vault custom data: `S-only` = `s` added, with item time 2026-10-24T10:00:00Z (the merge time, not 2021-01-01); `S-empty` not added; `T-only` and `_CREATED_demo` removed; the encoded browser key kept with `pk`; the source's padding key not copied; `_LAST_MODIFIED` refreshed to the merge time, `Sat Oct 24 10:00:00 2026 GMT`. MOD-11 decides what Larsal does. FMT-14.24 |
| 14-30 adding an icon (MOD-06 behavior) | Demo image file `photo.v2.png`, 300 × 200 pixels | The app adds it as a custom icon at 2026-10-24T10:00:00Z, then adds the same file again | One icon: PNG bytes of a 128 × 128 image, `Name` `photo`, time 2026-10-24T10:00:00Z. The second add reuses that id and adds no icon. The vault now needs V 4.1. Then the app downloads a 16 × 16 website icon for an entry at 2026-10-24T10:05:00Z: a second icon is added with no `Name` element written and with time 2026-10-24T10:05:00Z. Separately, in a 4.0 vault with no icons and nothing else that needs 4.1, the bulk icon download fetches a 16 × 16 website icon for one selected entry: one icon is added with no `Name` and no time, the entry points to it, and the version chooser stays at 4.0. Dragging that entry into another open vault that lacks the icon copies it there with the same id and bytes, no `Name` and no time. FMT-14.3, 14.4 |
| 14-31 protected custom data on read | Version 4 demo vault with inner stream key 64 bytes of 0x00 (the FMT-12.22 vectors: keystream bytes 0 to 7 are `14 7D 85 53 F7 D0 71 7E`). One entry holds, as the first two protected elements of the document and in this order (the reader accepts any order): `<CustomData><Item><Key>k</Key><Value Protected="True">RxjmIZKk</Value></Item></CustomData>`, then `<String><Key>Password</Key><Value Protected="True">AQk=</Value></String>` | Read, then write | Item `k` = `Secret` (keystream bytes 0 to 5). `Password` = `pw` (bytes 6 and 7). The item is written back as `<Value>Secret</Value>`, with no `Protected` and no keystream use. A reader that skipped the custom data value would decode the password from bytes 0 and 1 as the wrong bytes `15 74`. FMT-14.17 |
| 14-32 version 4.1 children read in a 3.1 file | A 3.1 file (text times) with `<Icon><UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Name>n</Name><LastModificationTime>2020-07-07T07:07:07Z</LastModificationTime><Data>QUFB</Data></Icon>` and a group item `<Item><Key>g</Key><Value>1</Value><LastModificationTime>2020-07-07T07:07:07Z</LastModificationTime></Item>` | Read; write at 4.1 | Opens. The icon is written `<UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Name>n</Name><LastModificationTime>GxaW1g4AAAA=</LastModificationTime><Data>QUFB</Data>`. The group item keeps its time: we write `<LastModificationTime>GxaW1g4AAAA=</LastModificationTime>` (the reference reads it and drops it on save). FMT-14.4, 14.6, 14.13 |
| 14-33 several icon and custom data blocks | File A, two Meta elements. First Meta: `<CustomIcons><Icon><UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Data>QUFB</Data></Icon></CustomIcons>` and `<CustomData><Item><Key>a</Key><Value>1</Value></Item></CustomData>`. Second Meta: `<CustomIcons><Icon><UUID>oqKioqKioqKioqKioqKiog==</UUID><Data>QkJC</Data></Icon><Icon><UUID>oaGhoaGhoaGhoaGhoaGhoQ==</UUID><Data>Q0ND</Data></Icon></CustomIcons>` and `<CustomData><Item><Key>b</Key><Value>2</Value></Item></CustomData>`. File B: one Meta holding the same two `CustomIcons` blocks and the same two `CustomData` blocks, one after the other | Read, write | Both files give the same vault. Icons, in this order: id(A1) = "AAA", id(A2) = "BBB", a fresh non-zero id = "CCC" (FMT-14.7). Vault custom data holds `a` = `1` and `b` = `2`. One `CustomIcons` and one `CustomData` element are written. FMT-14.5, 14.16 |
| 14-34 passkey field protection | Larsal registers a passkey for an entry through the browser service (INT-04), with user name `demo-user`, site `example.com` | Write | `KPEX_PASSKEY_CREDENTIAL_ID`, `KPEX_PASSKEY_PRIVATE_KEY_PEM` and `KPEX_PASSKEY_USER_HANDLE` are written with `<Value Protected="True">`. `KPEX_PASSKEY_USERNAME` = `demo-user`, `KPEX_PASSKEY_RELYING_PARTY` = `example.com`, `KPEX_PASSKEY_FLAG_BE` = `1` and `KPEX_PASSKEY_FLAG_BS` = `1` are written plain. No `KPEX_PASSKEY_GENERATED_USER_ID` is written. FMT-14.22 |
| 14-35 icon limit | File A: `CustomIcons` holding 100,000 icons with distinct ids and `<Data/>`. File B: 100,001 such icons, split over two `CustomIcons` blocks (50,000 and 50,001) | Read | A opens with 100,000 icons. B: `TooLarge`, naming the icon limit. FMT-14.25 |
| 14-36 items per container | File A: a group with two `CustomData` blocks of 50,000 items each, keys `k0` to `k99999`. File B: blocks of 50,000 and 50,001 items, where the last item repeats key `k0` | Read | A opens with 100,000 items. B: `TooLarge`, naming the per-container limit (the repeated key counts). FMT-14.25 |
| 14-37 items in the whole document | Total item limit lowered to 1,000 for the test, per-container limit left at its value. File A: 10 entries with 100 items each. File B: 11 entries with 91 items each (1,001) | Read | A opens. B: `TooLarge`, naming the total item limit. FMT-14.25 |
| 14-38 text in icons and items | Single text node cap lowered to 1 MiB for the test. File A: an icon whose `Data` text is 1,048,576 base64 characters (786,432 bytes). File B: the same with 1,048,580 characters. File C: a vault item whose `Value` holds 1,048,577 ASCII bytes | Read | A opens. B and C: `TooLarge`, naming the text limit (FMT-12). FMT-14.25 |
| 14-39 `_LAST_MODIFIED` with a single-digit day | Group container `a`=`1`. Second file: group container `a`=`1` and `_LAST_MODIFIED`=`So. Okt. 4 19:17:16 2026 GMT` (as the installed reference writes on a Mac with region de_DE) | Larsal changes `a` at 2026-10-04T19:17:16.750Z, on a Mac whose region is de_DE; for the second file: read, write without change | First: `_LAST_MODIFIED` = `Sun Oct 4 19:17:16 2026 GMT`, exactly the 27 bytes `53 75 6E 20 4F 63 74 20 34 20 31 39 3A 31 37 3A 31 36 20 32 30 32 36 20 47 4D 54` (English names whatever the region; milliseconds dropped). Second: the value is written back unchanged. FMT-14.18 |

## How this was learned

- **Reference source, read only.** These parts were studied:
  - the document reader and writer parts for icons and custom data,
  - the version chooser,
  - the core custom data container (automatic change-time item, protected and automatically made keys),
  - the vault metadata code for icons (adding, removing, the hash used to find identical bytes),
  - the icon edit screen (scaling to 128 px, PNG encoding, name and time),
  - the save routine (random padding item),
  - every place in the source that sets a custom data key: browser service and settings, entry and group edit screens, encryption settings, secret service settings, remote sync settings, shared-group code,
  - the merge routine's metadata part,
  - the code for entry attributes, one-time passwords and SSH agent settings, for the reserved names;
  - the browser service's passkey creation and the passkey import readers, for which passkey fields are protected (FMT-14.22);
  - the custom data set routine, for duplicate keys on read (FMT-14.16) and for the copy time and empty-value compare in merge (FMT-14.24);
  - the bulk icon download dialog and the drag-and-drop code for groups and entries, for the third way to add icons and for icon copies between open vaults (FMT-14.3);
  - the entry's one-time password update routine, for the read-only one-time password names (FMT-14.22).
- **The installed reference CLI, 2.7.11.** Demo documents were imported through its XML import, the saved demo vaults were decrypted with the scratch tool described in FMT-11, and the result was compared. Observed:
  - icon `Name` and time written before `Data` at 4.1;
  - a duplicate icon id replaced by a fresh one;
  - empty icon data kept;
  - vault item times written, entry item times dropped;
  - `_LAST_MODIFIED` set to the import time on the vault, group and entry containers;
  - a container holding only `_LAST_MODIFIED` dropped;
  - empty keys and values kept;
  - duplicate keys: the later one wins;
  - `KnownBad` conversion (`true` only);
  - the padding item written on each save, with a time at 4.1;
  - item order in hash order;
  - in review round 3 (`/tmp/spec-review-r3-fmt11-14-15/`): the legacy report flag removed with and without `_LAST_MODIFIED` in the file (test 14-24b).
- **The `_LAST_MODIFIED` text form (FMT-14.18), cross-check round.** Read in the source: the custom data container writes the value with its UI toolkit's default date-to-text form, on a UTC time. Observed in `/tmp/spec-fmt11-14-15/r5/` with a scratch probe that loads the installed reference's own toolkit library and calls its date-to-text routine on fixed UTC times (no vault involved): the day without a leading zero (`Sun Oct 4 …`, `Sun Mar 1 …`), two-digit time parts, ` GMT` at the end, and day and month names that follow the Mac's region (en_US, de_DE, fr_FR were tried by passing the region to the probe).
- **Installed version against the source.** One difference: the day and month names of `_LAST_MODIFIED` follow the Mac's region in the installed version and are always English in the source build (FMT-14.18). No other difference was found for these rules. The remote sync settings key was seen in the source only.
- **check with Verify:**
  - that a build of the source writes `_LAST_MODIFIED` with English day and month names whatever the region, and still ends it with ` GMT` (FMT-14.18; from the toolkit's documented behavior, not run). Needs a build of the source on toolkit version 6.
- **Checked by Verify (Sprint 2):** the installed version does not write the remote sync key. Its app and CLI binaries hold the neighbouring custom data key names (`_LAST_MODIFIED`, the secret service key) as UTF-16 text, but neither the remote sync key nor its JSON field names, in ASCII or UTF-16 (observed by searching the installed binaries): 2.7.11 ships no remote sync code.
- **Lead decisions (all decided, spec/decisions.md):**
  - L14-1 item times on group and entry items: written at 4.1 (default rule, the card's recommendation; FMT-14.13).
  - L14-2 `_LAST_MODIFIED` policy: keep as read, refresh only when Larsal changes the container (default rule, the card's recommendation; FMT-14.18). With LD-16, Larsal refreshes the vault `_LAST_MODIFIED` on every save, as the reference does (FMT-14.21).
  - L14-4 limits: LD-22, the numbers of FMT-08.12 (FMT-14.25).
  - Random padding item: LD-16, Larsal writes it on every save (FMT-14.21).
  - Kept unknown children: LD-27 (FMT-14.6, FMT-14.16).
- Sprint 1 close-out: the intro now points to FMT-16 for V, including FMT-16.24 (LD-09), instead of "4.0 or 4.1 only". FMT-14.25 now says only what each limit counts; FMT-08.12 alone gives the numbers.
