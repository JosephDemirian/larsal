# FMT-11 Document: groups and entries

Status: reviewed
Epics: E3-S6
Parity rows: SF-08, SF-09, SD-04, SD-05, SD-06

## What it does

Inside the decrypted, decompressed payload (FMT-08, FMT-09) a vault holds one XML document. This card covers:

- the frame of that document: the root element and the `Root` element,
- the group tree,
- every element of a group and of an entry: strings with their protected flags, the standard keys, attachment references, the auto-type block with its window associations, the times block, colors, override URL, tags, quality check, previous parent group, custom data and history,
- for each element: its name, its encoding, its default, the file version that introduced it and the order in which it is written,
- what the reader does with missing, duplicate, broken and unknown parts.

Other cards own the neighbours. Meta is FMT-10. FMT-10 also owns the document frame (FMT-10.1, FMT-10.4 to FMT-10.6), the write layout (FMT-10.2), the XML input rules (FMT-10.7 to FMT-10.9) and kept unknown children of the root element and `Root` (FMT-10.20); FMT-11.1 to FMT-11.5 and FMT-11.42 only point there. Custom icons and custom data are FMT-14. Deleted objects are FMT-15. FMT-12 owns value encodings (ids, times, booleans, numbers, base64). FMT-09 owns the protected-value stream. FMT-13 owns the attachment pool and `Ref` numbers. FMT-16 decides which version a save uses. FMT-17 covers version 3 details.

Words used in this card:

- **V**: the file version App writes. FMT-16 chooses it: 4.0 or 4.1 by content (FMT-16.18, FMT-16.19), or, while the vault holds kept unknown parts, at least the version the file was read as (FMT-16.24), which can be a higher 4.x minor such as 4.2. App never writes 3.x, so the gate "V ≥ 4.0" always holds for App. "V ≥ 4.1" means any 4.x minor of 1 or more; every known part is written in its 4.1 form then (FMT-16.24). The reference also writes 3.1 (FMT-16.1); the 3.1 forms in this card are reference facts, given so that App can read 3.1 files. They are never App write rules.
- **id**: a 16-byte UUID, written as the base64 of its 16 bytes (FMT-12). **id(xx)** in the test cases means 16 bytes that are all 0xxx. For example, id(01) is written `AQEBAQEBAQEBAQEBAQEBAQ==`, id(10) is `EBAQEBAQEBAQEBAQEBAQEA==` and id(A1) is `oaGhoaGhoaGhoaGhoaGhoQ==`.
- **zero id**: 16 zero bytes, written `AAAAAAAAAAAAAAAAAAAAAA==`. It means "none".
- **live entry**: an entry that sits in a group. **history item**: an older copy of an entry, kept in that entry's `History`.
- **fail**: the whole open fails with `Corrupt` (plan/architecture.md, error.rs). No part of the document is used. APP-06 owns the text shown on screen.
- **open time**: one UTC timestamp in whole seconds, taken once when the read starts (FMT-10.10, FMT-12.7). App uses this one value for every time it fills in while reading the document. The reference instead reads the clock each time it needs such a value, so its values can differ from each other by the time the read takes; tests compare against App's single value.
- **text**: an XML text value. It is read exactly as it is, including leading and trailing white space.

## Inputs and outputs

Read:
- In: the XML document as UTF-8 bytes (FMT-08), the inner-stream cipher state (FMT-09) and the attachment pool (FMT-13).
- Out: the `Vault` group tree in app-model, plus warnings for the debug log. Warnings name elements or ids. They never contain field values.

Write:
- In: the `Vault`, the version V (FMT-16), the inner-stream cipher state (FMT-09) and the attachment index map (FMT-13).
- Out: the XML document as UTF-8 bytes.

Limits: app-format `limits.rs` sets the limits. FMT-08.12 owns every number (decided: spec/decisions.md LD-22); FMT-11.48 says how each one is counted. The reference has none of these limits.

## Rules

### Document frame

FMT-11.1 **Root element and frame on write (pointer).** FMT-10.1 (declaration) and FMT-10.4 (top structure) own this. In short: the root element, whose name is the 11 ASCII bytes `4B 65 65 50 61 73 73 46 69 6C 65` (stored encoded, name rule), holds `Meta` first and `Root` second, followed only by the unknown root children App keeps (FMT-10.20), which come after `Root`.

FMT-11.2 **Reading the root element (pointer).** FMT-10.5 and FMT-10.7 own this: the first element must carry the root name (local name, case-sensitive), `Meta` may appear any number of times and anywhere, exactly one `Root` must be present, and any other child is an unknown element kept per FMT-10.20. Every rejection there is a fail.

FMT-11.3 **Root contents on write (pointer).** FMT-10.4 owns this: `Root` holds the root `Group` first and `DeletedObjects` (FMT-15) second, written as `<DeletedObjects/>` when the list is empty, followed only by kept unknown children (FMT-10.20).

FMT-11.4 **Reading Root (pointer).** FMT-10.6 owns this: exactly one `Group` child, or the open fails. `DeletedObjects` may appear anywhere inside `Root`, any number of times; FMT-15.6 adds their items up in document order. Any other child is an unknown element kept per FMT-10.20.

FMT-11.5 **After the end tag (pointer).** FMT-10.5 owns this: reading stops at the root element's end tag and whatever follows is ignored, whatever its bytes. The payload size limit still applies to the whole payload (FMT-08.12).

### Group

FMT-11.6 **Group elements, in write order.**

| # | Element | Content | If missing on read | Since | Written |
|---|---|---|---|---|---|
| 1 | `UUID` | id | fresh random id (FMT-11.34) | all | always |
| 2 | `Name` | text | empty | all | always |
| 3 | `Notes` | text | empty | all | always |
| 4 | `Tags` | text, kept raw (FMT-11.27) | empty | 4.1 | only when not empty |
| 5 | `IconID` | integer: the standard icon number (FMT-11.10) | 48 | all | always |
| 6 | `CustomIconUUID` | id of a custom icon (FMT-14) | none | all | only when the group has a custom icon |
| 7 | `Times` | times block (FMT-11.12) | every child takes its default | all | always |
| 8 | `IsExpanded` | boolean | True | all | always |
| 9 | `DefaultAutoTypeSequence` | text | empty | all | always |
| 10 | `EnableAutoType` | tri-state (FMT-11.9) | `null` | all | always |
| 11 | `EnableSearching` | tri-state | `null` | all | always |
| 12 | `LastTopVisibleEntry` | id of an entry (FMT-11.37) | none | all | always; zero id when none |
| 13 | `CustomData` | custom data block (FMT-14) | empty | 4.0 | only when not empty (V ≥ 4.0 always holds for App) |
| 14 | `PreviousParentGroup` | id of a group (FMT-11.30) | none | 4.1 | only when V ≥ 4.1 and set; in App, V is then always 4.1 (FMT-11.30) |
| 15 | `Entry`, repeated | the group's live entries | none | all | one per entry |
| 16 | `Group`, repeated | the group's child groups | none | all | one per child group |

"all" means: present in every file version, 3.1 included. App reads such an element in every version and writes it in every version App writes (4.0, 4.1, or a higher 4.x minor under FMT-16.24). Elements marked 4.0 or 4.1 are read in any file version. FMT-16 makes sure V is high enough for what the vault uses.

FMT-11.7 **Entries before child groups.** Inside a group, the writer puts all `Entry` elements before all child `Group` elements. Entries and child groups are written in their stored order. Reading keeps document order.

FMT-11.8 **Reading group children.** A group's children may come in any order. `UUID` may even come after the entries and child groups. When a single-value child appears more than once, the last one wins. Repeated blocks:
- several `Times` blocks: the last block replaces the earlier ones as a whole (FMT-11.12);
- several `CustomData` blocks: their items are added together (FMT-14.16);
- `Entry` and `Group` are repeated by design and all are kept, in document order.

A child that is not in the table of FMT-11.6 is an unknown element.

FMT-11.9 **Tri-state values.** `EnableAutoType` and `EnableSearching` hold one of three values: `null` (inherit from the parent group), `true` or `false`. The reader compares case-insensitively. Any other text, including empty text, fails the open. The writer writes lowercase `null`, `true` or `false`.

FMT-11.10 **Icon number.** `IconID`, in groups and in entries, is a decimal 32-bit signed integer (FMT-12).
- Empty, or not a number: fail.
- Negative: read as 0, with no error.
- There is no upper limit. 9999 and 2147483647 are kept and written back.
- If the element is missing, the default is 48 for a group and 0 for an entry.

FMT-11.11 **Icon number and custom icon together.** The reader applies a group's or entry's children in document order:
- `IconID` sets the icon number and removes any custom icon.
- `CustomIconUUID` holding a valid id that is not the zero id sets the custom icon and sets the icon number to 0.
- `CustomIconUUID` holding the zero id, an empty value, or a value that does not decode to exactly 16 bytes is ignored.

So `IconID` 5 followed by `CustomIconUUID` X reads as icon number 0 with custom icon X. `CustomIconUUID` X followed by `IconID` 7 reads as icon number 7 with no custom icon. The writer always writes `IconID` before `CustomIconUUID`, so the result is stable over a round trip. A `CustomIconUUID` that names no icon in Meta is kept and written back unchanged.

### Times block

FMT-11.12 **Times block.** Groups, live entries and history items each have one `Times` block. Its children, in write order:

| # | Element | Content | If missing on read |
|---|---|---|---|
| 1 | `LastModificationTime` | time | open time |
| 2 | `CreationTime` | time | open time |
| 3 | `LastAccessTime` | time | open time |
| 4 | `ExpiryTime` | time | open time |
| 5 | `Expires` | boolean | False |
| 6 | `UsageCount` | integer | 0 |
| 7 | `LocationChanged` | time | open time |

All seven exist in all versions and are always written. Times use FMT-12. App writes every time in the binary form (FMT-12.2): the base64 of 8 bytes, the little-endian count of seconds since 0001-01-01T00:00:00Z. The reader accepts the binary form and the text form in any file version (FMT-12.4). The text form `yyyy-MM-ddTHH:mm:ssZ` is what the reference writes in 3.1 files (FMT-12.3); App never writes it. If the whole `Times` element is missing, every child takes its default.

**Repeated Times.** The children of one `Times` block may come in any order; a child repeated inside one block: the last one wins. If a group, live entry or history item holds more than one `Times` block, each block starts from the defaults of the table above, and the last block replaces the whole result of the earlier ones. So a child that the last block lacks takes its default (open time, False or 0), even when an earlier block gave it. The writer writes one block, so this only happens in files from other writers. We do the same as the reference (AT-A11).

FMT-11.13 **Lenient times.** These cases are read without error:
- An empty time element reads as 0001-01-01T00:00:00Z, because empty text counts as the base64 of zero bytes.
- Text that is valid base64 but shorter than 8 bytes is padded with zero bytes. For example, `AAAA` reads as 0001-01-01T00:00:00Z.
- Text that is neither valid base64 nor a valid ISO-8601 date reads as the open time.

FMT-12.4 to FMT-12.7 give the exact shapes.

`UsageCount` is a decimal 32-bit signed integer (FMT-12). If it is empty or not a number, the open fails. Only that part of FMT-11.10 applies: a negative `UsageCount` is not changed to 0. Any 32-bit value, negative included, is kept and written back as read (observed: -5 is written back as -5). `DataTransferObfuscation` behaves the same way (FMT-11.24).

FMT-11.14 **Booleans.** This applies to booleans in groups, entries, times and the auto-type block:
- The reader accepts `true` and `false` in any case.
- An empty element reads as false.
- Any other text, including `1`, `0` and `yes`, fails the open.
- The writer writes `True` or `False`.

FMT-12.10 and FMT-12.11 give the exact comparison: no trimming, and the case folding rules.

### Entry

FMT-11.15 **Entry elements, in write order.** These apply to both live entries and history items.

| # | Element | Content | If missing on read | Since | Written |
|---|---|---|---|---|---|
| 1 | `UUID` | id | fresh random id; for a history item, the owner's id (FMT-11.32) | all | always |
| 2 | `IconID` | integer (FMT-11.10) | 0 | all | always; 0 when a custom icon is set |
| 3 | `CustomIconUUID` | id (FMT-11.11) | none | all | only when set |
| 4 | `ForegroundColor` | text (FMT-11.25) | empty | all | always |
| 5 | `BackgroundColor` | text | empty | all | always |
| 6 | `OverrideURL` | text (FMT-11.28) | empty | all | always |
| 7 | `Tags` | text, normalized (FMT-11.26) | empty | all | always |
| 8 | `Times` | times block (FMT-11.12) | defaults | all | always |
| 9 | `QualityCheck` | boolean (FMT-11.29) | included in reports | 4.1 | only when V ≥ 4.1 and the entry is excluded from reports; then always `False`. In App, V is then always 4.1, history items included (FMT-11.29) |
| 10 | `PreviousParentGroup` | id (FMT-11.30) | none | 4.1 | only when V ≥ 4.1 and set. In App, V is then always 4.1, history items included (FMT-11.30) |
| 11 | `String`, repeated | one field (FMT-11.16 to FMT-11.22) | the five standard fields, empty | all | one per field, sorted |
| 12 | `Binary`, repeated | one attachment reference (FMT-11.23) | none | all | one per attachment, sorted |
| 13 | `AutoType` | auto-type block (FMT-11.24) | defaults | all | always |
| 14 | `CustomData` | custom data block (FMT-14) | empty | 4.0 | only when not empty (V ≥ 4.0 always holds for App) |
| 15 | `History` | history items (FMT-11.31) | empty | all | live entries only, always (an empty element when there are no items); never inside a history item |

The reader accepts the children of an entry in any order. When a single-value child appears more than once, the last one wins. Repeated blocks each behave differently:
- `Times`: the last block replaces the earlier ones as a whole (FMT-11.12).
- `AutoType`: the blocks are merged child by child, and their associations add up (FMT-11.24).
- `History`: only the items of the last block are kept (FMT-11.31).
- `CustomData`: the items add up (FMT-14.16).
- `String` and `Binary` are repeated by design (FMT-11.18, FMT-11.23).

Unknown children follow FMT-11.44 and FMT-11.45.

FMT-11.16 **Standard fields.** Every entry, live or history, has five standard string fields: `Title`, `UserName`, `Password`, `URL` and `Notes`. Their names are exact and case-sensitive. A standard field missing from the file reads as empty and not protected. The writer always writes all five, even when they are empty.

FMT-11.17 **String element.** `String` holds `Key` (text) and `Value` (text). Both are required: if either one is missing, the open fails. An empty key (`<Key/>`) is accepted and written back as an empty key. Keys and values keep every character as read, including leading and trailing white space. Keys are case-sensitive.

FMT-11.18 **Duplicate keys.** If an entry already holds a key with a value that is not empty, a second `String` with the same key fails the open. If the earlier value is empty, the later `String` replaces both the value and the protected flag, without error. This is the case for every standard field until its own `String` appears.

FMT-11.19 **Protected flag on read.** A `Value` marks its field protected when its attribute `Protected` or `ProtectInMemory` reads as true. True means `true` in any case, or `1`. Any other attribute value, such as `yes` or `False`, leaves the field unprotected.

Decryption is a separate matter from the flag. Any value element in a group or an entry whose `Protected` attribute is true and whose text is not empty is run through the inner stream, in document order, not only `String` values (FMT-12.22, FMT-09). Only on a `String` `Value` does the attribute also set the field's protected flag. Text under `ProtectInMemory` is plain text.

FMT-11.20 **Protected flag on write.** A field is written protected in either of two cases:
- its own protected flag is set, or
- it is a standard field and the matching vault-level flag in `MemoryProtection` is on (FMT-10, MOD-12).

The writer writes a protected field as `<Value Protected="True">` followed by the base64 of the inner-stream output for the field's full UTF-8 bytes (FMT-09). An empty protected field is written as `<Value Protected="True"/>` and uses no keystream. An unprotected field's `Value` has no attribute. Inside a vault the writer never uses `ProtectInMemory`. That form belongs to plain XML exports (FEA-09).

FMT-11.21 **Reading sets the field's own flag.** A field read as protected keeps its own protected flag set. It therefore stays protected on every later save, even if the vault-level flag for that standard field is off. MOD-12 owns any change to this.

FMT-11.22 **String write order.** Strings are written sorted by key. Keys are compared as sequences of UTF-16 code units: binary and case-sensitive. This is not code-point order. Example of correct order: ` sp`, `1`, `Apple`, `KP2A_URL`, `Notes`, `Password`, `Title`, `URL`, `UserName`, `Z`, `_under`, `a`, `zlower`, `é`, U+1F600, U+E000, U+FFFD. U+1F600 comes before U+E000 because its first UTF-16 unit is D83D. The reader accepts strings in any order.

FMT-11.23 **Attachment references.** `Binary` holds `Key` (the attachment name, as text) and `Value`. FMT-13 owns the details; this rule gives the element's shape inside an entry.
- **Write.** The writer writes one `Binary` per attachment, sorted by name with the comparison of FMT-11.22. Each one has `<Value Ref="n"/>`, where n is the decimal pool index of the attachment's data (FMT-13). The `Value` has no text. History items write their own `Binary` elements the same way.
- **Read.** `Key` and `Value` are both required. If either one is missing, the open fails.
- **Value with a `Ref` attribute.** Once the whole document has been read, the attachment receives the pool item whose key equals the `Ref` text exactly (FMT-13.8). FMT-13.11 covers a key that is not found.
- **Value without `Ref`.** Its text is the base64 of the attachment data. This is an old inline form: we read it and write it back as a pool reference (FMT-13.9).
- **Same name twice in one entry.** Both attachments are kept; the second gets the name FMT-13.13 gives (decided: spec/decisions.md LD-29). FMT-13.13 owns the details. What the reference does: two `Ref` values for one name leave one attachment, and which pool item wins depends on hash order (observed: the later one). An inline value whose name is already used, with different data, is renamed to 8 random lowercase hex digits, then `_`, then the name (observed: `d02af814_f.txt`), and a warning is logged.

FMT-11.24 **Auto-type block.** The children of `AutoType`, in write order:
1. `Enabled`: boolean, default True.
2. `DataTransferObfuscation`: integer, default 0. Any 32-bit value, negative included, is kept and written back as read (FMT-11.13).
3. `DefaultSequence`: text, default empty.
4. One `Association` per window association, in stored order.

`Association` holds `Window` (text) and `KeystrokeSequence` (text). Both elements are required, but their text may be empty. If either element is missing, the open fails. Associations keep document order, and duplicate or empty associations are kept. The writer always writes both children, as an empty element when the text is empty. INT-05 says what these values mean.

**Several AutoType blocks.** The reader applies every child of every `AutoType` block of the entry, in document order, to the same entry:
- `Enabled`, `DataTransferObfuscation` and `DefaultSequence` take the last value given in any block. A block that lacks one of them does not reset it to its default.
- The associations of all blocks are added together, in document order.

The writer writes one block. We do the same as the reference (AT-A11).

FMT-11.25 **Colors.** `ForegroundColor` and `BackgroundColor` are text, normally `#` followed by six hex digits.
- The reader keeps any text unchanged and raises no error (`red` and `#GG0000` are kept).
- The writer writes the stored text. An empty value means no color.
- Colors that we create follow FMT-12.18. (The reference's own color picker writes lowercase `#rrggbb`. Both forms read the same.)

FMT-11.26 **Entry tags.** On read, the reader normalizes the `Tags` text in these steps:
1. Split at every `,`, `;` and tab.
2. Drop empty pieces.
3. Trim leading and trailing white space from each piece. White space here means every character with the Unicode White_Space property, the same set as FMT-12.15: U+0009 to U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F and U+3000.
4. Drop pieces that are now empty.
5. Remove exact duplicates.
6. Sort by UTF-16 code units (case-sensitive).

On write, the list is joined with `,`. Example: `zeta; alpha,beta<TAB>alpha ,Alpha` becomes `Alpha,alpha,beta,zeta`.

Note: the reference skips step 4. A piece made only of spaces survives as an empty tag for one save (`a, ,b;;c` becomes `,a,b,c`). The reference drops that empty tag again when it next reads the file, so our step 4 changes nothing that lasts. MOD-07 owns what tags mean.

FMT-11.27 **Group tags.** A group's `Tags` text is kept raw: it is not split and not sorted. It is written only when it is not empty. A group with non-empty tags needs V 4.1 (FMT-16).

FMT-11.28 **Override URL.** `OverrideURL` is text, kept as is. It may hold a `cmd://` command. The format layer never acts on it. INT cards and AT-E02 cover how it is used.

FMT-11.29 **Quality check.** `QualityCheck` is a boolean that means "include this entry in password reports".
- **Read.** The entry is excluded from reports when the value is false. So `False` means excluded and `True` means included. An empty element reads as false, so it means excluded. A missing element means included.
- **Write.** Written only when V ≥ 4.1 and the entry is excluded, and then always as `False`. An excluded live entry makes V 4.1 (FMT-16.8). An excluded history item also makes V 4.1 in App, so the flag is never dropped (decided: spec/decisions.md LD-08). The reference does not raise V for a history item and drops its flag at 4.0 and 3.1 (FMT-16.11, FMT-16.13; observed, see FMT-16).
- **Legacy flag.** An older exclude flag, kept in entry custom data, is converted on read (FMT-14.19).

FMT-11.30 **Previous parent group.** `PreviousParentGroup`, on groups and on entries, is the id of the group the item sat in before its last move inside the vault. The recycle bin's restore uses it (MOD-04).
- **Read.** Read in any version. A zero, empty or wrong-length id means none.
- **Write.** Written only when V ≥ 4.1 and set.
- **App: never dropped.** Any set previous parent makes V 4.1 in App: on a group or a live entry, on a history item, and also when the id names no existing group (decided: spec/decisions.md LD-08, the lossless choice of FMT-16.19). So App always writes it and it survives a round trip. An id that names no existing group is kept in memory and written back unchanged (FMT-11.38).
- **The reference.** Only a previous parent of a group or live entry whose group exists raises V to 4.1 (FMT-16.7, FMT-16.9). One on a history item, or one that names no existing group, does not raise V (FMT-16.11): it is written only when V is 4.1 for some other reason, and at 4.0 or 3.1 it is not written, so it is gone once the saved file is read again (FMT-16.13).

FMT-11.31 **History.** `History` holds `Entry` elements, the history items, oldest first, in stored order. A history item uses the entry elements of FMT-11.15 except `History`. A `History` inside a history item fails the open. The writer writes `History` for every live entry, as an empty element when there are no items, and never writes it inside a history item. Apart from the reading limits of FMT-11.48, the reader applies no count or size limit to history: the vault's history settings are not applied on read. MOD-03 limits apply when the app edits an entry.

**Several History blocks.** If one live entry element holds more than one `History` element, only the items of the last one are kept. The items of earlier blocks are dropped without an error or a warning. They are still read in full first: their protected values take keystream bytes in document order (FMT-09), and a failure inside them still fails the open. The writer writes one block, so this only happens in files from other writers. We do the same as the reference (AT-A11) (decided: spec/decisions.md LD-28). (FMT-11.35 covers history when the same entry id appears in several entry elements.)

FMT-11.32 **History item ids.** History items are not entered in the id registry. Each history item should carry its owner's id. If an item's id differs from the owner's, or is missing, zero or the wrong length, the item takes the owner's id. This is not an error.

### Reading: ids and references

FMT-11.33 **Two id spaces.** Group ids and entry ids are kept apart. A group and an entry may carry the same id. This is accepted and both are kept.

FMT-11.34 **Missing or bad id.** A group or live entry gets a fresh random id from app-crypto random, without error, when any of these is true:
- it has no `UUID` element,
- its `UUID` is empty,
- its `UUID` is the zero id,
- its `UUID` does not decode to exactly 16 bytes.

FMT-11.35 **Duplicate ids.** Two group elements, or two live entry elements, may carry the same id. The reference then makes them one object. Every occurrence is still read in full: its protected values take keystream bytes in document order, and a failure inside it fails the open.

What the one object holds:
- **Data.** Its own data are those of the occurrence that comes last in the document. For a group: name, notes, tags, icon, times, flags, sequence, last top visible entry, custom data and previous parent. For an entry: strings, icon, colors, URL override, tags, times, quality flag, auto-type block, custom data, previous parent, and the attachments that were given inline (without `Ref`). The data of earlier occurrences are dropped, including inline attachments that only an earlier occurrence had.
- **Child groups and entries (groups).** Those of all occurrences put together, placed per the position rule below.
- **History (live entries).** The history items of all occurrences, put together in document order. Each occurrence adds the items of its own last `History` block (FMT-11.31).
- **Attachments given by `Ref` (live entries).** Those of every occurrence are added, when the pool is resolved after the whole document has been read (FMT-11.23, FMT-13.8). Such an attachment replaces an attachment of the same name already present. When several `Ref` attachments carry one name, which one wins depends on hash order, as in FMT-11.23.

**Position rule.** The reader places objects when a group element ends. It then takes that group's collected child groups in document order and puts each one at the end of the group's list of child groups. A child group that is already in some list, this list included, is first taken out of it. Before each such placement, the cycle check of FMT-11.36 runs. Then it takes the group's collected entries in document order:
- an entry that already sits in this group stays at its current place;
- any other entry is taken out of its old group and put at the end of this group's entries.

What follows from this:
- An object ends up inside the parent group whose end tag comes last among the parents of all its occurrences. For nested parents, that is the outer one.
- A duplicate group takes the position of its last occurrence among its final parent's child group elements.
- A duplicate entry usually takes the position of its first occurrence among its final parent's entry elements. When it was placed in another group before (an occurrence inside a nested group closes first), it is taken out of that group; it is not left there.
- Exception for entries: when the final parent is itself a duplicate group, an occurrence of the entry in another group can end between two occurrences of the final parent. The entry then leaves the final parent, and the final parent's later occurrence puts it back at the end of its entries, not at its first place. Example: R holds X1 id(02) {E, F}, then Y {E}, then X2 id(02) {E}. Result: id(02) holds F, then E (test 11-63).
- In all cases the other objects of the final parent keep their document order.
- These bullets only summarize. When they and the position rule seem to differ, the position rule decides.

Examples:
- Root R holds entry E titled "first", and R's child group G2 holds entry E titled "second". After loading there is one entry E, titled "second", and it sits in R.
- R's child groups in document order are X1 (id 2), Y, X2 (id 2), Z. Result: Y, then the group with id 2 holding X2's data, then Z.
- R's entries in document order are E-first (id 10), F, E-second (id 10), G. Result: the entry with id 10 holding E-second's data, then F, then G.

We do the same as the reference, with one exception: a placement that would put a group inside itself fails with `Corrupt` (FMT-11.36), where the reference hangs (decided: spec/decisions.md LD-26).

FMT-11.36 **Group inside itself.** The reader places groups one at a time, by the position rule of FMT-11.35, in document order. Before it puts a child group C into a group P, it looks at P and at P's chain of parent groups as they are at that moment. If P is C, or C is in P's chain of parents (so P lies inside C), the placement would make a cycle. We then fail with `Corrupt` and the reason "a group is inside itself". The check is made before every placement, on the tree as it is at that moment, not only on the final tree: a cycle that later placements would undo still fails.

This one condition covers:
- **Self-nesting.** A group element contains, at any depth, a group element with its own id. This includes a group inside the root group that carries the root group's id. Such a document always meets the condition, at the latest when the outer element ends.
- **Cross-nested duplicates.** No element contains its own id, but duplicates point at each other. Example: R holds A id(02), which holds B' id(03); then R holds B id(03), which holds A' id(02). When B ends, the position rule would put the id(02) object into the id(03) object, which at that moment sits inside the id(02) object.
- **Longer chains of the same kind.** Example: A id(02) holds B' id(03); B id(03) holds C' id(04); C id(04) holds A' id(02).

The reference hangs in every one of these cases (observed: no output, killed by an alarm after 15 s or 30 s). Its group move routine puts the child under the new parent first and then runs a change check that walks up the chain of parents; once a group is its own ancestor, that walk never ends. We never build a cycle and never loop. Duplicates that move groups around without ever meeting the condition open normally (test 11-61).

FMT-11.37 **Forward references.** These references may point to elements later in the document:
- references to groups: the Meta fields `RecycleBinUUID`, `EntryTemplatesGroup`, `LastSelectedGroup` and `LastTopVisibleGroup` (FMT-10),
- references to entries: `LastTopVisibleEntry`.

They are resolved after the whole document has been read. A reference that finds no group (or no entry) resolves to none. There is no error, only a logged warning. The writer writes it back as the zero id. A group reference whose id belongs only to an entry does not resolve.

FMT-11.38 **Dangling ids are kept.** A `CustomIconUUID` that matches no custom icon is kept as read. So is a `PreviousParentGroup` that matches no group. FMT-13 covers attachment refs. FMT-15 covers deleted objects that name live items.

FMT-11.39 **Failures.** Inside groups and entries (everything under the root `Group`), only the conditions in the "Fail" table under Edge cases and errors fail the open. Everything else there is read leniently, as this card describes. The document frame, the XML input rules and `Meta` add their own failures, with their own error kinds (FMT-10.5 to FMT-10.9, FMT-10.14; for example a declared encoding other than UTF-8 is `Unsupported`, FMT-10.8), and every limit of FMT-11.48 gives `TooLarge`. The table lists these as pointer rows. The reference keeps reading after an error and reports only the last error it raised. We stop at the first error and report it in plain words. The report never includes a field value.

FMT-11.40 **The reference's strict mode.** The reference also has a stricter reading mode. Only its own tests use it; it never applies when a file is opened. We implement only the normal, lenient behavior in this card.

### XML handling

FMT-11.41 **Well-formedness.** Any XML syntax error fails the open.

FMT-11.42 **DTD and entities (pointer).** FMT-10.9 owns this for the whole document, groups and entries included: any `<!DOCTYPE` fails the open before any entity work, and so does a reference to an undefined entity. Together these leave only the five predefined entities (`&lt;` `&gt;` `&amp;` `&apos;` `&quot;`) and numeric character references: an entity declaration can only appear inside a DOCTYPE, and without a DOCTYPE every other entity reference is undefined. The reference accepts a DOCTYPE and expands its internal entities (observed: an entity reference in a group name was replaced by the entity text). This is a deliberate difference (plan/security.md, Extra hardening; AT-A07).

FMT-11.43 **Names, white space and stray content.** Element names are compared case-sensitively on the local name (FMT-10.7), so `<uuid>` is an unknown element. Directly inside any container element of this card (`Root`, `Group`, `Entry` live or history, `Times`, `String`, `Binary`, `AutoType`, `Association`, `History`), text between the children is ignored and not kept, whether it is white space or not. Comments and processing instructions there are ignored and not kept too. The reference skips every token that is not a start element in these places (observed: stray text in `Root`, `Group`, `Entry`, `Times`, `String`, `AutoType` and `Association`, a comment in a group and a processing instruction in an entry, all ignored without error; for `Binary` and `History`, read from the source). The same holds inside the containers of FMT-14 (`CustomIcons`, `Icon`, `CustomData`, `Item`) and FMT-15 (`DeletedObjects`, `DeletedObject`), read from the source. FMT-10.5 says the same for the children of the root element. White space inside a text value is kept. On read, `<X/>` and `<X></X>` both mean empty text, and the indentation of the file (spaces, tabs or none) does not matter. On write, empty values are always `<X/>` (FMT-12.27). Layout on write is FMT-10.2, for every element of this card: one TAB per depth, LF line ends, `<Name/>` for empty elements. It is the same layout the reference writes.

FMT-11.44 **Unknown elements: what the reference does.** A child element not listed for its parent is skipped with its whole subtree, and it is gone after the next save. A warning naming the element is logged. Unknown attributes on known elements are ignored, and are also gone after a save.

FMT-11.45 **Unknown elements: what we do (SD-06).** We keep each unknown child element of these parents: `Group`, `Entry` (live and history), `Times`, `AutoType` and `Association`. FMT-10.20 covers the root element and `Root`, with the same policy.
- An unknown element is kept as FMT-10.20 and FMT-10.27 define: its local name, its attributes, its child elements and its text. Comments, processing instructions, namespace prefixes and namespace declarations are not kept, and the write layout is the one of FMT-10.27. So the written element is equal to the read one per FMT-10.27, not necessarily byte for byte (for example `<X></X>` is written `<X/>`).
- It is written back inside the same parent, after all known children, in read order.
- **Repeated and merged parents.** Kept unknown children follow the known data of their parent:
  - Duplicate group or live entry ids (FMT-11.35): the one object keeps only the unknown children of the occurrence that comes last in the document, like its data. Those of earlier occurrences are dropped.
  - Several `Times` blocks (FMT-11.12): only the unknown children of the last block are kept.
  - Several `AutoType` blocks (FMT-11.24): the unknown children of all blocks add up, in document order, like the associations. Each `Association` keeps its own unknown children.
  - Several `History` blocks (FMT-11.31): the items of a dropped block are lost together with their unknown children. Every history item that is kept, including items added up from duplicate entry ids (FMT-11.35), keeps its own unknown children.
- Unknown children of `String`, `Binary` and `History` are dropped, as the reference drops them. Like kept unknown elements, they take no keystream bytes (FMT-09.14).
- A child element inside `Key`, `Value` or any other value element is not an unknown element: it fails the open (FMT-12.23).
- We never interpret its content. A `Protected="True"` value inside a kept unknown element takes no keystream bytes on read, as in the reference, and is kept and written back as read, with its attribute and its text unchanged, so it takes no keystream on write either (decided: spec/decisions.md LD-24; FMT-09.14, FMT-10.20).
- Unknown attributes on known elements are dropped, as the reference drops them.
- **Version (decided: spec/decisions.md LD-09).** When the vault holds kept unknown elements (from this card, FMT-10.20, FMT-14 or FMT-15), App writes at least the version the file was read as (FMT-16.24), even when no known content needs it: a file read as 4.1 is written as 4.1, a file read as 4.2 as 4.2. FMT-16 owns the version choice. The reference drops the elements and chooses V from known content only (FMT-16.2).
- FMT-10 covers unknown children of Meta. FMT-14 covers those of `CustomIcons`, `Icon`, `CustomData` and `Item`. FMT-15 covers those of `DeletedObjects` and `DeletedObject`.

These rules are decided as written (spec/decisions.md LD-27).

### Writing text

FMT-11.46 **Removing characters XML cannot hold.** The removal set of FMT-12.25 applies to every group and entry text: names, notes, tags, sequences, colors, `OverrideURL`, association texts, `String` keys, unprotected `String` values and attachment names (the `Binary` `Key`, FMT-13). Custom data keys and values follow FMT-14.10. It also applies to history items. Protected values are encrypted from the full value and are never stripped (FMT-11.20). For example, a protected password holding U+0001 survives a save; the same text in a plain field loses that character. Escaping and CR follow FMT-12.26.

FMT-11.47 **Fixed element sequence.** For the same `Vault` and the same V, the writer produces exactly the element sequence of the write-order tables in FMT-11.1, FMT-11.3, FMT-11.6, FMT-11.12, FMT-11.15 and FMT-11.24, in the layout of FMT-10.2. Tests that save twice compare element sequences (names and nesting) instead of raw bytes only because protected values and times change on every save.

### Limits

FMT-11.48 **Limits.** The reader checks each count below when the element that would pass it starts, before anything is stored for it, and stops with `TooLarge`, naming the limit. Nothing is used from the document. FMT-08.12 owns the numbers and the limit names (decided: spec/decisions.md LD-22: accepted, to be revisited if a demo vault, or a vault a user reports, passes one); this table says only what each limit counts. Test rows 11-64 to 11-73 use the numbers FMT-08.12 gives today; if FMT-08.12 changes a number, those rows change with it. Tests must be able to lower each limit, as for FMT-08.12.

| Limit (FMT-08.12 name) | What is counted |
|---|---|
| Element depth (`depth`) | The depth of any element, counted as FMT-10.2 does: the root element at depth 0, `Meta` and `Root` at 1, the root group at 2. An element one level deeper than the limit is over it. One limit for the whole document, `Meta` and kept unknown elements included. |
| Groups (`groups`) | Every `Group` element in the document, the root group included. Each occurrence of a duplicate id (FMT-11.35) counts. |
| Live entries (`entries`) | Every `Entry` element that is a child of a `Group`. Each occurrence counts. |
| Entry elements in all (`entry elements`) | Live entries plus history items in the whole document, including the items of `History` blocks that are later dropped (FMT-11.31). |
| History items of one live entry (`history`) | `Entry` elements in all `History` blocks of one live entry element, dropped blocks included. |
| Strings of one entry (`strings`) | `String` elements in one live entry element or one history item. Standard fields added because they are missing (FMT-11.16) do not count. |
| Attachments of one entry (`attachments`) | `Binary` elements in one live entry element or one history item. |
| Associations of one entry (`associations`) | `Association` elements in all `AutoType` blocks of one live entry element or one history item. |
| Kept unknown elements (`kept unknown elements`) | Elements kept under FMT-11.45, FMT-14 and FMT-15 in the whole document, each element inside a kept element counted too. |
| One text value (`text`) | FMT-12 says how a text value is measured. Base64 attachment text is exempt and bounded by the document limit (FMT-13.20, FMT-08.12). |

Counts not in this table (custom icons and custom data: FMT-14; deleted objects: FMT-15) are counted as those cards say; their numbers are in FMT-08.12 too. Everything else is bounded only by the document limit of FMT-08.12.

## Edge cases and errors

### Fail: the open fails

Every row fails with `Corrupt` unless the row says otherwise.

| Condition | Our reason text (plain, no values) |
|---|---|
| Per FMT-10: first element is not the root element name; no `Root`; `Root` without `Group` (FMT-10.5, FMT-10.6) | The vault document has no root group. |
| Per FMT-10: two `Root` elements, or two `Group` elements directly in `Root` (FMT-10.5, FMT-10.6) | The vault document has more than one root group. (The reference reports these as a missing root group.) |
| Per FMT-10: XML 1.1 declaration, undeclared namespace prefix, invalid `Meta` integer or boolean (FMT-10.7, FMT-10.8, FMT-10.14) | per FMT-10 |
| Per FMT-10: declared or detected encoding other than UTF-8 (FMT-10.8) | `Unsupported`, per FMT-10 |
| XML syntax error | The vault document is not valid XML (line, column). |
| Boolean that is not empty and not `true`/`false` (any case) | A yes/no value in the vault document is invalid. |
| Integer empty or not a 32-bit decimal (`IconID`, `UsageCount`, `DataTransferObfuscation`; Meta numbers per FMT-10) | A number in the vault document is invalid. |
| Tri-state not `null`/`true`/`false` (any case), including empty | A group setting in the vault document is invalid. |
| `String` without `Key` or without `Value` | An entry field is incomplete. |
| Second `String` with the same key when the earlier value is not empty | An entry has the same field twice. |
| `Binary` without `Key` or without `Value` | An entry attachment is incomplete. |
| `Association` without `Window` or without `KeystrokeSequence` | An auto-type association is incomplete. |
| `History` inside a history item | An entry's history is nested. |
| A child element inside a value element (FMT-12.23) | per FMT-12 |
| A protected value cannot be decrypted | per FMT-09 |
| Custom data item or custom icon incomplete | per FMT-14 |
| Pooled attachment cannot be decompressed | per FMT-13 |
| Ours only: DOCTYPE (FMT-10.9, FMT-11.42). The reference accepts it. An undefined entity reference fails in both | The vault document contains a forbidden declaration. |
| Ours only: a placement would put a group inside itself, by self-nesting, cross-nested duplicates or a longer chain (FMT-11.36). The reference hangs | A group is inside itself. |
| Ours only: a limit of FMT-11.48 (or of FMT-08.12, FMT-12, FMT-13.20, FMT-14, FMT-15) is exceeded. The reference has no limits | `TooLarge`, with the name of the limit. |

### Repaired: no error

| Condition | Result |
|---|---|
| Group or live entry: id missing, empty, zero or the wrong length | Fresh random id (FMT-11.34) |
| History item: id differs, missing, zero or the wrong length | The owner's id (FMT-11.32) |
| `IconID` negative | 0 |
| Time empty | 0001-01-01T00:00:00Z |
| Time unparseable | Open time |
| Group or entry reference not found | None; written back as the zero id |
| Duplicate group or entry ids | Merged per FMT-11.35, as the reference (decided: spec/decisions.md LD-26) |
| Several `Times`, `AutoType` or `History` blocks in one item | Per FMT-11.12, FMT-11.24 and FMT-11.31 |
| Two attachments with the same name in one entry | Both kept, the second renamed per FMT-13.13 (decided: spec/decisions.md LD-29). The reference: one survives, or an inline one is renamed with an 8-hex-digit prefix |
| Color text not in `#RRGGBB` form | Kept as is |
| Unknown element | The reference drops it; we keep it (FMT-11.45) |
| Text after the root element's end tag | Ignored (FMT-11.5, FMT-10.5) |

### Other edge cases

- **Protected values inside unknown elements.** They take no keystream bytes and are written back as read (FMT-11.45, FMT-09.14; decided: spec/decisions.md LD-24). The reference skips them and uses no keystream for them. If another app's writer did use keystream for one, every later protected value comes out wrong in the reference.
- **Deep nesting.** The reference reads groups recursively and has no depth limit. We stop at the element depth limit (FMT-11.48; the number is in FMT-08.12) with `TooLarge` (AT-A07: 100,000 levels).
- **A group and an entry with the same id.** Accepted (FMT-11.33). The model must not assume one shared id space for groups and entries. A deleted-object id may match either one (FMT-15).
- **An entry directly inside `Root`, outside any group.** It is an unknown child of `Root`: the reference drops it, and we keep it as raw XML (FMT-11.45).

## Security notes

- **Hostile document (AT-A08).** A document can be valid inside correct encryption and still be hostile: duplicate ids, cycles, missing fields, huge counts, dangling references. The reference hangs on any document whose duplicate ids would put a group inside itself, including cross-nested duplicates where no element contains its own id (FMT-11.36). We must fail cleanly instead, with no hang, no panic and no memory blow-up. Every count and length is checked against `limits.rs` before anything is allocated (FMT-11.48, Rust rule 5). Fuzz the reader (AT-A10). Compare it with the reference CLI (AT-A11), except in the deliberate differences: FMT-11.26 (step 4), FMT-11.29 and FMT-11.30 (version 4.1 for history flags and unresolved previous parents, LD-08), FMT-11.36, FMT-11.42, FMT-11.45 (kept unknown elements, and the version rule of LD-09) and FMT-11.48.
- **XML attacks (AT-A07).** DTDs and entities are rejected (FMT-11.42), unlike in the reference.
- **Protected fields (SF-08, SF-09).** A field that should be protected (FMT-11.20) must never be written as plain text inside a vault. History items hold old passwords and follow the same rule. Values read from protected fields are held in `SecretString` (architecture, secret.rs). No field value may appear in a warning, an error or a log line (AGENTS.md rule 4).
- **Untrusted text (AT-E01, AT-E02).** Every text value comes from the file and is untrusted. Names, notes, tags, keys, colors, `OverrideURL` (including `cmd://`) and auto-type sequences are shown as plain text and never run. Reading a document never acts on any value.
- **No data loss (SD-04, SD-05, SD-06).** History, previous parent groups and unknown elements survive a round trip. FMT-11.44 shows that the reference drops unknown elements, so row SD-06 ("keeps data it does not understand") is not true of the reference's document layer. For us it is an extra.

## Test cases

Notation: id(xx) as defined under What it does. "Write at V" means: run the document writer on the given vault with version V. "Read" means: run the document reader with a valid inner stream. Unless a case says otherwise, a document is a full document with the root element of FMT-11.1, an empty `Meta`, and the given `Root`.

| Case | Given | When | Then |
|---|---|---|---|
| 11-01 frame | Vault: root group id(01) "RootG"; entry id(10) "T1" in it; child group id(02) "Child"; empty deleted list | Write at 4.0 | Root element (FMT-11.1 bytes), then `Meta`, then `Root`. `Root` = `Group`, then `<DeletedObjects/>`. Root group children in exactly the FMT-11.6 order: `UUID`=`AQEBAQEBAQEBAQEBAQEBAQ==`, `Name`, `Notes`, `IconID`, `Times`, `IsExpanded`, `DefaultAutoTypeSequence`, `EnableAutoType`=`null`, `EnableSearching`=`null`, `LastTopVisibleEntry`=`AAAAAAAAAAAAAAAAAAAAAA==`, `Entry`, `Group`. No `Tags`, `CustomIconUUID`, `CustomData` or `PreviousParentGroup`. Covers FMT-11.1, 11.3, 11.6, 11.7, 11.47 |
| 11-02 wrong root name | `<?xml version="1.0"?><Other><Root><Group><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID></Group></Root></Other>` | Read | Fail: no root group. FMT-11.2 |
| 11-03 two Root | Root element with two `Root` children, each holding one valid group | Read | Fail. FMT-11.2 |
| 11-04 empty Root | `<Root></Root>` | Read | Fail: no root group. FMT-11.4 |
| 11-05 two root groups | `Root` with groups id(01) and id(10) | Read | Fail. FMT-11.4 |
| 11-06 two deleted blocks | `Root` = `DeletedObjects`[item id(77)], `Group` id(01), `DeletedObjects`[item id(78)] | Read | Deleted list = [id(77), id(78)]. FMT-11.4 |
| 11-07 trailing junk | Valid document followed by `\n<junk>not closed\n` | Read | Opens; the junk is ignored. FMT-11.5 |
| 11-08 UUID last | Group `<Name>R</Name><Entry>…<UUID>EBAQEBAQEBAQEBAQEBAQEA==</UUID></Entry><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID>` | Read | Group id(01) "R" holds entry id(10). FMT-11.8 |
| 11-09 repeated Name | Group with `<Name>a</Name><Name>b</Name>` | Read | Name is "b". FMT-11.8 |
| 11-10 tri-state | `<EnableAutoType>TRUE</EnableAutoType>`; second file `<EnableAutoType>inherit</EnableAutoType>`; third `<EnableAutoType/>` | Read; write the first | First: enabled, written `<EnableAutoType>true</EnableAutoType>`. Second: fail. Third: fail. FMT-11.9 |
| 11-11 icon numbers | Entry A `IconID` -3; entry B `IconID` 2147483647; group `IconID` 9999; group G2 with no `IconID`; entry C `<IconID/>` | Read (C in its own file) | A → 0; B → 2147483647; group → 9999; G2 → 48. File with C fails. FMT-11.10 |
| 11-12 icon order | Meta icon id(A1). Entry id(10) `<IconID>5</IconID><CustomIconUUID>oaGhoaGhoaGhoaGhoaGhoQ==</CustomIconUUID>`. Entry id(11) `<CustomIconUUID>oaGhoaGhoaGhoaGhoaGhoQ==</CustomIconUUID><IconID>7</IconID>`. Entry id(12) `<CustomIconUUID>7u7u7u7u7u7u7u7u7u7u7g==</CustomIconUUID>` (id(EE) is not in Meta) | Read, write at 4.0 | id(10): `IconID` 0 + `CustomIconUUID` id(A1). id(11): `IconID` 7, no `CustomIconUUID`. id(12): `IconID` 0 + `CustomIconUUID` `7u7u7u7u7u7u7u7u7u7u7g==`. FMT-11.11, 11.38 |
| 11-13 times defaults | Group with no `Times`; open time 2026-10-24T19:19:32Z (63928466372 s) | Read, write at 4.0 | `LastModificationTime`, `CreationTime`, `LastAccessTime`, `ExpiryTime` and `LocationChanged` = `xPtu4g4AAAA=` (bytes `c4 fb 6e e2 0e 00 00 00`); `Expires` `False`; `UsageCount` `0`. FMT-11.12 |
| 11-14 time encodings | App write: entry `LastModificationTime` 2020-07-07T07:07:07Z. Reference read: a 3.1 file (written by the reference, text times) whose entry has `<LastModificationTime>2020-07-07T07:07:07Z</LastModificationTime>` | App writes at 4.0; App reads the 3.1 file, then writes | Write: `GxaW1g4AAAA=` (bytes `1b 16 96 d6 0e 00 00 00` = 63729702427 s); App never writes the text form. Read: the same time, written back as `GxaW1g4AAAA=`. FMT-11.12 |
| 11-15 lenient times | `<Times><CreationTime>yesterday</CreationTime><LastModificationTime>AAAA</LastModificationTime><LastAccessTime/></Times>` | Read, write at 4.0 | `CreationTime` = open time. `LastModificationTime` = 0001-01-01 → `AAAAAAAAAAA=`. `LastAccessTime` → `AAAAAAAAAAA=`. FMT-11.13 |
| 11-16 empty usage count | `<Times><UsageCount/></Times>` | Read | Fail: invalid number. FMT-11.13 |
| 11-16b negative counts kept | Entry: `<Times><UsageCount>-5</UsageCount></Times>` and `<AutoType><DataTransferObfuscation>-7</DataTransferObfuscation></AutoType>` | Read, write at 4.0 | Opens. Written `<UsageCount>-5</UsageCount>` and `<DataTransferObfuscation>-7</DataTransferObfuscation>`; neither becomes 0 (observed with the installed CLI in review round 3). FMT-11.13, 11.24 |
| 11-17 booleans | Three files: `<IsExpanded/>`; `<IsExpanded>tRuE</IsExpanded>`; `<IsExpanded>1</IsExpanded>` | Read, write | First → false, written `False`. Second → true, written `True`. Third → fail. FMT-11.14 |
| 11-18 standard fields | Entry id(10) with only `<String><Key>Title</Key><Value>E</Value></String>` | Read, write at 4.0 | Five `String` elements in this order: `Notes` (empty), `Password` (`<Value Protected="True"/>`, because the default vault flag protects the password), `Title`=`E`, `URL` (empty), `UserName` (empty). FMT-11.15, 11.16, 11.20 |
| 11-19 incomplete string | Three files: `String` with only `<Value>v</Value>`; `String` with only `<Key>k</Key>`; `<String><Key/><Value>v</Value></String>` | Read | First fails, second fails. Third opens, and the field with empty key and value "v" is written back as `<Key/>` + `<Value>v</Value>`. FMT-11.17 |
| 11-20 white space kept | `<Name>  spaced  </Name>` and `<String><Key> k </Key><Value>  v  </Value></String>` | Read, write | Name is "  spaced  "; key " k "; value "  v  ", all unchanged. FMT-11.17 |
| 11-21 duplicate keys | File A: `Title` "E", then `Title` "again". File B: `<Key>X</Key><Value/>`, then `<Key>X</Key><Value>later</Value>` | Read | A fails (duplicate field). B opens with X = "later". FMT-11.18 |
| 11-22 protected read | Strings: `Password` `<Value ProtectInMemory="False">pw</Value>`; `c1` `<Value ProtectInMemory="1">x</Value>`; `c2` `<Value ProtectInMemory="yes">x</Value>`; vault flags at defaults (only the password protected) | Read, write at 4.0 | `Password` written `Protected="True"` (vault flag). `c1` written `Protected="True"`. `c2` written `<Value>x</Value>`. FMT-11.19, 11.20 |
| 11-23 protected write and keystream | Entry: `Apple`="p-secret", own flag set; `Password`="" (empty); `Title`="T1". Inner stream per FMT-09 with a fixed key | Write | `Apple` = `Protected="True"`, text = base64(keystream[0..8] XOR "p-secret"). `Password` = `<Value Protected="True"/>`, using no keystream. `Title` plain. The next protected value in the document starts at keystream byte 8. FMT-11.20 |
| 11-24 own flag sticks | Entry read with `<Key>Password</Key><Value Protected="True">…</Value>`; then the vault-level password flag is set off | Write | `Password` still written `Protected="True"`. FMT-11.21 |
| 11-25 string order | Entry keys read in this order: `Title`, `zlower`, `_under`, `KP2A_URL`, `Apple`, `Password`, ` sp`, `1`, `Z`, `a`, `é`, U+1F600, U+FFFD, U+E000 | Write | Order: ` sp`, `1`, `Apple`, `KP2A_URL`, `Notes`, `Password`, `Title`, `URL`, `UserName`, `Z`, `_under`, `a`, `zlower`, `é`, U+1F600, U+E000, U+FFFD. FMT-11.22 |
| 11-26 attachment refs | Pool (version 3 Meta or version 4 inner header) item 0 = "attach-zero", item 7 = "attach-seven". Entry: `<Binary><Key>b.txt</Key><Value Ref="7"/></Binary><Binary><Key>a.txt</Key><Value Ref="0"/></Binary>` | Read, write | Attachments a.txt = "attach-zero" and b.txt = "attach-seven". Written as `a.txt` `Ref="0"`, then `b.txt` `Ref="1"` (numbering per FMT-13). FMT-11.23 |
| 11-27 inline duplicate | Entry: `<Binary><Key>f.txt</Key><Value>QUFB</Value></Binary><Binary><Key>f.txt</Key><Value>QkJC</Value></Binary>` | Read | Both contents kept: `f.txt` = "AAA", and the second ("BBB") under the name FMT-13.13 gives (decided: spec/decisions.md LD-29). The reference names the second one with a match for `^[0-9a-f]{8}_f\.txt$` (observed). FMT-11.23 |
| 11-28 broken binary | File A: `<Binary><Key>f.txt</Key></Binary>`. File B: pool items with keys `0` = "AAA" and `1` = "BBB"; entry has `<Value Ref="1"/>` under the name `g.txt` | Read | A fails. B: attachment `g.txt` = "BBB". FMT-11.23 |
| 11-29 auto-type | `<AutoType><Enabled>False</Enabled><DataTransferObfuscation>1</DataTransferObfuscation><DefaultSequence>{PASSWORD}</DefaultSequence><Association><Window>Win B</Window><KeystrokeSequence>seqB</KeystrokeSequence></Association><Association><Window>Win A</Window><KeystrokeSequence/></Association></AutoType>` | Read, write | Written in the same order, with `<KeystrokeSequence/>` for Win A. FMT-11.24 |
| 11-30 auto-type errors and defaults | File A: `<Association><Window>w</Window></Association>`. File B: entry without `AutoType` | Read, write B | A fails. B written `<AutoType><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation><DefaultSequence/></AutoType>`. FMT-11.24 |
| 11-31 colors | `<ForegroundColor>red</ForegroundColor><BackgroundColor>#GG0000</BackgroundColor>`; another entry `<BackgroundColor>#00ff00</BackgroundColor>` | Read, write | All kept byte for byte. No error. A color the user picks in App is written per FMT-12.18. FMT-11.25 |
| 11-32 entry tags | `<Tags>zeta; alpha,beta&#9;alpha ,Alpha</Tags>`; second entry `<Tags>a, ,b;;c</Tags>` | Read, write | First: `<Tags>Alpha,alpha,beta,zeta</Tags>`. Second: `<Tags>a,b,c</Tags>` (the reference writes `,a,b,c`). FMT-11.26 |
| 11-33 group tags | Group `<Tags>gt2;gt1</Tags>` | Read, write at 4.1 | `<Tags>gt2;gt1</Tags>` between `Notes` and `IconID`. FMT-16 picks 4.1. FMT-11.27 |
| 11-34 override URL | `<OverrideURL>cmd://demo</OverrideURL>` | Read, write | Kept byte for byte. Nothing runs. FMT-11.28 |
| 11-35 quality check | Entry A `<QualityCheck>False</QualityCheck>`; B `<QualityCheck>True</QualityCheck>`; C `<QualityCheck/>`; D none | Read; write at 4.1 and at 4.0 | A and C excluded; B and D included. At 4.1: A and C have `<QualityCheck>False</QualityCheck>` right after `Times`; B and D have no `QualityCheck`. At 4.0: no `QualityCheck` at all. FMT-11.29 |
| 11-36 previous parent | First file: entry `PreviousParentGroup` id(02), where group id(02) exists. Second file: entry `PreviousParentGroup` id(98) (no such group) and nothing else that needs 4.1 (FMT-16.6 to FMT-16.10) | App lets FMT-16 choose V for each, writes, then reads its output back | First: V is 4.1 (FMT-16.9); `<PreviousParentGroup>AgICAgICAgICAgICAgICAg==</PreviousParentGroup>` after the `QualityCheck` position and before the first `String`. Second: V is 4.1 (LD-08); `<PreviousParentGroup>mJiYmJiYmJiYmJiYmJiYmA==</PreviousParentGroup>` is written at the same position, and after the read-back the entry still has previous parent id(98). The reference saves the second file at 4.0 (or 3.1 with the legacy AES-KDF) without the element, so its read-back has no previous parent (FMT-16.13). FMT-11.30, 11.38 |
| 11-36b history flags need 4.1 | Live entry id(10) "T1", not excluded, no previous parent, holding one history item (Title "T0") with `<QualityCheck>False</QualityCheck>` and `PreviousParentGroup` id(02), where group id(02) exists. Nothing else in the vault needs 4.1 | App lets FMT-16 choose V, writes, then reads its output back | V is 4.1. The history item is written with `<QualityCheck>False</QualityCheck>` right after its `Times`, then `<PreviousParentGroup>AgICAgICAgICAgICAgICAg==</PreviousParentGroup>`. After the read-back the history item is still excluded and still has previous parent id(02); the live entry is still included and has none. The reference does not raise V for these and drops both (FMT-16.11, FMT-16.13). FMT-11.29, 11.30 |
| 11-37 history shape | Live entry id(10) with one history item (Title "T0"); live entry id(11) with no history | Write | id(10) ends with `<History><Entry>…</Entry></History>`, and the item has its own `Times` and no `History`. id(11) ends with `<History/>`. FMT-11.15, 11.31 |
| 11-38 nested history | History item holding `<History/>` | Read | Fail. FMT-11.31 |
| 11-39 history ids | Entry id(10) with history items: one with `UUID` id(20), one with no `UUID` | Read, write | Both items written with `UUID` `EBAQEBAQEBAQEBAQEBAQEA==`. FMT-11.32 |
| 11-40 shared id across kinds | Group id(01) holds entry id(02) and child group id(02) | Read, write | Both kept. id(02) appears twice in the output, once as an entry and once as a group. FMT-11.33 |
| 11-41 bad ids | Entry `<UUID>QUJD</UUID>` (3 bytes); group with no `UUID`; group `<uuid>AQEBAQEBAQEBAQEBAQEBAQ==</uuid>` | Read | Each gets a fresh 16-byte, non-zero id. No error. The `<uuid>` element is an unknown element. FMT-11.34, 11.43 |
| 11-42 duplicate entry id | Root R id(01) holds entry id(10) titled "first" and child group G2 id(02); G2 holds entry id(10) titled "second" | Read | One entry id(10), titled "second", inside R. G2 has no entries. FMT-11.35 |
| 11-43 duplicate group id | R id(01) holds group A id(02) (with entry id(11)) and group B id(03); B holds group A2 id(02) (with entry id(12)) | Read | R's children are [id(02) named "A2", B]. id(02) holds entries id(11) and id(12). B is empty. FMT-11.35 |
| 11-44 group in itself | File A: R id(01) holds group id(02) "A", which holds group id(02) "A-inner". File B: R id(01) holds group id(01) | Read | Both fail with `Corrupt` ("a group is inside itself") within 1 second. No hang (the reference hangs). FMT-11.36 |
| 11-45 forward and broken refs | Meta `RecycleBinUUID` = id(10), which is an entry, not a group; `LastSelectedGroup` = id(01), the root group. Root group `LastTopVisibleEntry` = id(99), which does not exist | Read, write | Recycle bin = none, written `AAAAAAAAAAAAAAAAAAAAAA==`. Last selected group = the root group, written `AQEBAQEBAQEBAQEBAQEBAQ==`. `LastTopVisibleEntry` written as the zero id. Warnings logged; no error. FMT-11.37 |
| 11-46 first error reported | Group with `<IsExpanded>1</IsExpanded>`, later `<EnableAutoType>x</EnableAutoType>` | Read | Fail. The reason names the yes/no value (the first problem). The message has no field values. FMT-11.39 |
| 11-46b failures from FMT-10 | File A: a valid document declared `encoding="ISO-8859-1"`. File B: a valid document with `<Meta><RecycleBinEnabled>yes</RecycleBinEnabled></Meta>`. File C: a valid document whose root group holds 1,000,000 child `<Group/>` elements | Read | A: `Unsupported` (FMT-10.8). B: `Corrupt` (FMT-10.14). C: `TooLarge`, naming the group limit (FMT-11.48). None of these is in the group and entry rows of the Fail table, but all fail the open. FMT-11.39 |
| 11-47 lenient by default | Document whose only group has no `UUID` (`<Root><Group><Name>Test</Name></Group></Root>`, like the reference's sample with stem BrokenNoGroupUuid) | Read | Opens. The group gets a fresh id. FMT-11.40, 11.34 |
| 11-48 syntax error | `<Root><Group><Name>R</Group></Root>` (mismatched tags) | Read | Fail: not valid XML, with line and column. FMT-11.41 |
| 11-49 DOCTYPE | `<!DOCTYPE` + root name + ` [<!ENTITY demo "expanded-entity">]>` before the root element; group `<Name>&demo;</Name>` | Read | Fail (forbidden declaration). The reference opens it and names the group "expanded-entity". FMT-11.42 |
| 11-50 empty forms and layout | `<Name></Name>` in one file and `<Name/>` in another; the same document indented with spaces, with tabs and with no indentation | Read; write at 4.0 | Same result each time: empty name; identical vaults. Each write is in the FMT-10.2 layout: the root group's name line is exactly the 11 bytes `09 09 09 3C 4E 61 6D 65 2F 3E 0A` (TAB TAB TAB `<Name/>` LF), and its `UUID` line is TAB TAB TAB `<UUID>`, the id, `</UUID>`, LF. All writes give the same bytes apart from times and protected values. FMT-11.43 |
| 11-50b stray content | Text `rootjunk` directly in `Root`; text `gjunk` and `<!--c-->` directly in the root group; text `ejunk` and `<?pi x?>` directly in an entry; `tjunk` directly in its `Times` (which also holds `<UsageCount>4</UsageCount>`); `sjunk` directly in its `String` (`Title` = `T`); `ajunk` directly in its `AutoType`; `xjunk` directly in an `Association` (`Window` = `W`, `KeystrokeSequence` = `s`). Second file: the root element written with a declared prefix, `<p:` + root name + ` xmlns:p="urn:x">` … `</p:` + root name + `>` | Read, write | Opens with no error. `UsageCount` 4, `Title` `T` and `Window` `W` are kept. None of the stray text, the comment or the processing instruction is written back (observed with the installed CLI in review round 3). The second file opens like the same document without the prefix (FMT-10.7; observed with the installed CLI: the entry `T` was listed after import). FMT-11.43, 11.2 |
| 11-51 unknown elements | `<UnknownGroupThing a="1">x</UnknownGroupThing>` in the root group; `<UnknownEntryThing>y</UnknownEntryThing>` in an entry; `<UnknownTimesThing/>` in an entry's `Times`; `<String><Key>k</Key><Value>v</Value><StringExtra/></String>` in an entry | Read, write | Each unknown element is written back inside the same parent, after the known children, equal per FMT-10.27: `<UnknownGroupThing a="1">x</UnknownGroupThing>`, `<UnknownEntryThing>y</UnknownEntryThing>` and `<UnknownTimesThing/>`. `StringExtra` is dropped and the field `k` = `v` is kept. The reference instead logs one warning per skipped element and writes none of them (observed for the first three; for the `String` child, read from the source). For an unknown element that holds a `Protected="True"` value, see FMT-09 T09-14. FMT-11.44, 11.45 |
| 11-52 removing characters | Entry: plain custom field `PlainInvalid` = U+0002 U+0019 U+FFFE U+FFFF; group name "a" U+0084 "b"; protected custom field `Sec` = "x" U+0001 "y"; attachment named "f" U+0001 ".txt" | Write, read back | `PlainInvalid` is empty and written `<Value/>`. The group name is "ab". `Sec` is still "x" U+0001 "y". The attachment is written with `<Key>f.txt</Key>`. FMT-11.46 |
| 11-53 fixed sequence | The vault of 11-01, written twice with different random values | Write at 4.0 twice | The two element sequences (names and nesting) are identical. Only times and ciphertext may differ. FMT-11.47 |
| 11-54 two History blocks | Live entry id(10): `<History><Entry><UUID>EBAQEBAQEBAQEBAQEBAQEA==</UUID>` + Title "H1" + `</Entry></History><History><Entry><UUID>EBAQEBAQEBAQEBAQEBAQEA==</UUID>` + Title "H2" + `</Entry></History>` | Read, write | Opens. One history item, titled "H2". H1 is gone, with no error. One `History` element written. FMT-11.31, 11.15 |
| 11-55 two Times blocks | Entry: `<Times><LastModificationTime>GxaW1g4AAAA=</LastModificationTime><UsageCount>3</UsageCount></Times><Times><CreationTime>m2eX1g4AAAA=</CreationTime></Times>`; open time 2026-10-24T19:19:32Z | Read, write at 4.0 | One `Times` block: `CreationTime` = `m2eX1g4AAAA=` (2020-07-08T07:07:07Z); `LastModificationTime`, `LastAccessTime`, `ExpiryTime` and `LocationChanged` = `xPtu4g4AAAA=` (2026-10-24T19:19:32Z); `UsageCount` = 0; `Expires` = `False`. The first block's values are lost. FMT-11.12 |
| 11-56 two AutoType blocks | Entry: `<AutoType><Enabled>False</Enabled><DefaultSequence>{USERNAME}</DefaultSequence><Association><Window>W1</Window><KeystrokeSequence>s1</KeystrokeSequence></Association></AutoType><AutoType><DataTransferObfuscation>1</DataTransferObfuscation><DefaultSequence>{PASSWORD}</DefaultSequence><Association><Window>W2</Window><KeystrokeSequence>s2</KeystrokeSequence></Association></AutoType>` | Read, write | One block: `<Enabled>False</Enabled>` (from the first block), `<DataTransferObfuscation>1</DataTransferObfuscation>`, `<DefaultSequence>{PASSWORD}</DefaultSequence>`, then associations W1/s1 and W2/s2 in that order. FMT-11.24 |
| 11-57 duplicate entry: history and attachments | Pool item 0 = "AAA", item 1 = "BBB". Root R id(01) holds entry id(10) {Title "first"; `<Binary><Key>a.txt</Key><Value Ref="0"/></Binary>`; `<Binary><Key>c.txt</Key><Value>Q0ND</Value></Binary>`; history item titled "h-first"}, then entry id(20), then child group G2 id(02). G2 holds entry id(10) {Title "second"; `<Binary><Key>b.txt</Key><Value Ref="1"/></Binary>`; history item titled "h-second"} | Read, write | R's entries: id(10), then id(20). Entry id(10) is titled "second", has attachments a.txt = "AAA" and b.txt = "BBB" and no c.txt, and has history ["h-first", "h-second"]. G2 has no entries (observed with the installed CLI). FMT-11.35 |
| 11-58 duplicate positions | R id(01) child groups in document order: X1 id(02) named "X1", Y id(03), X2 id(02) named "X2", Z id(04). R entries in document order: id(10) titled "E-first", F id(11), id(10) titled "E-second", G id(12) | Read, write | R's child groups: Y, id(02) named "X2", Z. R's entries: id(10) titled "E-second", F, G (observed in the second Spec review). FMT-11.35 |
| 11-59 Unicode white space in tags | Entry `<Tags>` U+00A0 `x` U+00A0 `,` U+3000 `y</Tags>` | Read, write | `<Tags>x,y</Tags>` (observed with the installed CLI). FMT-11.26 |
| 11-60 cross-nested duplicates | File A (cross-nested): root R id(01) holds group A id(02) (`AgICAgICAgICAgICAgICAg==`), which holds group B' id(03) (`AwMDAwMDAwMDAwMDAwMDAw==`); then R holds group B id(03), which holds group A' id(02). File B (chain): R id(01) holds A id(02) holding B' id(03); then B id(03) holding C' id(04) (`BAQEBAQEBAQEBAQEBAQEBA==`); then C id(04) holding A' id(02). File C: file A with an extra wrapper group id(05) around A and B, and one entry in each group | Read | All three fail with `Corrupt` ("a group is inside itself") within 1 second. No group element in them contains its own id. File A fails when B ends; file B fails when C ends. The reference hangs on all three (observed with the installed CLI: killed by a 15 s alarm, exit code 142). FMT-11.36 |
| 11-61 duplicates without a cycle | R id(01) holds group A id(02), which holds group B' id(03); then R holds group X id(05) (`BQUFBQUFBQUFBQUFBQUFBQ==`), which holds group B id(03), which holds group Y id(04) | Read, write | Opens. R's child groups: A (empty), then X. X holds the id(03) group with B's data, and that group holds Y. Same result as the reference (observed with the installed CLI, under 1 s). FMT-11.36, 11.35 |
| 11-62 unknown children of repeated parents | Entry id(10): `<Times><UnknownT1/></Times><Times><UnknownT2/></Times>` and `<AutoType><UnknownA1/></AutoType><AutoType><UnknownA2/></AutoType>`. In the same group, entry id(11) twice: first occurrence holds `<UnknownE1/>`, the later one `<UnknownE2/>`. Entry id(12): `<History><Entry>` (Title "H1", `<UnknownH1/>`) `</Entry></History><History><Entry>` (Title "H2", `<UnknownH2/>`) `</Entry></History>` | Read, write | id(10): its `Times` holds the seven known children, then `<UnknownT2/>` only. Its `AutoType` holds the known children, then `<UnknownA1/>`, then `<UnknownA2/>`. id(11): `<UnknownE2/>` only, after all known children. id(12): one history item, "H2", which ends with `<UnknownH2/>`; `UnknownH1` is gone. (Ours, decided: spec/decisions.md LD-27; the reference drops all of them.) FMT-11.45 |
| 11-62b unknown element keeps the version | File A: a 4.1 file whose only entry holds `<UnknownEntryThing>y</UnknownEntryThing>`, and nothing in the vault needs 4.1 (no group tags, no excluded entry or history item, no previous parent, no custom icon with a name or time). File B: the same document in a 4.0 file. File C: the same document in a file whose header says 4.2 | Read, let FMT-16 choose V, write | A: V is 4.1 (LD-09, FMT-16.24), with `<UnknownEntryThing>y</UnknownEntryThing>` kept after the entry's known children. B: V is 4.0, with the element kept the same way. C: V is 4.2 (header minor version `02 00`), every known part in its 4.1 form, the element kept the same way. The reference saves all three at 4.0 and drops the element (FMT-16.2; for a 4.2 file see FMT-16 Edge cases). FMT-11.45 |
| 11-63 entry placed through another group | R id(01) holds, in document order: group X1 id(02) with entries E id(10) and F id(11); group Y id(03) with entry E id(10); group X2 id(02) with entry E id(10) | Read, write | R's child groups: Y, then the id(02) group with X2's data. Y has no entries. The id(02) group holds F, then E (E is not at its first place). FMT-11.35 |
| 11-64 depth limit | File A: the root group holds a chain of 510 nested child groups, each written `<Group>` … `</Group>` with no other children, the innermost written `<Group/>` (it sits at depth 512). File B: the same with 511 nested child groups (the innermost at depth 513). File C: 100,000 nested groups | Read | A opens: 511 groups, each with a fresh id. B: `TooLarge`, naming the depth limit. C: `TooLarge` within 1 second, with memory flat (AT-A07). FMT-11.48 |
| 11-65 group limit | File A: the root group holds 999,999 child `<Group/>` elements (1,000,000 groups). File B: 1,000,000 child `<Group/>` elements (1,000,001 groups) | Read | A opens. B: `TooLarge`, naming the group limit. FMT-11.48 |
| 11-66 live entry limit | File A: the root group holds 1,000,000 `<Entry/>` elements. File B: 1,000,001 | Read | A opens (each entry gets a fresh id and the five empty standard fields). B: `TooLarge`, naming the live entry limit. FMT-11.48 |
| 11-67 entry elements in all | File A: the root group holds 40 entries, each with one `History` holding 99,999 `<Entry/>` items (4,000,000 entry elements). File B: the same plus one more history item in the last entry | Read | A opens. B: `TooLarge`, naming the limit on entry elements in all. FMT-11.48 |
| 11-68 history limit | File A: one live entry whose `History` holds 100,000 `<Entry/>` items. File B: 100,001 items. File C: one live entry with two `History` blocks of 60,000 items each | Read | A opens with 100,000 history items, each with the owner's id (FMT-11.32). B and C: `TooLarge`, naming the history limit (C counts the dropped first block too). FMT-11.48 |
| 11-69 string limit | File A: one entry with 100,000 `String` elements, keys `k0` to `k99999`, empty values. File B: the same plus `k100000` | Read | A opens: 100,005 fields (the five standard fields added as empty do not count). B: `TooLarge`, naming the string limit. FMT-11.48 |
| 11-70 attachment limit | Pool item 0 = "AAA". File A: one entry with 100,000 `Binary` elements, names `b0` to `b99999`, each `<Value Ref="0"/>`. File B: 100,001 | Read | A opens with 100,000 attachments sharing one pool item. B: `TooLarge`, naming the attachment limit. FMT-11.48 |
| 11-71 association limit | File A: one entry with two `AutoType` blocks of 50,000 `Association` elements each. File B: blocks of 50,000 and 50,001 | Read | A opens with 100,000 associations. B: `TooLarge`, naming the association limit. FMT-11.48 |
| 11-72 kept unknown limit | File A: the root group holds 1,000,000 `<U/>` elements. File B: 1,000,001. File C: the root group holds one `<U>` that holds 1,000,000 `<V/>` | Read | A opens and keeps all of them. B and C: `TooLarge`, naming the kept unknown limit (C has 1,000,001 kept elements). FMT-11.48 |
| 11-73 text value limit | Single text node cap lowered to 1 MiB for the test. Entry `Notes` value of 1,048,576 ASCII bytes; another file with 1,048,577 | Read | The first opens; the second: `TooLarge`, naming the text limit (FMT-12). FMT-11.48 |

## How this was learned

- **Reference source, read only.** These parts were studied:
  - the XML document reader and writer, including the routine that removes invalid XML characters,
  - the routine that picks the file version on save,
  - the core group, entry, entry attribute, attachment, auto-type association, custom data and time-info code (defaults, tag normalization, icon setters),
  - the code that changes a parent when an item moves,
  - the reference tests for the XML format: the broken-document matrix and the invalid-character round trip.
- **Reference test documents.** Their content was paraphrased into the cases above, never copied. Stems: BrokenNoGroupUuid, BrokenNoEntryUuid, BrokenNoRootGroup, BrokenTwoRoots, BrokenTwoRootGroups, BrokenGroupReference, BrokenDifferentEntryHistoryUuid, EmptyUuids, NewDatabase.
- **The installed reference CLI, 2.7.11.** Its XML import command reads documents with the same lenient reader. Demo XML documents were made in `/tmp/spec-fmt11-14-15/` with demo password `demo-pass` and fed to the import. The saved demo vaults were then decrypted with a scratch, read-only decryptor in that folder (AES-KDF and AES-256-CBC through the macOS system crypto library), to see the exact document the CLI writes. Observed this way:
  - the 4.1 write order,
  - IconID set to 0 under a custom icon,
  - tag normalization,
  - string order with non-ASCII keys,
  - attachment renaming,
  - the handling of duplicate ids,
  - leniency on colors, dates and booleans,
  - unknown elements dropped,
  - DOCTYPE entities expanded,
  - text after the end tag ignored,
  - the hang on a group inside itself (CLI killed after 30 s by an alarm),
  - the hang on cross-nested duplicates and on a chain of three, and the normal open of a matching document without a cycle (FMT-11.36, tests 11-60 and 11-61), observed in review round 2 (`/tmp/spec-review-r2-fmt11-14-15/`) and again for the cross-nested and no-cycle documents in `/tmp/spec-fmt11-14-15/r3/` (15 s alarm, exit code 142). The expected results of tests 11-60, 11-61 and 11-63 were also checked with a scratch simulation of the position rule in that folder,
  - repeated `Times`, `AutoType` and `History` blocks (FMT-11.12, FMT-11.24, FMT-11.31) and the duplicate-id history union and positions (FMT-11.35), observed in the second Spec review (`/tmp/spec-review-fmt11-14-15/`, same method),
  - the duplicate-id attachment and history union, including the lost inline attachment of an earlier occurrence, and the U+00A0 and U+3000 tag trim (FMT-11.26), observed again in `/tmp/spec-fmt11-14-15/r2/`,
  - in review round 3 (`/tmp/spec-review-r3-fmt11-14-15/`): a negative `UsageCount` and `DataTransferObfuscation` kept (test 11-16b), and stray text, a comment and a processing instruction inside containers ignored (test 11-50b),
  - a root element with a declared namespace prefix read on its local name (test 11-50b), in `/tmp/spec-fmt11-14-15/r4/`.
- **App's own rules.** The limits of FMT-11.48 are App's own; the reference has no limits to observe (its source sets none for the document). The numbers are those of FMT-08.12 (decided: spec/decisions.md LD-22).
- **Installed version against the source.** For the rules in this card, no difference was found between the source and the installed 2.7.11. One unrelated difference (FEA-09): the installed CLI's XML export always writes the version 3.1 form (text times, no group or entry custom data), while the source exports in the vault's version.
- **Checked by Verify (Sprint 2):**
  - FMT-11.5: trailing text was first observed only through the import path. Observed by Verify through the vault open path too: a version 4 demo vault whose document is followed by `\n<junk>not closed\n` after the root end tag opened in the installed CLI (`show` printed the entry with its protected password) and in App's reader.
  - FMT-11.36: the source does hang, in the change check that runs after each group move (read from the source). Observed by Verify on five more self-nested documents inside valid version 4 demo vaults: a group four levels down carrying an ancestor's id; a group three levels down carrying the root group's id; a self-nested pair after an earlier sibling with the same id; a self-nested pair with entries and other child groups around it; a self-nested pair followed by later siblings. The installed CLI hung on every one (no output, stopped after 15 s) and App's reader failed each with `Corrupt`. A document with a duplicate id but no cycle opened in both.
  - Protected values in unknown elements: observed by Verify with rebuilt demo vaults of FMT-09 T09-14 and T09-37 (version 4, ChaCha20 stream). When the writer took no keystream for `<FooBar Protected="True">`, the installed CLI showed the password "pw-one"; when the writer did take keystream for it, the password came out garbled; a `Value Protected="True"` nested inside an unknown element took no keystream either. App's reader gave the same three results.
- **Lead decisions (all decided, spec/decisions.md):**
  - L11-1 duplicate ids: LD-26, mirror the reference merge; a placement that would put a group inside itself is `Corrupt` (FMT-11.35, FMT-11.36). Not chosen: fail on any duplicate, or give later duplicates fresh ids.
  - L11-2 unknown elements: LD-27, the rules of FMT-11.45 as written.
  - L11-4 limits: LD-22, the numbers of FMT-08.12 (FMT-11.48).
  - L11-5 several `History` blocks: LD-28, keep only the last block's items (FMT-11.31). Not chosen: keep the items of all blocks.
  - Also applied here: LD-08 (version 4.1 for history flags and unresolved previous parents, FMT-11.29, FMT-11.30), LD-09 (version kept with unknown elements, FMT-11.45), LD-24 (no keystream for protected values in kept unknown elements, FMT-11.45) and LD-29 (same attachment name twice, FMT-11.23).
  - (Text after the root end tag is not a lead decision: FMT-10.5 settles it, and FMT-11.5 follows.)
  - SD-06 wording: the reference does not keep unknown document elements.
- Sprint 1 close-out: the V definition and the version bullet of FMT-11.45 now say "at least the version the file was read as (FMT-16.24)" (LD-09); test 11-62b has a 4.2 file C. FMT-11.48 now says only what each limit counts; FMT-08.12 alone gives the numbers.
