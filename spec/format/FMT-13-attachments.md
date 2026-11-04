# FMT-13 Attachment pool and references

Status: reviewed
Epics: E3-S5, E3-S6
Parity rows: SD-06, SF-08

## What it does

A vault file stores the content of attachments once, in a pool. Entries and history entries do not hold attachment content themselves. Each one holds a list of names, and each name points to a pool item. Identical content used by several entries, or by an entry and its history entries, is stored only once.

- In version 4 the pool is a list of binary records in the inner header (FMT-09), numbered from 0.
- In version 3 the pool is the `Binaries` element in the document's `Meta` section (FMT-10), keyed by an `ID` attribute.

This card covers both forms: how references are written and resolved, how the reference removes duplicates when saving, the protected flag, empty attachments, broken references, unused items and limits. MOD-05 covers how users manage attachments.

## Inputs and outputs

Reading:

- Version 4: the field 3 records of the inner header (FMT-09.3), in order.
- Version 3: the `Meta/Binaries` element.
- In both: every `Entry/Binary` element, in current and history entries.

Output: for each entry and history entry, a list of (name, content). Content is bytes, possibly empty, kept in `SecretBytes`. Also: warnings for broken references (FMT-13.11).

Writing (version 4 only): the vault's entries and history entries with their attachments. Output:

- the field 3 records, in index order, for the inner header,
- one `Ref` index for each (entry, attachment name).

| Item | Form |
|---|---|
| Version 4 pool item | inner header field 3: 1 flags byte + raw content bytes |
| Version 4 pool key | the decimal index as text: "0", "1", "2", … |
| Version 3 pool item | `<Binary ID="…" Compressed="True">base64</Binary>` inside `Meta/Binaries` |
| Version 3 pool key | the `ID` attribute value, verbatim |
| Entry reference | `<Binary><Key>name</Key><Value Ref="key"/></Binary>` inside `Entry` |

## Rules

### Version 4 storage

FMT-13.1 One pool per file. Each entry attachment is a name plus a reference into the pool. Several references may point to the same item.

FMT-13.2 Version 4 pool items are inner header field 3 records (FMT-09.2). Their data is a 1-byte flags field followed by the content bytes. The content is raw, not base64 and not separately compressed; the whole payload's gzip applies (FMT-08). Indexes are 0-based and count only field 3 records, in the order they appear. Other inner header fields do not count. Item n has pool key equal to n written in decimal ("0", "1", …).

FMT-13.3 Flags byte. Bit 0 (`01`) means "keep protected in memory". The other bits are reserved. The reference ignores the whole byte when reading (observed: items with flags `00` and `FE` loaded normally) and always writes `01`. Larsal does the same: it ignores the flags on read and always writes `01`. Larsal keeps all attachment content in `SecretBytes` whatever the flag says.

FMT-13.4 A field 3 record must have length 1 or more; length 0 is `Corrupt` (FMT-09.6). Length 1 is a valid empty item, with content of 0 bytes. The reference writes empty attachments this way: `03 01 00 00 00 01`.

### Version 3 storage

FMT-13.5 A version 3 pool item is a `Binary` element inside `Meta/Binaries`:

- Attribute `ID`: any string. This is the pool key.
- Attribute `Compressed` (optional): `true` in any ASCII case, or `1`, means compressed. Any other value, or no attribute, means not compressed.
- Attribute `Protected` (optional): see FMT-09.12.
- Content: base64-decode the text (FMT-12), then XOR if protected (FMT-09.16), then gunzip if compressed (RFC 1952, same format checks as FMT-08.6). Count the decompressed bytes while inflating and stop at the attachment limits of FMT-13.20; never allocate from the gzip ISIZE field.

Empty text means empty content, even when `Compressed` is true. The reference writes an empty attachment in a compressed vault as `<Binary ID="2" Compressed="True"/>`, with no gzip data at all. A compressed item that does not gunzip is `Corrupt` (the reference says it cannot decompress the binary). That includes gzip data cut short, for example with its 8-byte trailer missing. Reference difference: the reference treats data that ends early as the end of the item, so it opens the vault without error and gives empty or partial content (observed in 2.7.11: an item without its trailer gave 0 bytes). This is an expected AT-A11 difference. Bytes after the gzip member inside one item are `Corrupt`, as in FMT-08.7 (decided: spec/decisions.md LD-02: the item lies inside the checked payload, so only the key holder can put them there). The reference ignores them (T13-35). Children of `Binaries` not named `Binary` are skipped with their whole subtree; they take no keystream bytes (FMT-09.14). Every `Binary` child is read as a pool item.

FMT-13.6 Pool keys are compared as strings. If two items have the same key, the later one replaces the earlier one. The reference does the same and logs a warning. Version 3 keys need not be numbers: a key "z9" works in the reference. A `Binary` with no `ID` attribute has the empty string as its key. No `Ref` can reach it, because an empty `Ref` is never resolved (FMT-13.11), so the item is unused and dropped (FMT-13.15). The reference does the same (source: an empty `Ref` is dropped before references are resolved).

FMT-13.7 A `Meta/Binaries` element inside a version 4 document is read the same way. Its items go into the same pool after the inner header items, replacing any item with the same key. Observed in the installed reference: `<Binary ID="0">` in `Meta` replaced inner header item 0, and ID "7" was added as a new key. Larsal does the same. Confirmed in the source and observed in 2.7.11: the version 4 reader hands its inner header pool to the document reader, which adds `Meta/Binaries` items to that same pool.

### References from entries

FMT-13.8 Inside an `Entry`, which may be a history entry, each attachment is written as `<Binary><Key>name</Key><Value Ref="r"/></Binary>`. The `Key` text is the attachment name (FMT-12 escaping). The `Ref` attribute is a pool key. It is matched by exact string comparison. The text is never parsed as a number, so "01", " 1", "+1" and "-1" do not match key "1". `Key` and `Value` may come in either order inside `Binary`. Larsal resolves the reference with the name from `Key` wherever it stands (the last `Key` when there are several, FMT-13.10; decided: spec/decisions.md default rule). Reference difference: the reference pairs the `Ref` with the name it has read so far, so when `Value` comes before `Key` it never resolves the `Ref`. The attachment gets its name and 0 bytes, and the pool item is reported unused (observed in 2.7.11; the source agrees). For an inline `Value` the order does not matter in either app. Larsal always writes `Key` first.

FMT-13.9 Inline content. When a `Value` has no `Ref` attribute, its text is the base64 content itself. This is a compatibility form; the reference reads it in version 4 too. `Protected` applies (FMT-09.16): base64-decode, then XOR. `Compressed` is not honored on inline values. Larsal reads inline content and writes it back as a normal pool item. When a `Value` has a `Ref` attribute, the `Ref` wins: any text it holds is ignored and takes no keystream bytes, even with `Protected` (FMT-09.13). Confirmed in the source and observed in 2.7.11.

FMT-13.10 A `Binary` element with no `Key` child or no `Value` child is `Corrupt`. The reference also fails the whole open, reporting a missing entry binary key or value.

Repeated children inside one `Binary` follow FMT-11's rule that the last single-value child wins. One `Binary` always gives exactly one attachment:

- Name: the text of the last `Key`.
- Content: if any `Value` in the `Binary` has a `Ref` attribute, the last such `Value` gives the content (resolved by FMT-13.11), whether it comes before or after the inline values. Otherwise the last inline `Value` gives the content.
- Keystream: every inline `Value` with `Protected` takes its keystream bytes in document order (FMT-09.13), even one whose content loses. A `Value` with `Ref` takes none (FMT-13.9).
- Children other than `Key` and `Value` are skipped with their subtree and take no keystream bytes (FMT-09.14).

The reference matches this (observed in 2.7.11; the source agrees) in these cases: a `Ref` beats an inline `Value` in either order, the last inline `Value` wins among inline values, the last `Key` names an inline value, and a losing protected inline `Value` still uses its keystream bytes. Reference difference: when a `Key` follows a `Ref` value, the reference makes two attachments. The `Ref` content goes under the name read before the `Ref`, and the last `Key` gets the inline content, or 0 bytes when there is none. Observed: `<Key>a.txt</Key><Value Ref="0"/><Key>b.txt</Key>` gave `a.txt` = the pool item and `b.txt` with 0 bytes. Larsal gives one attachment, `b.txt` = the pool item. No known writer produces repeated children, so this is an expected AT-A11 difference.

FMT-13.11 Dangling reference. If `Ref` matches no pool key (for example out of range, a sign or leading zero in version 4, or empty; non-numeric keys are valid where the pool has them, FMT-13.6, FMT-13.7), the attachment keeps its name and gets empty content (0 bytes). Larsal opens the vault and also returns a warning that lists the affected entries, so the user knows content is missing (decided: spec/decisions.md default rule). It never crashes. Reference: the same empty result, with only a log line and nothing shown to the user. On its next save the 0-byte attachment is written as a real empty item.

FMT-13.12 An empty attachment name (`<Key></Key>`). Larsal resolves the reference normally and keeps the content. Reference difference: the reference keeps an attachment with an empty name but skips resolving its reference, so the content becomes 0 bytes (observed). Decided: spec/decisions.md default rule. MOD-05 decides how an empty name is shown.

FMT-13.13 Duplicate names in one entry: keep both (decided: spec/decisions.md LD-29). This card owns the rule; FMT-11.23 points here. Larsal first resolves each `Binary` to a name and content (a `Ref` gives the pool item's content, or 0 bytes when dangling). It then adds them to the entry in document order. When the name is already in the entry, whatever form either value has (`Ref` or inline, FMT-13.9):

- If the new content is byte-for-byte equal to the content already stored under that name, nothing new is added. One attachment holds that content, so no data is lost.
- If it differs, both are kept. The earlier one keeps the name. The new one is renamed to 8 random lowercase hex digits, then `_`, then the original name (for example `d02af814_f.txt`), and a warning is logged. This is the same rename the reference uses (CRY-03.11 for the random digits). If the new name is also in the entry already, Larsal draws new digits. The reference does not check this (a 1 in 2^32 chance per rename) and would overwrite.

History: before LD-29 this card had two `Ref` values under one name keep only the later one.

Reference behavior, from the source and observed in 2.7.11:
- Two `Ref` values with different content: this differs. The reference keeps one attachment. Which pool item wins depends on hash table order, and that order changes from run to run. Observed in 2.7.11 with refs "0" and "1" on one demo vault: the later one in 184 of 200 runs, the earlier one in 16. Larsal keeps both.
- Two `Ref` values with equal content (the same key twice, or two items with the same bytes): as Larsal, one attachment.
- Inline then inline: as Larsal.
- `Ref` then inline with different content: as Larsal. The `Ref` name gets the pool content and the inline one is renamed.
- `Ref` then inline with equal content: this differs. The reference compares the inline content with the not-yet-resolved, empty `Ref` content, so it keeps a renamed copy with the same content (observed: `f.txt` and `1c4a88b5_f.txt`, both 3 bytes). Larsal adds nothing.
- Inline then `Ref`: this differs. The reference compares against the not-yet-resolved, empty `Ref` content, so it renames a 0-byte copy and then the pool content replaces the inline content under the original name. The inline content is lost. Larsal keeps it: the original name keeps the inline content, and the renamed attachment gets the pool content.
- Empty inline content, in either order (inline empty then `Ref`, or `Ref` then inline empty): this differs. The reference compares the empty inline content with the still-empty `Ref` content, finds them equal and does not rename. It keeps one attachment, which gets the pool content under the original name when references are resolved (source). Larsal's rule above gives two attachments: the original name and a renamed one, one of them 0 bytes and the other the pool content (unless the pool item is also empty, in which case the content is equal and Larsal keeps one).

The mixed-form differences touch only files that mix inline and `Ref` values under one name, which no current writer produces. The two-`Ref` case with different content always differs: the reference keeps one item, Larsal keeps both. No known writer puts one name twice in an entry: the reference keeps an entry's attachments in a map keyed by name. All of these are expected AT-A11 differences.

FMT-13.14 History entries resolve their references exactly like current entries, against the same pool.

FMT-13.15 Unused pool items, which no entry or history entry references, are dropped. They are not attached anywhere and are not written on the next save. The reference does the same and only logs it. Since such content is reachable from nowhere in the reference either, dropping it is not data loss under SD-06 (decided: spec/decisions.md default rule). An item referenced only by a history entry in a `History` block that is later dropped (FMT-11.31, LD-28) is not attached anywhere either, so it is not written on save. The reference does the same: it resolves that reference onto the dropped history entry, which never reaches the vault (source).

### Writing (version 4)

FMT-13.16 Building the pool on save. Walk the groups depth-first, starting at the root group. For each group:

1. Each entry of the group, in order.
2. Then the history entries of each of those entries: entry by entry in the same order, each entry's history oldest first.
3. Then each child group, in order.

Within one entry or history entry, take attachments in name order. The reference sorts names by UTF-16 code unit. For each attachment:

- If the same content is already in the pool, in the same dedupe namespace (FMT-13.17), use that item's index.
- Otherwise add a new item with flags `01` and give it the next index.

Write the items as field 3 records in index order, after field 2 and before the end field (FMT-09.4). Write each reference as `Ref` = the index in decimal, with no sign and no leading zeros. A vault with no attachments has no field 3 records.

FMT-13.17 Dedupe rule. Two attachments share one item when their content is byte-for-byte equal and they are in the same namespace. The namespace is the whole vault, except for entries inside a shared group (INT-08). A group is shared when it, or any group above it, has the custom data key stored encoded (name rule) as `4B 65 65 53 68 61 72 65 2F 52 65 66 65 72 65 6E 63 65` (FMT-14).

The reference keeps shared groups apart so that a shared group, exported on its own, cannot reveal anything through sizes. Its namespace for shared entries differs by version:

- Source: the namespace is the id of the entry's own group, whenever that group is shared or sits inside a shared group.
- Installed version: one namespace for the whole shared subtree. Observed: an item in a child group of a shared group reused the shared group's item, while an identical item outside got its own index. This differs in the installed version. Re-observed by Verify: a vault saved by the installed CLI from a document with the same bytes in a root entry, in an entry of a shared group S (two attachments), in an entry of S's child group T and in an entry of an unshared group has 2 pool items: the root and unshared entries share item 0, and S's two and T's one share item 1. Source, re-read by Verify: the version 4 writer keys each item by the id of the entry's own group (for a history item, its owner's group) whenever that group is shared or sits inside a shared group, and by the vault id otherwise.

A history entry uses its owner entry's group. The reference compares SHA-256 over a namespace string followed by the record bytes. That hash is never stored, so Larsal may compare content any way that is exact.

Larsal uses one namespace for the whole vault until INT-08 is built. With INT-08, Larsal follows the source rule above: an entry whose own group is shared, or sits inside a shared group, uses that group's id as its namespace; every other entry uses the whole-vault namespace (decided: spec/decisions.md default rule; the card gave no recommendation, so the reference behavior applies, and the source is the reference). The installed version's single namespace per shared subtree is kept here as a fact only.

FMT-13.18 Larsal writes only version 4 (FMT-16). A vault opened from version 3 is saved with its pool in the inner header and every `Ref` renumbered by FMT-13.16. No `Meta/Binaries` element is written. For reference only: the reference's version 3 save writes `Meta/Binaries` after `HistoryMaxSize`, with the same numbering and no flags byte in the dedupe, `Compressed="True"` plus gzip content when the vault's compression flag is on, and never `Protected`.

FMT-13.19 Round trip. Open, then save, then open again keeps every attachment's name and content on every entry and history entry. Indexes may change. The reference's own index stability test checks this, shared groups included.

### Limits

FMT-13.20 Limits. The numbers are in the one limits table in FMT-08.12 (decided: spec/decisions.md LD-22, which takes in the earlier L08-1 and L13-6). This rule sets no numbers. It says only how the attachment rows of that table apply. Check every declared length before allocating (FMT-09.6).

- A version 4 item counts toward total (its record bytes) and toward pool items. Its content counts toward one attachment and all attachments.
- Base64 attachment text in the document (version 3 `Meta/Binaries/Binary` items, and inline `Entry/Binary/Value`) is exempt from the text limit and bounded by the document limit instead (FMT-08.12). FMT-12 (Security notes) states the same exemption.
- Pool items: version 4 field 3 records and `Meta/Binaries/Binary` items count together. Items that a later item with the same key replaces still count. One more than the limit gives `TooLarge`.
- Attachments per entry: the attachments row of FMT-08.12, counted as FMT-11.48 says. FMT-11 owns the error.
- Decompressed content of a compressed document item (version 3 `Meta/Binaries/Binary` with `Compressed`, and the same element in a version 4 document, FMT-13.7). The base64 text of such an item is small compared with its content. For example, gzip of 1 GiB of zero bytes is 1,043,656 bytes, or 1,391,544 base64 characters, so the document limit does not bound it. Rules:
  - (a) Count the decompressed bytes of each item as they are produced. Return `TooLarge` (one attachment) the moment the count would pass the one attachment limit. Never allocate from the gzip ISIZE field or any other declared size.
  - (b) All attachments is the running total of all attachment content: the inner header pool items (version 4, content bytes), plus every attachment content decoded from the document (decompressed pool items, uncompressed pool items and inline `Value` content). Count each item when it is decoded. That includes items that a later item with the same key replaces (FMT-13.6), and items that turn out unused (FMT-13.15). Return `TooLarge` (all attachments) the moment the total would pass the limit. So a version 3 vault can never hold more attachment memory than a version 4 vault.
  - (c) Tests can lower both limits, like every FMT-08.12 limit.
  - The reference has no such limit. Its compressed-item routine reads the whole gunzip output into a buffer that grows without bound (source). A vault over Larsal's limits that the reference opens is an expected AT-A11 difference. This rule closes AT-A06 inside a valid document.

The reference has no format limit beyond the 4-byte field length (4 GiB − 1, flags byte included). Its desktop app asks for confirmation before adding a file larger than 5 MiB (MOD-05). Observed: a 512 MiB item opened in the installed reference.

## Edge cases and errors

| Case | Result |
|---|---|
| `Ref="5"` with 1 item; `Ref="abc"`; `Ref="-1"`; `Ref=""` | The attachment exists with 0 bytes, plus a warning (FMT-13.11) |
| `Ref="01"` or `Ref=" 1"` with 2 items | No match: 0 bytes, plus a warning |
| `Binary` with `Key` but no `Value` | `Corrupt` |
| One `Binary` with `Key`, `Value Ref`, then a second `Key` | One attachment: the last `Key` with the pool content. The reference gives two (FMT-13.10). |
| One `Binary` with an inline `Value` and a `Ref` `Value`, in either order | The `Ref` gives the content; a protected inline `Value` still takes its keystream bytes (FMT-13.10) |
| `<Key></Key>` with `Ref="0"` | Content resolved, name empty (FMT-13.12) |
| Two `a.txt` in one entry with refs 0 and 1, different content | `a.txt` = item 0, and a renamed `xxxxxxxx_a.txt` = item 1, plus a warning. The reference keeps one, picked by hash order (FMT-13.13, LD-29) |
| Two `a.txt` in one entry, both `Ref="0"` | One `a.txt` (FMT-13.13) |
| `f.txt` `Ref` to "AAA", then inline `f.txt` "AAA" | Larsal: one `f.txt` = "AAA". The reference: `f.txt` plus a renamed copy, both "AAA" (FMT-13.13) |
| Two inline `f.txt` with different content | Both kept, the second renamed `xxxxxxxx_f.txt` (8 lowercase hex digits), plus a warning (FMT-13.13) |
| Two inline `f.txt` with equal content | One attachment (FMT-13.13) |
| Inline `f.txt` "AAA", then `f.txt` `Ref` to "BBB" | Larsal: `f.txt` = "AAA", renamed one = "BBB". The reference: `f.txt` = "BBB", renamed one 0 bytes (FMT-13.13) |
| `<Value Ref="0"/>` before `<Key>a.txt</Key>` | Resolved: `a.txt` gets item 0. The reference gives 0 bytes and reports item 0 unused (FMT-13.8). |
| `<Value Ref="0" Protected="True">QUJDRA==</Value>` | `Ref` wins; text ignored; no keystream bytes (FMT-13.9) |
| Inline `Value` with base64 "aW5saW5lIQ==" in a version 4 file | Content "inline!" (7 bytes) |
| Inline `Value Protected="True"` | XOR-decoded in document order (FMT-09.13) |
| Version 4 pool item with flags `00` or `FE` | Loaded. Written back with `01`. |
| Version 4 pool item record `03 01 00 00 00 01` | Empty attachment |
| Version 3 `<Binary ID="0" Compressed="True">` holding text that is not gzip | `Corrupt` |
| Version 3 compressed item whose gzip data lacks its 8-byte trailer | `Corrupt`. The reference opens it and gives 0 bytes (FMT-13.5) |
| Version 3 compressed item with bytes after the end of its gzip member | `Corrupt` (FMT-13.5, FMT-08.7). The reference ignores the extra bytes and opens it. |
| Version 3 `<Binary Compressed="True">` with no `ID` | Key is the empty string; no `Ref` reaches it; dropped as unused (FMT-13.6) |
| Version 3 `<Binary ID="2" Compressed="True"/>` | Empty content |
| Version 3 `Compressed="1"` holding gzip of empty input | Empty content |
| Version 3 item both protected and compressed | base64-decode, then XOR, then gunzip (observed) |
| Items no entry uses | Dropped on save |
| Version 3 compressed item whose gzip inflates past the one attachment limit, or several items whose total passes the all attachments limit (FMT-08.12) | `TooLarge`, stopped while inflating, memory under the limit plus a small buffer (FMT-13.20). The reference opens it with no limit. |
| Inline empty `f.txt`, then `f.txt` `Ref` to "BBB" (or the reverse order) | Larsal: `f.txt` and a renamed one, one 0 bytes and one "BBB". The reference: one `f.txt` = "BBB" (FMT-13.13) |

## Security notes

- Attachments are secrets (plan/security.md "What we protect"). Content lives in `SecretBytes`, decoded buffers are wiped, and content never goes to logs or error text (AT-C06). Warnings list entry titles or ids, never content.
- Hostile pools (AT-A08, AT-A10): huge declared lengths, millions of tiny items, references to keys that do not exist, duplicate names, unknown flags. Each must give the result in this card with no panic and no allocation beyond the limits.
- Decompression bombs inside the document (AT-A06): a small gzip member in a version 3 pool item can inflate to many GB. Never inflate without counting, and never trust ISIZE (FMT-13.20).
- Dedupe happens only inside the encrypted payload, so it reveals nothing outside. Shared groups get their own namespace so that a separately exported share cannot leak through item sizes (INT-08).
- Never show partly resolved attachments from a file that fails a later check (FMT-08.11).
- SD-06: names and content always survive a round trip (FMT-13.19). The only content dropped is content no entry references (FMT-13.15).

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| T13-01 (FMT-13.2) | Record `03 12 00 00 00 01 68 65 6C 6C 6F 20 61 74 74 61 63 68 6D 65 6E 74 0A` | Parse | Item 0, flags `01`, content "hello attachment\n" (17 bytes) |
| T13-02 (FMT-13.2, FMT-09.5) | Inner header records: field 3 "A", field 9 (unknown), field 3 "B" | Parse | Pool key "0" = A, "1" = B |
| T13-03 (FMT-13.3) | Items with flags `00` and `FE` | Open, then Larsal saves | Both load. The saved records have flags `01`. |
| T13-04 (FMT-13.4) | Record `03 01 00 00 00 01`; separately record `03 00 00 00 00` | Open | First: empty attachment. Second: `Corrupt`. |
| T13-05 (FMT-13.5) | Version 3 item `<Binary ID="0" Compressed="True">H4sIAAAAAAAAEyszVkjOzy0oSi0uTk1RSEksSQQAfyMrRBIAAAA=</Binary>`, written by the reference | Decode | Content "v3 compressed data" (18 bytes). The gzip header is `1F 8B 08 00 00 00 00 00 00 13`. |
| T13-06 (FMT-13.5) | Version 3 items `<Binary ID="2" Compressed="True"/>` and `Compressed="1"` holding gzip of empty input | Decode | Both empty |
| T13-07 (FMT-13.5) | Version 3 compressed item whose text is base64 of "not gzip at all!!" | Open | `Corrupt` |
| T13-08 (FMT-13.5, FMT-09.16) | Version 3, stream key S3 (Salsa20, FMT-09 test vectors). Item `<Binary ID="0" Compressed="True" Protected="True">5jW9KWKDiiw8kQzmJ7/bPgk42i7hKKLJcdVn+GPrnR1/kWW2+4S/MA==</Binary>`, then an entry Password `<Value Protected="True">Exx8dFpyw1Y=</Value>` | Open | Base64-decoding gives 40 bytes. XOR with keystream bytes 0–39 gives the gzip member `1F 8B 08 00 00 00 00 00 00 13 2B 28 CA 2F 49 4D 2E 49 4D D1 4E CE CF 2D 28 4A 2D 2E 4E 4D 01 00 62 B4 14 C0 14 00 00 00` (as in FMT-08.9). Gunzip gives "protected+compressed" (20 bytes). The password uses bytes 40–47 and decodes to "Password". |
| T13-09 (FMT-13.6) | Version 3 items with ID "z9" and an entry `Ref="z9"` | Open | Resolved |
| T13-10 (FMT-13.6) | Version 3 items with ID "0" twice ("first", then "second") | Open | Ref "0" gives "second" |
| T13-11 (FMT-13.7) | Version 4: inner item 0 = "zero"; document `Meta/Binaries` with ID "0" = "from-meta" and ID "7" = "seven"; refs "0" and "7" | Open | "from-meta" (9 bytes) and "seven" (5 bytes) |
| T13-12 (FMT-13.8, FMT-13.11) | 1 item; refs "5", "abc", "-1", "" | Open | Four 0-byte attachments with their names, plus a warning naming the entry |
| T13-13 (FMT-13.8) | 2 items; refs "01" and " 1" | Open | 0-byte attachments, plus a warning (no number parsing) |
| T13-14 (FMT-13.9) | Version 4 entry `Binary` with `Value` text "aW5saW5lIQ==" and no Ref | Open, then save | Content "inline!". After save it is a pool item with a numeric Ref. |
| T13-15 (FMT-13.10) | Entry `<Binary><Key>a.txt</Key></Binary>` | Open | `Corrupt` |
| T13-16 (FMT-13.12) | `<Key></Key>` with `Ref="0"`, item 0 = "zero" | Open | Name empty, content "zero" (the reference gives 0 bytes) |
| T13-17 (FMT-13.13) | Version 4. Vault A, one entry: "a.txt" Ref 0 ("zero"), then "a.txt" Ref 1 ("one"). Vault B, one entry: "a.txt" Ref 0 ("zero") twice | Open | A: two attachments, "a.txt" = "zero" and a name matching `^[0-9a-f]{8}_a\.txt$` = "one", plus a warning; the same on every run apart from the random digits (LD-29). B: one "a.txt" = "zero", no warning. The installed reference CLI `attachment-export`, run 200 times on vault A, gave one "a.txt": "one" 184 times and "zero" 16 times (observed): expected AT-A11 difference. |
| T13-18 (FMT-13.14, FMT-13.16) | Root group: entry E1 (f.txt "e1cur"; history: f.txt "e1old"), entry E2 (f.txt "e2cur"; history: f.txt "e2old"). Child group G: entry E3 (f.txt "e3cur", zz.txt "y"; history h1 f.txt "e3old", h2 f.txt "e3cur") | Larsal saves | Field 3 records in order: e1cur(0), e2cur(1), e1old(2), e2old(3), e3cur(4), y(5), e3old(6). h2's f.txt has Ref "4". The installed reference produced exactly this order. |
| T13-19 (FMT-13.1, FMT-13.16, FMT-13.15, FMT-13.17) | Demo vault: pool [0] "hello attachment\n", [1] the same again, [2] empty, [3] "unused item", [4] flags `00` "second file". Root entry Alpha: b.txt→1, a.txt→4, empty.bin→2; Alpha history a.txt→0. Child group entry Beta: x.txt→0, new.txt = "second file" | Larsal saves | Pool: [0] `01` "second file", [1] `01` "hello attachment\n", [2] `01` empty. Alpha: a.txt 0, b.txt 1, empty.bin 2. Alpha history: a.txt 1. Beta: new.txt 0, x.txt 1. "unused item" is gone. The installed reference wrote exactly this. |
| T13-20 (FMT-13.16) | Vault with no attachments | Save | No field 3 records. The inner header is fields 1, 2 and 0 only. |
| T13-21 (FMT-13.17) | Shared group S (key `4B 65 65 53 68 61 72 65 2F 52 65 66 65 72 65 6E 63 65`, stored encoded (name rule), in its custom data) with child group T. Root entry: "same". Entry in S: two attachments "same". Entry in T: "same". | Reference save (installed version) | Root "same" = item 0; S's two = one item; T's = the same item as S's (installed version). Source rule: T gets its own item (source re-read and installed result re-observed by Verify, FMT-13.17). Larsal until INT-08: all four share item 0. Larsal with INT-08 (source rule, FMT-13.17): root "same" = one item, S's two share a second item, T's gets a third. |
| T13-22 (FMT-13.18) | The version 3 vault from T13-09 | Larsal saves | Version 4 output. Pool in the inner header, refs renumbered from "0", no `Meta/Binaries`. Content unchanged. |
| T13-23 (FMT-13.19) | Every demo vault in `testdata/` with attachments | Open, save, open | Same names and content per entry and history entry |
| T13-24 (FMT-13.20) | Inner header with 1,000,001 empty field 3 records (about 6 MB decompressed) | Open | `TooLarge` naming pool items, with memory under the limit |
| T13-25 (FMT-13.20) | Field 3 declaring length 2 GiB | Open | `TooLarge` naming total, before any allocation (FMT-09.6) |
| T13-26 (FMT-13.8) | Version 4: item 0 = "zero"; entry `<Binary><Value Ref="0"/><Key>a.txt</Key></Binary>` | Open | `a.txt` = "zero", no warning. The installed reference showed `a.txt (0 B)` and logged item 0 as unused (observed). |
| T13-27 (FMT-13.13) | Version 4 entry, pool item 1 = "BBB". Case A: inline `f.txt` `QUFB` ("AAA"), then `f.txt` `Ref="1"`. Case B: `f.txt` `Ref="0"` (item 0 = "AAA"), then inline `f.txt` `QkJC` ("BBB"). Case C: inline `f.txt` `QUFB` twice. Case D: `f.txt` `Ref="0"` (item 0 = "AAA"), then inline `f.txt` `QUFB` ("AAA") | Open | A: `f.txt` = "AAA", and a name matching `^[0-9a-f]{8}_f\.txt$` = "BBB", plus a warning. B: `f.txt` = "AAA", renamed one = "BBB". C and D: one `f.txt` = "AAA", no warning. Observed in the installed reference: A gave `f.txt` = "BBB" and a 0-byte renamed copy; B and C as Larsal; D gave `f.txt` and a renamed copy, both "AAA" (3 B). |
| T13-28 (FMT-13.9) | Version 4: item 0 = "AAA"; entry `<Binary><Key>f.txt</Key><Value Ref="0" Protected="True">QUJDRA==</Value></Binary>` before a protected Password | Open | `f.txt` = "AAA". The password decodes from keystream byte 0 (see FMT-09 T09-36). |
| T13-29 (FMT-13.5) | Version 3.0 demo vault: compressed item `t.txt` whose gzip data is complete except the 8-byte trailer | Open | `Corrupt`. The installed reference opened it and showed `t.txt (0 B)` (observed). |
| T13-30 (FMT-13.6, FMT-13.11) | Version 3: `<Binary Compressed="False">QUJD</Binary>` (no `ID`); entry `f.txt` `Ref=""` | Open, then save | `f.txt` has 0 bytes plus a warning. The ID-less item is not attached anywhere and is not written on save. |
| T13-31 (FMT-13.20) | Test limits: text 1 MiB, document 4 MiB. Version 3 item of 2 MiB (base64 about 2.7 MiB); separately a version 4 inline `Value` of the same size | Open | Both open (exempt from the text limit). A version 3 item whose base64 text is over the document limit: `TooLarge`. See FMT-08 T08-32. |
| T13-32 (FMT-13.20, FMT-13.5) | Test limits: one attachment 64 MiB, all attachments 64 MiB. Version 3 demo vault with one item `Compressed="True"` whose content is the gzip of 1 GiB of zero bytes (gzip 1,043,656 bytes, base64 1,391,544 characters), referenced by one entry | Open | `TooLarge` naming one attachment, raised while inflating. Peak memory stays under 64 MiB plus 8 MiB. The installed reference has no limit (expected AT-A11 difference). |
| T13-33 (FMT-13.20) | Test limits: one attachment 64 MiB, all attachments 64 MiB. Version 3 demo vault with three compressed items, each the gzip of 40 MiB of zero bytes (gzip 40,789 bytes, base64 54,388 characters each), IDs "0", "1", "2" | Open | `TooLarge` naming all attachments, while inflating the second item (the running total would pass 64 MiB). Each item alone is under the one attachment limit. The same vault with all three items using ID "0" (each replacing the last): also `TooLarge`, because replaced items still count. |
| T13-34 (FMT-13.13) | Version 4 entry, pool item 1 = "BBB". Case E: inline `f.txt` with empty text, then `f.txt` `Ref="1"`. Case F: `f.txt` `Ref="1"`, then inline `f.txt` with empty text | Open | E: `f.txt` = 0 bytes, and a renamed one (`^[0-9a-f]{8}_f\.txt$`) = "BBB", plus a warning. F: `f.txt` = "BBB", and a renamed one = 0 bytes, plus a warning. The reference (source): one `f.txt` = "BBB" in both cases, no rename. |
| T13-35 (FMT-13.5) | Version 3.1 demo vault. Item `<Binary ID="0" Compressed="True">H4sIAAAAAAAAE0tMSgYAwkEkNQMAAADerb7v</Binary>`: base64 of gzip("abc") (23 bytes, `1F 8B 08 00 00 00 00 00 00 13 4B 4C 4A 06 00 C2 41 24 35 03 00 00 00`) followed by 4 junk bytes `DE AD BE EF`. Entry `t.txt` `Ref="0"` | Open | `Corrupt`. The installed reference CLI 2.7.11 opened it and exported `t.txt` = "abc" (observed): expected AT-A11 difference. |
| T13-36 (FMT-13.10, FMT-13.8) | Version 4 demo vault, stream key S4, pool item 0 = "AAA". One entry `Binary` per case. G: `<Key>a.txt</Key><Value Ref="0"/><Key>b.txt</Key>`. H: `<Key>a.txt</Key><Value>QkJC</Value><Value Ref="0"/>`. I: `<Key>a.txt</Key><Value Ref="0"/><Value>QkJC</Value>`. J: `<Key>a.txt</Key><Value>QUFB</Value><Value>QkJC</Value>`. K: `<Key>a.txt</Key><Key>b.txt</Key><Value>QUJD</Value>` | Open | G: one attachment `b.txt` = "AAA". H and I: `a.txt` = "AAA". J: `a.txt` = "BBB"; pool item 0 is unused and dropped (FMT-13.15). K: one attachment `b.txt` = "ABC". Observed in the installed reference CLI 2.7.11: H, I, J and K the same as Larsal (J logged item 0 unused); G gave `a.txt` = "AAA" and `b.txt` with 0 bytes (expected AT-A11 difference). |
| T13-37 (FMT-13.10, FMT-09.13) | Version 4 demo vault, stream key S4, pool item 0 = "AAA". Entry: `<Binary><Key>a.txt</Key><Value Protected="True">1LHm</Value><Value Ref="0"/></Binary>`, then Password `<Value Protected="True">EX3tMJyG</Value>` | Open | `a.txt` = "AAA". The losing inline value decodes "XYZ" from keystream bytes 0–2, and Password = "pw-one" from bytes 3–8. The installed reference CLI 2.7.11 gave the same (observed). |
| T13-38 (FMT-13.15, LD-28) | Version 4 demo vault, pool [0] "AAA", [1] "BBB". One entry Alpha with a.txt→1 and two `History` blocks: the first holds one history item with h.txt→0, the second one history item with h.txt→1. Nothing else references item 0 | Open, then save | After open: Alpha has a.txt = "BBB" and one history item (from the last block) with h.txt = "BBB"; item 0 is attached nowhere. Saved file: the pool holds one item, `01` "BBB", referenced by a.txt and h.txt; "AAA" is not in the file. The reference resolves h.txt→0 onto the dropped history item, which never reaches the vault, so it does not write "AAA" either (source reading, FMT-13.15) |

## How this was learned

- Read in the reference source: the version 4 reader's inner header part (binary records and their keys), the version 4 save routine's attachment-writing part (order, flags byte, dedupe hash and the shared-group namespace), the XML reader's pool and entry-binary parts (references, inline values, duplicate names, the final step that resolves references and reports unmapped and unused keys), and the XML writer's version 3 pool writer and entry binary writer.
- Read the attachment container (name-sorted map), the group walk that lists entries with their history, the shared-group check, and the desktop app's large-file confirmation.
- Read the reference tests for attachment index stability, duplicate attachments and XML entry attachments.
- Ran experiments with the installed reference CLI 2.7.11 on demo vaults built in `/tmp/spec-fmt08-09-13/` with the demo password "demo-pass-1": the T13-19 and T13-18 vaults re-saved through `attachment-import`, then decoded; every reference variant in the edge case table; flags bytes; empty items; `Meta/Binaries` inside version 4; version 3 pools with compressed, protected, empty, non-numeric and broken items; shared-group namespacing.
- Round 2: read the entry attachment parser and the step that resolves references again, then opened demo vaults with the installed CLI 2.7.11 for the mixed duplicate-name cases (T13-27) and a `Ref` value holding protected text (T13-28).
- Round 3: opened two more demo vaults in `/tmp/spec-fmt08-09-13/work/exp3/` with the installed CLI 2.7.11: a `Ref` followed by an inline value with equal content under one name (T13-27 case D), and two `Ref` values under one name, exported 200 times to see the winner change with hash order (T13-17).
- Round 4: read the document reader's compressed-item routine (it reads the whole gunzip output with no limit), its pool parser (children not named `Binary` are skipped) and the entry attachment parser (it renames only when the stored and new content differ, and a `Ref` value's content is empty until the end of the document). Computed the gzip and base64 sizes for T13-32 and T13-33 with python3 zlib (window bits 31, level 6, memory level 8).
- Round 5: read the entry attachment parser again (it overwrites the name on each `Key` and the content on each inline `Value`, pairs a `Ref` with the name read so far, and resolves `Ref` values only at the end of the document). Opened demo vaults in `/tmp/spec-fmt08-09-13/work/exp4/` with the installed CLI 2.7.11 (demo password "demo-pass-1"): repeated `Key` and `Value` inside one `Binary` (T13-36, T13-37) and a version 3.1 compressed item with junk after its gzip member (T13-35).
- Round 6 (cross-check fixes): moved every attachment limit number into the one FMT-08.12 table (L08-1, since decided as spec/decisions.md LD-22). FMT-13.20 now says only how those rows apply.
- Sprint 0 close-out: wrote in the lead rulings (spec/decisions.md): LD-02 (FMT-13.5), LD-22 (FMT-13.20), LD-29 (FMT-13.13: two `Ref` values with different content now keep both), and the default rule for L13-1, L13-2, L13-4, L13-5 and the `Value`-before-`Key` choice. Read the entry attachment parser again for the rename (one random draw, no check that the new name is free) and the entry routine for dropped `History` blocks.
- Computed the vectors with python3 (base64, gzip, zlib, struct) and libsodium (Salsa20 keystream for T13-08).
- Sprint 1 close-out: added T13-38 for the LD-28 clause of FMT-13.15 (an item referenced only from a dropped `History` block is not written), from the source reading already recorded above.
