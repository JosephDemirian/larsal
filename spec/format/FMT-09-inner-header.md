# FMT-09 Inner header and the protected-field stream

Status: reviewed
Epics: E3-S5
Parity rows: SF-07, SF-08, SF-09, SF-12

## What it does

Protected values, such as passwords, are encrypted a second time inside the already-encrypted document. Each one is XORed with bytes from a keystream, then base64-encoded. One keystream runs across the whole document, and values take bytes from it in document order.

In version 4 the keystream algorithm and its key are stored in the inner header. The inner header is a short list of fields at the start of the decompressed payload (FMT-08.1). It also carries the attachment pool (FMT-13).

In version 3 there is no inner header. The algorithm id and the key are outer header fields 10 and 8 (FMT-02).

This card covers:

- the inner header bytes,
- how the keystream is made from the stream key,
- which algorithm ids exist and which are accepted,
- the exact order in which protected values use the keystream,
- how values are encoded before and after the XOR,
- which values the reference writes as protected.

## Inputs and outputs

Reading, version 4: the decompressed payload U (FMT-08). Output: the stream algorithm, the stream key (secret), the ordered list of pool items (handed to FMT-13), and the offset where the document starts. While the document is read: each protected value as a secret string or secret bytes, plus its protected flag.

Reading, version 3: header fields 8 and 10 (FMT-02), and the document.

Writing, version 4: a fresh 64-byte stream key (CRY-03), the pool items (FMT-13), and the values to protect. Output: the inner header bytes, and the protected values as base64 text in document order.

| Item | Size |
|---|---|
| Inner header field id | 1 byte |
| Inner header field length | 4 bytes, little-endian unsigned |
| Stream algorithm id value | exactly 4 bytes, little-endian unsigned |
| Stream key | 1 byte or more. App writes 64 bytes in version 4. The reference writes 32 bytes in version 3. |
| ChaCha20 key and nonce | 32 bytes and 12 bytes, from SHA-512 |
| Salsa20 key and nonce | 32 bytes from SHA-256, plus a fixed 8-byte nonce |

## Rules

### Inner header (version 4)

FMT-09.1 Position. In version 4 the inner header starts at byte 0 of the decompressed payload U (FMT-08.1). The document starts at the first byte after the end field. Version 3 has no inner header: the stream key is outer header field 8, and the stream algorithm id is outer header field 10 (4 bytes, little-endian unsigned). When field 10 is absent, the algorithm is Salsa20 (FMT-02.20).

FMT-09.2 Field format. Each field is a 1-byte id, a 4-byte little-endian unsigned length L, then L data bytes. Fields repeat until a field with id 0 (end) has been read, data included.

FMT-09.3 Field ids.

| Id | Name | Data |
|---|---|---|
| 0 | End | Ignored on read; App writes length 0 |
| 1 | Stream algorithm id | 4 bytes, little-endian unsigned (FMT-09.8) |
| 2 | Stream key | the key bytes |
| 3 | Pool item | 1 flags byte + content (FMT-13) |

Any other id: skip its data, ignore it, and do not write it back. The reference does the same.

FMT-09.4 Order written. Field 1, then field 2, then every field 3 in pool index order (FMT-13.16), then field 0. Exact bytes:

- Field 1: `01 04 00 00 00 03 00 00 00`
- Field 2: `02 40 00 00 00` followed by 64 fresh random bytes
- Field 0: `00 00 00 00 00`

FMT-09.5 Order accepted. Fields may come in any order. If field 1 or field 2 appears more than once, the last one wins (the reference does the same). Every copy of field 1 is checked as soon as it is read: exactly 4 bytes (FMT-09.6) and a known, accepted id (FMT-09.8). A copy that fails either check fails the open at once (`Corrupt` for the size, `Unsupported` for the id), even when a valid field 1 follows. So "last one wins" picks only among copies that passed. The reference does the same: it checks each field 1 when it reads it and stops at the first error (source; observed in 2.7.11: field 1 = 1, then field 1 = 3, failed on the stream id, and a 2-byte field 1, then a valid one, failed on the stream id size). This differs on purpose from FMT-02, which rejects repeated outer header fields to avoid parser differences: the inner header lies inside the encrypted, MAC-checked payload (FMT-06), so only someone holding the key can craft it, and taking the last one gives the same result as the reference, so the two apps never decode the same file differently. Field 3 records are numbered by their position among field 3 records only; other fields do not count (FMT-13.2).

FMT-09.6 Reading one field, and its errors. Each field is read in these steps, in this order:

1. Read the 1-byte id. If U has no byte left, the end field was never reached: `Corrupt`.
2. Read the 4-byte length L. If fewer than 4 bytes are left: `Corrupt`.
3. Limit check. Let s be the offset in U of the field's id byte. If s + 5 + L is more than the total limit of FMT-08.12, the result is `TooLarge`. Nothing is allocated or read for the data. The bound is the total limit, not the document limit, because inner header bytes count only toward total (FMT-08.12). This is the same check FMT-02.25 makes for the outer header, applied to U: the field could not end inside the largest payload App reads.
4. Truncation check. If fewer than L bytes are left in U: `Corrupt`. With a streaming decompressor this shows up when U ends before the data is complete. The limit check (step 3) always runs before this check, as in FMT-02.25, so a length that is both over the limit and cut short gives `TooLarge`.
5. Checks on the data that was read. Field 1 data that is not exactly 4 bytes: `Corrupt`. Field 3 with length 0: `Corrupt` (the reference also refuses it).

Reference: it reads the length as an unsigned 32-bit number and sets no limit. When fewer bytes are present than declared, it reports an inner header data length mismatch (source; observed with length `F0 FF FF FF`, see T09-25).

FMT-09.7 Required fields. In version 4, field 1 and a non-empty field 2 are required. If field 1 is missing, field 2 is missing, or field 2 has length 0, the result is `Corrupt`. With repeated fields this applies to the one that wins (FMT-09.5), so field 2 twice with the last one of length 0 is `Corrupt`. Reference difference:

- Field 1 missing: the reference fails, with an empty error text.
- Field 2 missing, or present with length 0 (`02 00 00 00 00`): the reference silently uses an empty key, which makes the ChaCha20 input SHA-512 of nothing (`CF 83 E1 35 …`). It never checks the field 2 length in version 4 (source). Observed in 2.7.11: a demo vault with field 2 of length 0 and its Password encrypted with that keystream opened and showed the password.

App is stricter in version 4: there is no usable field stream without a key. This version 4 rule is the card's own choice and stands under the default rule of spec/decisions.md; LD-23 does not cover it. In version 3 the key is outer header field 8: a missing field 8, or one of length 0, is `Corrupt` at header parse, before key derivation (decided: spec/decisions.md LD-23; FMT-02.18, FMT-02.23). The reference refuses it too, with its missing-header-fields error (FMT-17, field table).

### Stream algorithms

FMT-09.8 Algorithm ids.

| Value | Meaning | Version 4 read | Version 4 write | Version 3 read |
|---|---|---|---|---|
| 1 | An RC4-like stream | `Unsupported` | never | `Unsupported` |
| 2 | Salsa20 (FMT-09.10) | accepted | never | accepted |
| 3 | ChaCha20 (FMT-09.9) | accepted | always | `Unsupported` |
| absent | none | `Corrupt` (FMT-09.7) | never | Salsa20 (FMT-02.20) |
| any other | none | `Unsupported` | never | `Unsupported` |

Version 3 with id 3 is `Unsupported`, the same as FMT-02.20, CRY-01.17 and FMT-17.8 (decided: spec/decisions.md LD-10). Reference difference: the reference accepts id 3 in a version 3 header but still decodes with Salsa20. A demo vault with id 3 and Salsa20-encrypted values opens correctly in the installed reference, while ChaCha20-encrypted values come out garbled with no error (observed). App rejects the file rather than show wrong values.

FMT-09.9 ChaCha20 keystream. H = SHA-512(stream key). The key is H bytes 0 to 31 and the nonce is H bytes 32 to 43. The cipher is IETF ChaCha20 (RFC 8439 block function, 32-bit block counter) with the counter starting at 0. The keystream is block 0, block 1, block 2, and so on, 64 bytes each.

FMT-09.10 Salsa20 keystream. The key is SHA-256(stream key). The nonce is fixed: `E8 30 09 4B 97 20 5D 2A`. The cipher is Salsa20/20 with its 64-bit block counter starting at 0.

### Consumption order

FMT-09.11 One continuous keystream per document. Reading or writing a document starts at keystream byte 0. Each protected value with decoded length n takes the next n keystream bytes. Bytes left over in a 64-byte block carry on to the next value. Nothing resets per value, entry, group or history entry. Reading and writing use the same rule, so the writer must take bytes in exactly the order the reader will meet the values.

FMT-09.12 What marks a value as protected. An element is protected when its `Protected` attribute is `true` in any ASCII case, or `1`. Other values, such as `yes`, `False` or empty, mean not protected. The attribute only matters on elements whose content is text. On an element that has child elements it is ignored.

FMT-09.13 The order is document order. Protected elements take keystream bytes in the order of their start tags in the document. This includes:

- elements in `Meta`, which come before `Root` (for example a protected `DatabaseName`),
- version 3 pool items in `Meta/Binaries` (FMT-13.5), which come before every entry,
- entry `String/Value` elements,
- inline entry `Binary/Value` elements (FMT-13.9),
- every element of a history entry. A history entry sits inside its parent entry, after the parent's own fields, so its values follow the parent's values.
- the history entries of every `History` block of an entry, including a block that is later dropped because only the last block's items are kept (FMT-11.31; decided: spec/decisions.md LD-28). The reference reads every block in full before it keeps the last one, so the protected values of a dropped block take their keystream bytes (source; observed in 2.7.11, T09-44). App must take them too, or every later value decodes wrongly.
- any other known element that the reader decodes as a value (FMT-12.22, FMT-10.11). Observed: a protected `Tags` element and a protected `DatabaseName` element each took keystream bytes in the reference.

An element whose text is empty, or decodes to zero bytes (for example only whitespace), takes nothing. Its value is the empty string or empty bytes. A `Binary/Value` with a `Ref` attribute takes nothing, even when it also carries `Protected` and holds text: its text is ignored (FMT-13.9). Unknown elements take nothing (FMT-09.14).

FMT-09.14 Unknown elements. An element App keeps as unknown (FMT-10.20, FMT-11.45) takes no keystream bytes, even when it carries `Protected` and holds text. Nothing inside it takes any either, even a descendant whose name matches a known element (for example `<FooBar><Value Protected="True">…</Value></FooBar>`): the reference skips the whole subtree. The known set is exactly the reference's (FMT-10.11). Decided: spec/decisions.md LD-24. FMT-10.20 and FMT-12.22 name this rule as the only one for protected values in unknown elements. It matches the reference, which skips unknown elements without taking keystream bytes (confirmed in the source, observed in 2.7.11).

- Read: App keeps the element's raw text exactly as read and never decrypts it.
- Write: App never takes keystream bytes for a kept unknown element. It writes the element back with its raw text unchanged and its attributes as read, which is the only write FMT-10.20 allows (LD-24). Re-encrypting the value with the new stream at its position is never allowed: the reference takes no bytes for the element, so it would decode every later protected value, passwords included, wrongly.
- A file from another writer that did take keystream bytes for an unknown element decodes every later protected value wrongly, in App exactly as in the reference (observed in the reference). That file is already unreadable in the reference, so App does not try to repair it.


### Encoding

FMT-09.15 Decoding a protected string:

1. Base64-decode the element text (FMT-12). Whitespace inside the text is ignored; observed in the reference with spaces and line breaks.
2. XOR with the next keystream bytes.
3. Decode the bytes as UTF-8, exactly as follows. This is the reference's rule.
   - Leading byte order mark: if the bytes start with `EF BB BF`, drop those three bytes first, once. A later `EF BB BF`, including a second one right after the first, is decoded as U+FEFF and kept (decided: spec/decisions.md LD-25).
   - Then go from the first byte to the last. At each position, if the bytes there form a well-formed UTF-8 sequence as defined in RFC 3629 (no overlong forms, no surrogates U+D800 to U+DFFF, nothing above U+10FFFF), output its character and move past the sequence. Noncharacters such as U+FFFE are well-formed and kept.
   - Otherwise output one U+FFFD and move on by one byte only. So every byte that is not part of a well-formed sequence gives its own U+FFFD. A cut-off or broken sequence of n bytes gives n U+FFFD.
   - This is not the "maximal subpart" practice in chapter 3 of the Unicode standard, which Rust's standard lossy conversion and Python's "replace" mode follow. Those give one U+FFFD for `E2 82 41`, where the reference gives two. App must use the per-byte rule.
   - A `00` byte becomes U+0000 and is kept. App never cuts the value at a `00` byte.

The same decoding applies to every protected value in the text group of FMT-12.22 (protected `Meta` text, booleans, integers, times and colors), before the value is parsed by its type. FMT-12.22 points here for the replacement rule.

The result goes straight into a secret string with the field's protected flag set.

Evidence for the replacement rule and the byte order mark: observed in 2.7.11 with a demo vault (T09-41, T09-42). The CLI's `show` printed the values as above, and after the reference re-saved the vault, the stored values were the replaced bytes, with the leading `EF BB BF` gone. The source builds on toolkit version 6. Its UTF-8 converter is expected to follow the same rule, because the only change known between versions 5 and 6 is the `00` handling described next. That was not run here, since no version 6 toolkit is on this Mac: check with Verify.

Byte order mark (decided: spec/decisions.md LD-25). The rule above matches the reference, so the two apps never show different values from the same file. The reference's own round trip loses a leading U+FEFF: it writes the value's bytes, then drops them on the next read. App avoids that loss on write (FMT-09.17). History: the option not chosen was to keep a leading `EF BB BF` as U+FEFF on read.

Reference difference for `00` bytes: the installed reference (2.7.11, built on toolkit version 5.15) cuts the value off at the first `00` byte. It still uses up all of the value's keystream bytes, so later values decode correctly (observed). This differs in installed version. The source builds only on toolkit version 6: its build file requires 6.2.4 or later, and its document reader uses types that exist only in version 6. In version 6 the UTF-8 conversion of a byte array keeps `00` bytes as U+0000, where version 5 stopped at the first `00` byte. So the source keeps U+0000 and the rest of the value, the same as App. AT-A11 differs only from the installed version.

FMT-09.16 Decoding protected binary content (inline attachment values, and version 3 pool items): base64-decode, then XOR, then gunzip if the item is compressed (FMT-13.5). The XOR comes before the gunzip.

FMT-09.17 Encoding on write:

1. Take the value's UTF-8 bytes, with no terminator and no byte order mark added. If the value itself starts with U+FEFF (so its bytes start with `EF BB BF`), put one extra `EF BB BF` in front. Both App and the reference drop exactly one leading `EF BB BF` on read (FMT-09.15), so both read the value back unchanged (observed in 2.7.11: stored bytes `EF BB BF EF BB BF 41` showed as U+FEFF "A"). The extra bytes are part of the value's bytes for the XOR and use keystream like any other byte.
2. XOR them with the next keystream bytes.
3. Write the result in standard base64 (RFC 4648 section 4, `=` padding, no line breaks) as the element text, with the attribute written exactly as `Protected="True"`.

An empty value still gets the attribute but has no text (`<Value Protected="True"/>`) and takes no keystream bytes. Protected values are XORed as their exact bytes. The step in FMT-12 that strips characters invalid in XML 1.0 applies only to unprotected text.

FMT-09.18 `ProtectInMemory="True"` (also `true` in any case, or `1`). The value is plain text and takes no keystream bytes, but the field's protected flag is set. If both `Protected` and `ProtectInMemory` are true, `Protected` applies (XOR) and the flag is set. `ProtectInMemory` is honoured only on entry `String/Value` elements, in current and history entries. On every other element (inline `Binary/Value`, version 3 pool items, `Meta` values, a `String/Key`, and so on) it is ignored: no flag is set, no keystream bytes are taken, and the text is read as if the attribute were absent. The reference does the same: only its entry string reader uses the attribute (source). Attachment content still goes into `SecretBytes` (FMT-13.3). App never writes `ProtectInMemory` into a vault file. Plain XML export may use it (FEA-09).

### Which values are written protected

FMT-09.19 The reference protects only entry `String/Value` elements, in current and history entries alike. A value is written protected when either:

- it is a standard field (key `Title`, `UserName`, `Password`, `URL` or `Notes`) and the vault's flag for it is on (`ProtectTitle`, `ProtectUserName`, `ProtectPassword`, `ProtectURL`, `ProtectNotes` in `Meta/MemoryProtection`; FMT-10, MOD-12), or
- the field's own protected flag is set. For custom fields this is the only way.

New vaults have only `ProtectPassword` on. A field read as protected (`Protected` or `ProtectInMemory`) keeps its own flag, so it stays protected on save even when the vault flag is off. Observed: a `Notes` value read with `ProtectInMemory` was written with `Protected="True"` while `ProtectNotes` was `False`. MOD-12 owns how the user changes these flags.

Never written protected by the reference: custom data values, `Meta` values, group fields, the header hash, and attachments. In version 4 attachments live in the inner header; in version 3 pool items are written without `Protected`. App writes `Protected="True"` on exactly the entry `String/Value` elements, in current and history entries, that meet one of the two conditions above, and on no other element it encodes. The one other place the attribute can appear in App's output is a kept unknown element written back raw (FMT-09.14), which takes no keystream bytes.

FMT-09.20 The order the reference writes. Within an entry, `String` elements are sorted by key in UTF-16 code unit order (example: `API key`, `Notes`, `Password`, `Title`, `URL`, `UserName`, `Zeta`). Then come the entry's `Binary` elements, auto-type, custom data, and last `History` with each history entry in turn, oldest first. A group writes its own fields, then its entries, then its child groups. FMT-11 owns the element order. Whatever that order is, FMT-09.11 and FMT-09.13 define keystream use from it.

FMT-09.21 Fresh key on every save. App writes a new 64-byte random stream key on every save (CRY-03, AT-B03). It never reuses a stream key, and never copies protected base64 text from the old file into the new one, except the raw text of kept unknown elements, which FMT-09.14 writes back as read and which takes no keystream bytes.

## Edge cases and errors

| Case | Result |
|---|---|
| Unknown inner header field (id 9, 3 data bytes) between fields 1 and 2 | Ignored. The vault opens; the reference behaves the same. |
| Field 3 before fields 1 and 2 | Accepted (FMT-09.5); the reference behaves the same |
| End field carrying 4 data bytes | Accepted; the data is ignored. The reference behaves the same. |
| Field 1 = `01 00 00 00` or `04 00 00 00` | `Unsupported`. The reference says the inner random stream cipher is invalid. |
| Field 1 two bytes long | `Corrupt`. The reference says the stream id size is invalid. |
| Field 3 of length 0 | `Corrupt` |
| Field 2 missing | `Corrupt` (FMT-09.7, default rule). The reference opens the file using an empty key. |
| Version 3: outer header field 8 missing, or of length 0 | `Corrupt` at header parse, before key derivation (FMT-09.7, FMT-02.18, FMT-02.23; decided: spec/decisions.md LD-23). The reference refuses it with its missing-header-fields error (FMT-17). |
| Field 2 of length 0 (`02 00 00 00 00`) | `Corrupt` (FMT-09.7). The reference opens it with the SHA-512-of-empty keystream (observed). |
| Field 2 twice, the last one of length 0 | `Corrupt` (FMT-09.5, FMT-09.7) |
| `ProtectInMemory="True"` on an inline attachment `Value`, a `Meta` value or a `String/Key` | Ignored: plain text, no flag, no keystream bytes (FMT-09.18) |
| Field 1 missing | `Corrupt`. The reference fails with an empty message. |
| Field 2 of 8 bytes | Accepted. Any length of 1 or more is fine; the reference behaves the same. |
| Field 2 twice | The last one is used; the reference behaves the same |
| Field 1 = `01 00 00 00` (id 1, RC4-like), then a valid field 1 = `03 00 00 00` | `Unsupported` at the first copy; the later valid copy does not rescue it (FMT-09.5). The reference fails the same way (observed). |
| Field 1 of 2 bytes, then a valid field 1 | `Corrupt` at the first copy (FMT-09.5, FMT-09.6). The reference fails on the stream id size (observed). |
| Version 4 with id 2 (Salsa20) | Accepted, decoded with FMT-09.10. The reference behaves the same. |
| `Protected="yes"` | Not protected: the text is kept as plain text |
| Protected text that is only spaces | Empty value, no keystream bytes used |
| Decrypted bytes `41 FF 42 C3` | Value "A\u{FFFD}B\u{FFFD}" (observed in the reference) |
| Decrypted bytes `E2 82 41` (cut-off 3-byte sequence) | Two U+FFFD, then "A": one per byte (FMT-09.15). A maximal-subpart decoder gives one, which is wrong here. |
| Decrypted bytes starting `EF BB BF` | Those three bytes are dropped. `EF BB BF 41` is "A", and `EF BB BF` alone is the empty string (FMT-09.15, LD-25) |
| Field 3 whose end offset is past the total limit, and whose data is also cut short | `TooLarge`, because the limit check runs first (FMT-09.6) |
| Decrypted bytes `41 00 42 43 44` | App: "A\u{0}BCD", 5 characters (FMT-09.15). The source does the same. The installed reference 2.7.11 shows "A" (differs in installed version); the next value still decodes correctly. |
| Version 3 with field 10 = 3 | `Unsupported` (FMT-09.8, LD-10). The reference opens it and decodes with Salsa20. |
| Version 3 with field 10 absent | Salsa20 (FMT-09.8, FMT-02.20) |
| Unknown element `<FooBar Protected="True">` before a protected value | Takes no keystream bytes; raw text kept and written back unchanged (FMT-09.14, LD-24) |
| An entry with two `History` blocks, each holding a protected value | Both blocks take keystream bytes in document order; only the last block's items are kept (FMT-09.13, LD-28) |
| Unknown element `<FooBar>` holding `<Value Protected="True">` | The inner `Value` takes no keystream bytes either (FMT-09.14) |
| `<Value Ref="0" Protected="True">QUJDRA==</Value>` in an entry `Binary` | Text ignored, no keystream bytes (FMT-09.13, FMT-13.9) |
| Keystream running out | Cannot happen within the FMT-08.12 limits: ChaCha20 with a 32-bit counter covers 256 GiB |

## Security notes

- What could go wrong:
  - A reused stream key across saves would let an attacker who has two files and both outer keys XOR the protected values together. Rule FMT-09.21 and AT-B03 prevent it.
  - A wrong consumption order corrupts every later protected value silently, with no error. Test the order across history entries and unknown elements.
  - A UTF-8 decoder with a different replacement rule, or one that keeps a leading byte order mark, shows a different value from the reference for the same bytes. It then writes that value back on save (FMT-09.15, AT-A11).
  - The raw text of a kept unknown element (FMT-09.14, the one exception in FMT-09.21) is copied as read. It stays under whatever key its original writer used and is never XORed with the new keystream, so it reveals nothing new.
- The stream is for confidentiality only: XOR without a MAC. Integrity comes from FMT-05, FMT-06 and FMT-07. Never decrypt or act on protected values before those checks pass (FMT-08.11).
- In version 3 the stream key is in the unencrypted outer header, so protected values there are protected only by the outer encryption. That is a weakness of version 3 against SF-12. App never writes version 3.
- Decrypted values go straight into `SecretString` or `SecretBytes`. The keystream buffer, the XOR buffer and the base64 text of protected values are wiped after use. The stream key is a secret. None of these appear in logs, errors or `Debug` output (rule 4 in AGENTS.md, AT-C01, AT-C06).
- Parity: SF-08 (second encryption layer), SF-09 (per-field protection flags), SF-07 (fresh stream key).
- AT-A08 and AT-A11: crafted documents with odd protected placements must give the decoded values defined here and never panic.

## Test cases

Common vector, version 4: stream key S4 = `00 01 02 … 3F` (64 bytes).

- SHA-512(S4) = `EE 43 20 EB AF 3F DB 4F 2C 83 2B 13 72 00 C0 8E 23 5E 0F A7 BB D0 EB 17 40 C7 06 3B A8 A0 D1 51 DA 77 E0 03 39 8E 17 14 A9 55 D4 75 B0 5E 3E 95 0B 63 95 03 B4 52 EC 18 5D E4 22 9B C4 87 39 49`
- ChaCha20 key = `EE 43 20 EB AF 3F DB 4F 2C 83 2B 13 72 00 C0 8E 23 5E 0F A7 BB D0 EB 17 40 C7 06 3B A8 A0 D1 51`
- ChaCha20 nonce = `DA 77 E0 03 39 8E 17 14 A9 55 D4 75`
- Keystream bytes 0 to 63 = `8C E8 BC 61 0A C0 5F F2 E3 DD 88 B4 9A 14 04 C2 84 4F 14 80 37 02 74 76 B8 3D 58 F5 60 9A DF 65 F8 FA 87 D8 B5 F5 28 7F 6C FD BD B6 9A DE A2 F9 42 E4 AC F5 A9 AD 9E 86 06 23 47 7A 73 A2 4C 4E`
- Keystream bytes 64 to 127 = `3A 32 18 FC 03 06 B0 95 A7 E7 05 DF 6C B0 3F FC 59 2D 2C E6 E3 A9 BA 6C 5A 78 A8 BC 8B 90 8A 71 D2 93 94 59 F6 40 3E 65 9B A4 40 EB 2F AA 46 50 E3 78 BE 36 E8 98 DB 36 6A 2D 6F 28 55 5D 76 E1`

Common vector, version 3: stream key S3 = `00 01 02 … 1F` (32 bytes).

- Salsa20 key = SHA-256(S3) = `63 0D CD 29 66 C4 33 66 91 12 54 48 BB B2 5B 4F F4 12 A4 9C 73 2D B2 C8 AB C1 B8 58 1B D7 10 DD`
- Nonce = `E8 30 09 4B 97 20 5D 2A`
- Keystream bytes 0 to 63 = `F9 BE B5 29 62 83 8A 2C 3C 82 27 CE ED 90 92 73 27 71 97 FF AF E6 6D E4 59 9F 4A D6 2D A6 9C 1D 1D 25 71 76 EF 84 BF 30 43 7D 0F 07 2D 1D B1 32 C7 0A F1 BF 83 6C CC 08 19 18 A2 36 19 4C A6 AE`

| Case | Given | When | Then |
|---|---|---|---|
| T09-01 (FMT-09.1, FMT-09.2, FMT-09.3, FMT-09.4) | U begins `01 04 00 00 00 03 00 00 00 02 40 00 00 00` + S4 + `03 03 00 00 00 01 68 69 00 00 00 00 00` followed by `3C 3F 78 6D 6C` | Parse the inner header | Algorithm 3, key S4, one pool item with flags `01` and content "hi". The header is 91 bytes and the document starts at offset 91. |
| T09-02 (FMT-09.4, FMT-09.21) | Any vault | App saves twice | Each inner header starts `01 04 00 00 00 03 00 00 00 02 40 00 00 00`, ends with `00 00 00 00 00`, and the two 64-byte keys differ |
| T09-03 (FMT-09.9) | S4 | Derive | The key, nonce and keystream bytes 0 to 127 above. Cross-checked: the openssl ChaCha20 tool with IV `00 00 00 00` + nonce gives the same bytes. |
| T09-04 (FMT-09.10) | S3 | Derive | The Salsa20 key and keystream above. A separate textbook Salsa20/20 implementation agrees. |
| T09-05 (FMT-09.10, FMT-09.8) | Version 4, field 1 = 2, field 2 = S4 | Derive | Salsa20 key = SHA-256(S4) = `FD EA B9 AC F3 71 03 62 BD 26 58 CD C9 A2 9E 8F 9C 75 7F CF 98 11 60 3A 8C 44 7C D1 D9 15 11 08`. Keystream bytes 0 to 15 = `0F 49 B2 BD 13 92 F3 03 C0 2E EF 12 4C D0 FD A0`. |
| T09-06 (FMT-09.11, FMT-09.17) | S4. Values in document order: "pw-one", "Sécret ✓", "" (empty), "zz" | Encode | `/J+RDmSl` (bytes 0–5), `DDFKvvrR7jTmXhc=` (bytes 6–16, UTF-8 `53 C3 A9 63 72 65 74 20 E2 9C 93`), empty element with no text and no bytes used, `NW4=` (bytes 17–18) |
| T09-07 (FMT-09.11) | S4. The same 128 plaintext bytes split into values of 7, 1, 12, 44 and 64 bytes | Encode value by value | The joined output equals the 128 bytes XORed with keystream bytes 0 to 127 in one go |
| T09-08 (FMT-09.13, FMT-09.19, FMT-09.20) | Demo vault with S4. Entry "Alpha": vault flag `ProtectUserName` on; Notes protected by its own flag; strings sorted `API key`, `Notes`, `Password`, `Title`, `URL`, `UserName`, `Zeta` | Encode | Notes "secret note" = `/43fE2+0f5yMqe0=` (bytes 0–10), Password "pw-alpha" = `xO05Za70J3U=` (bytes 11–18), UserName "alice" = `4VtrFxM=` (bytes 19–23). Then Zeta, then the history entries' values. |
| T09-09 (FMT-09.13) | Reference-saved demo vault: entry Alpha (Notes, Password, UserName, Zeta protected), its history entry (Password "pw-old", empty UserName), then entry Beta and Beta's history | Decode | Offsets observed in the installed reference: 0 "secret note" (11), 11 "pw-alpha" (8), 19 "alice" (5), 24 "zz" (2), 26 "pw-old" (6), 32 "pw-beta" (7), 39 "pw-beta" (7). The empty history UserName uses no bytes. |
| T09-10 (FMT-09.10, FMT-09.13) | The reference test vault "ProtectedStrings" (version 3.1, password "masterpw") | Decode protected values | In order: "ProtectedPassword", "ABC", "ProtectedPassword", "ABC" (the second pair is in a history entry) |
| T09-11 (FMT-09.10) | S3, values "Password", "ABC" | Encode | `qd/GWhXs+Eg=`, `fcBk` |
| T09-12 (FMT-09.12) | Values with `Protected="1"`, `"true"`, `"TRUE"`, `"yes"` | Decode | The first three are XOR-decoded in order. The fourth is plain text and uses no bytes. |
| T09-13 (FMT-09.13) | A protected `DatabaseName` in `Meta`, then a protected Password in an entry | Decode | DatabaseName uses bytes first. The password decodes correctly from the next offset. |
| T09-14 (FMT-09.14) | Version 4 demo vault with S4. Entry: `<FooBar Protected="True">QUJD</FooBar>` (its writer took no keystream bytes for it), then Password `<Value Protected="True">/J+RDmSl</Value>`. Second vault: the same, but FooBar = `zar/JQ==` ("ABCD" XOR keystream bytes 0–3) and Password = `erdynY24` ("pw-one" XOR bytes 4–9) | App reads | First vault: FooBar kept with raw text `QUJD`, never decrypted; Password "pw-one" from byte 0. Second vault: FooBar kept raw; the password decodes from byte 0 to garbage, exactly as in the reference. The installed reference CLI showed "pw-one" for the first vault and a garbled password for the second (observed). |
| T09-15 (FMT-09.14, FMT-09.21) | The first vault from T09-14 | App saves, then the reference CLI `show` runs on the saved file, then App reopens it | The reference shows Password "pw-one". In the saved file FooBar is still in the entry, with its raw text `QUJD` and attributes as read, and the password's base64 decodes with the new stream key from byte 0. App reopens it with the same values. |
| T09-16 (FMT-09.15) | Protected text whose base64 has a line break and spaces inside | Decode | The same value as without the whitespace (observed in the reference) |
| T09-17 (FMT-09.13) | `<Value Protected="True">  </Value>` (spaces only) | Decode | Empty value. The next protected value starts at the same offset. |
| T09-18 (FMT-09.15) | S4. Decrypted bytes `41 FF 42 C3` (base64 `zRf+og==` at offset 0) | Decode | "A", U+FFFD, "B", U+FFFD |
| T09-19 (FMT-09.18) | `<Value ProtectInMemory="True">pw-one</Value>` then a `Protected` value | Read | The first is plain "pw-one" with its protected flag set and uses no bytes. The second starts at byte 0. |
| T09-20 (FMT-09.18) | `Protected="True" ProtectInMemory="True"` | Read | XOR-decoded, flag set |
| T09-21 (FMT-09.6) | Field 1 with data `03 00` | Open | `Corrupt` |
| T09-22 (FMT-09.8) | Field 1 = `01 00 00 00`; separately `04 00 00 00` | Open | `Unsupported` each time |
| T09-23 (FMT-09.6) | Field 3 with length 0 (`03 00 00 00 00`) | Open | `Corrupt` |
| T09-24 (FMT-09.6) | U stops after field 2 with no end field | Open | `Corrupt` |
| T09-25 (FMT-09.6) | Default limits. Field 3 declaring length `F0 FF FF FF` (4,294,967,280) with 6 data bytes present, then U ends | Open | `TooLarge`, because s + 5 + L is past the 1 GiB total limit. Raised before any allocation, and before the truncation check that would give `Corrupt`. The reference reports a length mismatch, and its memory stayed at 26 MB. |
| T09-26 (FMT-09.7, FMT-09.5) | Field 2 missing; separately field 1 missing; separately field 2 = `02 00 00 00 00` (length 0) with Password "pw-one" encrypted with the keystream from H = SHA-512 of empty input (key = H bytes 0–31 starting `CF 83 E1 35`, nonce = H bytes 32–43); separately field 2 = S4 followed by a second field 2 of length 0 | Open | `Corrupt` each time. The installed reference opens the length-0 case and shows Password "pw-one" (observed). |
| T09-27 (FMT-09.5) | Field 2 = S4, then field 2 = K2 | Open | Values decode with K2 |
| T09-28 (FMT-09.3, FMT-09.5) | Unknown field `09 03 00 00 00 78 79 7A` between fields 1 and 2; end field with data `0D 0A 0D 0A`; field 3 placed first | Open, then save | Opens. The saved file has no field 9, and its end field is `00 00 00 00 00`. |
| T09-29 (FMT-09.8) | Version 3 demo vault with header field 10 = 3 (values encrypted with ChaCha20 from field 8); the same vault with field 10 removed and values encrypted with Salsa20 | App opens | First: `Unsupported`, at header parse (FMT-02.20). The reference opens it and garbles the values. Second: opens and decodes with Salsa20. |
| T09-30 (FMT-09.19) | New vault; an entry with a custom field marked protected and a Title | App saves | Password and the custom field are written with `Protected="True"`. Title, URL, UserName and Notes are plain. |
| T09-31 (FMT-09.19) | A vault read with Notes protected by the field's own flag, vault flag `ProtectNotes` = False | App saves | Notes is still written protected |
| T09-32 (FMT-09.21) | 10,000 saves (AT-B03) | Collect field 2 | No repeats |
| T09-33 (FMT-09.1, FMT-09.10) | Version 3 demo vault: outer header field 8 = S3, field 10 = `02 00 00 00`; the first protected value in the document is base64 `qd/GWhXs+Eg=` | Open | No inner header is parsed. The document starts at byte 0 of the hashed-block data, and the value decodes to "Password". |
| T09-34 (FMT-09.16, FMT-09.13) | Version 4 entry: protected Password "pw-one" (bytes 0–5), then an inline attachment `<Value Protected="True">` holding the base64 of "inl-prot" XORed with keystream bytes 6–13 | Open | Attachment content "inl-prot" (8 bytes). For the version 3 case where an item is both protected and compressed (XOR before gunzip), see T13-08. |
| T09-35 (FMT-09.15) | Version 4 demo vault with S4. Entry: Password `<Value Protected="True">zej+Ik4=</Value>` (decrypts to `41 00 42 43 44`, keystream bytes 0–4), then Zeta `<Value Protected="True">oTmGhq8=</Value>` ("after", bytes 5–9) | App reads | Password is "A", U+0000, "B", "C", "D" (5 characters). Zeta is "after". The installed reference CLI `show` printed "Password: A" and "Zeta: after" (observed). |
| T09-36 (FMT-09.13) | Version 4 demo vault with S4. Entry: `<Binary><Key>f.txt</Key><Value Ref="0" Protected="True">QUJDRA==</Value></Binary>` before Password `<Value Protected="True">/J+RDmSl</Value>`; pool item 0 = "AAA" | App reads | f.txt = "AAA". Password "pw-one" from byte 0: the Ref value took no keystream bytes. The installed reference gave the same (observed). |
| T09-37 (FMT-09.14) | Version 4 demo vault with S4 and no pool items. Entry: `<FooBar><Value Protected="True">QUJD</Value></FooBar>`, then Password `<Value Protected="True">/J+RDmSl</Value>` | App reads, saves, reads again | FooBar is kept with its child as read. Password is "pw-one" from byte 0. After the save, FooBar and its child are written back unchanged and Password decodes with the new key from byte 0. The installed reference CLI `show` printed "Password: pw-one" and logged that it skipped FooBar (observed). |
| T09-38 (FMT-09.18) | Version 4 demo vault with S4, pool empty. Entry: `<Binary><Key>f.txt</Key><Value ProtectInMemory="True">QUJD</Value></Binary>`, then Password `<Value Protected="True">/J+RDmSl</Value>`. Also `Meta/DatabaseName` with `ProtectInMemory="True"` and text "db" | App reads | `f.txt` = "ABC" (3 bytes, plain base64, no protected flag). DatabaseName = "db", no flag. Password "pw-one" from keystream byte 0: neither element took keystream bytes. |
| T09-39 (FMT-09.5, FMT-09.6, FMT-09.8) | Inner header: field 1 = `01 04 00 00 00 01 00 00 00` (id 1), then field 1 = `01 04 00 00 00 03 00 00 00`, then field 2 = S4 and field 0. Separately: field 1 = `01 02 00 00 00 03 00`, then field 1 = `01 04 00 00 00 03 00 00 00`, field 2 = S4, field 0 | Open | First: `Unsupported`. Second: `Corrupt`. A valid later copy never rescues an invalid earlier one. The installed reference CLI 2.7.11 also failed both (observed: on the stream id, then on the stream id size). Third, for contrast: field 1 = `03 00 00 00`, then field 1 = `02 00 00 00`, both valid: the later one wins and values decode with Salsa20 (FMT-09.10). Observed in 2.7.11 with a Password encrypted under the ChaCha20 keystream: it opened and the password came out garbled, which shows the later copy won. |
| T09-40 (FMT-09.6) | Test limit total = 4,096. U = field 1 (offsets 0–8), field 2 = `02 40 00 00 00` + S4 (offsets 9–77), then field 3 at offset 78. Case A: `03 AD 0F 00 00` (L = 4,013) with 6 data bytes, then U ends. Case B: `03 AE 0F 00 00` (L = 4,014) with 6 data bytes, then U ends. | Open | A: 78 + 5 + 4,013 = 4,096, which is within the limit, so the truncation check runs: `Corrupt`. B: 4,097 is past the limit: `TooLarge`. |
| T09-41 (FMT-09.15) | Version 4 demo vault with S4. One entry, Title "T1", then protected custom strings K01 to K14 in this order. Each is given as decrypted bytes, keystream bytes used, and stored base64. K01 `E2 82 41` (0–2) `bmr9`. K02 `F0 80 80 41` (3–6) `kYpAHg==`. K03 `ED A0 80 41` (7–10) `H0NdyQ==`. K04 `41 E2 82` (11–13) `9XiW`. K05 `F0 9F 98 41` (14–17) `9F0cDg==`. K06 `C0 AF 41` (18–20) `1C92`. K07 `EF BB BF 41` (21–24) `7c/J+Q==`. K08 `41 EF BB BF 42` (25–29) `fLdO39g=`. K09 `EF BF BE 41` (30–33) `MNpGuw==`. K10 `F4 90 80 80 41` (34–38) `c0g1dWk=`. K11 `80 41` (39–40) `/y0=`. K12 `E2 82 AC` (41–43) `Hz8a`. K13 `EF BB BF` (44–46) `dWUd`. K14 `F0 9F 98` (47–49) `Cd18`. | App reads | K01: U+FFFD ×2, "A". K02: U+FFFD ×3, "A". K03: U+FFFD ×3, "A". K04: "A", U+FFFD ×2. K05: U+FFFD ×3, "A". K06: U+FFFD ×2, "A". K09: U+FFFE, "A". K10: U+FFFD ×4, "A". K11: U+FFFD, "A". K12: U+20AC. K14: U+FFFD ×3. K07, K08 and K13: see T09-42. Observed exactly so with the installed CLI 2.7.11 (`show -s -a`), both on this vault and after the reference re-saved it. |
| T09-42 (FMT-09.15) | The T09-41 vault | App reads K07, K08 and K13 | K07 = "A", with the leading `EF BB BF` dropped. K08 = "A", U+FEFF, "B", because a byte order mark that is not at the start is kept. K13 = the empty string. The installed reference gave the same, and after its re-save it stored K07 as the bytes `41` and K13 as `<Value Protected="True"/>`. |
| T09-43 (FMT-09.17, FMT-09.15) | S4. A protected Password whose value is U+FEFF, "A" | App encodes | The value's bytes become `EF BB BF EF BB BF 41`, stored as `Y1MDjrF/Hg==` (keystream bytes 0–6). App reads it back as U+FEFF, "A". The installed reference CLI showed the bytes `EF BB BF 41` for it (observed). |
| T09-44 (FMT-09.13) | Version 4 demo vault with S4, pool empty. One entry, id `AA`×16, Title "T1", in this order: Password `<Value Protected="True">/J+RDmSl</Value>` ("pw-one", bytes 0–5); a first `History` block with one history item (same id) whose Password is `L4XOsuTQ` ("pw-old", bytes 6–11); a second `History` block with one history item whose Password is `6mMprOE4` ("pw-new", bytes 12–17); then a string Zeta `<Value Protected="True">deZDZwY=</Value>` ("after", bytes 18–22) | App reads | Password "pw-one". The entry has one history item, with Password "pw-new". Zeta is "after", which shows the dropped block's "pw-old" took bytes 6–11. Observed exactly so with the installed CLI 2.7.11: `show` printed "Password: pw-one" and "Zeta: after", and `export -f xml` held one history item with Password "pw-new" and no "pw-old". |
| T09-45 (FMT-09.7, LD-23) | Version 3 demo vault (as T09-33) with outer header field 8 removed; separately the same vault with field 8 of length 0 (`08 00 00`, no data) | Open | `Corrupt` both times, at header parse, before key derivation (KDF spy: zero calls). Same as FMT-02 test C32. The reference refuses both with its missing-header-fields error (FMT-17) |

## How this was learned

- Read in the reference source: the version 4 reader's inner header part and the version 4 save routine (field order and the values written), the shared header reader (stream id checks), the keystream helper (key and nonce derivation, continuous buffering), the XML reader (protected attribute handling for text and binary values, skipping unknown elements, history entries) and the XML writer (which fields it protects, how empty values are written, String order).
- Read the vault metadata defaults, entry field storage (the sticky per-field flag) and the reference's keystream test (which checks that values split at odd lengths use one continuous stream).
- Ran experiments in `/tmp/spec-fmt08-09-13/` against the installed reference CLI 2.7.11, with demo vaults built from scratch under the demo password "demo-pass-1": every inner header variant in the edge case table; protected attribute spellings; unknown, `Tags` and `DatabaseName` protected elements; base64 with whitespace; invalid UTF-8; version 3 vaults with stream ids 0, 1, 2 and 3 and a 5-byte stream key.
- Decoded a vault re-saved by the reference to observe the order and the empty-value form.
- Opened "ProtectedStrings" read-only with the password from the reference tests.
- Round 2: built more demo vaults with stream key S4 and opened them with the installed CLI 2.7.11: an unknown protected element that took no keystream bytes and one that did (T09-14), a protected value that decrypts to bytes with `00` in them (T09-35), and a `Ref` value that also holds protected text (T09-36). Read the document reader again for how it skips unknown elements and `Ref` values.
- Round 3: a demo vault with a protected `Value` nested in an unknown element (T09-37), opened with the installed CLI 2.7.11.
- Round 4: read the document reader's text and binary value routines again (only the entry string reader uses `ProtectInMemory`) and the version 4 reader's field 2 handling (no length check). The field 2 of length 0 observation comes from a review experiment on a demo vault (password "demo-pass-1") with the installed CLI 2.7.11.
- Round 5: read the shared header reader's stream id check and the inner header loop again (each field 1 is checked when read; the loop stops at the first error), the reference build file (toolkit 6.2.4 or later required) and the document reader's UTF-8 conversion of decrypted bytes. Opened three demo vaults with repeated field 1 (T09-39) with the installed CLI 2.7.11, demo password "demo-pass-1".
- Round 6 (cross-check fixes): read the version 4 reader's inner header field routine again. It reads the length unsigned, sets no limit, and reports a mismatch when data is short. Read the document reader's protected string routine, which converts the decrypted bytes with the toolkit's UTF-8 conversion. Built the T09-41 and T09-43 demo vaults in `/tmp/spec-fmt08-09-13/work/exp6/` (password "demo-pass-1") and opened them with the installed CLI 2.7.11. Re-saved T09-41 with the CLI's `edit` and decoded the stored values.
- Sprint 0 close-out: wrote in the lead rulings (spec/decisions.md) LD-10, LD-23, LD-24, LD-25 and LD-28. For LD-28, read the document reader's entry routine again (each `History` block is read in full, then the last one replaces the item list) and built the T09-44 demo vault in `/tmp/spec-fmt08-09-13/work/exp7/` (password "demo-pass-1"), opened with the installed CLI 2.7.11 (`show`, `export -f xml`).
- Computed the vectors with python3 hashlib, libsodium (ChaCha20 IETF and Salsa20 keystreams), the openssl ChaCha20 tool and a scratch Salsa20 implementation for cross-checking.
- Sprint 1 close-out: LD-23 is now cited only for version 3 header field 8 (new edge row and T09-45); the version 4 field 2 rule of FMT-09.7 stands under the default rule. FMT-09.14's write bullet now says the raw write-back is the only write FMT-10.20 allows (LD-24).
