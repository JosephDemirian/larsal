# FMT-08 Payload encryption and compression

Status: reviewed
Epics: E3-S5
Parity rows: SF-01, SF-06, SF-07, SF-11, SF-12

## What it does

The payload is everything in a vault file that holds the user's data. This card says how the payload is layered, how it is decrypted and decompressed when a vault is opened, and how it is compressed and encrypted when a vault is saved.

Version 4 (4.0 and 4.1 alike), from the outside in:

1. Outer header, header hash and header HMAC (FMT-02, FMT-05).
2. Block integrity stream (FMT-06). Removing it gives the ciphertext.
3. Cipher (this card; primitive details in CRY-01). Decrypting gives the plaintext.
4. Optional gzip compression (this card). Decompressing gives the decompressed payload.
5. Inner header (FMT-09), then the XML document (FMT-10, FMT-11) right after it.

Version 3 (and the older version 2, read the same way, decided: spec/decisions.md LD-06; see FMT-17), from the outside in:

1. Outer header (FMT-02). No header hash or HMAC fields follow it.
2. Cipher. Decrypting gives the plaintext.
3. The first 32 plaintext bytes are the stream start bytes (wrong-key check, FMT-05).
4. Hashed block stream (FMT-07) over the rest of the plaintext, up to its final block. That block is the logical end of the file (FMT-08.2).
5. Optional gzip compression.
6. The XML document. Version 3 has no inner header: the protected-field stream key and algorithm sit in the outer header (FMT-09).

The integrity layer is outside the cipher in version 4 (the MAC covers ciphertext) and inside the cipher in version 3 (hashes cover plaintext).

Larsal reads versions 4 and 3 and writes only version 4 (plan/architecture.md, FMT-16).

## Inputs and outputs

Reading:

| Input | Type | Source |
|---|---|---|
| Cipher id | 16 bytes | Outer header field 2 (FMT-02) |
| Compression flag | 4 bytes, little-endian unsigned | Outer header field 3 |
| IV or nonce | 16 bytes (CBC) or 12 bytes (ChaCha20) | Outer header field 7 |
| Stream start bytes (version 3 only) | 32 bytes | Outer header field 9 |
| Final key | 32 bytes, secret | FMT-04 |
| Ciphertext | bytes | Version 4: output of FMT-06. Version 3: the bytes after the outer header end field, read only up to the end of the final hashed block (FMT-08.2). |
| Limits | numbers | `larsal-format/limits.rs` (FMT-08.12) |

Output: the decompressed payload as bytes. Version 4: inner header followed by the document. Version 3: the document. Or one error kind from FMT-08.13.

Writing (version 4 only):

| Input | Type |
|---|---|
| Inner header bytes | from FMT-09 and FMT-13 |
| Document bytes | UTF-8 XML from FMT-10, FMT-11 |
| Cipher id, compression setting | vault settings |
| Final key | 32 bytes, secret (FMT-04) |
| IV or nonce | fresh random bytes for this save (CRY-03) |

Output: the ciphertext, which FMT-06 splits into blocks.

## Rules

### Layering

FMT-08.1 Version 4 read order. Take the ciphertext C from the block integrity stream (FMT-06). Decrypt C with the cipher named in header field 2, the final key (FMT-04) and the IV or nonce from header field 7. This gives the plaintext P. If the compression flag is 1, gunzip P to get U. If it is 0, U = P. U is the inner header (FMT-09) followed directly by the document bytes. No byte separates them, and the document begins with the first byte after the inner header end field. Versions 4.0 (file version bytes `00 00 04 00`) and 4.1 (`01 00 04 00`) are layered the same way. Bytes in the file after the final block of FMT-06 are not part of C: they are ignored and never read as content (FMT-06.12; decided: spec/decisions.md LD-01).

FMT-08.2 Version 3 read order. The ciphertext starts right after the outer header end field. Decrypt it from the start, in order, with the same cipher table (FMT-08.4) to get P. The first 32 bytes of P must equal header field 9. A mismatch means the wrong key (FMT-05; decided: spec/decisions.md LD-12) and nothing else is decoded. Compare in constant time. The rest of P is a hashed block stream (FMT-07), read up to and including its final block. Its data, joined, is H. If the compression flag is 1, gunzip H to get the document. If it is 0, the document is H. There is no inner header.

The logical end of a version 3 file is the last byte of the final hashed block. Everything after it is ignored and never read as content: the CBC padding, any plaintext a writer put between the final block and the padding, and any bytes a longer file holds after the padded end (decided: spec/decisions.md LD-01; FMT-07.11, FMT-17.15 and FMT-01.20 own the details). So Larsal decrypts no further than the cipher block that holds the last byte of the final hashed block. A file that ends before that byte, or for a CBC cipher before the end of the 16-byte block that holds it, is `Corrupt` (FMT-07). Observed: version 3.1 demo vaults with 1, 16 and 4,096 random bytes appended open in the installed reference 2.7.11, and so do vaults with trailing plaintext or a bad all-padding last block (FMT-07.11).

### Compression flag

FMT-08.3 The compression flag is header field 3. It is a 4-byte little-endian unsigned integer. The values are 0 = no compression and 1 = gzip. Any other value is `Unsupported`. A field length other than 4 is `Corrupt`. A missing field 3 is `Corrupt` (FMT-02.23, FMT-17.7): Larsal never assumes a compression the file did not state. Reference difference: the reference keeps its model default, gzip, when the field is missing (source), so such a file opens there when the payload is gzip and fails when it is plain (observed in 2.7.11). When Larsal writes, the field is always present: `00 00 00 00` or `01 00 00 00`. New vaults use gzip. A vault keeps the setting it was opened with until the user changes it.

### Cipher modes as used here

FMT-08.4 Cipher table. CRY-01 owns the primitive details. The key is always the 32-byte final key.

| Cipher id (header field 2, bytes as stored) | Mode | IV or nonce (field 7) | Padding |
|---|---|---|---|
| `31 C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A FF` | AES-256-CBC | 16 bytes | PKCS#7 |
| `AD 68 F2 9F 57 6F 4B B9 A3 6A D4 7A F9 65 34 6C` | Twofish-256-CBC | 16 bytes | PKCS#7 |
| `D6 03 8A 2B 8B 6F 4C B5 A5 24 33 9A 31 DB B5 9A` | ChaCha20, RFC 8439 block function, 96-bit nonce, 32-bit block counter starting at 0 | 12 bytes | none: ciphertext length = plaintext length |

The ChaCha20 counter starts at 0, not at 1 as in the RFC 8439 AEAD construction. A field 7 length that does not match the table is `Unsupported`, detected while the outer header is parsed, before any key derivation (FMT-02.11, CRY-01.9). Reference difference: the reference also accepts 8-byte nonces (the original ChaCha20 layout) and 24-byte nonces (XChaCha20) for the ChaCha20 id; CRY-01 edge cases describe both. Larsal rejects them. Unknown cipher ids are handled in FMT-02 and CRY-01.

FMT-08.5 CBC padding. On write, the plaintext is padded once, at the very end, with PKCS#7. Add n bytes, each of value n, where n = 16 − (length mod 16), so n is 1 to 16. A plaintext whose length is a multiple of 16 gets a full block of `10` bytes. On read, version 4: the ciphertext (the joined block data of FMT-06) must have a non-zero length that is a multiple of 16, or the result is `Corrupt`. After decryption the last byte n must be 1 to 16, and the last n bytes must all equal n. Otherwise the result is `Corrupt` (decided: spec/decisions.md LD-03). Strip the padding. The padding is checked only after every block MAC has passed (FMT-06), and the cipher layer returns one error for any decrypt failure (CRY-01; decided: spec/decisions.md LD-04), so nothing about the padding is visible without the key and a padding failure cannot be an oracle (AT-B07). Reference difference: the reference does not check the padding in practice. Version 4 demo vaults with padding `00`×16, with mixed padding bytes, and with a last byte of `11` all opened in the installed version. Larsal is stricter: only the key holder can make such a file.

On read, version 3: the padding lies after the final hashed block, so it is never checked (FMT-08.2, LD-01). Reference: it checks the padding only when the file's last cipher block also holds the end of the final hashed block, and then a bad padding fails the open (FMT-07.11, observed). Larsal opens that file: an expected AT-A11 difference, which only the key holder can cause.

### Gzip

FMT-08.6 Reading gzip. The compressed payload must be exactly one gzip member as defined in RFC 1952, with deflate data as defined in RFC 1951:

- Bytes 0 to 2 must be `1F 8B 08`.
- FLG bits 5 to 7 (mask `E0`) must be 0.
- FEXTRA, FNAME, FCOMMENT and FHCRC are accepted and skipped. When FHCRC is set, the header CRC16 must match.
- MTIME, XFL and OS are ignored.
- Any deflate block type is accepted, stored blocks included.
- The trailer CRC32 (little-endian) must equal the CRC32 of the decompressed bytes. ISIZE (little-endian) must equal the decompressed length mod 2^32.

Any failure is `Corrupt`. A zlib-wrapped stream (RFC 1950, for example starting `78 9C`) and raw deflate are `Corrupt`. The reference rejected every one of these cases in the installed version. Its message varies with the size of the document: small documents fail while the inner header is read, large ones fail as a premature end of the document.

FMT-08.7 Nothing may follow the gzip member. Larsal reports `Corrupt` if any byte follows the end of the member's trailer in the decrypted plaintext, and that includes a second gzip member. Reference difference: the reference stops reading at the end of the first member and ignores everything after it. Observed: 20 junk bytes after the member, inside valid encryption, opened fine. A document split over two members failed only because the first member held an incomplete document. Decided: spec/decisions.md LD-02. These bytes lie inside the checked payload, so only the key holder can put them there. This is not the LD-01 case, which covers bytes outside the checked data (FMT-08.1, FMT-08.2).

FMT-08.8 The flag is trusted, never guessed. If the flag is 1 and the plaintext is not gzip, the result is `Corrupt`. If the flag is 0 and the plaintext is gzip, the inner header parse fails, so the result is `Corrupt` (FMT-09). Larsal never sniffs the payload to pick a mode.

FMT-08.9 Writing gzip. Larsal writes exactly one member:

- the 10-byte header `1F 8B 08 00 00 00 00 00 00 13` (FLG 0, MTIME 0, XFL 0, OS `13`, which is what the reference's macOS build writes),
- deflate data at the default level 6,
- CRC32 (little-endian),
- ISIZE (little-endian).

Larsal's deflate output does not have to match the reference byte for byte. Any valid deflate stream is correct. The reference uses zlib-style settings: level 6, a 15-bit window, memory level 8, default strategy, a single finishing flush at the end. Other writers produce other header bytes (for example XFL `04`, OS `00`, as seen in the reference's older test vaults), and FMT-08.6 accepts them.

### Writing the payload

FMT-08.10 Version 4 write order:

1. U = inner header bytes (FMT-09) followed by the document bytes.
2. If compression is on, P = gzip(U) (FMT-08.9). Otherwise P = U.
3. Encrypt P as one stream with the vault's cipher, the final key and a fresh IV or nonce (CRY-03), which is also written to header field 7. CBC pads once at the end (FMT-08.5).
4. Hand the ciphertext to FMT-06.

Larsal writes cipher ids from the FMT-08.4 table only.

### What is checked, and when data may be used

FMT-08.11 A vault is returned to the caller only after every check below has passed for the whole file. Decoding may stream, but if any later check fails, everything decoded so far is wiped and dropped, and only the error is returned. Before any of these, the outer header is parsed and checked (FMT-02), including the presence of field 3 and the length of field 7; those errors come before key derivation. Order for version 4:

1. Header hash and header HMAC (FMT-05).
2. Every block MAC, including the final empty block (FMT-06).
3. CBC padding (FMT-08.5).
4. The gzip header, the deflate data, CRC32, ISIZE, and no trailing bytes (FMT-08.6, FMT-08.7).
5. A well-formed inner header (FMT-09).
6. A well-formed document (FMT-10, FMT-11, FMT-12).
7. Attachment references resolved (FMT-13).

Order for version 3:

1. Start bytes (FMT-05).
2. Every hashed block, up to and including the final block (FMT-07). Nothing after the final block is checked or used (FMT-08.2, LD-01).
3. Gzip.
4. Document.
5. The header hash stored in the document, when present (FMT-05, FMT-17).

### Size limits

FMT-08.12 Size limits. This is the one table of reading limits for the payload and the document, and the only place that gives their numbers. The numbers are decided (spec/decisions.md LD-22, which accepted this card's L08-1 values and the earlier per-card limits L11-4, L13-6, L14-4 and L15-4 that it takes in). Revisit a value only if a demo vault, or a vault a user reports, passes it. FMT-09, FMT-10, FMT-11, FMT-12, FMT-13, FMT-14 and FMT-15 set no numbers. FMT-11.48, FMT-13.20, FMT-14.25 and FMT-15.14 say only how their rows are counted, and FMT-12 says how a text value is decoded before it is measured. If any of those cards still shows a number or a decision ID of its own, this table wins. The values live in `larsal-format/limits.rs`. (Edit caps that keep a save within these limits: decided: spec/decisions.md LD-56, MOD-01.9.)

How the limits apply:

- Count while data is produced or read. Stop with `TooLarge` the moment a count would pass its limit: for an element count, when the start tag of the element that would pass it is read, before anything is stored for it. The error names the limit, using the names in the first column (FMT-11 errors).
- Each limit is checked on its own. The first limit that is passed stops the read.
- Never allocate from ISIZE, from a declared length, or from any count read from the file before it has been checked against this table.
- The payload limits apply to the plaintext when the compression flag is 0, the same as to gunzipped data.
- Tests must be able to lower every limit.
- At these values, every count limit can be reached before the elements limit is passed (for example 10,000,000 custom data items of 3 elements each).
- Larsal never writes a vault it would refuse to read. Before a save, Larsal checks what it is about to write against the same limits. If a limit would be passed, the save fails with `TooLarge` and the old file is left as it was.

| Limit (name) | Value | What is counted |
|---|---|---|
| total | 1,073,741,824 bytes (1 GiB) | Bytes of the decompressed payload U. Version 4: inner header plus document. Version 3: the document. |
| document | 536,870,912 bytes (512 MiB) | Bytes of the document: in version 4 every byte after the inner header end field, in version 3 the whole decompressed payload. Inner header bytes (version 4 pool items included) count only toward total. Version 3 documents carry attachments as base64, so they need the room. |
| depth | 512 | The largest depth an element may have, with depth counted as in FMT-10.2: the root element at depth 0, `Meta` and `Root` at 1, the root group at 2. An element at depth 513 is over the limit, so at most 513 elements are open at the same time. One limit for the whole document, `Meta`, custom data and kept unknown elements included. |
| elements | 67,108,864 | Start tags in the whole document, with an empty-element tag counting once. Kept unknown elements and everything inside them count. |
| text | 67,108,864 bytes (64 MiB) | The text of one element (all its direct text parts together, CDATA included), or the value of one attribute. Counted in UTF-8 bytes after character references and the predefined entities are replaced (FMT-12), and before base64 or any other value decoding. Exemption below. |
| groups | 1,000,000 | Every `Group` element, the root group included. Each occurrence of a duplicate id counts (FMT-11.48). |
| entries | 1,000,000 | Live entries: every `Entry` element that is a child of a `Group`. History items are not counted here (FMT-11.48). |
| entry elements | 4,000,000 | Live entries plus history items in the whole document, including the items of `History` blocks that are later dropped (FMT-11.48). |
| history | 100,000 | History items of one live entry: `Entry` elements in all `History` blocks of that entry, dropped blocks included (FMT-11.48). |
| strings | 100,000 | `String` elements in one live entry or one history item. Standard fields added because they are missing do not count (FMT-11.48). |
| attachments | 100,000 | `Binary` elements in one live entry or one history item (FMT-11.48, FMT-13.20) |
| associations | 100,000 | `Association` elements in all `AutoType` blocks of one live entry or one history item (FMT-11.48) |
| kept unknown elements | 1,000,000 | Elements kept as unknown (FMT-10, FMT-11.45, FMT-14, FMT-15) in the whole document, with each element inside a kept element counted too (FMT-11.48) |
| pool items | 1,000,000 | Version 4 inner header field 3 records plus `Meta/Binaries/Binary` items, counted together, including items that are later replaced (FMT-13.6, FMT-13.7, FMT-13.20) |
| one attachment | 1,073,741,824 bytes (1 GiB) | Content bytes of one attachment: a version 4 pool item after its flags byte, or the decoded content of one document item after base64, XOR and gunzip (FMT-13.20) |
| all attachments | 1,073,741,824 bytes (1 GiB) | The sum of all attachment content decoded while reading, counted as FMT-13.20 says |
| icons | 100,000 | `Icon` elements in the whole document, in all `CustomIcons` blocks of all `Meta` elements, icons that get a fresh id included (FMT-14.25) |
| icon data | the text limit | The `Data` text of one icon is one text value, so at this value an icon holds at most 50,331,648 decoded bytes. No separate limit (FMT-14.25). |
| custom data items | 100,000 | `Item` elements read into one container (the vault, one group, one entry or one history item), across all its `CustomData` blocks, and for the vault across all `Meta` elements, duplicate keys included (FMT-14.25) |
| custom data items in all | 10,000,000 | `Item` elements of all containers together, history items included (FMT-14.25) |
| custom data key, custom data value | the text limit | (FMT-14.25) |
| deleted objects | 1,000,000 | `DeletedObject` elements in all `DeletedObjects` blocks, including items that are then dropped (FMT-15.14) |
| key file attributes | 1,024 | Attributes on one tag of a key file document; each gathered key file token (name, namespace value, declaration value) is also capped at 1 MiB. Inside a key file document over the cap is `TooLarge`; before the root is known the file falls back to the other key file forms (FMT-18; LD-83) |
| model | 2,147,483,648 bytes (2 GiB; LD-89) | The in-memory size (per-type costs listed next to the limit in `limits.rs`) of every model object read (group, entry, history item, field, tag, attachment ref, custom data item, association, icon, deleted object, kept unknown element) plus its text bytes, and the attachment content the model holds (LD-90), added to one counter as each is read (LD-85) |

Exemption from text: base64 attachment text in the document is not held to the text limit. This means version 3 `Meta/Binaries/Binary` items, and inline `Entry/Binary/Value` text in either version. The document limit bounds it instead, so such an attachment can hold up to about three quarters of the document limit (about 384 MiB at this value). Compressed attachment items inside the document are gunzipped separately, after this payload step. Their decompressed size is bounded by one attachment and all attachments (FMT-13.20), because the document limit does not bound it. Icon `Data` text is not exempt.

Reference: no limit of any kind. Observed: a 0.5 MB demo vault holding a 512 MiB attachment of zero bytes opened in 0.9 s, with peak memory of 1.1 GB.

### Errors

FMT-08.13 Error kinds (`larsal-format/error.rs`). Messages come from APP-06. No error, log line or `Debug` output may contain key bytes, IV, decrypted bytes or decompressed bytes.

| Case | Kind |
|---|---|
| Compression flag not 0 or 1 | `Unsupported` |
| IV or nonce length wrong for the cipher (raised at header parse, before key derivation; FMT-02.11, CRY-01.9) | `Unsupported` |
| Compression flag field not 4 bytes; compression flag field missing (FMT-02.23) | `Corrupt` |
| Version 4 CBC ciphertext empty or not a multiple of 16; bad padding in version 4 (FMT-08.5) | `Corrupt` |
| Version 3 file that ends before the final hashed block is complete (FMT-08.2, FMT-07) | `Corrupt` |
| Any gzip problem (FMT-08.6), trailing bytes (FMT-08.7) | `Corrupt` |
| Over a limit (FMT-08.12) | `TooLarge` |
| Version 3 start bytes mismatch | `WrongKey` (FMT-05) |
| Read failure of the underlying source | `Io` |

FMT-08.14 An empty plaintext (no data at all, or only CBC padding) is `Corrupt`, because a payload always holds at least the inner header (version 4) or a document (version 3). The reference also fails on it.

## Edge cases and errors

- Compression flag `02 00 00 00`: `Unsupported`. The reference says the compression algorithm is unsupported.
- Compression field missing: `Corrupt` (FMT-08.3, FMT-02.23). Reference difference: the reference treats the payload as gzip. Observed in the installed version: such a file opens when the payload is gzip and fails when it is plain.
- ChaCha20 id with an 8-byte or 24-byte field 7: `Unsupported` (FMT-08.4). The reference opens both (CRY-01 edge cases).
- CBC ciphertext of 37 bytes inside valid blocks: `Corrupt` (FMT-08.5).
- Version 4, bad padding with a correct key and valid MACs: `Corrupt` (LD-03). The reference opens it.
- Version 3 file with 1, 16 or 4,096 bytes appended: opens, and the extra bytes are ignored (FMT-08.2, LD-01). The installed reference opens it too (observed).
- Version 3, bad padding or extra plaintext after the final hashed block: opens (FMT-08.2, FMT-08.5, LD-01). The reference opens it too, except a bad padding in a last cipher block that also holds the end of the final hashed block, which fails there (FMT-07.11).
- 16 extra ciphertext bytes inside valid blocks: the old padding block becomes data, and the result is `Corrupt` either from the padding check or from the trailing bytes (FMT-08.7). The reference opens it when the payload is gzip (trailing bytes ignored) and fails when it is plain.
- A gzip header carrying FEXTRA, FNAME, FCOMMENT and a correct FHCRC: accepted. A wrong FHCRC, a reserved flag bit set, or CM other than 8: `Corrupt`. The installed reference behaves the same.
- Gzip trailer CRC32 or ISIZE wrong, or the trailer missing: `Corrupt`, always. The installed reference rejects these through read side effects, but not at every buffer boundary (observed, Sprint 2 Verify): it reads in 16 KiB pieces and stops at the root end tag, so when the unpacked length is at or just past a 16,384-byte boundary it accepts a wrong CRC, a wrong length or no trailer. Larsal stays strict (LD-84); differential fuzzing (AT-A11) lists this as a known difference.
- Junk after the gzip member, or two members: `Corrupt` (FMT-08.7, LD-02). The reference ignores the junk.
- Plaintext larger than a limit: `TooLarge`. Memory stays near the limit, never above it plus a small working buffer (AT-A06).
- Twofish payloads: same layering as AES-256-CBC (observed by Verify in Sprint 2: a scratch copy of a demo version 4.1 vault, encrypted with Twofish-256-CBC through libgcrypt 1.12.1 with `K_enc`, the 16-byte IV of field 7 and PKCS#7 padding, cipher id `AD 68 F2 9F ...` and a re-signed header, opened in the installed CLI, which reported Twofish 256-bit; the CLI's own re-save of it decrypted with libgcrypt the same way, and both files opened in Larsal's reader). The Twofish known-answer vectors belong to CRY-01.

## Security notes

- Integrity comes from FMT-05, FMT-06 and FMT-07, not from this layer. Gzip CRC32 and CBC padding are not security checks. Still, Larsal never uses data before every layer has been checked (FMT-08.11). The promise to tamperers in plan/security.md is never to show half-checked data (SF-06, AT-A03, AT-A04).
- Padding oracle: in version 4 the padding is checked only after all MACs pass, with one error for any decrypt failure (LD-04). In version 3 the padding is never checked (LD-01), and every hashed block failure after the start bytes maps to the same `Corrupt` (AT-B07).
- Bytes after the logical end (FMT-08.1, FMT-08.2, LD-01) lie outside the checked data. Larsal never reads them as content, so they cannot change what Larsal shows, and never writes them: a save writes the whole file fresh (SF-06, AT-A03). Cuts and swaps inside the block stream still fail (FMT-06, FMT-07).
- Decompression bomb: streaming counts with hard limits. No allocation from declared sizes (AT-A06, SF-11). The reference has no limit, so Larsal is stricter here.
- The compression flag, cipher id and IV are public header data. They hold no secret (SF-12). The final key and all plaintext are secrets. Keep them in `SecretBytes`, wipe working buffers (decrypt buffers, inflate output buffers) after use, and never log them (AT-C06).
- Fresh IV or nonce on every save (SF-07, AT-B03). Reusing a ChaCha20 nonce with the same key would expose the XOR of two payloads.
- Hostile documents inside valid encryption are possible for anyone holding a demo key: AT-A08 and AT-A11 cover them. The stricter rules in FMT-08.5 (version 4) and FMT-08.7 change differential results only for such crafted files.

## Test cases

All hex is shown byte by byte. K = `00 01 02 … 1F` (32 bytes). Payload vector G = gzip("hello") as written with the reference's settings:
`1F 8B 08 00 00 00 00 00 00 13 CB 48 CD C9 C9 07 00 86 A6 10 36 05 00 00 00` (25 bytes).

| Case | Given | When | Then |
|---|---|---|---|
| T08-01 (FMT-08.4, FMT-08.1) | AES-256-CBC, key K, IV `A0 A1 … AF`, ciphertext `B9 94 AC 0F EC A7 00 C7 CF 21 10 83 F9 3A 67 F2 50 CE 69 12 25 E0 10 04 BC 56 F0 4F C4 6A 11 63` | Decrypt | Plaintext = G. The last raw block ends in `07`×7. Gunzip gives `68 65 6C 6C 6F` ("hello"). |
| T08-02 (FMT-08.4) | ChaCha20, key K, nonce `C0 C1 … CB`, ciphertext `1A B9 7D E8 D0 61 2B 20 DF D5 0F FC BB DD 0D AC 60 A9 C9 C9 25 19 8D F6 B0` | Decrypt with block counter 0 | Plaintext = G. Decrypting this ciphertext with block counter 1 instead (keystream starting `19 F8 2F 84`) gives `03 41 52 6C …`, which is wrong. Encrypting G with counter 1 would give `06 73 27 84 …`. |
| T08-03 (FMT-08.5) | AES-256-CBC, key K, IV `A0 … AF`, plaintext "0123456789abcdef" (16 bytes) | Encrypt | 32 bytes `CE 1C F3 A4 E3 B8 7B 13 9B A3 CF F1 0A CE 35 B6 06 D9 6B 2E 18 4B F2 2B 73 D3 1B A4 BE 14 D8 C9`. The second block decrypts to `10`×16. |
| T08-04 (FMT-08.5) | Version 4 demo vault with a correct key and valid block MACs, last plaintext block padded `00`×16 | Open | `Corrupt` (LD-03), nothing returned. The reference opens it. |
| T08-05 (FMT-08.5) | Valid vault whose ciphertext has 5 extra bytes inside valid MAC blocks (length not a multiple of 16) | Open | `Corrupt` |
| T08-06 (FMT-08.3) | Header field 3 = `02 00 00 00` | Open | `Unsupported` |
| T08-07 (FMT-08.3) | Header field 3 two bytes long | Open | `Corrupt` |
| T08-08 (FMT-08.6) | Bytes G | Gunzip | "hello", CRC32 `3610A686`, ISIZE 5 |
| T08-09 (FMT-08.6) | G with the byte at offset 17 (first CRC32 byte, `86`) changed to `87` | Gunzip | `Corrupt` |
| T08-10 (FMT-08.6) | G with the byte at offset 21 (first ISIZE byte, `05`) changed to `04` | Gunzip | `Corrupt` |
| T08-11 (FMT-08.6) | G without its last 8 bytes | Gunzip | `Corrupt` |
| T08-12 (FMT-08.6) | Gzip member with FLG `1E` (FEXTRA, FNAME, FCOMMENT, FHCRC), correct header CRC16, MTIME 123456, XFL 2, OS `FF` | Open demo vault | Opens, same content |
| T08-13 (FMT-08.6) | Same member with a wrong header CRC16; separately FLG with bit `20` set; separately CM = `07` | Open | `Corrupt` each time |
| T08-14 (FMT-08.6) | Flag 1, payload zlib-wrapped (`78 9C …`) | Open | `Corrupt` |
| T08-15 (FMT-08.7) | Valid gzip member followed by 20 bytes "GARBAGE-AFTER-MEMBER" inside valid encryption | Open | `Corrupt` (LD-02). The reference opens it. |
| T08-16 (FMT-08.7) | Payload as two gzip members, split at decompressed byte 200 | Open | `Corrupt` |
| T08-17 (FMT-08.8) | Flag 1 with a plain payload; separately flag 0 with a gzip payload | Open | `Corrupt` each time. The second fails in the inner header parse. |
| T08-18 (FMT-08.9) | Any vault | Larsal saves with compression on | The plaintext starts `1F 8B 08 00 00 00 00 00 00 13`. Gunzip returns exactly U. The reference CLI `ls` opens the file. |
| T08-19 (FMT-08.10, FMT-08.3) | Vault with compression off | Larsal saves | Field 3 = `00 00 00 00`. The plaintext starts with inner header byte `01` (FMT-09). The reference CLI opens it. |
| T08-20 (FMT-08.11) | Valid vault whose last data block MAC is changed | Open with a streaming reader | `Corrupt`. No entry, attachment or field value reached the caller. |
| T08-21 (FMT-08.12) | 0.5 MB demo vault whose payload inflates to 512 MiB plus a few bytes (one zero-filled attachment); test limit total set to 64 MiB | Open | `TooLarge` naming total. Peak memory under 64 MiB plus 8 MiB. |
| T08-22 (FMT-08.12) | Decompressed payload of exactly the test limit total; then that limit + 1 | Open | First opens; second `TooLarge` |
| T08-23 (FMT-08.2) | The reference test vault "ProtectedStrings" (version 3.1, AES-KDF 6000 rounds, password "masterpw", gzip header `1F 8B 08 00 00 00 00 00 04 00`) | Open | Start bytes match. The document begins with `3C 3F 78 6D 6C` ("<?xml"). |
| T08-24 (FMT-08.2) | Same vault, password "wrong" | Open | `WrongKey` from the start-bytes check, before any hashed block is read |
| T08-25 (FMT-08.13) | Every error case in this table | Format the error with `Display` and `Debug` | No key, IV, plaintext or password bytes in the text |
| T08-26 (FMT-08.3) | Version 4 demo vault without header field 3, gzip payload; the same file with a plain payload | Open | `Corrupt` each time, raised at header parse before key derivation. The reference opens the first (payload treated as gzip) and fails on the second (observed). |
| T08-27 (FMT-08.14) | AES-256-CBC payload that is only one padding block (empty plaintext) | Open | `Corrupt` |
| T08-28 (FMT-08.4) | AES cipher id with a 12-byte field 7; ChaCha20 id with field 7 of 8, 16 and 24 bytes | Open | `Unsupported` each time, before key derivation (no KDF run). The reference rejects the 12-byte AES IV and the 16-byte nonce, and opens the 8- and 24-byte nonces (CRY-01). |
| T08-29 (FMT-08.1) | Demo vault with version bytes `01 00 04 00` and one with `00 00 04 00`, same payload | Open | Both decode the same way |
| T08-30 (FMT-08.1, FMT-08.2, FMT-08.9) | Two demo vaults made by the reference CLI with password "demo-pass-1". A: `db-create -p`, which always gives version 3.1 (FMT-01.25; file bytes 8 to 11 = `01 00 03 00`). B: the v40-password recipe (FMT-01.29 gap table: export A to XML, add one custom data item to the root group, `import -p`), which gives version 4.0 (bytes 8 to 11 = `00 00 04 00`). | Open each, then inspect the decrypted data | Both decode, and in both the gzip header is `1F 8B 08 00 00 00 00 00 00 13`. In A it starts the joined hashed-block data H, and in B it starts the plaintext P. A: there is no inner header, and the gunzipped data starts with the document, `3C 3F 78 6D 6C` ("<?xml"). B: U begins `01 04 00 00 00 03 00 00 00 02 40 00 00 00`, then a 64-byte stream key, and the document after the end field begins `3C 3F 78 6D 6C`. Observed with the installed CLI 2.7.11. |
| T08-31 (FMT-08.12) | Test limits: document 1 MiB, total 64 MiB. Vault A: version 4, one entry whose Notes holds 2 MiB of "a" (document about 2 MiB). Vault B: version 4, a 2 MiB attachment of zero bytes in the inner header and a small document. | Open each | A: `TooLarge` (document limit). B: opens, because inner header bytes count only toward the total. |
| T08-32 (FMT-08.12) | Test limits: document 4 MiB, total 64 MiB, text 1 MiB. Version 3 demo vault holding one 2 MiB attachment of random bytes (base64 text about 2.7 MiB) | Open | Opens: the base64 pool item is not held to the text limit. The same vault with a 4 MiB attachment (base64 text about 5.3 MiB): `TooLarge` (document limit). |
| T08-33 (FMT-08.12) | Test limits: depth 8, text 1,048,576 bytes, document 8 MiB. Doc A: the deepest element is at depth 8 as FMT-10.2 counts it (9 elements open, root included). Doc B: the deepest element is at depth 9 (10 open). Doc C: one Notes value of 1,048,576 "a" characters, each written as the character reference `&#97;` (about 5 MiB of raw text). Doc D: the same with 1,048,577 characters. | Open each | A opens. B: `TooLarge` naming depth. C opens, because text is counted after references are replaced. D: `TooLarge` naming text. |
| T08-34 (FMT-08.12) | Test limits lowered one at a time, the others left at their defaults: elements 100; then 3 for each of groups, entries, entry elements, history, strings, attachments, associations, kept unknown elements, pool items, icons, custom data items, custom data items in all and deleted objects | Open, for each limit, a demo vault with exactly the limit, then one with one more | Exactly the limit opens. One more gives `TooLarge` naming that limit. A history item's strings count toward strings. History items do not count toward entries, but they count toward entry elements. |
| T08-35 (FMT-08.12) | Test limit total 1 MiB. Open vault, then Larsal adds a 2 MiB attachment to an entry | Larsal saves | `TooLarge`. The old file is byte for byte unchanged. |
| T08-36 (FMT-08.2, FMT-08.11) | Version 3.1 demo vault made by the reference CLI `db-create -p` with password "demo-pass-1" (file bytes 8 to 11 = `01 00 03 00`). Three copies with 1, 16 and 4,096 random bytes appended to the file | Open each | Each opens with the same groups and entries as the untouched vault, and the appended bytes are never decrypted as content (LD-01). The installed reference CLI `ls` opened all three (observed 2026-10-25). The untouched file with its last 17 bytes removed: `Corrupt`, because the 40-byte final hashed block always reaches into the cipher block before the last one, so it is no longer complete. |
| T08-37 (FMT-08.2, FMT-08.5) | Version 3 AES-256 demo vault whose hashed block data is laid out so that the plaintext before the padding is a multiple of 16, re-encrypted with its own key and IV: (a) with its last block `00`×16 instead of `10`×16; (b) with the 8 bytes "TRAILING" between the final hashed block and a valid padding | Open each | Both open with the same content as the untouched vault (LD-01). The reference opens both (observed, FMT-07.11). Compare T08-04: in version 4 a bad padding is `Corrupt`. |

## How this was learned

- Read in the reference source: the version 4 and version 3 readers and save routines, the shared header reader (compression flag and IV handling), the cipher stream layer (block buffering, when the final block is unpadded), the cipher wrapper (cipher id table, IV sizes, block sizes, padding scheme names), and the gzip stream layer (inflate and deflate settings, what happens at end of stream and on errors).
- Read the reference tests for the format and the cipher layer.
- Built demo vaults with a scratch tool in `/tmp/spec-fmt08-09-13/`, all with the demo password "demo-pass-1" and small Argon2d settings. Opened them with the installed reference CLI 2.7.11 (`ls`, `show`, `attachment-import`) to observe: gzip header variants, trailer damage on small and large documents, trailing junk, two members, zlib wrapping, compression flag values, a missing flag, CBC padding damage, extra ciphertext, empty payload, ChaCha20 payloads, and a 512 MiB decompression case with memory measured.
- Decoded vaults written by the reference CLI to see the gzip header bytes it writes.
- Opened the reference's version 3 test vault "ProtectedStrings" read-only, with the password from the reference tests.
- Round 2 (cross-check fixes): made two demo vaults with the installed CLI 2.7.11 in `/tmp/spec-fmt08-09-13/work/exp6/`, password "demo-pass-1". `db-create -p` gave version 3.1, and the v40-password import recipe (FMT-01.29 gap table) gave version 4.0. Decoded both to get the bytes in T08-30. Gathered the limits proposed in FMT-10, FMT-11, FMT-12, FMT-13, FMT-14 and FMT-15 into the one FMT-08.12 table.
- Round 3 (cross-check fixes): made FMT-08.12 the only limits table, under the card-scoped decision L08-1 (since decided as spec/decisions.md LD-22). Took in the rows that only FMT-11.48 and FMT-14.25 had (entry elements, kept unknown elements, custom data items in all), and settled each value that differed: strings, attachments and associations 100,000 as in FMT-11.48; depth as FMT-10.2 counts it, with depth 512 allowed and 513 over, as in FMT-11.48; icon data bounded by the text limit only, as in FMT-14.25. Raised elements from 16,777,216 to 67,108,864 so that 10,000,000 custom data items can be reached. Searched the reference XML reader and stream layers again for any depth, count or size limit: none.
- Sprint 0 close-out: wrote in the lead rulings (spec/decisions.md) LD-01 (bytes after the final block or the logical end are ignored; version 3 now stops at the final hashed block and no longer checks the padding or the ciphertext length), LD-02, LD-03, LD-04, LD-06, LD-12 and LD-22. Re-ran the appended-bytes case on version 3.1 vaults made with the installed CLI 2.7.11 `db-create -p` in `/tmp/spec-fmt08-09-13/ld01/` (T08-36).
- Computed the vectors with python3 (hashlib, zlib) and the Homebrew openssl tool (AES-256-CBC, ChaCha20, Argon2d).
