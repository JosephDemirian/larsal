# FMT-17 Version 3 differences

Status: reviewed
Epics: E3-S8
Parity rows: SF-01, SF-02, SF-04, SF-05, SF-06, SF-08, SF-11, SF-12

## What it does

Files with major version 3 (3.0, 3.1, any 3.x) and major version 2 (2.x) use the version 3 layout (FMT-01.8). Larsal reads them and never writes them (FMT-16). This card lists everything in that layout that differs from version 4, in the order a reader meets it, so that a Builder can write the version 3 reader from this card plus the cards it points to:

- outer header: 2-byte field lengths, different fields (FMT-17.2 to FMT-17.8);
- key derivation input and the hardware key step (FMT-17.9, FMT-17.10);
- no header hash or HMAC after the header (FMT-17.11);
- the start-bytes check, the only wrong-key signal (FMT-17.13; decided: spec/decisions.md LD-12);
- hashed blocks instead of HMAC blocks (FMT-17.14);
- no inner header; Salsa20 protected-field stream keyed from the outer header (FMT-17.16, FMT-17.17);
- attachments inside the document (FMT-17.18);
- the header hash inside the document (FMT-17.19);
- ISO time text (FMT-17.20);
- 3.0 versus 3.1, and 2.x (FMT-17.21, FMT-17.22).

Details shared with version 4 are not repeated: header field limits in FMT-02, the composite key in FMT-04, the wrong-key rule in FMT-05, hashed blocks in FMT-07, payload decryption and gzip in FMT-08, the protected-field stream in FMT-09, time and binary encodings in FMT-12, attachments in FMT-13.

## Inputs and outputs

Input: the file bytes after detection (FMT-01) has found major version 2 or 3, and the composite key parts (password, key file, hardware key response; FMT-04).

Output: the vault model (same as a version 4 read), or one error kind of FMT-01.33, the one list of kinds: from this card Corrupt, Unsupported, TooLarge, and WrongKey for a start-bytes mismatch (FMT-05.11; decided: spec/decisions.md LD-12); from the key flow the kinds of FMT-04.21 (`NoCredentials`, `KeyFile`, `HardwareKey`). The reader also keeps the header bytes [0, H) to check the header hash (FMT-17.19).

Limits: the whole file is bounded by the total file limit and held in one buffer (FMT-01.31, FMT-01.32); header field lengths are at most 65,535 by the format; every other length (hashed block size, decompressed size, document depth) is bounded by `limits.rs` (FMT-07, FMT-08).

## Rules

### Outer header

FMT-17.1 The first 12 bytes are as in FMT-01.12 with major 2 or 3. The rest of this card applies to every minor value; a 3.x minor of 2 or more opens without a notice (FMT-01.10, decided: spec/decisions.md LD-05).

FMT-17.2 Each header field is: id (1 byte), data length (u16 little-endian, 0 to 65,535), data. This is the only framing difference from version 4, which uses a u32 length (FMT-02.1, FMT-02.2). The header ends after the field with id 0; the reference writes its data as `0D 0A 0D 0A` (length 4) and accepts any length.

FMT-17.3 Header fields used in the version 3 layout, their data, and what each app does when a field is missing (Larsal's limits and checks are in FMT-02; FMT-02.23 is Larsal's required-field rule):

| Id | Field | Data | Reference when missing | Larsal when missing |
|---|---|---|---|---|
| 2 | Cipher id | 16 bytes, one of the cipher ids in FMT-01.24 (AES-256, Twofish or ChaCha20 are all valid in 3.x) | uses AES-256, its model default (FMT-17.6) | Corrupt |
| 3 | Compression flags | u32 LE, 0 (none) or 1 (gzip); other values are Unsupported | uses gzip, its model default (FMT-17.7) | Corrupt |
| 4 | Master seed | exactly 32 bytes | missing-fields error | Corrupt |
| 5 | Transform seed (AES-KDF seed) | exactly 32 bytes | uses a random seed (FMT-17.7) | Corrupt |
| 6 | Transform rounds (AES-KDF rounds) | exactly 8 bytes, u64 LE | uses 1,000,000 rounds (FMT-17.7) | Corrupt |
| 7 | Encryption IV | Reference: any non-empty length in the header; its ChaCha20 setup then also accepts 8 and 24 bytes besides 12 (FMT-02.11). Larsal: exactly 16 bytes for AES-256 and Twofish (CBC), 12 bytes for ChaCha20, otherwise Unsupported (FMT-02.11, CRY-01). The reference writes 16 or 12. | missing-fields error (length 0 counts as missing) | Corrupt (length 0 counts as missing) |
| 8 | Protected stream key | any non-empty length; the reference writes 32 random bytes | missing-fields error (length 0 counts as missing) | Corrupt (length 0 counts as missing; decided: spec/decisions.md LD-23) |
| 9 | Stream start bytes | exactly 32 bytes | missing-fields error | Corrupt |
| 10 | Inner random stream id | exactly 4 bytes, u32 LE: 2 (Salsa20) or 3; 1 and any other value are rejected (FMT-17.8) | uses Salsa20 | uses Salsa20 (optional field) |

A wrong size of field 2, 3, 4, 5, 6, 9 or 10 is Corrupt (the reference rejects each with a size error; FMT-02.7 and on). An unknown 16-byte cipher id is Unsupported (FMT-02.7).

FMT-17.4 Field ids 1 (comment), 11 (KDF map), 12 (public custom data) and any unknown id are skipped in the version 3 layout (observed: a 3.0 file with an added field 1, 11 or 99 opened). The KDF map is never used in 3.x: the KDF is always AES-KDF from fields 5 and 6.

FMT-17.5 Duplicate fields: Larsal treats a repeated defined id (2 to 10 in the version 3 layout) as Corrupt (FMT-02.22). The reference instead uses the last copy of each repeated field (from the source; observed: a Format300 copy with a second field 6, the first copy holding 12,345 rounds and the last one the right 6,000 rounds, opened with "a"). Expected AT-A11 difference.

FMT-17.6 Missing required fields. Larsal: if any of fields 2, 3, 4, 5, 6, 7, 8 or 9 is missing, or field 7 or 8 has length 0, the file is Corrupt (FMT-02.23). The reference reports missing header fields only for fields 4, 7, 8 and 9 (length 0 of field 7 or 8 counts as missing). For fields 2, 3, 5 and 6 it keeps the defaults of its vault model (FMT-17.3, FMT-17.7). A missing field 2 means AES-256 to the reference, so the file opens there when it really is AES-256 encrypted (observed: a Format300 copy without field 2 opened with "a" and listed "Sample Entry"; a copy of the scratch 3.1 vault of Vector L3 without field 2 failed with the header-hash mismatch of FMT-17.19, because the 3.1 header hash covers the changed header). Expected AT-A11 difference.

FMT-17.7 Missing field 5, 6 or 3. Larsal: Corrupt for each (FMT-02.23); these are expected AT-A11 differences. The reference does not require them. It keeps the defaults of a new vault model: legacy AES-KDF with a random 32-byte seed and 1,000,000 rounds, and gzip (from the source):

- Missing field 5: the seed is random, so the derived key is always wrong and the result is the wrong-key message.
- Missing field 6: 1,000,000 rounds are used. A file stored with exactly 1,000,000 rounds (the default of the reference's command line tool, FMT-01.25) therefore passes the start-bytes check (FMT-17.13). It then opens when the document has no header hash element, or one that matches the changed header; otherwise it fails with the header-hash mismatch (FMT-17.19). Any other stored rounds value gives the wrong-key message. Observed: a Format300 copy (6,000 rounds) without field 6 gave the wrong-key message; a copy of the Vector L3 vault (1,000,000 rounds) without field 6 gave the header-hash mismatch; the same copy with its payload re-sealed around an updated header hash element opened, and the reference's info command showed AES-KDF with 1,000,000 rounds.
- Missing field 3: gzip is used. The reference always writes field 3.

FMT-17.8 Field 10 handling. Value 1 (an old stream cipher) and every value other than 2 and 3 are rejected (observed: "invalid inner stream" error, paraphrased). Value 2 means Salsa20. Value 3 is accepted by the reference, but its version 3 reader then still uses Salsa20 (observed: a 3.0 test vault with field 10 changed from 2 to 3 opened and showed the correct protected password). A missing field 10 also means Salsa20. Larsal: value 2 or missing means Salsa20; value 3 is Unsupported (decided: spec/decisions.md LD-10; no tool writes it, and the reference's behavior would show wrong protected values for a file that really used ChaCha20 there).

### Key derivation and checks

FMT-17.9 Key derivation in 3.x (summary; the steps are in FMT-04):

1. The composite key is SHA-256 over the static parts only: the password part (SHA-256 of the UTF-8 password) and the key file part (FMT-18), in that order. The hardware key response is not part of it in 3.x.
2. The transformed key is AES-KDF of the composite key with seed = field 5 and rounds = field 6 (CRY-02).
3. The final cipher key is SHA-256(master seed (field 4) || CR || transformed key), where CR is empty when there is no hardware key, and is SHA-256 of the hardware key response(s) otherwise (FMT-17.10).
4. There is no HMAC key in 3.x.

In version 4 the hardware key response is hashed into the composite key before the KDF, its challenge is the KDF seed, and the final key is SHA-256(master seed || transformed key) (FMT-04).

FMT-17.10 Hardware key in 3.x: the challenge is the 32-byte master seed (field 4); the response (or the responses, joined in order, if there is more than one) is hashed with SHA-256 and that 32-byte value is CR in FMT-17.9 step 3. Challenge padding and the device protocol are in INT-07.

FMT-17.11 There is no header SHA-256 and no header HMAC after the header. The ciphertext starts at H, right after the end-of-header field, and runs to the end of the file (FMT-01.13).

FMT-17.12 The ciphertext is decrypted with the cipher of field 2, the final key and the IV of field 7. AES-256 and Twofish use CBC with PKCS#7 padding; ChaCha20 has no padding (FMT-08, CRY-01). A file the reference writes has a CBC ciphertext whose length is a multiple of 16. Larsal needs only the whole cipher blocks up to the end of the final hashed block (FMT-17.15). The padding and every ciphertext byte after the final hashed block are ignored, whatever their length, so a total length that is not a multiple of 16 is not an error by itself (FMT-01.20, FMT-05.13 step 2; decided: spec/decisions.md LD-01). A ciphertext that ends before the final hashed block is complete is Corrupt. (Larsal-crypto end call for version 3: decided: spec/decisions.md LD-41.)

FMT-17.13 Start-bytes check: the first 32 bytes of the plaintext must equal field 9. If they differ, the result is WrongKey (FMT-05.11; decided: spec/decisions.md LD-12). The reference shows its "invalid credentials" message here (paraphrased). This is the only wrong-key signal in 3.x: hashed block failures, decompression and document errors and a header hash mismatch are Corrupt, and the padding is never checked, so it gives no result at all (FMT-07.11). The check runs before any other part of the plaintext is used (FMT-05).

FMT-17.14 After the 32 start bytes comes the hashed block stream (FMT-07): blocks of block index (u32 LE, counting from 0), SHA-256 of the block data (32 bytes), data size (i32 LE), data; it ends with a block of size 0 whose hash is 32 zero bytes. A wrong index, a negative size, a hash mismatch or a non-zero hash on the final block is Corrupt. The reference writes blocks of 1,048,576 bytes (1 MiB). This replaces the HMAC blocks of version 4, which sit outside the encryption; hashed blocks sit inside it.

FMT-17.15 The hashed block walk ends at the final hashed block; that is the logical end of a version 3 vault (FMT-01.20). Every byte after it, the cipher padding and ciphertext appended to the file included, is ignored: never checked, never decompressed, never parsed, never an error (FMT-07.11; decided: spec/decisions.md LD-01). The reference also stops reading at the final hashed block and ignores bytes appended to the file (observed: a 3.1 demo vault with 1, 16 or 4,096 bytes appended opened). It checks the padding in one case: when the file's last cipher block also holds the end of the final hashed block (CRY-01.10). So a vault whose plaintext before the padding is a multiple of 16, cut by exactly its last 16 bytes (the block that holds only padding), fails in the reference with a no-root-group message and opens in Larsal (observed with an aligned demo vault; cut by 8 bytes it opened in the reference too). Expected AT-A11 difference. When field 3 is 1, the joined block data is one gzip stream (FMT-08); when it is 0, it is the document itself.

### Inside the payload

FMT-17.16 There is no inner header. The joined (and decompressed) block data is the XML document from its first byte, possibly starting with a UTF-8 byte order mark `EF BB BF` (seen in the reference's 2.0 test vault). The document structure is the same as in version 4 (FMT-10, FMT-11) except for FMT-17.18 to FMT-17.20.

FMT-17.17 Protected-field stream (FMT-09): Salsa20 (20 rounds) with key = SHA-256(field 8 data) and the fixed 8-byte nonce `E8 30 09 4B 97 20 5D 2A`. The keystream is used in document order for every protected value the document reader handles, exactly as in version 4 (where ChaCha20 is keyed from the inner header instead). This includes attachment data in the metadata pool and inline attachments (FMT-17.18). A `Protected="True"` value inside a kept unknown element takes no keystream bytes (FMT-09.14; decided: spec/decisions.md LD-24).

FMT-17.18 Attachments are inside the document, not in an inner header (FMT-13):

- The metadata holds a `Binaries` element with one `Binary` element per stored attachment. Its `ID` attribute is a decimal number; its text is base64. With `Compressed="True"` the decoded bytes are a gzip stream of the attachment (the reference writes this attribute, and compresses each attachment, exactly when field 3 is 1). With `Protected="True"` the decoded bytes are first decrypted with the protected-field stream (FMT-17.17), then decompressed if `Compressed="True"`.
- An entry's `Binary` element holds a `Key` (the attachment name) and a `Value` with a `Ref` attribute naming a pool `ID`.
- Older documents (the reference's 2.0 test vault) instead put the attachment data inline: `Value` has no `Ref`, its text is base64 data, possibly with `Protected="True"`.
- The reference writes pool ids 0, 1, 2 and so on, one per distinct attachment content (dedupe per namespace, FMT-13.17), in the order entries are visited (FMT-13).

FMT-17.19 Header hash inside the document: the metadata may hold a `HeaderHash` element whose text is base64 of the SHA-256 of header bytes [0, H). The check is FMT-10.21: after the whole document has been read, take the last `HeaderHash` element and decode it (FMT-12.20, lenient). If the element is missing, empty, or decodes to zero bytes, nothing is checked. Any other value must equal SHA-256 of header bytes [0, H); otherwise, a value of the wrong length included, the file is Corrupt (the reference reports that the header does not match its hash, paraphrased). Observed: a copy of the Vector L3 vault whose header gained a field 1, payload re-sealed, opened with empty header hash text and with `!!!!` (decodes to zero bytes), and failed with the mismatch with `AAAA` (3 zero bytes) and with the original correct hash. Larsal: same as the reference, so an empty element or one that decodes to zero bytes is treated like a missing one (decided: spec/decisions.md default rule, the card's recommendation, together with LD-11). The reference's writer puts it right after the `Generator` element. 3.0 files have no such element. Every 3.1 file written by the reference has one, but the reference also accepts a 3.1 file without it (observed: a 3.0 test vault stamped 3.1 opened). Larsal: accepts a 3.1 file without it too (decided: spec/decisions.md LD-11). If the element is present in a 3.0 file, it is checked too.

FMT-17.20 Times are ISO 8601 text in UTC, for example `2026-10-24T19:10:41Z`. Readers accept both the ISO text and the version 4 base64 form in either version (the reference tries base64 first, then ISO; FMT-12).

FMT-17.21 3.0 versus 3.1: the reference knows only one difference, the header hash element (FMT-17.19). Header fields, key derivation, start bytes, hashed blocks, streams and document are the same.

FMT-17.22 2.x files are read as vaults by the same rules, with this reader, not through import (FMT-01.11; decided: spec/decisions.md LD-06). The extras seen in the reference's 2.0 test vault are inline attachment data (FMT-17.18) and a byte order mark (FMT-17.16, FMT-10.8); its XML declaration also names the encoding in lowercase and its lines end with CR LF, which an XML reader accepts as usual.

FMT-17.23 Document elements that only version 4 writers produce (group and entry custom data, group tags, report exclusion, previous-parent groups, custom icon names, the settings-changed time) are read in 3.x too if present: the reference's document reader does not check the version. Larsal: same (FMT-10, FMT-11, FMT-14).

FMT-17.24 What Larsal does with 3.x: reads it per this card; on save writes version 4 (4.0 or 4.1, FMT-16.18, FMT-16.19), never 3.x. The KDF is carried over as version 4 AES-KDF with the same rounds and a new 32-byte seed, and the user is told once that the vault moves to the newer format (FMT-16.21; decided: spec/decisions.md LD-07). Larsal never writes the protected-field stream key into a public header.

FMT-17.25 Reference writer facts, for the test-only version 3 builder (plan (e) of FMT-01.26: test code in `tests/`, never shipped; decided: spec/decisions.md LD-35; Larsal's product code never writes 3.x): header field order 2, 3, 4, 5, 6, 7, 8, 9, 10, 0; field 8 is 32 random bytes; field 9 is 32 random bytes and is also written as the first 32 plaintext bytes; field 10 is 2; master seed 32 random bytes; field 5 a new 32-byte random seed on every save (CRY-03; the rounds stay); IV 16 random bytes (12 for ChaCha20); hashed blocks of 1 MiB; the header hash element is written; the attachment pool is written in the metadata after the history settings and before the vault custom data.

### Differences in rounds handling

FMT-17.26 Field 6 is a u64. The reference keeps the low 32 bits as a signed 32-bit number; if that number is outside 1 to 2,147,483,646, it uses 1 round, without a message (from the source; CRY-02.13 has observations). So the reference processes 0, 2,147,483,647 and 2,147,483,648 stored rounds with 1 round each, and 4,294,967,301 with 5 rounds. Larsal reads the full u64 value and accepts only 1 to 2,147,483,646; any other stored value is Unsupported, before any KDF work, with no capping and no substitute value (CRY-02.13, FMT-02.17, AT-A05). This is a known difference for differential fuzzing (AT-A11).

## Edge cases and errors

| Case | Reference | Larsal |
|---|---|---|
| Field 4, 5 or 9 not 32 bytes | Size error | Corrupt |
| Field 6 not 8 bytes | Size error | Corrupt |
| Field 2 not 16 bytes | Cipher id length error | Corrupt (FMT-02.7) |
| Field 2 of 16 bytes but not a known cipher id | Rejected | Unsupported (FMT-02.7) |
| Field 3 not 4 bytes, or value above 1 | Error | Corrupt (size) / Unsupported (value) |
| Field 10 = 1 or 9 | Rejected (observed) | Unsupported |
| Field 10 = 3 | Accepted, Salsa20 used (observed) | Unsupported (LD-10) |
| Field 10 missing | Salsa20 | Salsa20 |
| Field 4, 7, 8 or 9 missing (or 7 or 8 of length 0) | Missing-fields error | Corrupt |
| Field 2 missing | AES-256 used; an AES-256 file opens (observed with Format300; a 3.1 file fails the header hash, FMT-17.19) | Corrupt (FMT-17.6; AT-A11 difference) |
| Field 3 missing | gzip used | Corrupt (FMT-17.7) |
| Field 5 missing | Random seed used: wrong-key message | Corrupt (FMT-17.7) |
| Field 6 missing, stored rounds were 1,000,000 | 1,000,000 used: key check passes; opens without a header hash element or with a matching one, else header-hash mismatch (observed with the Vector L3 vault) | Corrupt (FMT-17.7; AT-A11 difference) |
| Field 6 missing, any other stored rounds | Wrong-key message (observed with Format300) | Corrupt (FMT-17.7) |
| A defined field (2 to 10) repeated | Last copy used (observed with field 6 in Format300) | Corrupt (FMT-17.5, FMT-02.22; AT-A11 difference) |
| Wrong password, wrong key file, missing hardware key | "invalid credentials" (paraphrased), from the start bytes (observed) | WrongKey (FMT-05.11, LD-12); same result for every wrong case (AT-A01). A hardware key that cannot be asked at all is `HardwareKey` (FMT-04.10) |
| Header byte changed in a 3.1 file (observed with field 10) | Header hash mismatch after decrypting | Corrupt |
| Header byte changed in a 3.0 file outside the key fields | Not found; opens (observed with fields added or field 10 changed) | Same; the format has no check |
| `BrokenHeaderHash` test vault (protected stream key changed in the header) | Header hash mismatch (observed) | Corrupt |
| CBC ciphertext length not a multiple of 16 because bytes were appended to the file | Ignored; opens (observed with 1 byte appended) | Same: opens (FMT-17.12, LD-01) |
| CBC ciphertext cut before the end of the final hashed block | Error | Corrupt (FMT-17.12) |
| CBC ciphertext cut by exactly the 16-byte block that holds only padding (plaintext before the padding a multiple of 16) | "No root group" (observed): its last cipher block now holds the end of the final hashed block, so its padding check fails (CRY-01.10) | Opens (FMT-17.15, FMT-07.11, LD-01); expected AT-A11 difference |
| Bytes after the final hashed block (the padding, and bytes appended to the file) | Appended bytes ignored; opens (observed with 1, 16 and 4,096 bytes). The padding is checked in one case (CRY-01.10) | Ignored, the padding never checked (FMT-17.15, FMT-07.11, LD-01) |
| Stored rounds outside 1 to 2,147,483,646 (0, 2,147,483,647 and above) | Low 32 bits as signed; outside 1 to 2,147,483,646 runs 1 round, else the cut value (FMT-17.26) | Unsupported, before any KDF work (CRY-02.13, FMT-02.17) |
| 3.1 file without a header hash element | Accepted (observed) | Accepted (LD-11) |
| Header hash element empty, or its text decodes to zero bytes | Not checked; opens even when the header was changed (observed) | Same (FMT-10.21; default rule, with LD-11) |
| Header hash element that decodes to 1 or more bytes but not the right 32 (wrong length or wrong value) | Header-hash mismatch (observed with `AAAA`) | Corrupt |
| Hashed block index out of order, or bad hash | Error | Corrupt (FMT-07) |

## Security notes

- Version 3 integrity is weaker than version 4: there is no keyed check of the header, header tampering is found only after the whole payload is decrypted and parsed (and never in 3.0), and a wrong key is found only through the start bytes after decrypting the first block (SF-05, SF-06). Larsal must not show or use any document data before the start-bytes check, the hashed-block checks and, when present, the header hash check have all passed (AT-A02, AT-A03).
- The protected-field stream key (field 8) and the start bytes (field 9) are in the clear header. Protected fields in a 3.x file are therefore protected only by the outer encryption. Larsal never writes this layout (SF-08, SF-12).
- The start bytes give a known plaintext for the first cipher block by design of the format. A wrong key is found at the start bytes (WrongKey, LD-12). The padding is never checked (FMT-07.11, CRY-01.10), so there is no padding result at all, with or without the key. AT-B07 is read this way (LD-04).
- Bytes appended after the final hashed block are ignored for parity (LD-01). They must never reach the decompressor or the parser, and Larsal's next save drops them (Larsal writes version 4 only).
- The AES-KDF rounds come straight from the file: refuse values beyond the CRY-02 limits before any work, and never fall back silently to a weaker value (FMT-17.26, AT-A05).
- Hashed block sizes come from the decrypted stream: check each against `limits.rs` before allocating (AT-A04, AT-A06).
- Saving a 3.x vault in Larsal raises it to version 4 (FMT-16.18; KDF carry-over per FMT-16.21, decided: spec/decisions.md LD-07), which restores keyed integrity on the next save (AT-A09). The rounds never go down (FMT-16.23).

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| FMT-17.1 any minor | Format300 copies stamped 3.0, 3.1, 3.2, 3.65535 (password "a") | Open | All open; root group "Format300" |
| FMT-17.2 2-byte lengths | Vector L3 below | Parse | Fields 2 (16), 3 (4), 4 (32), 5 (32), 6 (8), 7 (16), 8 (32), 9 (32), 10 (4), 0 (4); H = 222 (0xDE) |
| FMT-17.3 field values | Vector L3 | Read fields | Cipher AES-256; compression 1; rounds = `40 42 0F 00 00 00 00 00` = 1,000,000; field 10 = 2 |
| FMT-17.3 size errors | Vector L3 with field 9 length 31 (data shortened, H shifted) | Parse | Corrupt |
| FMT-17.3 cipher id size | Vector L3 with field 2 length 15 (last data byte removed, H shifted) | Parse | Corrupt |
| FMT-17.4 skipped fields | Format300 copies with an added field 1 (5 bytes), 11 (3 bytes) or 99 (2 bytes) | Open with "a" | Each opens (observed) |
| FMT-17.5 duplicate field | Vector L3 with a second field 10 (`0A 04 00 02 00 00 00`) inserted at offset 0xD7, before the end field (H becomes 229) | Larsal parses | Corrupt (FMT-02.22) |
| FMT-17.5 reference uses last copy | Format300 copy with an extra field 6 holding 12,345 rounds (`06 08 00 39 30 00 00 00 00 00 00`) inserted before the original field 6 (6,000 rounds) | Open with "a" | Larsal: Corrupt. Reference: opens, lists "Sample Entry" (observed) |
| FMT-17.6 missing required | Vector L3 header with field 9 removed | Parse | Corrupt (reference: missing-fields error) |
| FMT-17.6 missing cipher | Format300 copy with field 2 (19 bytes at offset 12) removed | Open with "a" | Larsal: Corrupt. Reference: opens with AES-256, lists "Sample Entry" (observed) |
| FMT-17.6 missing cipher, 3.1 | `password-only.larsalvault` copy with field 2 (19 bytes at offset 12) removed | Open with `demo-pass-1` | Larsal: Corrupt. Reference: header-hash mismatch (observed on the Vector L3 vault) |
| FMT-17.7 missing rounds, 1,000,000 stored | `default-time.larsalvault` copy (1,000,000 rounds) with field 6 (11 bytes at offset 0x6C) removed | Open with `demo-pass-3` | Larsal: Corrupt. Reference: header-hash mismatch, so the key check passed (observed on the Vector L3 vault) |
| FMT-17.7 missing rounds, re-sealed | The same `default-time` copy with its payload re-encrypted around a `HeaderHash` that matches the shortened header (test tool, plan (e)) | Open with `demo-pass-3` | Larsal: Corrupt. Reference: opens; its info command shows AES-KDF, 1,000,000 rounds (observed on the Vector L3 vault) |
| FMT-17.7 missing rounds, other value | Format300 copy (6,000 rounds) with field 6 removed | Open with "a" | Larsal: Corrupt. Reference: wrong-key message (observed) |
| FMT-17.7 missing seed | Format300 copy with field 5 removed | Open with "a" | Larsal: Corrupt. Reference: wrong-key message (observed) |
| FMT-17.7 missing compression | Vector L3 header with field 3 removed | Larsal parses | Corrupt |
| FMT-17.8 stream id | Format300 copies with field 10 = 1, 9, 3 | Open with "a" | 1 and 9: Unsupported (reference: rejected, observed); 3: Larsal Unsupported (LD-10; reference: opens with Salsa20, observed) |
| FMT-17.9 key flow | Vector L3, password `demo-pass-1`, no key file | Derive | Password part `89FE410C 581E0E30 9E8852E2 67653DA9 15198960 0138C790 1B635DB0 E4BD46C3`; composite key `CA6C3AA4 439AE1DE BE011A79 5F6E0BD9 5CE30FDD E4CA7FAC 92395588 EEDDF7A2`; AES-KDF output before hashing `D9813D57 D04BDCAF 6C485569 35A51128 FCFA13D6 2307513C 26E05B15 8C23EDCE`; transformed key `ACBFEEFF 70B21EF0 B85E79D0 442887C2 97E0DB34 A7A02EB2 5ECF9E53 69736785`; final key `A55252A5 9D717D59 109E3F56 C92E5ED5 26F4E60C 6718A58A FF379C45 BA527771` |
| FMT-17.10 hardware key step | A 3.1 vault with a hardware key (plan (c) or (e)) and a software response | Derive and open | Opens only when SHA-256(response) is placed between master seed and transformed key; with the response hashed into the composite key instead (version 4 way): WrongKey |
| FMT-17.11 no check bytes | Vector L3; `password-only.larsalvault` | Locate the ciphertext | It starts at offset 222, directly after the end field |
| FMT-17.12 CBC length | `password-only.larsalvault`, `default-time.larsalvault`, `rich-v3.larsalvault` | Check | File size minus 222 is a multiple of 16 for each (AES-256-CBC) |
| FMT-17.12 odd length after the end | `password-only.larsalvault` with 1 byte (`00`) appended, so the ciphertext length is 1 more than a multiple of 16 | Open with `demo-pass-1` | Opens with the same content (LD-01; reference: opens, observed) |
| FMT-17.12 cut ciphertext | `password-only.larsalvault` without its last 48 bytes; and without its last 47 bytes | Open with `demo-pass-1` | Corrupt for each (the final hashed block is incomplete), never WrongKey |
| FMT-17.13 start bytes | Vector L3 ciphertext start `CA D3 FE 0F 32 C9 F0 15 99 97 B2 D8 44 AC FD C1 26 90 BC 24 26 C8 ED 29 C6 E5 D4 EA 04 E6 83 B4`, IV `9B B8 89 95 35 B4 6B E0 42 33 5A 17 C5 63 1B 32`, the final key above | AES-256-CBC decrypt these 32 bytes | `6C CB 4E 01 E7 25 E9 FE 0C 32 66 41 3B 49 5B B8 69 CF FC 15 82 67 E3 55 60 39 DC 78 56 18 D2 30`, equal to field 9: key accepted |
| FMT-17.13 wrong key | `password-only.larsalvault` with password `wrong`; `password-and-keyfile.larsalvault` with `demo-pass-2` and no key file | Open | WrongKey (FMT-05.11, LD-12) (reference: "invalid credentials", observed) |
| FMT-17.14 hashed blocks | `password-only.larsalvault` decrypted with `demo-pass-1` | Walk blocks | Block 0: index 0, hash matches its data; block 1: index 1, size 0, hash all zeros. A vault this small has one data block, because the reference writes 1 MiB blocks |
| FMT-17.15 end of plaintext | `password-only.larsalvault` decrypted | After the final block | Only the PKCS#7 padding remains (1 to 16 bytes) |
| FMT-17.15 padding never checked | A version 3 AES-256 demo vault whose plaintext before the padding is a multiple of 16 (test-only builder, plan (e), password `demo-pw`), with its last 16 ciphertext bytes removed; separately the same vault with its last 16 ciphertext bytes replaced by random bytes | Open with `demo-pw` | Both open with the same content; no padding byte reaches the decompressor or parser (spy). Reference: the cut copy fails with a no-root-group message, the replaced copy opens (observed): expected AT-A11 difference |
| FMT-17.15 appended bytes ignored | `password-only.larsalvault` with 16, then 4,096 random bytes appended | Open with `demo-pass-1` | Opens with the same content; the appended bytes never reach the decompressor or the parser (spy) (LD-01; reference: opens, observed) |
| FMT-17.16 byte order mark | Format200 (password "a") | Decrypt and parse | Document starts with `EF BB BF`; parses |
| FMT-17.17 Salsa20 stream | ProtectedStrings (password "masterpw") | Open | Entry "Sample Entry": user name "Protected User Name", password "ProtectedPassword", custom field TestProtected = "ABC" (protected), TestUnprotected = "DEF" (not protected) |
| FMT-17.17 unknown element takes no keystream | A 3.1 document made by the test builder (plan (e)) whose metadata holds a kept unknown element `<FooBar><Value Protected="True">QUJD</Value></FooBar>` before the root group, and one entry with protected password `demo-entry-pass-1`, encrypted with the Salsa20 stream skipping the unknown value | Open | The entry password reads `demo-entry-pass-1`; the unknown element is kept with its text `QUJD` unchanged (FMT-09.14, LD-24) |
| FMT-17.18 pool attachments | `rich-v3.larsalvault` decrypted with `demo-pass-4`; separately the base64 text `H4sIAAAAAAAAE0tJzc1XSCwpSUzOyE3NK+ECAH7YfX8QAAAA` (the pool item the reference wrote for the 16-byte attachment "demo attachment" plus a line feed, observed on the Vector L3 vault) | Decrypt and read; decode the text | `Binaries` comes after `HistoryMaxSize` and before `CustomData`, with `Binary` items `ID="0"` to `ID="3"`, each `Compressed="True"`; the empty attachment is `<Binary ID="1" Compressed="True"/>` with no gzip data (FMT-13.5); each other item gunzips to the bytes in `rich-v3.json`; entries point at them by `Value Ref`, and the two shared attachments both use `Ref="3"`. The text decodes to gzip (header bytes `1F 8B 08 00 00 00 00 00 00 13`) that decompresses to `64 65 6D 6F 20 61 74 74 61 63 68 6D 65 6E 74 0A` |
| FMT-17.18 inline attachments | Format200 | Open | Entry "Sample Entry" has attachments myattach.txt = "abcdefghijk" and test.txt = "this is a test"; its second history entry has myattach.txt |
| FMT-17.19 header hash | Vector L3; `password-only.larsalvault` | SHA-256 of bytes [0, 222); decrypt and read `HeaderHash` | For Vector L3: `2B985B7D EB7F246F 5D67329A 7B0E0E9F 65519B86 DD055AAE A0A95831 36B4792C`, so its document holds `HeaderHash` = `K5hbfet/JG9dZzKaew4On2VRm4bdBVquoKlYMTa0eSw=` (observed). For `password-only.larsalvault`: the base64-decoded `HeaderHash` equals the SHA-256 of its own first 222 bytes |
| FMT-17.19 mismatch | BrokenHeaderHash (empty password) | Open | Corrupt (reference: header hash mismatch, observed) |
| FMT-17.19 3.0 without hash | Format300 | Open | Opens; no header hash element |
| FMT-17.19 3.1 without hash | Format300 copy stamped 3.1 (password "a") | Open | Opens (LD-11; reference: opens, observed) |
| FMT-17.19 empty hash switches the check off | `password-only.larsalvault` copy whose header gained a field 1 (so header bytes change), payload re-encrypted by a test tool (plan (e)) with the `HeaderHash` text set to empty, then to `!!!!` | Open with `demo-pass-1` | Opens in both apps (reference observed on the Vector L3 vault; Larsal per FMT-10.21) |
| FMT-17.19 short hash value | The same copy with `HeaderHash` text `AAAA` (decodes to `00 00 00`), then with the original correct hash of the unchanged header | Open with `demo-pass-1` | Corrupt (reference: header-hash mismatch, observed for both) |
| FMT-17.20 time text | `2026-10-24T19:10:41Z` in a 3.1 document | Decode | 63,928,465,841 seconds since 0001-01-01 UTC; the same instant as base64 `sflu4g4AAAA=` in version 4 |
| FMT-17.21 3.0 = 3.1 layout | Headers of Format300 (3.0) and Vector L3 (3.1) | Parse | Same field ids, sizes and order |
| FMT-17.22 version 2 | FileKeyBinary, FileKeyHex, FileKeyHashed (version 2.4) with their key files only | Open | Each opens; metadata name is the stem followed by " Database" |
| FMT-17.23 version 4 elements in 3.x | A 3.1 document holding group custom data (made by a test tool, plan (e)) | Open | The custom data is read |
| FMT-17.24 Larsal never writes 3.x | `password-only.larsalvault` opened and saved in Larsal | Read back | Version 4.0, version 4 layout, AES-KDF in the KDF map with the rounds of field 6 and a new 32-byte seed (FMT-16.21, LD-07) |
| FMT-17.25 writer facts | Every 3.1 vault in `testdata/` (written by the reference) | Parse | Field order 2, 3, 4, 5, 6, 7, 8, 9, 10, 0; field 8 and 9 each 32 bytes; field 10 = 2 |
| FMT-17.26 rounds out of range | Vector L3 with the 8 field 6 data bytes at offset 0x6F replaced by `00 00 00 00 00 00 00 00` (0), `FF FF FF 7F 00 00 00 00` (2,147,483,647), `00 00 00 80 00 00 00 00` (2,147,483,648), `05 00 00 00 01 00 00 00` (4,294,967,301) | Larsal parses | Unsupported for each, before any KDF work; no capping (the reference would run 1, 1, 1 and 5 rounds) |
| FMT-17.26 top of range | Vector L3 with field 6 data `FE FF FF 7F 00 00 00 00` (2,147,483,646) | Larsal parses | Passes the FMT-02.17 range check (CRY-02 may still apply a cost ceiling; the test does not run the KDF) |

Vector L3: the 222 header bytes of a scratch demo vault made by the installed command line tool on 2026-10-24 with db-create, password `demo-pass-1` and default rounds (version 3.1, AES-256, AES-KDF with 1,000,000 rounds, gzip). The file is not stored (FMT-01.29: bytes of tool-made vaults are never pinned); the vector is self-contained: the key flow of FMT-17.9 and the header hash of FMT-17.19 follow from these bytes and the password, and the FMT-17.13 case gives the first 32 ciphertext bytes. "The Vector L3 vault" in this card means that scratch vault, on which the observations so named were made. Offsets in hex.

| Offset | Bytes |
|---|---|
| 0000 | 03 D9 A2 9A 67 FB 4B B5 01 00 03 00 02 10 00 31 |
| 0010 | C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A FF 03 |
| 0020 | 04 00 01 00 00 00 04 20 00 30 16 C0 D9 6D 00 70 |
| 0030 | B5 AF 02 12 73 33 AF DE 72 39 81 A6 2F 5C 20 13 |
| 0040 | A4 9E 54 FC C5 33 33 2C 26 05 20 00 58 21 C9 8B |
| 0050 | 89 6E 99 07 5E 97 0E CE E5 7E 29 F5 D6 CC A2 F9 |
| 0060 | 25 7C 0C 76 0C 5C E7 8F A3 DB 25 1A 06 08 00 40 |
| 0070 | 42 0F 00 00 00 00 00 07 10 00 9B B8 89 95 35 B4 |
| 0080 | 6B E0 42 33 5A 17 C5 63 1B 32 08 20 00 B3 21 CD |
| 0090 | A3 B8 4D 81 6E F4 08 77 77 D9 49 73 77 E4 00 33 |
| 00A0 | AF FA B3 47 C6 AB 70 93 DD 1D 61 51 3E 09 20 00 |
| 00B0 | 6C CB 4E 01 E7 25 E9 FE 0C 32 66 41 3B 49 5B B8 |
| 00C0 | 69 CF FC 15 82 67 E3 55 60 39 DC 78 56 18 D2 30 |
| 00D0 | 0A 04 00 02 00 00 00 00 04 00 0D 0A 0D 0A |

Reading of Vector L3: 0x0C field 2 (length `10 00` = 16, AES-256 id); 0x1F field 3 (4 bytes, 1); 0x26 field 4 (32, master seed `30 16 C0 ...`); 0x49 field 5 (32, transform seed `58 21 C9 ...`); 0x6C field 6 (8, 1,000,000); 0x77 field 7 (16, IV); 0x8A field 8 (32, protected stream key); 0xAD field 9 (32, start bytes); 0xD0 field 10 (4, value 2); 0xD7 field 0 (4, `0D 0A 0D 0A`); H = 0xDE = 222. The 32 ciphertext bytes at offset 222 are given in the FMT-17.13 case.

## How this was learned

- Read in the reference source: the version 3 reader (header field loop with 2-byte lengths, required fields, key derivation with the hardware key step, start-bytes check, hashed block stream, fixed Salsa20 stream, header hash comparison after the document); the shared header-field setters and their size checks; the version 3 writer (field order, random values, start bytes, header hash); the hashed block stream; the protected-stream setup (key hashing and the fixed Salsa20 nonce); the document reader (header hash element, metadata attachment pool, inline attachment values, protected and compressed binaries, the time parser) and the document writer's version 3 branches; the composite key code that keeps the hardware key out of the version 3 transform; the KDF rounds setter.
- Read the reference's unit tests for version 2 and version 3 files (2.0 and 3.0 test vaults, compressed, non-ASCII password, protected strings, broken header hash) and the key file tests on the 2.4 test vaults.
- Ran the installed reference command line tool 2.7.11 on demo vaults and on scratch copies of test vaults: a 3.0 vault stamped with other version numbers, with added header fields, with field 10 set to 1, 3 and 9; a 3.1 demo vault with field 10 changed; the broken header hash test vault; wrong passwords. In review round 1: Format300 copies without field 2, 5 or 6, and with field 6 repeated; copies of the Vector L3 vault without field 2 or 6, one of them with a re-sealed payload; copies of it with an added header field and an empty, undecodable, short or stale header hash element. In review round 2: read the headers of the 3.1 vaults in `testdata/` and decrypted scratch copies of `password-only`, `default-time` and `rich-v3` (start bytes, hashed blocks, header hash, attachment pool). Read the vault model's defaults (cipher, compression, KDF with its seed and rounds) and the version 3 missing-fields test in the source.
- Decrypted a demo 3.1 vault and copies of the 2.0, 3.0 and 3.1 test vaults with a short script using standard hashes and the system's AES command: checked the key flow, start bytes, hashed blocks, gzip, the byte order mark, the inline attachments of the 2.0 document, and that the header hash element equals the SHA-256 of the header bytes.
- Review round 3 (cross-check findings): FMT-17.13 and the rows that expect WrongKey for a start-bytes mismatch now say "per D-05-1 (FMT-05.11)", because that lead decision is still open; read the version 3 reader again in the source (a start-bytes mismatch raises its invalid-credentials error). FMT-17.24 now points to FMT-16.21 (lead to confirm) for the KDF carry-over. The error kinds point to FMT-01.33.
- Sprint 0 close-out: wrote the lead rulings into the card. LD-01 changed FMT-17.12 and FMT-17.15 (bytes after the final hashed block and its padding are ignored; a CBC length that is not a multiple of 16 is no longer an error by itself). LD-12 decided the start-bytes WrongKey (FMT-17.13), LD-10 field 10 = 3, LD-11 and the default rule the header hash cases of FMT-17.19, LD-23 field 8, LD-24 the keystream rule in FMT-17.17, LD-06 version 2 files, LD-07 the KDF carry-over (FMT-17.24), LD-35 the test builder (FMT-17.25), LD-04 the padding security note.
- Sprint 1 close-out: FMT-17.12, FMT-17.13, FMT-17.15, two edge rows and a security note no longer say the version 3 padding is checked; they follow FMT-07.11, FMT-05.13 step 6 and CRY-01.10 (LD-01). FMT-17.1 now names LD-05. Observed with the installed CLI (2.7.11) on an aligned scratch version 3.1 demo vault (password `demo-pw`): with its last 16 bytes cut it failed with a no-root-group message; with its last 8 bytes cut it opened; with its last 17 bytes cut it failed.
