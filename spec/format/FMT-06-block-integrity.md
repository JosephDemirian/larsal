# FMT-06 Block integrity stream, version 4

Status: reviewed
Epics: E3-S4
Parity rows: SF-06

## What it does

In a version 4 file, the encrypted payload is not stored as one blob. It is cut into blocks, and each block carries its own HMAC-SHA-256. The HMAC key of each block is derived from the block's position in the stream, and the position is also part of the HMAC input. So a block cannot be changed, cut short, moved, repeated, dropped or swapped with another without its HMAC failing. A last, empty block marks the end, so cutting off whole blocks at the end is found too.

The stream starts right after the header HMAC (FMT-05.2). Joining the data of all blocks gives the encrypted payload. FMT-08 decrypts it.

The key is already proven by the header HMAC (FMT-05) when this stream is read. So every failure here means damage or tampering, never a wrong key.

## Inputs and outputs

Notation: `||` joins byte strings. `LE64(i)` is i as an unsigned 64-bit little-endian integer. `LE32s(n)` is n as a signed 32-bit little-endian integer. `K` is the 64-byte HMAC base key from FMT-05.4: `K = SHA-512(S || T || 01)`.

Reading:

- Input: the file bytes from offset `H+64` (FMT-05.2) to the end of the file, and `K` (secret, 64 bytes). App holds the whole file in memory, bounded by the file size limit in `limits.rs` (FMT-01).
- Output: the encrypted payload (the joined block data), or `Corrupt`. App returns nothing until the whole stream has passed every check in this card.

Writing:

- Input: the encrypted payload (from FMT-08), and `K` for this save (fresh master seed, CRY-03).
- Output: the block stream bytes, written right after the header HMAC.

Limits:

- A block's size field is a signed 32-bit integer. Valid sizes are 0 to 2,147,483,647.
- The block index is an unsigned 64-bit integer. It starts at 0.
- Written data blocks hold 1,048,576 bytes (1 MiB), except the last one.

## Rules

FMT-06.1 **Position.** The block stream exists only in version 4 files. It starts at file offset `H+64`, right after the stored header HMAC (FMT-05.2), and ends with the final block (FMT-06.6). The end of the final block is the logical end of the file. Bytes after it are not part of the stream (FMT-06.12).

FMT-06.2 **Block layout.** Each block is laid out as follows:

| Offset in block | Length | Content |
|---|---|---|
| 0 | 32 | HMAC-SHA-256 of the block (FMT-06.5) |
| 32 | 4 | data size `n`, signed 32-bit little-endian |
| 36 | n | data: the next `n` bytes of the encrypted payload |

A block is `36 + n` bytes long. The next block starts right after it, with no gap or padding.

FMT-06.3 **Block index.** The index is never stored in the file. It is the block's position in the stream: the first block after the header HMAC has index 0, the next 1, and so on, up to and including the final block. App counts it with checked unsigned 64-bit arithmetic. Index 2^64 − 1 is reserved for the header (FMT-05.5). No real stream can reach it, but if a count would reach it the result is `Corrupt`.

FMT-06.4 **Per-block key.** `K_i = SHA-512(LE64(i) || K)`. That is 8 + 64 = 72 input bytes, giving a 64-byte key. Each block has its own key.

FMT-06.5 **Block HMAC.** The stored HMAC of block `i` is HMAC-SHA-256 with key `K_i` (all 64 bytes) over the message `LE64(i) || size field || data`. The size field is the 4 bytes as stored (`LE32s(n)`), and the data is `n` bytes. The message is `12 + n` bytes long. So the HMAC covers the index twice (through the key and the message), the size and the data.

FMT-06.6 **Final block.** The stream ends with a block whose size is 0 and which has no data. Its HMAC is computed like any other block's: key `K_m`, message `LE64(m) || 00 00 00 00`, where `m` is the number of data blocks before it. The first block with size 0 is always the final block, and the format has no other way to end the stream. The final block must be present, and its HMAC must be valid.

FMT-06.7 **Payload.** The data of blocks 0 to m − 1, joined in order, is the encrypted payload (FMT-08). Block boundaries carry no meaning: they do not line up with cipher blocks, compression or the inner header. Two streams that split the same payload differently are both valid and give the same payload.

FMT-06.8 **Writing.** App writes data blocks of exactly 1,048,576 bytes. The last data block holds whatever is left, which is between 1 and 1,048,576 bytes. Then App writes the final block. App never writes an empty data block. If the payload length is an exact multiple of 1,048,576, the last data block is full and the final block comes right after it. The index starts at 0 in every file. The `K` used is the same one that keys this save's header HMAC (FMT-05.9). The reference writes exactly this layout (observed: a payload of 1,502,224 bytes became blocks of 1,048,576 and 453,648 bytes, then the final block).

FMT-06.9 **Read everything first.** App checks every block up to and including the final block (layout, size, HMAC, final block) before any payload byte goes to decryption. HMACs are compared in constant time (`app-crypto` verify). On the first failure, App stops and returns `Corrupt`. The reference instead checks blocks while it decrypts and decompresses. App's way means no partly checked data ever reaches the next layer.

FMT-06.10 **Size checks.** For each block, App checks the following before reading or copying any data:
- A negative size field (top bit set, for example `FF FF FF FF` or `00 00 00 80`) gives `Corrupt`.
- A size larger than the bytes left in the input after this block's 36-byte head gives `Corrupt`. App checks this before allocating anything.
- Any other size from 0 to 2,147,483,647 is accepted. Blocks larger than 1 MiB are valid, and the reference reads them (observed with a single 1,502,224-byte block). The `block` entry in `limits.rs` (Rust rule 5) is set to 2,147,483,647, the format maximum, so in practice a block is bounded by the bytes left in the input, which the file size limit already bounds (FMT-01.31). (D-06-2, decided: spec/decisions.md default rule, the card's option.)

FMT-06.11 **Truncation.** The result is `Corrupt` if the input ends inside a block's HMAC, size field or data, or ends after a complete data block but before a final block.

FMT-06.12 **Bytes after the final block are ignored (decided: spec/decisions.md LD-01).** The walk stops at the end of the final block. Every byte after it is never checked and never read as content: one stray byte, 36 zero bytes, a whole extra block with a valid HMAC, a second final block, or old file content that a sync tool left behind. The file opens as if those bytes were absent. App does not keep them and never writes them (FMT-06.8), so App's next save of the vault drops them. The reference does the same: such files open in it (observed). Cuts, swaps, repeats and drops inside the stream still fail (FMT-06.3, FMT-06.6, FMT-06.11; AT-A03). History: the proposal to reject these bytes as `Corrupt` was not chosen.

FMT-06.13 **Error kind.** Every failure in this card is `Corrupt`, never `WrongKey` (FMT-05.8). The debug log may record which block index failed and which check failed (size, truncation, HMAC, final block). It never records key bytes or data.

FMT-06.14 **Empty payload.** A stream whose first block is the final block (index 0, size 0) holds no payload. App returns `Corrupt`, because a version 4 encrypted payload is never empty (FMT-08: it always holds at least the inner header, and a CBC payload holds at least one 16-byte block). The reference writer would write no blocks at all for an empty payload, but that case cannot happen.

## Edge cases and errors

How the reference reports block failures, observed with the installed command line tool 2.7.11 on demo vaults. The block stream has its own internal messages: the HMAC field is short, the size field is short, the size is invalid, the block is too short, and the HMAC does not match the data. The user never sees them. The layer above (cipher, gzip, inner header, XML) fails instead, and its message is shown. Which message appears depends on where the damage is and how much data the upper layers had already read:

| Damage (version 4, AES, gzip) | Reference message (paraphrased) | App |
|---|---|---|
| Any byte flipped in block 0 (HMAC, size or data) in a small vault | The inner header field id could not be read | `Corrupt` |
| Final block removed, final block HMAC flipped, final block size set to −1 | The inner header field id could not be read | `Corrupt` |
| Size field set to `FF FF FF FF`, `00 00 00 80`, `00 00 00 00` or `FF FF FF 7F` | The inner header field id could not be read. The last one also prints a warning that the read size exceeds a buffer limit | `Corrupt` |
| File cut right after the header HMAC, or in the middle of block 0 | The inner header field id could not be read | `Corrupt` |
| Damage or truncation in block 1 of a 1.5 MB vault | An inner header error saying an attachment field expected 1,500,001 bytes but found fewer | `Corrupt` |
| Final block removed, no compression (AES or ChaCha20) | The document has no root group (it is cut short) | `Corrupt` |
| Blocks swapped, repeated or dropped, or HMACs computed with indexes starting at 1 | The inner header field id could not be read | `Corrupt` |
| Valid HMAC stream around ciphertext whose last byte was changed, when the last cipher block holds more than padding (the end of the gzip data and the padding both decrypt to garbage) | The inner header field id could not be read (observed on the `D4` vault, padding 6 bytes). The gzip layer fails, not a padding check | `Corrupt` (from FMT-08; the key is already proven, so never `WrongKey`) |
| Valid HMAC stream around a bad padding, everything else intact (rebuilt with the key: last padding byte `00`, or all padding bytes `41`) | Ignored; the vault opens. In version 4 the reference never checks the padding (observed, CRY-01) | `Corrupt` (FMT-08.5, CRY-01.10; decided: spec/decisions.md LD-03) |
| 1 stray byte, 36 zero bytes, an extra valid block, or a second final block after the final block | Ignored; the vault opens | Opens; the bytes are ignored (FMT-06.12, LD-01) |
| Blocks of 1, 17 or 64 bytes instead of 1 MiB | Opens | Opens |
| One block bigger than 1 MiB | Opens | Opens |

More edge cases:

- **Missing final block when the upper layers stop early.** The reference rejects a missing final block only because its upper layers read until the block stream ends. Every configuration tried was rejected: AES and ChaCha20, with and without gzip, small and 1.5 MB payloads. Source reading suggests a payload whose last gzip or XML read ends exactly on a chunk boundary might never ask for the final block. Reproduced by Verify in Sprint 2 with the installed CLI, on scratch copies of a demo version 4.1 vault (AES-KDF) with the final block removed and every other block MAC valid: the reference opens such a file whenever every layer's last read is served before the end of the last data block. After the inner header the document reader reads 8,192 bytes at a time; the cipher layer reads 16 bytes (CBC) or 1,024 bytes (ChaCha20); the gzip layer reads 65,500 compressed bytes. Seen: AES-256, no gzip, inner header 89 bytes, a document of 32,759 to 32,769 bytes with nothing after it: opens; 32,758 bytes: "premature end of document". Also opened: 20,000 spaces after the document's end tag (AES-256 and ChaCha20, no gzip), and 70,000 junk bytes after the gzip member. Without such extra bytes, at the demo vault's own length (24,748 bytes), it fails as before, with and without gzip. So a file cut by exactly its final block (36 bytes) can open in the reference. App always requires the final block (FMT-06.6) and gave `Corrupt` for each of these files, so App does not depend on this; it is a known difference for AT-A11.
- **Size field changed by +1 on the low byte.** The block then takes one byte from the next block's head, and its HMAC fails: `Corrupt`.
- **Size field changed on the high byte.** The size becomes larger than the rest of the file: `Corrupt` from FMT-06.10, before any allocation.
- **Huge file of tiny blocks.** Each block costs at least 36 bytes, so the block count is bounded by the file size divided by 36. No extra limit is needed.

Decisions:

- **D-06-1** (decided: spec/decisions.md LD-01). Bytes after the final block are ignored, as the reference does (FMT-06.12). The card had proposed `Corrupt`; that was not chosen.
- **D-06-2** (decided: spec/decisions.md default rule, the card's option). The `block` entry of `limits.rs` is 2,147,483,647 bytes, the largest non-negative signed 32-bit size. So the check against `limits.rs` that Rust rule 5 asks for exists, but it rejects no valid file. The bound that matters is the bytes left in the input, which the total file limit already bounds (FMT-01.31). History: the other option, dropping the `block` entry from plan/architecture.md, was not chosen. If `app-format` ever reads from a stream of unknown length instead of a whole buffer, lower the cap then (for example 64 MiB, error `TooLarge`). FMT-07.9 uses the same entry.

## Security notes

- This stream is what makes payload tampering visible in version 4 (SF-06). Because the index is part of both the key and the message, moving, repeating or dropping blocks is found. The final empty block finds truncation at a block boundary.
- The HMAC covers ciphertext. So no modified ciphertext ever reaches the cipher or its padding check: no padding oracle (AT-B07). It also keeps damaged data away from gzip and the XML parser (AT-A03, AT-A06, AT-A07).
- Never pass any payload byte to decryption, decompression or parsing before the whole stream has passed (FMT-06.9). The plan promises "We never show half-checked data".
- Every length read from the file is checked against the bytes actually left in the input before any allocation (Rust rule 5). A negative or huge size must never cause an allocation, a panic or an overflow (AT-A04, AT-A10).
- `K` and every `K_i` are secret: wiped-on-drop types, never logged. Stored HMACs are public.
- HMACs are compared in constant time (Rust rule 6, AT-B05).
- Bytes after the final block lie outside every HMAC, and App never reads them (FMT-06.12, LD-01), so they cannot change what App shows. They can carry hidden data inside a vault file, but App drops them on the next save. AT-A03's "append" check is read this way: blocks appended after the final block are ignored and the content shown is unchanged; anything inserted before the final block fails.
- Errors here are never `WrongKey`, so a damaged file is never blamed on the user's password, and the user is not led to retype it or try other key files.
- Attacks that test this card: AT-A03, AT-A04, AT-A10, AT-A11, AT-B05, AT-B07.

## Test cases

Fixed vectors (python3 hashlib/hmac, cross-checked with the openssl tool). `S` = `00 01 … 1F`, `T` = `20 21 … 3F`, so `K` = `f09af394435628155b2d8ba7af6236610e63c26d6595f5bc508d3e1f2328dd7040c6ce1001efc85f9e7ef54e83df08e2c448fcc47dfd768d7f130de6666c37c3` (FMT-05).

- `K_0` = `5fd83d7f7d7b305ee3f6fb6e32b10588475e83260943216f945afb84b92ac0d2284bd1976e759a9af6f7d0fbab79e7fe740d364c3930c0913d2ae4bc3277df0d`
- `K_1` = `458372f688d541486fc919fce3dd5ab1505cc7c84d391f22e68b76bfc77a7b28f6c8c490826ead358b6ab76f0d1456e4cf00acb1da066075a58972e07e703d76`
- `K_2` = `aef1919fecc7c88b0ce6023c54d0835a9daf0646b886750b6553462f4c0692de49f330ba0eae1d8e8aa8fe5617233f67e4d9f91510d797f302d4ffe76afb1d15`
- Payload `P` = the 31 ASCII bytes "App block stream test vector 01" = `41707020626c6f636b2073747265616d207465737420766563746f72203031`
- **Three-block form** (P split 16 + 15, as a test writer with block size 16 would split it):
  - HMAC message of block 0 = `0000000000000000` `10000000` `41707020626c6f636b2073747265616d`
  - Block 0: HMAC `27b81f94a5af7c1530621adc2ef1b382a42fdcaee910fe714d809a94e236ef7c`, size `10000000`, data `41707020626c6f636b2073747265616d`
  - Block 1: HMAC `b04705121b65cae9fece6ab9a5d9ecd06e75aa8c54885f6ff1b639c1dc903cb4`, size `0f000000`, data `207465737420766563746f72203031`
  - Block 2 (final): HMAC message `0200000000000000` `00000000`; HMAC `3b11fbddce34f0ecaf4597332bbab78bb992807d91bb509eaba01ea80822960b`, size `00000000`
  - Whole stream (139 bytes) = `27b81f94a5af7c1530621adc2ef1b382a42fdcaee910fe714d809a94e236ef7c1000000041707020626c6f636b2073747265616db04705121b65cae9fece6ab9a5d9ecd06e75aa8c54885f6ff1b639c1dc903cb40f000000207465737420766563746f722030313b11fbddce34f0ecaf4597332bbab78bb992807d91bb509eaba01ea80822960b00000000`
- **One-block form** (what the 1 MiB writer produces for P):
  - Whole stream (103 bytes) = `e5044488d2529ddf1e84b9de6463f045983c0a8805aa402971cb6cf5de2f90ae1f00000041707020626c6f636b2073747265616d207465737420766563746f72203031aefcc91d8fb70ad4625a68e65c9844b8198b2c9631bcb0f43cbf8d2f36c2407d00000000`
- **Final block only** (index 0): HMAC `a81cb0e4a59e138e1a5ee1755c778c30a45cb02d6c6382d78a627b7715eeefce`, size `00000000`

"Demo vault v4" means a version 4 vault made by our test-data script (or the reference command line tool) with password `demo-pass`. Offsets `B` are relative to the start of the block stream (file offset `H+64`).

| Case | Given | When | Then |
|---|---|---|---|
| FMT-06.1 position in any file | Any demo vault v4, as written by App or the reference tool (neither writes bytes after the final block) | Find `H` (FMT-05.1), then walk the blocks from offset `H+64` | Block 0 starts at `H+64`. The walk passes every check, and the final block ends exactly at the last byte of the file |
| FMT-06.1 / FMT-06.6 values from the `D4` vault (no file needed) | `K` of the `D4` vault as listed in FMT-05 (`96aff2c2…1814e8b7`) | Compute `K_1`, then HMAC-SHA-256(`K_1`, `0100000000000000 00000000`) | `601fb5c16408feed310b9f9488f70b7a2b84840aa7315f012d56aefe0fe12a4a`. For reference, in that 1,927-byte file block 0 starts at offset 271 = `H+64` with size field `30 06 00 00` (1,584), and the last 36 bytes are this HMAC followed by `00000000`: 207 + 64 + 36 + 1,584 + 36 = 1,927 |
| FMT-06.4 per-block keys | `K` as listed | Compute `K_0`, `K_1`, `K_2` | Equal to the listed values |
| FMT-06.5 block HMAC | `K_0`, message of block 0 | HMAC-SHA-256 | `27b81f94…e236ef7c` |
| FMT-06.5 second block | `K_1`, `LE64(1)` ‖ `0f000000` ‖ last 15 bytes of P | HMAC-SHA-256 | `b0470512…dc903cb4` |
| FMT-06.6 final block HMAC | `K_2`, message `0200000000000000 00000000` | HMAC-SHA-256 | `3b11fbdd…0822960b` |
| FMT-06.2 / FMT-06.7 read three-block stream | Three-block stream, `K` | Read | Payload = P (31 bytes) |
| FMT-06.7 boundaries carry no meaning | One-block stream, `K` | Read | Payload = P, the same as the three-block form |
| FMT-06.8 writer, small payload | P, `K` | Write with the default block size | Exactly the one-block stream bytes (103 bytes) |
| FMT-06.8 writer, exact multiple | Payload of 1,048,576 bytes | Write | One 1,048,576-byte data block, then the final block (index 1); total 1,048,648 bytes |
| FMT-06.8 writer, one byte over | Payload of 1,048,577 bytes | Write | Blocks of 1,048,576 and 1 bytes, then the final block (index 2) |
| FMT-06.8 writer, two full blocks | Payload of 2,097,152 bytes | Write | Two 1 MiB blocks, then the final block (index 2). No empty data block |
| FMT-06.8 reference layout | Demo vault v4 with a 1,500,000-byte random attachment, saved by the reference tool | Walk the blocks | Sizes 1,048,576, then the rest, then 0. App opens it |
| FMT-06.8 interop | App saves a vault with a payload over 1 MiB | Open with the reference tool (`REF_CLI`) | Opens with the same content |
| FMT-06.9 / FMT-06.13 flipped data | Three-block stream, byte at `B`=36 flipped | Read | `Corrupt` (block 0 HMAC). The decrypt function is never called |
| FMT-06.9 flipped HMAC | Three-block stream, byte at `B`=0 flipped | Read | `Corrupt` |
| FMT-06.5 size covered by HMAC | Three-block stream, size byte at `B`=32 changed `10`→`11` | Read | `Corrupt` (block 0 HMAC fails) |
| FMT-06.10 size beyond input | Three-block stream, byte at `B`=35 changed `00`→`01` (size 16,777,232) | Read | `Corrupt`, with no allocation of that size (memory stays flat) |
| FMT-06.10 negative size | Three-block stream, size of block 0 set to `ffffffff`; also `00000080` | Read | `Corrupt` |
| FMT-06.10 maximum size | Size of block 0 set to `ffffff7f` (2,147,483,647) | Read | `Corrupt` (larger than the input), no allocation |
| FMT-06.10 large blocks accepted | Demo vault v4 with a 1.5 MB attachment, rewrapped as one data block of 1,502,224 bytes with valid HMACs | Open with `demo-pass` | Opens (the reference also opens it) |
| FMT-06.7 small blocks accepted | Demo vault v4 rewrapped with 1-byte, 17-byte and 64-byte blocks, valid HMACs | Open | Opens (the reference also opens them) |
| FMT-06.3 swapped blocks | Three-block stream with blocks 0 and 1 swapped as stored | Read | `Corrupt` |
| FMT-06.3 dropped block | Three-block stream with block 1 removed | Read | `Corrupt` (the final block is checked with key `K_1` and fails) |
| FMT-06.3 repeated block | Three-block stream with block 0 stored twice | Read | `Corrupt` |
| FMT-06.3 wrong index base | A stream whose HMACs were made with indexes 1, 2, 3 | Read with `K` | `Corrupt` |
| FMT-06.6 / FMT-06.11 missing final block | Three-block stream without its last 36 bytes | Read | `Corrupt` (the reference also rejects it) |
| FMT-06.6 damaged final block | Three-block stream, byte at `B`=110 (inside the final HMAC) flipped | Read | `Corrupt` |
| FMT-06.6 negative final size | Final block size `ffffffff`, HMAC made over that size | Read | `Corrupt` |
| FMT-06.11 cut inside data | Three-block stream cut to 40 bytes | Read | `Corrupt` |
| FMT-06.11 cut inside head | Three-block stream cut to 20 bytes, and to 34 bytes | Read | `Corrupt` |
| FMT-06.12 stray byte | Three-block stream plus one byte `00`; separately, plus 36 bytes of `00` | Read | Payload = P both times. The extra bytes are not read. The reference opens a vault changed this way |
| FMT-06.12 extra valid block | Three-block stream plus a block with index 3, data "EXTRA" and a valid HMAC; also plus a second final block with index 3 | Read | Payload = P both times ("EXTRA" is not part of it). The reference opens both |
| FMT-06.12 sync-tool leftovers, then save | Demo vault v4 with 1, 16 and 4,096 random bytes appended | Open with `demo-pass`; then save with App and read the saved file | Opens with the same content as the unchanged vault each time. The saved file ends exactly at its final block (FMT-06.8). The reference opens the changed files too (observed) |
| FMT-06.14 empty payload | Final-block-only stream | Read | `Corrupt` |
| FMT-06.13 never WrongKey | Demo vault v4, each byte at offsets `H+64` to the end flipped one at a time | Open with `demo-pass` | Every file `Corrupt`. Never `WrongKey`, no panic |
| FMT-06.13 bad padding after valid HMACs | Demo vault v4 whose last ciphertext byte was changed before the HMACs were computed | Open with `demo-pass` | `Corrupt` (FMT-08, LD-03), not `WrongKey` |
| FMT-06.13 bad padding, rest intact | Demo vault v4 whose payload was decrypted, its last padding byte set to `00`, encrypted again with the same key and IV, and wrapped with valid block HMACs | Open with `demo-pass` | `Corrupt` (FMT-08.5, LD-03), not `WrongKey`. The reference opens it (observed) |
| FMT-06.11 truncation sweep (AT-A04) | Demo vault v4 | Cut at every 1 KB step and at every byte of the last 100 | `Corrupt` each time, no panic |
| FMT-06.13 log content | Case "flipped data" | Read the debug log | It names block 0 and the HMAC check, and holds no key bytes |

## How this was learned

- Read the reference's HMAC block stream (its block reader, block writer, per-block key helper and end handling), the version 4 reader and writer that wrap it around the cipher stream, and the cipher stream itself, to see when the final block is requested.
- Read the reference's unit test for this stream. It writes with a 16-byte block size, flips the data, HMAC and size bytes, and expects the mismatch and too-short errors.
- Made demo vaults with the installed reference command line tool 2.7.11 in a scratch folder under `/tmp` (password `demo-pass`), including one with a 1.5 MB random attachment. Recomputed every block HMAC with a scratch python3 tool and confirmed the stored values and the 1 MiB block size.
- Rewrapped the demo payload with a scratch tool into many block layouts: small blocks, one big block, a missing final block, an extra block after the final one, two final blocks, swapped, repeated and dropped blocks, indexes starting at 1, a negative final size, and bad padding under valid HMACs. Did this with AES and ChaCha20, with and without gzip, and opened each result with the reference tool. Also flipped and cut bytes in unmodified demo vaults.
- Separated bad padding from a garbled tail: on the `D4` vault (padding 6 bytes), a bad padding with everything else intact opens in the reference, while flipping the last ciphertext byte (which also garbles the end of the gzip data) gives the inner-header message. On a vault whose last cipher block is all padding, flipping its last ciphertext byte opens too. The reference's cipher layer would check the padding only at the end of its input, and the block stream reports that end only after the final block, by which time the last cipher block has already been decrypted without the check.
- Sprint 0 close-out: wrote in the lead rulings of spec/decisions.md. LD-01 turned FMT-06.12 around (bytes after the final block are ignored, no longer `Corrupt`), with its edge row and test rows. LD-03 is cited for bad padding. D-06-2 follows the default rule. The observed reference results are unchanged.
- The installed tool (2.7.11) behaved as the source reading predicts in every case. No "differs in installed version" items were found.
