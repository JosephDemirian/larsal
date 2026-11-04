# FMT-07 Hashed block stream, version 3

Status: reviewed
Epics: E3-S4, E3-S8
Parity rows: SF-06

## What it does

In a version 3 file, the decrypted payload is cut into blocks after the 32 stream start bytes (FMT-05.10). Each block stores its index, the SHA-256 of its data, and its size. A last block with size 0 and an all-zero hash marks the end. Joining the data of all blocks gives the document bytes: gzip-compressed or plain XML (FMT-08).

Unlike version 4 (FMT-06), this stream sits **inside** the encryption, and its hashes have no key. It finds damage to the decrypted data, and it finds blocks out of order, repeated or missing, but it does not authenticate anything by itself. Its protection against tampering comes only from the encryption around it.

Larsal reads this stream to open version 3 vaults. Larsal's product code never writes version 3 (plan/architecture.md, FMT-16). The write rules are given so readers know the layout the reference produces, and for the test-only version 3 builder: test code in `tests/`, built from FMT-17 with FMT-07.7, FMT-05.10 and FMT-05.12, never shipped (FMT-01.26 plan (e), decided: spec/decisions.md LD-35). Version 3 demo vaults come from the reference command line tool or from that builder.

The reference reads version 2 files with the same reader and the same hashed block stream (observed with the reference test vault `Format200`). Larsal opens version 2 files with the version 3 reader, as the reference does (FMT-01.11, FMT-17.22, decided: spec/decisions.md LD-06), so this card applies to them unchanged.

## Inputs and outputs

Notation: `||` joins byte strings. `LE32u(i)` is i as an unsigned 32-bit little-endian integer. `LE32s(n)` is n as a signed 32-bit little-endian integer.

Reading:

- Input: the decrypted version 3 plaintext after the 32 start bytes, which have already been checked and dropped (FMT-05.10, FMT-05.13). For a CBC cipher the padding is still on, and the plaintext may hold more bytes after the final block (FMT-07.11). The walk is the same for every cipher. Larsal holds the plaintext in memory. It is never larger than the file, which is bounded by `limits.rs` (FMT-01).
- Output: the document bytes (the joined block data), or `Corrupt`. Larsal returns nothing until the whole stream, up to and including the final block, has passed every check in this card.

Writing (test-only version 3 builder, LD-35):

- Input: the document bytes, gzip-compressed if the header's compression flag says so (FMT-08).
- Output: the hashed block stream. The writer puts the 32 start bytes in front of it, then encrypts the whole thing (FMT-05.10, FMT-08).

Limits:

- The index is unsigned 32-bit.
- The size is signed 32-bit, with valid values 0 to 2,147,483,647.
- Written data blocks hold 1,048,576 bytes (1 MiB), except the last one.

## Rules

FMT-07.1 **Position.** In version 3, the decrypted payload is: 32 stream start bytes (FMT-05.10), then this hashed block stream, then the cipher padding when the cipher is CBC (PKCS#7, FMT-08.5). The stream starts at plaintext offset 32 and ends with the final block (FMT-07.5). Whatever follows the final block is ignored (FMT-07.11).

FMT-07.2 **Block layout.** Each block is laid out as follows:

| Offset in block | Length | Content |
|---|---|---|
| 0 | 4 | index, unsigned 32-bit little-endian |
| 4 | 32 | SHA-256 of the data (FMT-07.4); 32 zero bytes in the final block |
| 36 | 4 | data size `n`, signed 32-bit little-endian |
| 40 | n | data |

A block is `40 + n` bytes long. The next block starts right after it, with no gap.

FMT-07.3 **Index.** The index is stored in the block. The first block has index 0, and each next block has the previous index + 1. The final block carries the next index too. On reading, every stored index must equal the block's position (counting from 0), otherwise `Corrupt`.

FMT-07.4 **Hash.** For a block with size `n` > 0, the stored hash is SHA-256(data), over the `n` data bytes only. The index and the size are not part of the hash. A data block with a hash mismatch gives `Corrupt`.

FMT-07.5 **Final block.** The stream ends with a block whose size is 0, whose hash is 32 zero bytes, and whose index is `m`, the number of data blocks before it. The first block with size 0 is the final block. Its hash must be all zero, otherwise `Corrupt`. Its index is checked like any other (FMT-07.3). The final block must be present.

FMT-07.6 **Document bytes.** The data of blocks 0 to m − 1, joined in order, is the document stream (FMT-08: gzip or plain, then the XML of FMT-10 and FMT-11). Block boundaries carry no meaning. Two streams that split the same bytes differently are both valid.

FMT-07.7 **Writing (reference layout; only the test-only version 3 builder writes it).** Data blocks are exactly 1,048,576 bytes, and the last data block holds the rest (1 to 1,048,576 bytes). The final block follows, and after it only the CBC padding that encryption adds (FMT-08.5, CRY-01.4); nothing at all for ChaCha20. No empty data block is ever written, and the index starts at 0. The reference writes exactly this layout (observed: blocks of 1,048,576 and 468,685 bytes, then the final block with index 2).

FMT-07.8 **Read everything first.** Larsal checks the whole stream up to and including the final block (layout, indexes, sizes, hashes, final block) before any byte goes to decompression or the XML parser. On the first failure, Larsal stops and returns `Corrupt`. The reference instead checks blocks while it decompresses and parses.

FMT-07.9 **Size checks.** For each block, Larsal checks the following before reading or copying data:
- A negative size gives `Corrupt`.
- A size larger than the bytes left after this block's 40-byte head gives `Corrupt`. Larsal checks this before allocating anything.
- Any other size is accepted. Blocks larger than 1 MiB are valid, and the reference reads them (observed with a single 1,517,261-byte block). Blocks smaller than 1 MiB are valid too, and the reference reads them (observed with 1-byte and 64-byte blocks). The size is checked against the same `block` entry in `limits.rs` as FMT-06.10: 2,147,483,647 (D-06-2, decided: spec/decisions.md default rule, the card's option).

FMT-07.10 **Truncation.** The result is `Corrupt` if the plaintext ends inside a block's index, hash, size or data, or ends before a final block.

FMT-07.11 **Nothing after the final block is read (decided: spec/decisions.md LD-01).** The walk stops at the end of the final block. Every plaintext byte after it is ignored: never checked and never read as content. That covers the CBC padding, whatever it holds, any other plaintext between the final block and the padding, and plaintext from extra cipher blocks appended to the file. Leftover ciphertext bytes that do not fill a 16-byte cipher block are not even decrypted (FMT-05.13 steps 2 and 6). So Larsal does not check the PKCS#7 padding in version 3, and the rule is the same for CBC and ChaCha20. Larsal never writes such bytes (FMT-07.7). History: the proposal to accept only a valid padding after the final block and reject everything else as `Corrupt` was not chosen.

The reference also ignores bytes after the final block, with one exception. It checks the padding only when its walk reads the file's last cipher block, which happens when that block also holds part of the final hashed block. Then a bad padding fails, and the user sees that the document has no root group (observed). Larsal opens that file: a known difference for AT-A11. Only the key holder can make it (the vault must be encrypted again with its key), and its document is intact. Files changed in these ways open in both: trailing plaintext, 1 and 16 appended ciphertext bytes, and a bad last cipher block made only of padding (all observed in the reference).

FMT-07.12 **Error kind.** Every failure in this card is `Corrupt`, never `WrongKey`. The start bytes have already matched (FMT-05.11). The padding is never checked (FMT-07.11), so no padding result exists (AT-B07, read as spec/decisions.md LD-04 says). The debug log may say which block index failed and which check failed. It never records data or keys.

FMT-07.13 **No data blocks.** A stream whose first block is the final block (index 0, size 0, zero hash) holds an empty document. Larsal returns `Corrupt`, because an empty document cannot be parsed (FMT-08, FMT-10). Plaintext that is empty after the start bytes is `Corrupt` under FMT-07.10.

## Edge cases and errors

How the reference reports hashed block failures, observed with the installed command line tool 2.7.11 on version 3.1 demo vaults (AES-256, gzip). The stream has its own internal messages: the index is wrong, the hash field is short, the size is invalid, the final block's hash is not zero, the block is too short, and the hash does not match the data. The user never sees them. The gzip and XML layers fail instead:

| Damage (version 3) | Reference message (paraphrased) | Larsal |
|---|---|---|
| Ciphertext byte flipped in the middle (hashed block data damaged) | The document has no root group | `Corrupt` |
| Index of every block shifted to start at 1 | The document has no root group | `Corrupt` |
| Final block hash first byte `01` | The document has no root group | `Corrupt` |
| Final block index 7 instead of 2 | The document has no root group | `Corrupt` |
| Final block size −1 | The document has no root group | `Corrupt` |
| 64-byte blocks, two blocks swapped as stored | The document has no root group | `Corrupt` |
| 64-byte blocks, block 0 stored twice | The document has no root group | `Corrupt` |
| Final block missing | The document has no root group | `Corrupt` |
| Plaintext "TRAILING-PLAINTEXT-DATA" after the final block (padding valid) | Ignored; the vault opens | Opens (FMT-07.11) |
| Bad padding, hashed blocks intact, last cipher block also holds the end of the final block | The document has no root group | Opens (FMT-07.11; known difference) |
| Bad padding, hashed blocks intact, last cipher block made only of padding (16 `00` bytes instead of 16 `10` bytes) | Ignored; the vault opens | Opens (FMT-07.11) |
| 1 or 16 bytes appended to the file | Ignored; the vault opens | Opens (FMT-07.11, FMT-05.13 step 6) |
| Damage anywhere in a 1.5 MB vault (block 0, block 1, last byte, last 16 bytes or last 100,000 bytes cut) | The document has no root group | `Corrupt` |
| 1-byte, 64-byte, 1 MiB or bigger blocks with correct hashes and indexes | Opens | Opens |

More edge cases:

- **Damage in the first two ciphertext blocks.** In CBC mode, a flipped ciphertext bit in block `j` garbles plaintext block `j` and flips the same bit in plaintext block `j+1`. Damage at ciphertext offsets 0 to 31, or in the IV, changes the start bytes, so the result is `WrongKey` under FMT-05.11, not this card. From ciphertext offset 32 on, a flipped byte garbles a plaintext block. If any byte of that block lies in this stream, the result is `Corrupt`. Only a flip inside a last cipher block made of padding alone is ignored (FMT-07.11).
- **Index field written as signed by the reference writer and read as unsigned.** The bytes are the same for every index below 2^31, so this makes no difference.
- **Index wraparound.** A stream would need 2^32 blocks of at least 40 bytes, more than 160 GiB, so this cannot happen within the file size limit. Larsal still counts the index with checked arithmetic, and an overflow gives `Corrupt`.

Decisions:

- **D-07-1** (decided: spec/decisions.md LD-01). Everything after the final hashed block is ignored (FMT-07.11): trailing plaintext, the padding, and ciphertext appended to the file. The card had proposed `Corrupt` for all three; that was not chosen. Differential fuzzing (AT-A11) lists one known difference here: a bad padding in a last cipher block that also holds the end of the final hashed block opens in Larsal and fails in the reference. The other known differences are D-05-3 and D-05-4 (FMT-05).

## Security notes

- The hashes have no key. Anyone who can decrypt can rebuild them. They protect against damage, not against someone who holds the key. Against an attacker without the key, the protection comes from the encryption: changing CBC ciphertext garbles a whole plaintext block, and SHA-256 then fails. This is weaker than version 4: there is no authentication of the header (FMT-05.12). Padding cannot be an oracle because Larsal never checks it in version 3 (FMT-07.11). Version 3 is read only in Larsal, and saving moves the vault to version 4 (FMT-16).
- Never pass any document byte to gzip or the XML parser before the whole stream has passed (FMT-07.8). Damaged data must not reach the decompressor or parser (AT-A03, AT-A06, AT-A07).
- Every size read from the stream is checked against the bytes actually left before any allocation (Rust rule 5). A negative or huge size must never cause an allocation, a panic or an overflow (AT-A04, AT-A10).
- Bytes after the final block, the padding included, are never read (FMT-07.11, LD-01). Someone without the key can append bytes, or replace a last cipher block made of padding alone, and the vault still opens with the same document. That changes nothing the user sees, and the reference opens such files too. No padding result exists to observe (AT-B07).
- The decrypted plaintext is secret: wiped-on-drop buffers, never logged.
- The hash compare uses the shared constant-time compare in `larsal-crypto`. The value is not secret, but one compare function everywhere is simpler (Rust rule 6).
- Attacks that test this card: AT-A03, AT-A04, AT-A10, AT-A11, AT-B07.

## Test cases

Synthetic demo answers changed by the rename follow LD-347; unchanged reference-vault values and earlier dated observations retain their original input scope.

Fixed vectors (E14-S1 independent recomputation with Python hashlib and libgcrypt AES-256-CBC; LD-347). Payload `P` = the 31 ASCII bytes "Larsal block stream test vec 01" = `4c617273616c20626c6f636b2073747265616d207465737420766563203031`.

- SHA-256 of the first 16 bytes of P = `e3c0a7a3375948832e2acea67686ca5628ff02f0a623208c5b962b76a13a09ab`
- SHA-256 of the last 15 bytes of P = `48e27c0212a775566758c465f0883d2c22414eb11e1bc6475d168ba3044bd728`
- SHA-256 of P = `d226535d5e4992f915d2812e2e03bde16380c90dcd676f3401868e4db4406a99`
- **Three-block form** (P split 16 + 15), 151 bytes:
  - Block 0: index `00000000`, hash `e3c0a7a3…a13a09ab`, size `10000000`, data `4c617273616c20626c6f636b20737472`
  - Block 1: index `01000000`, hash `48e27c02…044bd728`, size `0f000000`, data `65616d207465737420766563203031`
  - Block 2 (final): index `02000000`, hash 32 × `00`, size `00000000`
  - Whole stream = `00000000e3c0a7a3375948832e2acea67686ca5628ff02f0a623208c5b962b76a13a09ab100000004c617273616c20626c6f636b207374720100000048e27c0212a775566758c465f0883d2c22414eb11e1bc6475d168ba3044bd7280f00000065616d20746573742076656320303102000000000000000000000000000000000000000000000000000000000000000000000000000000`
- **One-block form** (what the 1 MiB writer produces for P), 111 bytes = `00000000d226535d5e4992f915d2812e2e03bde16380c90dcd676f3401868e4db4406a991f0000004c617273616c20626c6f636b2073747265616d20746573742076656320303101000000000000000000000000000000000000000000000000000000000000000000000000000000`
- **Encrypted form** (CBC): the synthetic version 3 payload of FMT-05 (final key `60 61 … 7F`, IV `40 41 … 4F`, start bytes `80 81 … 9F`, then the three-block form, then PKCS#7 padding of nine `09` bytes). Ciphertext (192 bytes, AES-256-CBC) = `23db97b1fbe632c63b581e30a4df5f878944ccc91e52c4bcf08eddcb124d45cc1a7f15b7ee289331a8832a62f5d8cd424df7a6090126b10e0b213ebeadb9b92aa607c0332d468313b05785278ef8409330c6d6eb77b2bb77c97384e0ed1d4f3dcc127b6bbb69bfe4f0fb156265fcdf0b8fc7180f4fd3a097538f3df6b13001a3452c7153367661fff6de47a0670d0e8f5e2987e7685b127574aebf9760f8db76c74454a1dcb46627e9b70fbd038d46533135ec6b80334157f5e120481889a662`. The last decrypted block, before the padding is removed, is `00000000000000090909090909090909`.

"Demo vault v3" means a version 3.1 vault made by the reference command line tool (its default), or by the test-only version 3 builder (LD-35), with password `demo-pass`. Larsal's product code never writes version 3. Offsets `B` are relative to the start of the hashed block stream. "Read" means: run this card's checks on the given bytes as the plaintext after the start bytes. The result does not depend on the cipher.

| Case | Given | When | Then |
|---|---|---|---|
| FMT-07.4 block hashes | P | SHA-256 of bytes 0–15 and of bytes 16–30 | `e3c0a7a3…`, `48e27c02…` |
| FMT-07.2 / FMT-07.3 / FMT-07.5 / FMT-07.6 read three-block form | Three-block stream | Read | Document bytes = P |
| FMT-07.6 boundaries carry no meaning | One-block stream | Read | Document bytes = P |
| FMT-07.7 writer layout | P | Write with the default block size (test-only builder) | Exactly the one-block stream (111 bytes) |
| FMT-07.7 writer, exact multiple | 1,048,576 document bytes | Write (test-only builder) | One full block (index 0), then the final block (index 1); 1,048,656 bytes |
| FMT-07.7 reference layout | Demo vault v3 with a 1,500,000-byte random attachment, saved by the reference tool | Decrypt and walk the blocks | Sizes 1,048,576, then the rest, then the final block with index 2. Larsal opens it |
| FMT-07.1 / FMT-07.11 encrypted form | Encrypted form ciphertext, final key `60…7F`, IV `40…4F` | Decrypt, check and drop the 32 start bytes, walk the stream | Document bytes = P. The 9 bytes after the final block (`09` × 9, the padding) are not read |
| FMT-07.3 wrong index | Three-block stream, byte at `B`=56 (index of block 1) changed `01`→`02` | Read | `Corrupt` |
| FMT-07.3 index base 1 | A stream with indexes 1, 2, 3 and correct hashes | Read | `Corrupt` (the reference also rejects it) |
| FMT-07.3 swapped blocks | Three-block stream with blocks 0 and 1 swapped as stored | Read | `Corrupt` |
| FMT-07.3 repeated block | Three-block stream with block 0 stored twice | Read | `Corrupt` |
| FMT-07.4 damaged data | Three-block stream, byte at `B`=40 flipped | Read | `Corrupt` |
| FMT-07.4 damaged hash | Three-block stream, byte at `B`=4 flipped | Read | `Corrupt` |
| FMT-07.5 final hash not zero | Three-block stream, byte at `B`=115 (first hash byte of the final block) set to `01` | Read | `Corrupt` (the reference also rejects it) |
| FMT-07.5 final index wrong | Three-block stream, final index `07000000` | Read | `Corrupt` |
| FMT-07.9 negative size | Three-block stream, size of block 0 set to `ffffffff`; separately, final size set to `ffffffff` | Read | `Corrupt` |
| FMT-07.9 size beyond input | Three-block stream, byte at `B`=39 changed `00`→`01` | Read | `Corrupt`, no allocation of 16 MiB |
| FMT-07.9 large block accepted | Demo vault v3 with a 1.5 MB attachment, rebuilt as one 1,517,261-byte block and re-encrypted with its own key | Open with `demo-pass` | Opens (the reference also opens it) |
| FMT-07.9 small blocks accepted | Demo vault v3 rebuilt with 1-byte and with 64-byte blocks | Open | Opens (the reference also opens them) |
| FMT-07.10 missing final block | Three-block stream without its last 40 bytes | Read | `Corrupt` |
| FMT-07.10 cut inside a head | Three-block stream cut to 2, 20 and 38 bytes | Read | `Corrupt` |
| FMT-07.10 empty | Empty stream (0 bytes after the start bytes) | Read | `Corrupt` |
| FMT-07.11 bytes after the final block | Three-block stream followed by each of: nothing; `09` × 9; `09` × 8 then `01`; "TRAILING"; "TRAILING" then `01` | Read | Document bytes = P every time. No byte after the final block is checked |
| FMT-07.11 trailing plaintext in a vault | Demo vault v3 rebuilt with "TRAILING-PLAINTEXT-DATA" after the final block, then a valid padding, re-encrypted with its own key and IV | Open with `demo-pass` | Opens with the same content as the unchanged vault. The reference opens it too (observed) |
| FMT-07.11 bad all-padding block | Demo vault v3 rebuilt with its data split into two blocks so the plaintext before the padding is a multiple of 16, then padded with 16 `00` bytes instead of 16 `10` bytes, re-encrypted with its own key and IV | Open with `demo-pass` | Opens with the same content. The reference opens it too (observed) |
| FMT-07.11 bad padding in a shared last block | Demo vault v3 rebuilt so the plaintext before the padding is not a multiple of 16 (the last cipher block also holds the end of the final block), with every padding byte set to `00`, re-encrypted with its own key and IV | Open with `demo-pass` | Opens with the same content. The reference fails with the no-root-group message (observed; known difference, D-07-1) |
| FMT-07.11 trailing ciphertext | Demo vault v3 plus 1 byte at the end of the file; separately plus 16 zero bytes | Open with `demo-pass`; then with `wrong-pass` | `demo-pass`: opens with the same content both times. `wrong-pass`: `WrongKey` (FMT-05.11). The reference opens both with the right password (observed) |
| FMT-07.12 never WrongKey | Demo vault v3, each byte from offset `H+32` to the end flipped one at a time | Open with `demo-pass` | Never `WrongKey`, no panic. Every file is `Corrupt`, except that a flip inside a last cipher block made of padding alone opens with the same content (FMT-07.11) |
| FMT-07.12 log content | Three-block stream, byte at `B`=40 flipped | Read | `Corrupt`. The debug log names block 0 and the hash check, and holds no data bytes |
| FMT-07.13 no data blocks | Stream made only of a final block with index 0 | Read and parse | `Corrupt` |
| FMT-07.8 nothing reaches the parser early | Three-block stream with the final block damaged | Read | `Corrupt`. The gzip and XML functions are never called (spy) |
| FMT-07.1 version 2 | Reference test vault `Format200` (password `a`) through `REF_TESTDATA` | Open | Opens with the version 3 reader (LD-06). Its stream has one data block of 1,956 bytes and a final block |

## How this was learned

- Read the reference's hashed block stream (block reader, block writer, end handling), and the version 3 reader and writer that place it between the cipher stream and gzip after the start bytes.
- Read the reference's unit test for this stream: write and read with a 16-byte block size, and a check that a second reset writes only one final block.
- Made version 3.1 demo vaults with the installed reference command line tool 2.7.11 (its default) in a scratch folder under `/tmp`, with password `demo-pass`, including one with a 1.5 MB random attachment. Decrypted them with a scratch python3 tool, an AES-KDF helper and the openssl tool, and confirmed the start bytes, indexes, hashes, the zero hash of the final block and the 1 MiB block size.
- Rebuilt the decrypted stream of a demo vault with a scratch tool (small blocks, one big block, index base 1, non-zero final hash, wrong final index, negative final size, swapped and repeated blocks, missing final block, trailing plaintext), re-encrypted it with the vault's own key and IV, and opened each result with the reference tool. Also flipped, cut and appended bytes in unmodified demo vaults.
- Rebuilt a demo vault v3 with bad padding under intact hashed blocks, in two layouts: last cipher block shared with the final hashed block (padding 8 bytes, changed four ways), and last cipher block made only of padding. Opened each with the reference tool: the first layout gives "no root group", the second opens. This matches the source: the reference's cipher layer checks the padding only when it reads the input's last cipher block. Walked the reference test vaults `Format200` and `Format300` (read only).
- Sprint 0 close-out: wrote in the lead rulings of spec/decisions.md. LD-01 turned FMT-07.11 around (everything after the final block is ignored, the padding included), with its edge rows and test rows. LD-35 settles who makes version 3 test data, with the same wording as FMT-05. LD-06 settles version 2. LD-04 is how AT-B07 is read. D-06-2 follows the default rule. The observed reference results are unchanged.
- The installed tool (2.7.11) behaved as the source reading predicts in every case. No "differs in installed version" items were found.
