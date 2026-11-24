# FMT-01 File layout, versions and the interop matrix

Status: reviewed
Epics: E0-S5, E3 (mainly E3-S2, E3-S4, E3-S7, E3-S8, E3-S10); written in E1-S1 and E1-S9
Parity rows: SF-01, SF-02, SF-04, SF-05, SF-06, SF-11, SF-12

## What it does

This card is the frame of the vault file. It says what every byte of a vault file is, from the first byte to the last, for each file version; how a reader tells a vault from any other file by its first bytes; which version numbers are accepted; and which reader (version 3 or version 4 layout) handles the rest. The other format cards fill in each part of the frame; this card points to them.

It also holds the interop matrix (story E1-S9): every vault variant (file version, cipher, KDF, compression, key kind), whether the reference app can create it and open it, and how we will get a demo vault of it.

Vocabulary used in this card:

- "Version 4 layout": files with major version 4 (4.0, 4.1, and any 4.x).
- "Version 3 layout": files with major version 2 or 3 (2.x, 3.0, 3.1, and any 3.x). Version 3 details are in FMT-17.
- "Version 1 format": the older format with a different second signature. It is not opened as a vault; it belongs to import card FEA-08.
- H: the offset of the first byte after the outer header (after the end-of-header field). "Header bytes" always means bytes [0, H), signatures and version included.

## Inputs and outputs

Input: the vault file as bytes (a `Read` source; `larsal-format` never sees a path). The reader accepts a source of any size, empty included, and gives a defined result for each: under 12 bytes is TooShort (FMT-01.2), over the total file limit is TooLarge (FMT-01.31). The name and extension of the file play no part. The read model (the whole file in one buffer, every block checked before decryption) is FMT-01.32.

Outputs of the frame reader (`detect.rs`, `header.rs`):

| Output | Type | Notes |
|---|---|---|
| Detection result | one of: Vault(major, minor), OldFormatVault, NotAVault, TooShort | From the first 12 bytes only (FMT-01.2 to FMT-01.5) |
| Version | major u16, minor u16 | From bytes 8 to 11 (FMT-01.6) |
| Layout | version 3 or version 4 | From the major version (FMT-01.8) |
| Header fields | list of (id u8, data bytes) in file order | Parsed by FMT-02; framing in FMT-02.1 to FMT-02.3 (FMT-01.14) |
| Header bytes | bytes [0, H) | Input to the header checks (FMT-05 for version 4, FMT-17 for version 3) |
| Payload start | offset | H + 64 for version 4, H for version 3 |

Limits: this card owns the total file limit (FMT-01.31). Every length read in the frame is checked against `larsal-format/limits.rs` before any memory is allocated (FMT-01.22). The other numbers live in FMT-02 (header, 1 MiB), FMT-06 and FMT-07 (blocks) and FMT-08 (decompressed payload, 1 GiB; document, 512 MiB).

Error kinds: the frame's outcomes and their mapping to `larsal-format/error.rs` are in FMT-01.33.

## Rules

### Detection and version

FMT-01.1 Every integer in the outer file (signatures, version, field lengths, block lengths) is little-endian.

FMT-01.2 A reader needs the first 12 bytes to decide anything. A file with fewer than 12 bytes is TooShort and is not opened. The reference gives one "could not read the file" error for every file under 12 bytes, empty files included (observed with 0, 8 and 11 bytes).

FMT-01.3 Bytes 0 to 3 must be `03 D9 A2 9A` (signature 1, the 32-bit value 0x9AA2D903). Bytes 4 to 7 equal to `67 FB 4B B5` (signature 2, the value 0xB54BFB67) mark a vault of the version 2, 3 and 4 family. Only then is the version field read.

FMT-01.4 Signature 1 followed by `65 FB 4B B5` (0xB54BFB65) marks the version 1 format. It is reported as OldFormatVault and not opened as a vault. The reference shows a message that the file is an old-format vault and that it can be imported instead (paraphrased); the import itself is FEA-08. In that format bytes 8 to 11 are encryption flags, not a version, so FMT-01.6 does not apply.

FMT-01.5 Any other first 8 bytes give NotAVault. This includes signature 1 with `66 FB 4B B5` as the second signature (observed: the reference says the file is not a vault). The reference message is a plain "not a vault of this kind" (paraphrased).

FMT-01.6 The version field is the 32-bit little-endian value at bytes 8 to 11. The minor version is the low 16 bits (bytes 8 and 9, u16 little-endian). The major version is the high 16 bits (bytes 10 and 11, u16 little-endian). Examples: `00 00 04 00` is 4.0, `01 00 04 00` is 4.1, `01 00 03 00` is 3.1, `00 00 03 00` is 3.0, `00 00 02 00` is 2.0.

FMT-01.7 Accepted versions: major 2, 3 or 4 with any minor (0 to 65535). Major 0, 1, or 5 and above are Unsupported and the file is not opened. The reference's exact test: reject when the whole 32-bit value is below 0x00020000, or when the value with the low 16 bits cleared is above 0x00040001 (which is the same as major above 4). Its message is a plain "unsupported vault version" (paraphrased).

FMT-01.8 Dispatch: major 2 or 3 goes to the version 3 layout (FMT-17). Major 4 goes to the version 4 layout (this card and FMT-02 to FMT-15). The minor version never changes the dispatch.

FMT-01.9 The minor version does not change the byte layout. 4.0 and 4.1 files have the same outer layout; 4.1 only allows more elements in the document (list in FMT-16). 3.0 and 3.1 files have the same outer layout; 3.1 adds the header hash element in the document (FMT-17).

FMT-01.10 Unknown minor versions are read like known ones: 4.x with x of 2 or more goes to the version 4 reader, 3.x with x of 2 or more to the version 3 reader. The reference command line opens such files without a message (observed with 4.2, 4.65535, 3.2 and 3.65535). The reference's open screen has a "made by a newer version, saving may lose data" (paraphrased) warning for versions above 4.1, but the reference replaces the recorded version while it reads the KDF header field of a version 4 file (FMT-16.2), so the warning does not appear for version 4 files in practice (source, re-read by Verify in Sprint 2: the reader first records the version from the file, then reading the version 4 KDF field sets the recorded version to the one the vault's settings need, and the open screen checks the recorded version only after the whole read; the window was not run). Larsal: opens the file without a notice, as the reference command line does (decided: spec/decisions.md LD-05). Larsal keeps unknown document parts (SD-06), and when it keeps any, it never saves a lower version than the one read (FMT-16.24, decided: spec/decisions.md LD-09).

FMT-01.11 Version 2.x files: the reference opens them directly as vaults with its version 3 reader (same layout as 3.0) and saves them as 3.1. Its own test data has 2.0 and 2.4 files. Larsal: reads them with the FMT-17 reader, same as 3.0 (decided: spec/decisions.md LD-06). History: routing them through import (FEA-08) was not chosen.

### The layout of each version

FMT-01.12 Version 4 layout, from the first byte to the last:

| Offset | Size | Content | Card |
|---|---|---|---|
| 0 | 4 | Signature 1: `03 D9 A2 9A` | this card |
| 4 | 4 | Signature 2: `67 FB 4B B5` | this card |
| 8 | 2 | Minor version, u16 LE | this card |
| 10 | 2 | Major version, u16 LE (4) | this card |
| 12 | H - 12 | Outer header fields, each: id (1 byte), length (u32 LE), data. The last one has id 0. | FMT-02, FMT-03 |
| H | 32 | SHA-256 of header bytes [0, H) | FMT-05 |
| H + 32 | 32 | HMAC-SHA-256 of header bytes [0, H) with the header HMAC key | FMT-05 |
| H + 64 | to the end of the final block | HMAC block stream: blocks of (HMAC 32 bytes, size i32 LE, data), ending with a block of size 0; a negative size is Corrupt | FMT-06 |
| end of final block | 0 | Larsal writes nothing here; a reader ignores any bytes found here (FMT-01.20) | this card |

FMT-01.13 Version 3 layout (major 2 or 3), from the first byte to the last:

| Offset | Size | Content | Card |
|---|---|---|---|
| 0 | 12 | Signatures and version, as in FMT-01.12 (major 2 or 3) | this card |
| 12 | H - 12 | Outer header fields, each: id (1 byte), length (u16 LE), data. The last one has id 0. | FMT-17, FMT-02 |
| H | to the end of the file | Ciphertext of the payload. There is no header hash or HMAC between the header and the ciphertext. | FMT-17, FMT-08 |

FMT-01.14 Header field framing is owned by FMT-02: the field layout in FMT-02.1, the end-of-header field in FMT-02.3, the raw header bytes in FMT-02.4. This card only uses the result: H is the offset right after the data of the end-of-header field, and a reader never reads a header field beyond it. The one framing difference of the version 3 layout is its 2-byte length (FMT-02.2, FMT-17.2).

FMT-01.15 Which field ids each layout uses, which Larsal requires, which are an error in version 4, which are skipped, and what the reference does when one is missing: owned by FMT-02 (the field table, FMT-02.14, FMT-02.15, FMT-02.21, FMT-02.23). The version 3 details (sizes, the reference's defaults for missing fields, field 10) are in FMT-17.3 to FMT-17.8. In the version 4 layout the inner random stream id and key live in the inner header (FMT-09).

FMT-01.16 The order in which Larsal writes version 4 header fields is owned by FMT-02.6. The reference's version 3 writing order (for test tools only) is in FMT-02.6 and FMT-17.25.

FMT-01.17 In the version 4 layout the 64 bytes after the header are: the SHA-256 of header bytes [0, H), then the HMAC-SHA-256 of the same bytes (keys and checking order in FMT-05). Because both cover bytes [0, H), they also protect the signatures and the version field. The block stream starts at H + 64 and ends with its final block of length 0 (FMT-06).

FMT-01.18 Version 4 payload nesting, outside to inside:

1. The HMAC block stream (FMT-06). The data parts of all blocks, joined in order, are the ciphertext.
2. The ciphertext is decrypted with the cipher from field 2, the final key (FMT-04) and the IV or nonce from field 7 (FMT-08, CRY-01). For AES-256 and Twofish (CBC with PKCS#7 padding) the ciphertext length is a multiple of 16; for ChaCha20 it equals the plaintext length.
3. If field 3 is 1, the plaintext is a gzip stream and is decompressed (FMT-08). If it is 0, the plaintext is used as is.
4. The result starts with the inner header (inner stream id and key, then attachments; FMT-09, FMT-13), followed by the XML document (FMT-10 to FMT-15). The document's root element name is stored encoded (name rule): `4B 65 65 50 61 73 73 46 69 6C 65`.

FMT-01.19 Version 3 payload nesting, outside to inside: the ciphertext runs from H to the end of the file; its plaintext is the 32 stream start bytes, then the hashed block stream (FMT-07); the joined block data is the document, gzip-compressed when field 3 is 1. There is no inner header. Details in FMT-17.

FMT-01.20 The logical end of a vault: in the version 4 layout, the end of the final (length 0) block (FMT-06); in the version 3 layout, the end of the final (size 0) hashed block in the plaintext (FMT-07). The cipher padding after it lies past the logical end and is never checked (FMT-07.11, FMT-05.13 step 6, CRY-01.10). Bytes after the logical end are ignored: never decrypted as content, never parsed, never an error (decided: spec/decisions.md LD-01). Larsal never writes them: every Larsal save ends the file at its final block (version 4 only, FMT-16.18). The reference does the same: it stops reading at the final block, and a demo vault of each layout with 1, 16 or 4,096 extra bytes appended still opened (observed). So in the version 3 layout a ciphertext whose length is not a multiple of 16 is not an error by itself when the final hashed block comes before the extra bytes (FMT-05.13 step 2, FMT-17.12). Changes inside the block stream (cut, swap, repeat, flip) still fail (FMT-06, FMT-07, AT-A03). History: the earlier proposal (Corrupt for any byte after the final block) was not chosen, because a sync tool that rewrites a file in place without truncating it leaves old bytes at the end.

FMT-01.21 The frame reader never reports a wrong key. Its outcomes are TooShort, NotAVault, OldFormatVault, Unsupported (version) and Corrupt (a header that cannot be parsed, a missing required field, a file cut off before its logical end). WrongKey comes only from the header HMAC in the version 4 layout (FMT-05) and from the start-bytes check in the version 3 layout (FMT-17.13, FMT-05.11; decided: spec/decisions.md LD-12). The error kind of each outcome is in FMT-01.33; user messages are in APP-06. Lead to align plan/architecture.md: its `error.rs` line says WrongKey only when the header HMAC fails, and lists five kinds where FMT-01.33 has ten.

FMT-01.22 Every length taken from the file (header field length, block length, KDF map entry length) is checked against `limits.rs` before memory is allocated or the data is read. A header field whose end would lie past the 1 MiB header limit is TooLarge, and that check runs first (FMT-02.25); a length that stays within the limits but runs past the end of the file is Corrupt. "The end of the file" is the end of the buffer of FMT-01.32, which FMT-01.31 bounds. (Observed: the reference reports a header field length larger than the rest of the file as an invalid data length.)

FMT-01.23 Which versions are read and written:

| | Reads | Writes |
|---|---|---|
| Reference | Version 1 format through import only (FEA-08); 2.x, 3.x and 4.x as vaults | 3.1 (and keeps a 3.x minor of 2 or more read from the file), 4.0 and 4.1; never 3.0, never 2.x (rule in FMT-16) |
| Larsal | 3.x and 2.x (FMT-17; 2.x per FMT-01.11), 4.x | 4.0 and 4.1; a higher 4.x minor only when it keeps unknown document parts of a file read with that minor (FMT-16.24); never 3.x or 2.x (FMT-16) |

### Interop matrix (story E1-S9)

FMT-01.24 Variant dimensions and the valid combinations:

- File version: 2.x (read only), 3.0, 3.1, 4.0, 4.1.
- Cipher (field 2): AES-256 `31C1F2E6-BF71-4350-BE58-05216AFC5AFF`, Twofish `AD68F29F-576F-4BB9-A36A-D47AF965346C`, ChaCha20 `D6038A2B-8B6F-4CB5-A524-339A31DBB59A`. Any of the three is valid in any version (the reference writes 3.1 files with any of them). A fourth id, AES-128 `61AB05A1-9464-41C3-8D74-3A563DF8DD35`, is recognized by the reference's header reader but such a file never opens (observed: generic error); Larsal treats it as Unsupported. Ids are written in the file as the 16 bytes of the UUID in RFC 4122 order (CRY-01).
- KDF: in 3.x files only AES-KDF, through header fields 5 and 6. In 4.x files the KDF map (FMT-03) holds AES-KDF, Argon2d or Argon2id. Any KDF other than the version 3 AES-KDF forces 4.0 or higher (FMT-16).
- Compression: off (field 3 = 0) or gzip (field 3 = 1), in every version.
- Key kind: the composite key from a password, a key file, a hardware key response, in any combination (FMT-04, FMT-18, INT-07). It does not depend on cipher, compression or version, except that a hardware key response enters the key flow at a different step in 3.x files (FMT-17).

Because cipher, KDF, compression and key are separate layers of the file, the matrix lists version x cipher x KDF in Table A (with compression as two columns) and the key kinds in Table B. Every key kind applies to every row of Table A.

FMT-01.25 What the reference can create (facts for the plan):

- Installed command line tool, db-create: always version 3.1, AES-256, AES-KDF, gzip. There is no cipher, KDF or compression choice. The only setting is a target decryption time (`-t`, 100 to 5,000 ms), which sets the AES-KDF rounds by a benchmark (observed: 28,571,428 rounds for 200 ms on this Mac). Without `-t` the rounds are 1,000,000 (observed, and the source default).
- Installed command line tool, import (from an XML export): the same settings as db-create, then the FMT-16 version rule applies to the imported content, so an XML holding a version 4 feature gives a 4.0 or 4.1 file that still uses AES-KDF, stored in the KDF map (observed: group custom data gave 4.0; group tags, a custom icon name, a previous-parent group or an entry excluded from reports gave 4.1; entry tags alone stayed 3.1). `testdata/README.md` says the tool writes 4.1 whenever the content needs 4.x; that is inexact, because group, entry or history entry custom data alone give 4.0 (FMT-16.5). The E0-S5 status line in plan/epics.md repeats it ("or 4.1 when content needs it"). Lead to correct both lines (this card cannot edit them).
- Installed command line tool, credentials: `-p` sets a password (an empty answer plus "y" to the follow-up question sets an empty password component); `--set-key-file` adds a key file, and creates it first when the path does not exist: an XML 2.0 key file when the file name ends with the bytes `2E 6B 65 79 78` (name stored encoded, name rule), otherwise a file of 128 random bytes (hashed kind). A project script that wants the tool to make an XML 2.0 key file builds that suffix from its bytes (for example with printf and hex escapes) and never writes it as text, or the name guard (E0-S3) fails; the E0-S5 script avoids this by writing its XML key files itself (FMT-01.29). It cannot add a hardware key; it can open a vault that needs one with `-y slot[:serial]` when the device is present. `db-edit -p` with the same password re-saves a vault without changing its entries (observed).
- The source of the command line tool behaves the same as the installed version 2.7.11 for all of the above (no difference found).
- Graphical app (from the source, re-read by Verify in Sprint 2; the app was not run): a new vault defaults to version 4 with Argon2d, AES-256 and gzip, tuned to 1 second. Its encryption settings offer a "version 4 (recommended)" (paraphrased) choice with Argon2d, Argon2id or AES-KDF, and a "version 3" choice with AES-KDF only; each with AES-256, Twofish or ChaCha20. The general settings have a compression on/off box. The version 3 choice is greyed out when the vault holds a version 4 feature (FMT-16). Keys: password, key file (existing file of any kind, or a new one), hardware key, in any combination with at least one part. An empty password field means "no password part", not an empty password.

FMT-01.26 Ways to get a demo vault of a variant (the "plan" codes used in the tables):

- (CLI) Made by the installed command line tool with demo passwords and stored in `testdata/` by story E0-S5 (Table C, FMT-01.29). Cells name the vault by its stem.
- (CLI, gap) The installed command line tool can make it, but the E0-S5 set does not hold it yet (FMT-01.29 lists these gaps). Until E0-S5 adds it, the cell counts as the plan written after it.
- (a) A reference test vault read through `REF_TESTDATA` at test time, read only, never copied into this folder.
- (b) Made by our writer (Sprint 3, Larsal writes version 4 only), then opened by the reference command line tool (export compared) and re-saved by it (`db-edit -p` with the same password), which gives a reference-written vault of the same variant, because the tool keeps cipher, KDF and compression on save. A reference save changes some content: every save writes a new random padding item into the vault custom data (CRY-03.7; in 4.1 also with a new item time), stamps the `_LAST_MODIFIED` custom data items, and `db-edit -p` also sets the master-key-changed time (`MasterKeyChanged`) to the save time. So every export comparison ignores the random padding item, the `_LAST_MODIFIED` items, `MasterKeyChanged` and the creator field (the same normalization as `testdata/README.md` for E0-S5, plus `MasterKeyChanged`).
- (c) Made by a Verify agent with the reference graphical app, using a throwaway settings folder and demo passwords, never the real settings folder (decided: spec/decisions.md LD-34). Cells that also need a hardware key wait for OD-01 (FMT-01.28).
- (d) A re-sealed mutation: change bytes of a demo vault whose key is known, then recompute the header SHA-256 and HMAC with our own crypto (FMT-05). Only possible for the version 4 layout. Used for header-level variants that no app writes.
- (e) A test-only version 3 builder: test code in `tests/`, built from FMT-17 (writer facts in FMT-17.25), never shipped (decided: spec/decisions.md LD-35).
- (L) Covered by layers: no vault of this exact cell; the cell counts as covered when every layer it combines (version 3 layout, cipher, compression, key kind) is tested in other cells (decided: spec/decisions.md LD-36 for the 3.0 cells; the 2.x cell A01 gzip off by the default rule of spec/decisions.md, because 2.x is read exactly as 3.0, LD-06).

FMT-01.27 Table A, version x cipher x KDF. "GUI" is the graphical app (from the source, re-read by Verify in Sprint 2: the version 3 choice lists only AES-KDF, the version 4 choice Argon2d, Argon2id and AES-KDF, the cipher list is AES-256, Twofish and ChaCha20 for both, and the writer always stores AES-KDF under the older id, which a CLI re-save also showed; the app was not run); "CLI" is the installed command line tool (observed). Compression columns give the plan for gzip on / off.

| Row | Version | Cipher | KDF | GUI creates | CLI creates | Reference opens | Plan, gzip on | Plan, gzip off |
|---|---|---|---|---|---|---|---|---|
| A01 | 2.x | AES-256 | AES-KDF | no | no | yes (observed) | (a) Format200 (2.0), FileKeyBinary, FileKeyHex, FileKeyHashed (2.4) | (L) |
| A02 | 3.0 | AES-256 | AES-KDF | no | no | yes (observed) | (a) Format300 | (e) or (L) |
| A03 | 3.0 | Twofish | AES-KDF | no | no | yes (source) | (e) or (L) | (e) or (L) |
| A04 | 3.0 | ChaCha20 | AES-KDF | no | no | yes (source) | (e) or (L) | (e) or (L) |
| A05 | 3.1 | AES-256 | AES-KDF | yes | yes, gzip only | yes (observed) | (CLI) every 3.1 vault of Table C; (a) ProtectedStrings, Compressed | (a) NewDatabase, NonAscii |
| A06 | 3.1 | Twofish | AES-KDF | yes | no | yes (source) | (c) or (e) | (c) or (e) |
| A07 | 3.1 | ChaCha20 | AES-KDF | yes | no | yes (observed, CRY-01 T33) | (e) (a scratch 3.1 ChaCha20 vault built by a test tool was opened and re-saved by the reference, CRY-01 T33), or (c) | (e) or (c) |
| A08 | 4.0 | AES-256 | AES-KDF | yes | yes, gzip only | yes (observed) | (CLI, gap) v40-password; until then (b) | (a) NewDatabaseBrowser; (b) |
| A09 | 4.0 | AES-256 | Argon2d | yes | no | yes (observed) | (a) KeyFileProtected, KeyFileProtectedNoPassword, the hardware-key test vault; (b) | (b) |
| A10 | 4.0 | AES-256 | Argon2id | yes | no | yes (observed, CRY-02 T8) | (b) | (b) |
| A11 | 4.0 | Twofish | AES-KDF | yes | no | yes (source) | (b) | (b) |
| A12 | 4.0 | Twofish | Argon2d | yes | no | yes (source) | (b) | (b) |
| A13 | 4.0 | Twofish | Argon2id | yes | no | yes (source) | (b) | (b) |
| A14 | 4.0 | ChaCha20 | AES-KDF | yes | no | yes (source) | (b) | (b) |
| A15 | 4.0 | ChaCha20 | Argon2d | yes | no | yes (observed) | (a) Format400; (b) | (b) |
| A16 | 4.0 | ChaCha20 | Argon2id | yes | no | yes (source) | (b) | (b) |
| A17 | 4.1 | AES-256 | AES-KDF | yes | yes, gzip only | yes (observed) | (CLI) rich-v4; (b) | (b) |
| A18 | 4.1 | AES-256 | Argon2d | yes | no | yes (source) | (b) | (b) |
| A19 | 4.1 | AES-256 | Argon2id | yes | no | yes (source) | (b) | (b) |
| A20 | 4.1 | Twofish | AES-KDF | yes | no | yes (source) | (b) | (b) |
| A21 | 4.1 | Twofish | Argon2d | yes | no | yes (source) | (b) | (b) |
| A22 | 4.1 | Twofish | Argon2id | yes | no | yes (source) | (b) | (b) |
| A23 | 4.1 | ChaCha20 | AES-KDF | yes | no | yes (source) | (b) | (b) |
| A24 | 4.1 | ChaCha20 | Argon2d | yes | no | yes (source) | (b) | (b) |
| A25 | 4.1 | ChaCha20 | Argon2id | yes | no | yes (source) | (b) | (b) |
| A26 | 3.x or 4.x | AES-128 id | any | no | no | no (observed: error) | (d) for 4.x; byte edit of a 3.0 copy (no check to fix) | same |
| A27 | 4.x | any | AES-KDF stored with the newer id `7C02BB82-79A7-4AC0-927D-114A00648238` | no (the reference always stores AES-KDF with `C9D9F39A-628A-4460-BF74-0D08C18A4FEA`) | no | yes (observed, CRY-02 T4, FMT-03 D26) | (d) from rich-v4 | (d) |
| A28 | 4.x, minor 2 or more | any | any | no | no | yes (observed with 4.2 and 4.65535) | (d) from rich-v4 | (d) |
| A29 | 3.x, minor 2 or more | any | AES-KDF | no | no | yes (observed with 3.2 and 3.65535) | version bytes edited in a 3.0 copy (3.0 has no header hash to fix) | same |

No version 2, 3 or 4 reference test vault is version 4.1, uses Argon2id, or uses Twofish (checked: the headers of every test vault were read). The version 1 format Twofish test file belongs to FEA-08.

FMT-01.28 Table B, key kinds. Each applies to every row of Table A. "Opens" means the reference opens a vault of this kind when given the right key.

| Row | Key kind | GUI creates | CLI creates | Reference opens | Plan, version 3 layout | Plan, version 4 layout |
|---|---|---|---|---|---|---|
| B01 | Password (not empty) | yes | yes (`-p`) | yes | (CLI) password-only, default-time, rich-v3, big-10000; (a) Format300, ProtectedStrings | (CLI) rich-v4; (a) Format400 |
| B02 | Empty password (a password part of zero length) | no (an empty field means no password part) | yes (`-p`, empty, then "y") | yes (the GUI offers a retry with an empty password) | (CLI, gap) empty-password; until then (a) Compressed | (CLI, gap) v40-empty-password; until then (b) |
| B03 | No password, key file only | yes | yes (`--set-key-file` without `-p`; open with `--no-password`) | yes | (CLI) keyfile-binary32, keyfile-hex64, keyfile-hashed, keyfile-xml-v1, keyfile-xml-v2, keyfile-cli-made; (a) FileKeyBinary, FileKeyHex, FileKeyHashed | (CLI, gap) v40-keyfile; until then (a) KeyFileProtectedNoPassword |
| B04 | Password and key file | yes | yes | yes | (CLI) password-and-keyfile | (CLI, gap) v40-password-and-keyfile; until then (a) KeyFileProtected (password "a") |
| B05 | Key file, XML version 1.0 (base64 data) | uses only | uses only | yes (with an old-format warning) | (CLI) keyfile-xml-v1 (key file written by the E0-S5 script per FMT-18); (a) the reference's XML 1.0 key file test vault (2.4) | (b) |
| B06 | Key file, XML version 2.0 (hex data with check value) | yes | yes (new file named with `2E 6B 65 79 78`, stored encoded, name rule) | yes | (CLI) keyfile-xml-v2 (key file written by the E0-S5 script, not by the tool); (a) the reference's XML 2.0 key file test vault (3.1), plus its broken-hex and wrong-check-value siblings, which must fail | (b) |
| B07 | Key file, 32 raw bytes | uses only | uses only | yes (with an old-format warning) | (CLI) keyfile-binary32; (a) FileKeyBinary | (b) |
| B08 | Key file, 64 hex characters | uses only | uses only | yes (with an old-format warning) | (CLI) keyfile-hex64; (a) FileKeyHex | (b) |
| B09 | Key file, any other file (hashed) | yes (random content) | yes (128 random bytes) | yes | (CLI) keyfile-hashed, keyfile-cli-made (128 random bytes made by the tool); (a) FileKeyHashed (an image file) | (a) KeyFileProtected, KeyFileProtectedNoPassword (128 bytes) |
| B10 | Hardware key alone | yes (with a device) | no (opens with `-y`) | yes, with the device | (e) with a software response; (c) needs a device and waits for OD-01 | (b) with a software response (INT-07); the reference check needs a device and waits for OD-01 |
| B11 | Hardware key and password | yes | no | yes, with the device | (e) with a software response; (c) waits for OD-01 | (a) the reference's hardware-key test vault: version 4.0, AES-256, Argon2d, password "a", HMAC-SHA1 secret `1C E3 0F D7 8D 20 DC FA 40 B5 0C 18 77 9A FB 0F 02 28 8D B7`; our tests answer the challenge in software as a variable-mode slot: the challenge is the 32-byte KDF salt padded to 64 bytes (each padding byte holds the padding length, here 32 bytes of `20`); a variable-mode slot ignores the trailing bytes equal to the last byte, so the response is HMAC-SHA1(secret, the 32 salt bytes). This opens the vault (observed by recomputing its header HMAC, Vector HK below); a fixed-mode answer (HMAC-SHA1 over all 64 padded bytes) does not (INT-07, FMT-04) |
| B12 | Hardware key and key file, with or without password | yes | no | yes, with the device | (e) with a software response; (c) waits for OD-01 | (b) with a software response; the reference check waits for OD-01 |
| B13 | No key part at all | no (refused) | no (refused) | the reference's reader accepts an empty key in its unit tests; the command line tool opens such a vault with its no-password option and no key file, while its create command refuses to make one (observed by Verify, Sprint 1); expected difference for AT-A11 | none | none; Larsal never creates such a vault, and an open with no key part is refused with `NoCredentials` before the KDF (FMT-04.16; decided: spec/decisions.md LD-13) |

OD-01 (waiting for the owner): proving that the reference opens Larsal's hardware-key vaults (B10 to B12) needs a physical key with a demo secret in one slot. Until the owner decides, tests use a software challenge-response and the reference's own hardware-key test vault (B11).

FMT-01.29 Table C, the demo vaults of story E0-S5 in `testdata/`, made by the installed command line tool. `testdata/README.md` lists each password, key file and content ("basic", "rich", "big"). All use AES-256, AES-KDF and gzip (field 3 = 1). Rounds: `default-time` has the tool's fixed default, 1,000,000; every other vault was made with `-t 100`, so its rounds come from a benchmark (13,043,478 or 13,636,364 in the current files) and change when the set is remade. Vault bytes (seeds, IVs, keys, ciphertext) change on every remake; only the content is fixed. So no test may pin bytes of these files. Byte-exact vectors are self-contained instead: Vector L4 below and Vector L3 in FMT-17.

| Vault (stem) | Version | Key | Cells it covers |
|---|---|---|---|
| password-only | 3.1 | password | A05, B01 |
| keyfile-binary32 | 3.1 | key file only, 32 raw bytes | A05, B03, B07 |
| keyfile-hex64 | 3.1 | key file only, 64 hex characters | A05, B03, B08 |
| keyfile-hashed | 3.1 | key file only, hashed kind (one line of text) | A05, B03, B09 |
| keyfile-xml-v1 | 3.1 | key file only, XML 1.0 | A05, B03, B05 |
| keyfile-xml-v2 | 3.1 | key file only, XML 2.0 | A05, B03, B06 |
| keyfile-cli-made | 3.1 | key file only, 128 random bytes made by the tool (hashed kind) | A05, B03, B09 |
| password-and-keyfile | 3.1 | password and the 64-hex key file | A05, B04 |
| default-time | 3.1 | password; 1,000,000 rounds | A05, B01, FMT-01.25, FMT-16.21, FMT-17.7 |
| rich-v3 | 3.1 | password | A05, B01; entry tags without a version raise (FMT-16.11) |
| rich-v4 | 4.1 | password | A17, B01; 4.1 by group tags, entry report exclusion, previous-parent groups and a named icon together |
| big-10000 | 3.1 | password | A05, B01; 10,000 entries |

Gaps: variants the tool can make that the E0-S5 set does not hold. Lead to reopen E0-S5 and add them (proposed stems; each is one more import or db-create in `scripts/make-testdata.sh`). Until a gap is filled, its cells use the plan named in the last column, and the tests below that need it wait.

| Proposed stem | Variant | How the tool makes it | Until added |
|---|---|---|---|
| v40-password | 4.0, password | import of the basic content plus one custom data item on the root group, with `-p` (observed: 4.0, AES-KDF in the KDF map, rounds kept) | (b) |
| v40-keyfile | 4.0, key file only | as v40-password with `--set-key-file` and no `-p` | (a) KeyFileProtectedNoPassword |
| v40-password-and-keyfile | 4.0, password and key file | as v40-password with `-p` and `--set-key-file` | (a) KeyFileProtected |
| empty-password | 3.1, empty password | db-create or import with `-p`, an empty answer, then "y" | (a) Compressed |
| v40-empty-password | 4.0, empty password | as v40-password with an empty password | (b) |
| history-excluded | 3.1, one history entry excluded from reports | import of the basic content whose entry has one history entry with `QualityCheck` = `False` (observed: saved as 3.1 and the flag dropped) | none; the FMT-16.11 and FMT-16.19 tests wait |

The single-trigger 4.1 cases (only an entry excluded from reports, only a named icon, only a previous-parent group) are not needed as stored vaults: rich-v4 covers reading them, and the version each one gives is an observed fact (FMT-01.25) tested at the rule level in FMT-16.

Reference test vaults for plan (a), with their passwords from the reference's tests: Format200 ("a"), Format300 ("a"), Format400 ("t"), NewDatabase ("a"), NewDatabaseBrowser ("a", observed), Compressed (empty password), NonAscii (UTF-8 `CE 94 C3 B6 D8 B6`), ProtectedStrings ("masterpw"), BrokenHeaderHash (empty password; must fail), KeyFileProtected ("a" plus its key file), KeyFileProtectedNoPassword (its key file only), FileKeyBinary, FileKeyHex, FileKeyHashed and the two XML key file test vaults (each with its key file of the same stem only), the hardware-key test vault (B11).

FMT-01.30 Acceptance for E1-S9 and E3 interop: every row of Tables A and B has a plan. By the end of Sprint 3 every row with plan (CLI), (a), (b), (c), (d) or (e) has a test that opens the vault and compares its content; a cell that lists several plans ("(e) or (L)", "(c) or (e)") needs one of them. A (CLI, gap) cell counts as the plan written after it until E0-S5 adds the vault. A cell with plan (L) counts as covered when every layer it combines has a passing test in another cell (LD-36). A cell whose only plan needs a hardware key device stays open until OD-01 is settled; its software-response test still runs.

### Total file limit, read model and error kinds

FMT-01.31 Total file limit (this card is its only owner; decided: spec/decisions.md LD-22, revisit if a demo vault or a vault a user reports passes it). The `total file` entry of `limits.rs` is 1,140,850,688 bytes (1 GiB + 64 MiB). Why this number: a file must fit the 1 GiB decompressed payload limit (FMT-08.12; with compression off the ciphertext is about as large as the plaintext), plus the 1 MiB header limit (FMT-02.25), the 64 check bytes, the block framing (36 bytes per version 4 block, FMT-06; 40 bytes per version 3 block, FMT-07; 36 KiB or 40 KiB for 1 GiB in the reference's 1 MiB blocks), the 32 start bytes and up to 16 padding bytes. The 63 MiB left for framing allow a full 1 GiB payload in blocks down to about 600 bytes. The check:

1. Read the first 12 bytes and run detection and the version check (FMT-01.2 to FMT-01.7). Their result is used here for one thing only: a source whose 12 bytes fail them (TooShort, NotAVault, OldFormatVault, Unsupported) is never TooLarge, so a large file that is not a vault gets the right result. The read may stop early for such a source. The result itself is not reported here: it is kept and reported at FMT-05.7 step 1, after the credentials step, so a key file error still comes first (FMT-05.7 owns the order).
2. Read the rest of the source into the buffer of FMT-01.32, never more than the limit in total. If the source holds at least one byte more than the limit and its 12 bytes passed step 1, stop: TooLarge. Nothing is parsed, decrypted or derived.
3. Grow the buffer as bytes arrive. Never reserve memory from a size someone declares (a file system length, a header or block length). A caller that knows the file length may refuse a file over the limit before reading, with the same TooLarge.

A file of exactly the limit is read. Tests must be able to lower the limit (as for FMT-08.12). The reference has no total file limit (from the source: it reads the file as a stream with no size check). Expected AT-A11 difference.

FMT-01.32 Read model (one rule for FMT-05 to FMT-08). Larsal holds the whole file in one buffer, bounded by FMT-01.31, before it parses the header. Every length in the frame is checked against the bytes left in that buffer (FMT-01.22). The order of the checks is owned by FMT-05.7 (version 3: FMT-05.13). Version 4: the header checks (FMT-05), then every block and its HMAC, up to the final block (FMT-06.9), all before any byte is decrypted; bytes after the final block are ignored (FMT-01.20). Version 3: the start bytes (FMT-05, FMT-17.13), then the plaintext is decrypted in whole cipher blocks as far as the final hashed block, and every hashed block checked (FMT-07.8), before any byte is decompressed or parsed; the padding and any ciphertext after the final hashed block are never checked or read (FMT-07.11, FMT-01.20). Only the steps after these checks (decompression, inner header, document parsing) may stream; FMT-08.11 and its limits apply to them.

FMT-01.33 Error kinds (this list stands by the default rule of spec/decisions.md; `NoCredentials` on open decided by LD-13, the version 3 `WrongKey` by LD-12). This table is the one list of the error kinds of `larsal-format/error.rs` for opening, creating and saving a vault. Other cards name the kind of each of their outcomes and point here for the list. Every outcome maps to exactly one kind. The order in which outcomes are met is owned by FMT-05.7 (version 3: FMT-05.13): the read (FMT-01.31), then the credentials (FMT-04.21 step 1), then detection and the header fields (FMT-01.2 to FMT-01.7, FMT-02.30), then the header hash (version 4) or the ciphertext length (version 3), then the rest of the key flow (FMT-04.21 steps 2 to 5), then FMT-06 to FMT-08. Messages are in APP-06. No error value holds a secret (FMT-04.19).

| Outcome | Owner | Kind |
|---|---|---|
| Detection TooShort (under 12 bytes) or NotAVault | FMT-01.2, FMT-01.5 | `NotAVault` (new) |
| Detection OldFormatVault | FMT-01.4 | `OldFormat` (new); APP-06 offers import (FEA-08) |
| Version, cipher id, KDF, compression flag, IV length, inner stream id or another field value Larsal cannot handle; the KDF library refuses the settings while computing | FMT-01.7, FMT-02, FMT-03, FMT-08, FMT-09, FMT-17, CRY-02.16 | `Unsupported` |
| Damaged frame, header, map, block, padding, gzip, inner header or document; a missing required field; a file cut off before its logical end (bytes after the logical end are not an error, FMT-01.20) | FMT-01, FMT-02 to FMT-15, FMT-17 | `Corrupt` |
| No credential part at all: on create, credential change, save and open (open: before the KDF, decided: spec/decisions.md LD-13) | FMT-04.16 | `NoCredentials` (new) |
| Key file: empty, unsupported version, check value mismatch, unreadable data, not a regular file, DTD, over a key file limit, or the key file cannot be read (reason I/O) | FMT-18.19 | `KeyFile` (new), with one reason per FMT-18.19 row (the reason for an unsupported version carries the version text); never `WrongKey`, never `Io` |
| Hardware key: device missing or removed, timed out, slot not configured, answer not 20 bytes, any other device failure, on open or on save | FMT-04.10, FMT-04.17 | `HardwareKey` (new), with a reason owned by INT-07; never `WrongKey` |
| Over a limit: total file (FMT-01.31), header (FMT-02.25), payload and document (FMT-08.12), attachments (FMT-13.20), other document limits (FMT-11, FMT-15), KDF cost above a refuse ceiling (CRY-02.14) | each owner | `TooLarge` |
| Header HMAC mismatch (version 4); start bytes mismatch (version 3; decided: spec/decisions.md LD-12) | FMT-05, FMT-17.13 | `WrongKey` |
| Reading the vault file fails in the operating system | this card | `Io` (the vault file only; a key file is `KeyFile`) |

Not an error kind: a KDF cost in the "ask" band of CRY-02.14. The key flow returns the decision "ask the user first" with the cost report, as FMT-04.21 (step 2) states. A decline ends the open with nothing done and no error; there is no `Cancelled` kind and a decline is never `TooLarge`. CRY-02.14 and FMT-05.7 step 4a state the ask the same way.

Change for the lead to apply to the `error.rs` row of plan/architecture.md, which lists only `WrongKey`, `Corrupt`, `Unsupported`, `TooLarge` and `Io`: add `NotAVault`, `OldFormat`, `NoCredentials`, `KeyFile` and `HardwareKey` (ten kinds in all), and widen `WrongKey` to the version 3 start bytes (LD-12). APP-06 has one message per row. History: carrying `NotAVault` and `OldFormat` as reasons inside `Unsupported` was the other option; by the default rule the separate kinds stand.

## Edge cases and errors

| Case | Reference behavior | Larsal behavior |
|---|---|---|
| Empty file, or under 12 bytes | Read error, paraphrased "could not read the file" (observed for 0, 8, 11 bytes) | TooShort |
| Signature 1 plus `65 FB 4B B5` | Not opened; message points to import (observed) | OldFormatVault; offer import (FEA-08) |
| Signature 1 plus `66 FB 4B B5`, or any other bytes | Not-a-vault error (observed) | NotAVault |
| Text file | Not-a-vault error (observed) | NotAVault |
| Version 0.0, 1.0, 1.65535 | Unsupported-version error (observed) | Unsupported |
| Version 5.0 or 65535.0 | Unsupported-version error (observed) | Unsupported |
| Version 4.0 stamped on a version 3 layout file | Read with the version 4 reader; the 2-byte lengths are misread and the header fails (observed: a header data length error) | What FMT-02 gives for the misread header: TooLarge when a misread length runs past the 1 MiB header limit (FMT-02.25), else Corrupt (LD-77) |
| Version 3.1 stamped on a version 4 layout file | Read with the version 3 reader and fails (observed: the cipher id is misread and rejected) | Unsupported: the misread cipher id is unknown (FMT-02.7; LD-77) |
| 12 valid bytes and nothing more | Header read error: no field id could be read (observed) | Corrupt |
| Version 4 header with only the end field | Required header fields missing (observed) | Corrupt |
| Header field length past the end of the file | Header data length error (observed) | Corrupt, before allocating; TooLarge when the field would end past the 1 MiB header limit (FMT-02.25) |
| Version field changed in a version 4 file without fixing the checks | Header SHA-256 mismatch (source) | Corrupt (FMT-05) |
| Version field changed in a 3.1 file | Header hash mismatch, found after decrypting (source; observed when another header byte was changed) | Corrupt (FMT-17) |
| Version field changed in a 3.0 file | Not detected (no header check in 3.0); opens (observed) | Same; nothing to check (FMT-17) |
| Bytes after the logical end | Ignored; opens (observed) | Same: ignored, opens (FMT-01.20; decided: spec/decisions.md LD-01); Larsal's next save does not write them |
| Version 3 CBC file with 1 byte appended (ciphertext length no longer a multiple of 16) | Opens (observed) | Same: opens (FMT-01.20, FMT-17.12) |
| File cut off before the final block | Error (source) | Corrupt (FMT-06, FMT-07) |
| Version 4.2 or 3.2 | Opens without a notice (observed) | Same (LD-05) |
| AES-128 cipher id | Generic error (observed) | Unsupported |
| File larger than the total file limit (1,140,850,688 bytes), with valid first 12 bytes | No limit; reads it (source) | TooLarge after reading at most limit + 1 bytes (FMT-01.31) |

## Security notes

- The outer header is public: anyone with the file can read it. It must never hold a secret (SF-12). In the version 3 layout the protected stream key (field 8) and the start bytes (field 9) are in the clear by design of that old format; Larsal never writes that layout (FMT-16, FMT-17).
- The version field must never switch off a check. In the version 4 layout the header SHA-256 and HMAC cover the version bytes, so a changed version is found before decrypting (SF-05, AT-A02). In the version 3 layout only a 3.1 header hash inside the encrypted document covers it, after decryption; 3.0 has no header check at all (FMT-17). Larsal writes only the version 4 layout, so every save restores full header protection (AT-A09).
- A tamperer cannot downgrade a version 4 file to version 3 without the key: the version 3 reader cannot parse a version 4 header, and building a valid version 3 payload needs the key.
- Detection reads only 12 bytes and allocates nothing based on them. The whole file is bounded by FMT-01.31, and every later length is bounded first (FMT-01.22, AT-A04, AT-A10). No panic on any input.
- No payload byte reaches decryption, decompression or the parser before the checks of FMT-01.32 pass (AT-A02, AT-A03).
- The frame reader must never return WrongKey; a damaged frame is Corrupt. Mixing the two would give an attacker a way to probe, and would mislead users (AT-A01, FMT-05).
- Appended bytes are never read as content, so they cannot change what either app shows. They can hide unrelated data in a vault file; Larsal accepts that for parity (LD-01), and its next save removes them because Larsal never writes bytes after the final block. What must never happen: a byte after the logical end reaches the decryptor's output as content, the decompressor or the parser. Cuts, swaps, repeats and flips inside the block stream still fail (AT-A03; its "append" is read this way per LD-01). AT-A11 lists no difference here.
- Hardware-key secrets used for tests are demo secrets from the reference's own test data, never a real device's secret.

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| FMT-01.1 little-endian | Bytes 8 to 11 `01 00 04 00` | Read the version | 0x00040001, not 0x01000400 |
| FMT-01.2 too short | Files of 0, 8 (`03 D9 A2 9A 67 FB 4B B5`) and 11 bytes | Detect | TooShort for each |
| FMT-01.3 vault | `03 D9 A2 9A 67 FB 4B B5 00 00 04 00` | Detect | Vault(4, 0) |
| FMT-01.3 vault 3.1 | `03 D9 A2 9A 67 FB 4B B5 01 00 03 00` | Detect | Vault(3, 1) |
| FMT-01.4 old format | `03 D9 A2 9A 65 FB 4B B5 03 00 00 00 02 00 03 00` (start of a version 1 file) | Detect | OldFormatVault; no version check |
| FMT-01.5 other second signature | `03 D9 A2 9A 66 FB 4B B5 00 00 03 00 00 00 00 00` | Detect | NotAVault |
| FMT-01.5 text | ASCII "hello world, not a vault" | Detect | NotAVault |
| FMT-01.6 minor and major | `02 00 04 00` / `FF FF 03 00` / `04 00 02 00` | Split | 4.2 / 3.65535 / 2.4 |
| FMT-01.7 accepted | Versions 2.0, 2.1, 3.0, 3.1, 3.2, 3.65535, 4.0, 4.1, 4.2, 4.65535 | Version check | All accepted |
| FMT-01.7 rejected | `00 00 00 00`, `00 00 01 00`, `FF FF 01 00`, `00 00 05 00`, `00 00 FF FF` | Version check | Unsupported for each |
| FMT-01.8 dispatch | Versions 2.0, 3.0, 3.1, 3.65535 / 4.0, 4.1, 4.65535 | Dispatch | Version 3 reader / version 4 reader |
| FMT-01.9 same layout | Vector L4 (4.0) and the header of `rich-v4.larsalvault` (4.1) | Parse | Same field ids, sizes (16, 4, 32, 16, 93, 4) and order; H = 207 in both; only bytes 8 to 9, the random values and the rounds value R differ |
| FMT-01.10 unknown minor | `rich-v4.larsalvault` re-sealed with version 4.2, then 4.65535 (plan (d)); Format300 copies stamped 3.2 and 3.65535 | Open with `demo-pass-5` / "a" | Each opens with the same content and no notice or warning is returned (LD-05; the reference opened scratch 4.0 demo vaults re-sealed this way, observed) |
| FMT-01.11 version 2 | Format200, password "a" (REF_TESTDATA) | Open | Opens with the version 3 reader, not through import (LD-06); root group name "Format200"; 1 entry "Sample Entry" with 2 attachments |
| FMT-01.12 version 4 frame | Vector L4 below | Parse the frame | Fields 2 (16 bytes), 3 (4), 4 (32), 7 (16), 11 (93), 0 (4) in this order; H = 207 (0xCF); bytes 207 to 238 = `16F1F620 4BAEF1AC 71143BF9 4F3C719E BEC9B5EC FD524DF0 84EC355A 403B6E64` = SHA-256 of bytes [0, 207); bytes 239 to 270 = `D5F280EF 3AC39CCE 7A915EA7 702B6EC7 117C96EF 1B600455 B5E7DDED 1F50225A` = the header HMAC, which the keys listed under Vector L4 reproduce from password `demo-pass-1` (FMT-04, FMT-05.4 to FMT-05.6); block stream starts at 271 |
| FMT-01.12 whole file | `rich-v4.larsalvault` (password `demo-pass-5`) | Walk the frame | Blocks start at H + 64 = 271; each block takes 36 bytes plus its size; the block of size 0 is the last 36 bytes of the file, so the logical end equals the file size (in the current file: one data block of 4,496 bytes, then the final block, file size 4,839) |
| FMT-01.13 version 3 frame | Vector L3 in FMT-17 (a 3.1 header, 222 bytes); then `password-only.larsalvault` | Parse the frame | 2-byte lengths; H = 222; the ciphertext starts at 222 and runs to the end of the file; for `password-only.larsalvault` the file size minus 222 is a multiple of 16 |
| FMT-01.14 end field | A version 4 header whose end field has length 0, then one of length 4 | Parse | Both end the header; H is after the end field's data |
| FMT-01.14 stop at end | Header bytes followed by a byte `05` right after the end field | Parse | The `05` is not read as a header field (it is the first byte of the header SHA-256 area) |
| FMT-01.15 legacy field in version 4 | `rich-v4.larsalvault` re-sealed with an extra field 9 (32 bytes) before the end field | Open | Corrupt (FMT-02.14; the reference rejects it as a legacy field, observed on a scratch 4.0 vault) |
| FMT-01.15 unknown fields in version 4 | `rich-v4.larsalvault` re-sealed with an extra field 1 (5 bytes), then 13 (3 bytes), then 99 (3 bytes) | Open with `demo-pass-5` | Each ignored (FMT-02.21); the vault opens (observed on a scratch 4.0 vault) |
| FMT-01.15 required in Larsal | Vector L4 with field 3 (9 bytes at 0x21) removed; then with field 11 (98 bytes at 0x64) removed | Larsal parses the header | Corrupt for each (FMT-02.23), before any key work |
| FMT-01.15 version 4 field in version 3 | Format300 copy with a field 11 of 3 bytes inserted before the end field; also field 1 (5 bytes) and 99 (2 bytes) | Open with "a" | Field ignored (FMT-02.15, FMT-02.21), the vault opens (observed; 3.0 has no header check) |
| FMT-01.16 write order | Any Larsal save | Read back the header | Field order 2, 3, 4, 7, 11, (12), 0; end data `0D 0A 0D 0A` (FMT-02.6, FMT-02.3) |
| FMT-01.17 checks cover the version | `rich-v4.larsalvault` with bytes 8 to 11 set to `02 00 04 00`, checks not recomputed; Vector L4 with bytes 8 to 11 set to `01 00 04 00` | Open / check the header hash | Corrupt (header SHA-256 mismatch, FMT-05); never opened as 4.2 or 4.1 |
| FMT-01.18 nesting | `rich-v4.larsalvault` with password `demo-pass-5` | Decrypt | Ciphertext = the joined block data, a multiple of 16; after gunzip, inner header field 1 = `03 00 00 00` (ChaCha20), field 2 = 64 bytes, then four field 3 records (its four distinct attachment contents), then field 0; then the XML document whose root element name is `4B 65 65 50 61 73 73 46 69 6C 65` (stored encoded, name rule) |
| FMT-01.19 version 3 nesting | `password-only.larsalvault` with password `demo-pass-1` | Decrypt | First 32 plaintext bytes equal header field 9; one hashed block with index 0, then the final block (index 1, size 0); only padding after it |
| FMT-01.20 appended bytes | `password-only.larsalvault` (with `demo-pass-1`) and `rich-v4.larsalvault` (with `demo-pass-5`), each with 1, 16 and 4,096 random bytes appended | Open | Larsal: opens with the same content as the unchanged file; the appended bytes never reach the decompressor or parser (spy) (LD-01). Reference: opens (observed on scratch 3.1 and 4.0 vaults) |
| FMT-01.20 Larsal never writes a tail | `rich-v4.larsalvault` with 4,096 random bytes appended, opened in Larsal | Larsal saves | The new file ends with its final block (the last 36 bytes are a block of size 0); none of the 4,096 bytes is in it |
| FMT-01.20 cut stays Corrupt | `rich-v4.larsalvault` without its last 36 bytes (the final block); `password-only.larsalvault` without its last 48 bytes (this always cuts into its 40-byte final hashed block, whatever the padding length, and keeps the length a multiple of 16) | Open with `demo-pass-5` / `demo-pass-1` | Corrupt for each |
| FMT-01.21 no wrong key from the frame | Every file in the Edge cases table | Open | None gives WrongKey |
| FMT-01.22 bounded length | A version 4 header with field 2 length `FF FF FF FF` | Parse | TooLarge (FMT-02.25), before any allocation; memory stays flat |
| FMT-01.22 length past the end | The first 25 bytes of Vector L4 (signatures, version, field 2 id `02`, length `10 00 00 00`, then only 8 of the 16 data bytes) | Parse | Corrupt (the field ends at byte 33, inside the 1 MiB limit but past the 25-byte input), before any allocation |
| FMT-01.23 read and write set | A version 3 vault opened and saved by Larsal | Read back | Saved as 4.0 or 4.1 (FMT-16), never 3.x |
| FMT-01.24 AES-128 id | Format300 copy with the cipher id replaced by `61AB05A1-...` | Open with "a" | Larsal: Unsupported. Reference: generic error (observed) |
| FMT-01.24 cipher in 3.1 | A 3.1 vault with ChaCha20 or Twofish (plan (c) or (e)) | Open | Opens (FMT-17) |
| FMT-01.25 CLI defaults | `default-time.larsalvault`; `password-only.larsalvault` | Read the header | Both: version 3.1, cipher AES-256, field 3 = 1. `default-time`: field 6 = `40 42 0F 00 00 00 00 00` (1,000,000). `password-only` (`-t 100`): field 6 is the benchmark result (13,043,478 in the current file), not a fixed value |
| FMT-01.25 CLI import raises version | `rich-v4.larsalvault` / `rich-v3.larsalvault` (holds entry tags) / v40-password (gap, FMT-01.29) | Read the header | 4.1 / 3.1 / 4.0; the 4.x files hold a KDF map with AES-KDF id `C9D9F39A-628A-4460-BF74-0D08C18A4FEA` and the rounds of the import (13,043,478 in the current rich-v4; 1,000,000 observed for a scratch 4.0 import without `-t`) |
| FMT-01.26 re-save keeps the variant | A plan (b) vault re-saved by `db-edit -p` with the same password | Read the header | Same version, cipher, KDF type and compression; new seeds and IV (observed for a 4.1 AES-KDF vault) |
| FMT-01.27 Table A coverage | The Table A rows with plan (CLI) or (a) | Open each in Larsal with its key | Every one opens with the expected content (AT-B02) |
| FMT-01.27 newer AES-KDF id | `rich-v4.larsalvault` re-sealed with the KDF map id changed to `7C02BB82-79A7-4AC0-927D-114A00648238` | Open with `demo-pass-5` | Opens (same AES-KDF) |
| FMT-01.28 Table B coverage | The Table C vaults and the plan (a) key-file vaults | Open each with its key, then with each key part missing | Opens only with the full key; every wrong case gives WrongKey (AT-A01) |
| FMT-01.28 hardware key | The reference's hardware-key test vault, password "a", the variable-mode software response of Vector HK | Derive the keys and check the header HMAC (FMT-05), then open | The HMAC matches and the vault opens (HMAC match observed by recomputation). With the fixed-mode response of Vector HK, or without a response: the HMAC differs, WrongKey |
| FMT-01.29 demo set | `scripts/make-testdata.sh --verify` with `REF_CLI` set | Run; then read each Table C header | Exits 0: the vaults made in this run and the stored vaults all export to the stored JSON, compared after the normalization of FMT-01.26 (b) (creator, `_LAST_MODIFIED` items and the random padding item left out; the inputs use fixed ids and times, so every run gives the same JSON). Vault bytes are not compared. Each Table C vault exists with the version in Table C, cipher AES-256, compression 1, AES-KDF (fields 5 and 6 in 3.1, the KDF map in 4.1), rounds 1,000,000 in `default-time`. Each gap vault, once added, has the version in the gap table |
| FMT-01.30 acceptance | The tables in this card | Review at the end of Sprint 3 | Every cell has a passing test by one of its plans; an (L) cell has a passing test for each of its layers in other cells (LD-36); only the device checks of B10 to B12 may stay open, waiting for OD-01 |
| FMT-01.31 at the limit | Test limit lowered to 4,096 bytes. The first 4,096 bytes of `rich-v4.larsalvault` (4,839 bytes); then its first 4,097 bytes | Open with `demo-pass-5` | First: not TooLarge (it is cut inside the first block: Corrupt); second: TooLarge, and the header is never parsed (spy) |
| FMT-01.31 detection first | Test limit 4,096 bytes. 4,097 bytes of ASCII text; a 12-byte prefix `03 D9 A2 9A 67 FB 4B B5 00 00 05 00` followed by 4,085 zero bytes | Open | NotAVault; Unsupported (both from the first 12 bytes, not TooLarge; reported at FMT-05.7 step 1. With an empty key file the key file error comes first: FMT-05 test "FMT-05.7 12-byte look of the read step") |
| FMT-01.31 no reservation | Default limit. A source that reports a length of 8 GiB but yields a valid demo vault and then ends; a source that yields more than 1,140,850,688 bytes | Open | First: opens, and memory follows the bytes actually read; second: TooLarge after reading at most limit + 1 bytes |
| FMT-01.32 read model | `rich-v4.larsalvault` with the last byte of its first block's data flipped | Open with `demo-pass-5` | Corrupt from the block HMAC (FMT-06); the decrypt, gunzip and XML functions are never called (spy) |
| FMT-01.33 one kind per outcome | One file, key or device state for each row of the FMT-01.33 table (for `NoCredentials`, a create with no credential part; for `HardwareKey`, a vault that needs a hardware key with no device; for `KeyFile` reason I/O, a key file path that does not exist) | Open, or create | Exactly the kind in that row; only the header HMAC mismatch (version 4) and the start bytes mismatch (version 3) give WrongKey; a missing key file gives `KeyFile`, not `Io` |
| FMT-01.33 the ask is not an error | A vault whose KDF cost is in the ask band of CRY-02.14 (the case of FMT-04.21-b) | Open; decline | The open returns the decision "ask the user first", not an error kind; after the decline no error is reported, no KDF work ran, and no `TooLarge` or `Cancelled` value exists |

Vector L4: the first 271 bytes of a scratch demo vault made by the installed command line tool on 2026-10-24: import of the basic content plus one custom data item on the root group, password `demo-pass-1`, default rounds (version 4.0, AES-256, AES-KDF with 1,000,000 rounds, gzip). The file is not stored (FMT-01.29: bytes of tool-made vaults are never pinned); the vector is self-contained, because every value below follows from these bytes and the password. Offsets in hex.

| Offset | Bytes |
|---|---|
| 0000 | 03 D9 A2 9A 67 FB 4B B5 00 00 04 00 02 10 00 00 |
| 0010 | 00 31 C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A |
| 0020 | FF 03 04 00 00 00 01 00 00 00 04 20 00 00 00 A7 |
| 0030 | 16 30 9A 25 DE 3F 8A FE C0 28 99 E2 14 0E BC B2 |
| 0040 | CD E9 F1 61 AA 40 DA BA D6 B1 F7 65 F6 9C 3C 07 |
| 0050 | 10 00 00 00 F5 07 28 E5 6B A1 CF 03 F0 58 E7 15 |
| 0060 | 43 E0 58 84 0B 5D 00 00 00 00 01 42 05 00 00 00 |
| 0070 | 24 55 55 49 44 10 00 00 00 C9 D9 F3 9A 62 8A 44 |
| 0080 | 60 BF 74 0D 08 C1 8A 4F EA 05 01 00 00 00 52 08 |
| 0090 | 00 00 00 40 42 0F 00 00 00 00 00 42 01 00 00 00 |
| 00A0 | 53 20 00 00 00 F5 B2 EE EA 62 90 79 96 95 CE C4 |
| 00B0 | 8F 7D 69 E7 32 9E 55 86 18 A7 2A 80 15 35 E0 CF |
| 00C0 | 41 89 A4 7B 20 00 00 04 00 00 00 0D 0A 0D 0A 16 |
| 00D0 | F1 F6 20 4B AE F1 AC 71 14 3B F9 4F 3C 71 9E BE |
| 00E0 | C9 B5 EC FD 52 4D F0 84 EC 35 5A 40 3B 6E 64 D5 |
| 00F0 | F2 80 EF 3A C3 9C CE 7A 91 5E A7 70 2B 6E C7 11 |
| 0100 | 7C 96 EF 1B 60 04 55 B5 E7 DD ED 1F 50 22 5A |

Reading of Vector L4: 0x00 to 0x0B signatures and version 4.0; 0x0C field 2 (length 16, AES-256 id); 0x21 field 3 (length 4, value 1 = gzip); 0x2A field 4 (length 32, master seed); 0x4F field 7 (length 16, IV); 0x64 field 11 (length 93: map version `00 01`, then `$UUID` = AES-KDF id, `R` = 1,000,000 as u64, `S` = 32-byte seed, then the end byte; FMT-03); 0xC6 field 0 (length 4, `0D 0A 0D 0A`); 0xCF header SHA-256; 0xEF header HMAC.

Keys of Vector L4 (computed with python3 hashlib and hmac, AES-KDF through the system's AES command; FMT-04 gives the steps, FMT-05.4 to FMT-05.6 the header keys). Master seed S = bytes 0x2F to 0x4E; KDF seed = bytes 0xA5 to 0xC4; R = 1,000,000.

| Value | Hex |
|---|---|
| Password part SHA-256(`demo-pass-1`) | `89FE410C 581E0E30 9E8852E2 67653DA9 15198960 0138C790 1B635DB0 E4BD46C3` |
| Composite key | `CA6C3AA4 439AE1DE BE011A79 5F6E0BD9 5CE30FDD E4CA7FAC 92395588 EEDDF7A2` |
| AES-KDF output before hashing | `2E398EDE C478E36C EBFE9F42 2D396E32 42B212BD 3F770AF1 B85F024C 3E18C1E1` |
| T (transformed key) | `6466C670 B915F3B5 502EC910 BC1895E9 665A29C2 A2AB731B F5F6CD12 7383EB2E` |
| Payload cipher key SHA-256(S ‖ T) | `65061551 DA83D0BC C3C7A60C 50DA0A7F 70DAB836 5A954187 D9274FA6 E43F037B` |
| K = SHA-512(S ‖ T ‖ 01) (FMT-05.4; M in FMT-04) | `0775582A 05C6D298 C2FD959B 5444244D D7C83407 280F8010 3E9B5939 CFC9A6F8 61C18326 F41CDFE8 1F36737D A0582BA8 7CDAA49B 7D2EC83E F4B8A687 8C34AC5A` |
| K_hdr = SHA-512(FF×8 ‖ K) (FMT-05.5) | `0183E1AB 5171E4DD 098903F5 32423C4D 64B98BE8 13C156EF BAE13F0E 53A5FA2E 09EA11F0 7E37E7D2 41B146C0 BE8470E2 2C7BED47 6BB2DA0E B6F7CA4D 0ABD0B89` |
| HMAC-SHA-256(K_hdr, bytes [0, 207)) | `D5F280EF 3AC39CCE 7A915EA7 702B6EC7 117C96EF 1B600455 B5E7DDED 1F50225A` = bytes 239 to 270 |
| The same HMAC with password `wrong` | `D6169368 60041257 F7572438 EFAD232C A0788838 2CCEB6BC EB225755 615DC0AF` (differs: WrongKey) |

The vector names in the format cards differ on purpose: Vector L4 (this card), Vector L3 (FMT-17), D4 and D3 (FMT-05, password `demo-pass`), H4demo (FMT-02), the demo vault V4 of FMT-04 (password and key file). They are different vaults.

Vector HK: the reference's hardware-key test vault (B11), read only. Its header: version 4.0, AES-256, Argon2d with I = 8, M = 134,217,728 (128 MiB), P = 4, V = 0x13, KDF salt S_kdf = `828824CB E1A43319 BE44B303 DDCE4FCB F3DAA0A0 2FE5D65F A73C5C90 3A8485D8`; H = 253. Demo HMAC-SHA1 secret `1CE30FD7 8D20DCFA 40B50C18 779AFB0F 02288DB7`; password "a". The challenge is S_kdf (FMT-04, INT-07).

| Value | Variable mode (HMAC over the 32 salt bytes) | Fixed mode (HMAC over the 64 padded bytes, salt then 32 × `20`) |
|---|---|---|
| Response (20 bytes) | `EC5F7C14 27D8B26B 9984228A BB98621B 1165BA18` | `9C401F62 A28029F8 37EFBEC2 C66C5A0F F89A19C0` |
| SHA-256(response) | `709B0674 AA1124DA B024C7D5 0E428BAD B26829CA 8485E038 44300DAA DFF5BF6A` | `AC09BCF2 8C54311A 3D8A9F81 7A823331 848FE61D B4FEE63F 144E3928 5B9F797D` |
| Composite key SHA-256(SHA-256("a") ‖ SHA-256(response)) | `DF5D072B 8C138F85 DEA5D2F0 4CEEFCF3 C001F3C8 3C25D9A2 A5C0F548 FBD8BFA1` | `23112080 91A3912B 3EAC398E 867873F0 8DB702C7 C9C8E998 2D9EC163 78F06D6E` |
| T (Argon2d) | `D38EA2AD C675AF76 807A298A 49D1CFCE 2ED837E8 D28AD2A4 34D70988 9162F22E` | `62EFC477 C9350F91 0E6751A7 85560D41 8CE85A11 8B2CC33E 8BC52F68 352AEAB1` |
| Header HMAC | `7B2D9FF3 CF55BBC5 B51892FD DECD3418 8422556B 82741024 43BC81D1 5BCB4C7D` = the stored value (opens) | `C34777E9 DFD10EDD 353CFCEE 264E1695 C7EB9774 EB3BB0A1 5E38AB3E 5054008F` (differs: WrongKey) |

The reference's hardware-key unit test agrees: with the same secret and the challenge "UnitTest", it expects SHA-256(response) = `2F7802C7 112C3013 03526E77 37B54D54 6C905076 DCA6E953 8EDF761A 2264CD70`, which is the variable-mode result (fixed mode gives `C05A5646 D42CC6BC 55878434 2EE8A083 4D6FB561 2A131CFA A2CAD43C B4023C8E`). Variable mode strips trailing bytes equal to the last padding byte, so a challenge whose own last bytes equal that value loses them too; INT-07 owns that case. FMT-04 and INT-07 should note that the reference's test data uses variable mode, and keep fixed mode as a second vector.

## How this was learned

- Read in the reference source: the top-level reader that checks the two signatures and the version and picks the version 3 or version 4 reader; the shared routine that reads the 12 first bytes and keeps the raw header bytes for the checks; the version 3 and version 4 readers (header field loops, required fields, legacy-field rejection, header SHA-256 and HMAC order); the version 3 and version 4 writers (field order, end-of-header bytes, check values, block streams); the format constants (signatures, version masks, cipher and KDF ids); the cipher id to cipher mapping and IV sizes; the vault model's version and KDF setters; the save routine that picks the version (details in FMT-16); the command line create, import and edit commands and their key file loader; the graphical new vault wizard, encryption settings and key settings code (not run).
- Read the reference's unit tests for version 2, 3 and 4 files, key files, and the command line, and took the test vault passwords from them. Read the outer header of every reference test vault (version, cipher, KDF, compression) with a short script.
- Ran the installed reference command line tool 2.7.11 on demo vaults in a scratch folder: db-create with password, empty password, each key file kind, password plus key file, with and without `-t`; import of edited XML exports to trigger each version rule; `db-edit -p` re-save; opening copies with edited version bytes (3.0 base: 0.0 to 65535.0 range samples; 4.0 base re-sealed with recomputed header SHA-256 and HMAC: 4.1, 4.2, 4.65535, 5.0, 3.1); copies with extra header fields (1, 9, 11, 13, 99); files under 12 bytes, a text file, other second signatures, an old-format test vault, files with bytes appended, an AES-128 cipher id.
- Review round 2: read the outer header of every E0-S5 vault in `testdata/` and decrypted scratch copies of `password-only`, `default-time`, `rich-v3` and `rich-v4` with their demo passwords (blocks, start bytes, inner header, header hash, version-gated elements). Recomputed the Vector L4 keys and HMAC from the card bytes alone. Recomputed the header HMAC of the reference's hardware-key test vault (read only) with a variable-mode and a fixed-mode software response, and checked the expected value in the reference's hardware-key unit test; read the challenge padding in the reference's hardware key drivers. Searched the reference source for a total file size check (none).
- Confirmed the whole layout of a demo 4.0 and a demo 3.1 vault end to end by recomputing the key flow, header SHA-256, header HMAC, block HMACs, the start bytes and the header hash in the document with standard hashes and the system's AES command, and decompressing the payload. Every value matched the files the reference wrote.
- Review round 3 (cross-check findings): turned FMT-01.14 to FMT-01.16 into pointers to FMT-02, which owns framing, the field table and the write order. No fact changed: the removed text matched FMT-02.1 to FMT-02.6, FMT-02.14, FMT-02.21, FMT-02.23 and the FMT-02 field table. Read the version 4 writer's field order again in the source (2, 3, 4, 7, 11, 12 only when not empty, then 0). Made FMT-01.33 the one list of error kinds: added `NoCredentials` and `HardwareKey` from FMT-04.21, moved key file read failures from `Io` to `KeyFile` to match FMT-18.19, and stated the CRY-02.14 ask the way FMT-04.21 does (a returned decision; a decline is not an error; `Cancelled` dropped). Marked the version 3 wrong-key rule "per D-05-1" (FMT-05.11). Read testdata/README.md and the E0-S5 status line in plan/epics.md; both still give 4.1 for any 4.x content, so FMT-01.25 now names both for the lead.
- Sprint 0 close-out: wrote the lead rulings of spec/decisions.md into the card. LD-01 changed FMT-01.20 (bytes after the logical end are ignored, not Corrupt; the observed reference behavior is kept as the fact behind it), the layout table, FMT-01.21, FMT-01.32, the FMT-01.33 Corrupt row, the edge cases, the security note and the tests. LD-05 (FMT-01.10), LD-06 (FMT-01.11), LD-12 (FMT-01.21, FMT-01.33), LD-13 (FMT-01.33, B13), LD-22 (FMT-01.31), LD-34 to LD-36 (plans (c), (e), (L), FMT-01.30) and OD-01 (B10 to B12) are now stated as decided; FMT-01.33 stands by the default rule. Added the rule that a script builds the XML 2.0 key file suffix from bytes, and made the demo-set test name its comparison. Read testdata/README.md, plan/epics.md (E0-S5) and plan/architecture.md (`error.rs` row) again: the lead's changes named in FMT-01.21, FMT-01.25, FMT-01.29 and FMT-01.33 are still to be made.
- Sprint 1 close-out: FMT-01.20 and FMT-01.32 no longer say the version 3 padding is checked (FMT-07.11, LD-01). FMT-01.31 step 1, FMT-01.32 and FMT-01.33 now follow FMT-05.7: the detection result of the read step is kept and reported after the credentials step, and the order of outcomes points to FMT-05.7. Reviewed the layout rulings LD-01, LD-05, LD-06, LD-09, LD-12, LD-13, LD-34, LD-35 and LD-36 in this card; LD-07, LD-08, LD-10 and LD-11 are owned by FMT-16 and FMT-17, which this card points to.
