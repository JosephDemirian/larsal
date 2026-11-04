# CRY-03 Random values made on each save

Status: reviewed
Epics: E3-S7
Parity rows: SF-07, SF-10

## What it does

Every time a vault is written to a file, the writer draws new random values: the master seed, the payload IV or nonce, the KDF salt, the field stream key, and a random padding item inside the document. Because the master seed and the salt change, the final key and the HMAC key change too. The field stream keystream changes because its own key is drawn fresh on every save. So no key and nonce pair is ever used twice, and two saves of the same vault never share ciphertext.

This card lists every random value the reference makes when it saves, creates a vault or creates a key file: which value, how many bytes, whether it is fresh on every save or only on some events, and where the randomness comes from. It then fixes what App does.

Plain answer to the main question: **the reference refreshes the KDF salt on every save**, in both file versions, not only when the key or the KDF settings change. It also refreshes the master seed, the IV or nonce, the field stream key and (version 3) the stream start bytes on every save. Values it does **not** refresh on save are listed in CRY-03.12.

## Inputs and outputs

- In: the vault to write, its cipher (CRY-01) and KDF settings (CRY-02), and the operating system's random source.
- Out: fresh random bytes placed in the file as below. Nothing random is kept in memory after the save except as part of the vault's in-memory settings (the new salt). Or a failed save with nothing written, when a random draw fails (CRY-03.9) or the new transformed key equals the previous one (CRY-03.16).

### Values drawn on every save, version 4 (what App writes)

| Value | Size | Where in the file | Fresh |
|---|---|---|---|
| Master seed | 32 bytes | outer header field 4 (FMT-02) | every save |
| Payload IV or nonce | 16 bytes (AES-256, Twofish-256), 12 bytes (ChaCha20) | outer header field 7 | every save |
| KDF salt (`S`) | 32 bytes in App; the reference keeps the current length, see CRY-03.4 | KDF map, header field 11 (FMT-03) | every save; also when KDF settings change; also when a vault is created |
| Field stream key | 64 bytes | inner header field 2 (FMT-09) | every save |
| Random padding item | 64 to 511 random bytes, written as lowercase hex text (128 to 1,022 characters) | an item in the document's metadata custom data (FMT-10, FMT-14) | every save to a file; see CRY-03.7 |

### Values drawn on every save, version 3 (reference writer only; App does not write version 3)

| Value | Size | Where | Fresh |
|---|---|---|---|
| Master seed | 32 bytes | header field 4 | every save |
| Payload IV or nonce | 16 or 12 bytes | header field 7 | every save |
| KDF seed | 32 bytes | header field 5 | every save |
| Field stream key | 32 bytes | header field 8 | every save |
| Stream start bytes | 32 bytes | header field 9, and again as the first 32 plaintext bytes (FMT-07) | every save |
| Random padding item | as above | metadata custom data | every save to a file |

### Values derived from them (not drawn, but therefore also new on every save)

The final key and the HMAC key (FMT-04), the header hash and header HMAC (FMT-05), every block HMAC (FMT-06), the field stream cipher key and nonce (CRY-01.14), the transformed key (CRY-02, because the salt changed), and in version 3.1 the header hash stored in the document.

## Rules

CRY-03.1 Every save draws a new 32-byte master seed.

CRY-03.2 Every save draws a new payload IV or nonce of the cipher's size: 16 bytes for AES-256 and Twofish-256, 12 bytes for ChaCha20 (CRY-01.8).

CRY-03.3 Every save draws a new KDF salt and runs the KDF again with it, so every save costs one full KDF run (CRY-02.15) and produces a new transformed key. The reference does exactly this, in version 3 and version 4 (source reading, and observed: the salt changed on each of 30 saves of a version 3 demo vault and on saves of version 4 demo vaults with Argon2d, AES-KDF old id and AES-KDF new id).

CRY-03.4 The new salt App writes is always 32 bytes, whatever length the file had. The reference instead keeps the length of the salt it currently holds: 32 bytes for vaults it created, but a vault read with a shorter salt (8 to 31 bytes, allowed by CRY-02.7) keeps that shorter length on every later save (observed: a 16-byte Argon2 salt stayed 16 bytes after a save; a 16-byte AES-KDF seed stayed 16 bytes, which also keeps that vault without AES work, see CRY-02.12). App is stricter here (decided: spec/decisions.md LD-15; it costs nothing, because every save runs the KDF again).

CRY-03.5 Every save draws a new 64-byte field stream key and writes field stream id 3 (CRY-01.18). The protected values are encrypted again with the new keystream.

CRY-03.6 The hardware-key challenge is fresh on every save because it is made from a fresh value: in version 4 the challenge is the KDF salt, in version 3 the master seed (FMT-04). So a save with a hardware key in the composite key asks the hardware key again.

CRY-03.7 Random padding item. The reference adds, on every save to a file (create, save, save as; also from the command line tool), one item to the vault's metadata custom data: key stored encoded (name rule) `4B 50 58 43 5F 52 41 4E 44 4F 4D 5F 53 4C 55 47`; value = L random bytes as lowercase hex, where L is drawn uniformly from 64 to 511 inclusive (unbiased). Its purpose is to make the file size differ from save to save, so that two copies of one vault cannot be matched by size or by storage deduplication. Observed: present after every save; over 30 saves L ranged from 118 to 510 and the value always changed; the item is in version 3.1 files too. The reference marks the item as automatic: a merge never copies it from one vault into another (MOD-11), and each save replaces its value. App writes the same item, with the same encoded key and the same value rule (L uniform from 64 to 511, unbiased, lowercase hex), with a fresh value on every save to a file; an existing copy, from the reference or an earlier App save, is replaced, never kept or merged (decided: spec/decisions.md LD-16).

CRY-03.8 All values in CRY-03.1 to CRY-03.7 come from separate draws. No value is reused from an earlier save, and no value is derived from another drawn value (AT-B03: across 10,000 saves no master seed, IV or nonce, salt or field stream key repeats).

CRY-03.9 All random bytes come from `app-crypto::random`, which reads the operating system's random source only (AT-B04, architecture Rust rule 7). If the source fails, the save fails before any byte of the new file is written, and the old file stays as it was (atomic save, SD-01). The reference draws all values in CRY-03.1 to CRY-03.7 from one random module that wraps its crypto library's system generator (the operating system's source); a failure there raises an error that the save code does not catch (source, re-read by Verify in Sprint 3: the random module fills each value straight from the crypto library's system generator, which signals a failure by throwing; no code on the save path catches it: not the version 3 or version 4 writers that draw the master seed, IV, stream key and start bytes, not the KDF seed refresh, not the vault save routine that draws the padding item, and neither the command line tool nor the app has a handler around them, so the process ends before the new file is committed. Not run: the system source cannot be made to fail from outside).

CRY-03.10 Order on save: App draws all random values for the save and derives the keys first, then runs the key-change check of CRY-03.16, then writes. A failure at any step writes nothing (the temp file is removed).

CRY-03.11 Creating a vault: the new vault's KDF salt is drawn when its KDF settings are first set and again at the first save (CRY-03.3); everything else in CRY-03.1 to CRY-03.7 is drawn at the first save. New object ids (root group, recycle bin when it is first made, every new group and entry) are 16 random bytes. The reference makes them with its UI toolkit's random UUID function, which gives RFC 4122 version 4 ids (high nibble of byte 6 = `4`, top two bits of byte 8 = `10`) from the operating system's source, not from its own random module. App makes ids from `app-crypto::random` with the same version and variant bits, so ids look alike. Other random ids made the same way and then saved: custom icon ids (an icon added in the icon editor or fetched by the icon download gets a new random version 4 id, unless the same icon bytes are already in the vault, whose id is then reused; FMT-14), copies of groups and entries, and ids the reference's document reader makes while reading: a group or live entry with a missing or invalid id gets a fresh random id (FMT-11.34), a custom icon whose id repeats an earlier icon's id gets a fresh random id (FMT-14.7), and a clashing inline attachment name, in any version, gets a prefix of 8 random lowercase hex digits and `_` (FMT-13.13, which owns when App renames: only when at least one of the two values is inline; the reference takes the 8 digits from the start of a new random version 4 id's text, so all 8 are random). All of these come from `app-crypto::random` in App.

CRY-03.12 Not refreshed on save (by design): object ids; the KDF type and every KDF setting other than the salt, except that an Argon2 version 0x10 is written as 0x13 (CRY-02.19, LD-17); the cipher choice; the compression flag; attachment contents; custom data other than the padding item; the public vault id item (FMT-03.23).

CRY-03.13 The gzip stream adds no randomness (observed in reference-written files: header `1f 8b 08 00 00 00 00 00 00 13`, modification time zero; FMT-08 owns the details).

CRY-03.14 Creating a key file draws random bytes once, at creation (FMT-18 has the layouts). The reference makes two kinds. Plain key file: 128 random bytes written as the whole file. Structured XML key file, version 2.0 (chosen by the reference when the file name ends with the extension stored encoded (name rule) `2E 6B 65 79 78`, compared case-sensitively, so an uppercase ending gives the plain form; FMT-18 owns the details): 32 random bytes, written as uppercase hex, with a check value = the first 4 bytes of SHA-256(the 32 bytes), as uppercase hex. The reference sets the new key file to owner read-only (observed: mode 0400) and, in the command line tool, silently creates a missing key file when one is named for a new vault (observed for both kinds). App creates only the XML 2.0 kind, whatever the file name: each created file draws 32 random bytes once from `app-crypto::random` (decided: spec/decisions.md LD-31; FMT-18.21 owns the layout). App never creates the 128-byte plain kind. App sets every new key file to owner read-only, mode 0400, like the reference (FMT-18.22, compare AT-I06); App's own key file extension is `.appkey` (AGENTS.md naming). App's command line tool, like the reference's, creates a missing key file named for a new vault, in the same XML 2.0 kind (decided: spec/decisions.md default rule, reference behavior; INT-10 owns the command).

CRY-03.15 Nothing random is ever derived from the password, from time, from a counter or from a non-cryptographic generator. Ids, salts, seeds, IVs, keys and padding all come from CRY-03.9.

CRY-03.16 Key-change check on save (SF-07). After the new transformed key is derived with the fresh salt or seed (CRY-03.3), App compares it in constant time with the vault's previous transformed key: the one from the last open or successful save of this vault, held in wiped memory. If they are equal, the save fails and nothing is written: no temp file is made (APP-05.11 builds the bytes before it touches any file), the vault file stays as it was, and the vault in memory stays changed (APP-05.13). The error holds no key bytes. When the vault has no previous transformed key (the first save of a new vault), there is nothing to compare. Why: equal keys mean the KDF did not run with the new salt, or ignored it. The file would then carry a salt that does not produce the key that encrypted it, and it could never be opened again. Reference (source reading, the same in the installed 2.7.11 tag and the development source): its save routine has a similar guard, with three differences. (1) It keeps the previous transformed key only when the vault's composite key has no component at all. For a vault with a password, key file or hardware key it keeps nothing, so the comparison never matches, and the guard then catches only an empty new key. (2) It compares after its writer has written the whole file into the save target (a pending atomic save file, a temp file, or a memory buffer in its direct-write mode). On a failure it does not commit, rename or write, so the vault file on disk stays unchanged, and it shows a message that the key was not transformed and that this is a bug to report. (3) It compares with plain byte equality, not in constant time. App differs on all three: it checks every vault, before any byte is written, in constant time.

## Edge cases and errors

- **Random source fails** (simulated in a test build): save fails with `Io` (or the random error kind `app-crypto` defines), no temp file left, the vault file unchanged, the vault in memory unchanged and still marked as changed.
- **Two saves within the same millisecond**: still different values (nothing depends on time).
- **Vault read with a 16-byte salt**: next App save writes a 32-byte salt (CRY-03.4); the reference would keep 16.
- **Vault read with field stream id 2 (Salsa20)**: next save writes id 3 with a fresh 64-byte key (CRY-03.5).
- **Vault with an 8-byte or 24-byte ChaCha20 nonce**: App refuses to open it (CRY-01.9), so no App save follows. The reference opens it, and its next save writes a fresh 12-byte nonce (observed for 8 bytes).
- **Cipher changed before save**: the IV drawn has the new cipher's size (CRY-03.2).
- **Save fails after the KDF ran** (disk full, AT-I02): the new salt and seed are dropped; the next save attempt draws new ones again.
- **New transformed key equals the previous one** (a KDF fault): the save fails before any file is made, the old file stays as it was, the vault stays changed (CRY-03.16).
- **The padding item already exists with any value** (from the reference or an earlier App save): replaced with a fresh value (CRY-03.7, LD-16).
- **Export to an unencrypted format**: not a save of the vault file; no values from this card are drawn (FEA-09).

## Security notes

- What must never happen: the same master seed or IV reused across saves (for ChaCha20 that would reuse a keystream and leak the XOR of two payloads); the same field stream key reused (leaks protected values across saves); a salt reused (lets one precomputed guess table serve many saves); random values taken from anything but the OS source (AT-B04).
- The salt refresh makes each save run the KDF, so saves are slow (about the unlock time). That cost is part of parity and must stay off the screen thread (CRY-02.15).
- The padding item hides the exact size of the vault's content only roughly (it adds 128 to 1,022 hex characters before compression, a spread of 894, and hex text compresses to about half). It is a privacy measure, not a security boundary.
- Header values (master seed, IV, salt) are public by design; they are random but not secret (SF-12). The field stream key is secret and lives only inside the encrypted payload; in memory it is a wiped secret type.
- Random draws happen in `app-crypto` only; `app-format` asks for bytes and never seeds or stores a generator.
- A save that wrote a new salt while encrypting with keys from the old transformed key would lock the user out of the vault for good. CRY-03.16 stops that save before anything is written, and compares in constant time so the check itself leaks nothing about the key.
- Parity rows: SF-07 (fresh random values on every save), SF-10 (new key files with random content and a check value). Attacks and checks: AT-B03, AT-B04, AT-I01, AT-I02.

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| T1 CRY-03.1 and CRY-03.2 | Demo vault, AES-256 | Save twice without changes; parse both files | Field 4 (32 bytes) differs; field 7 (16 bytes) differs |
| T2 CRY-03.2 ChaCha20 | Demo vault, ChaCha20 | Save twice | Field 7 is 12 bytes both times and differs |
| T3 CRY-03.3 salt | Demo vaults with Argon2d, Argon2id, AES-KDF | Save twice each | `S` differs each time; every other KDF setting is equal; both files open with the same password |
| T4 CRY-03.3 KDF runs on save | KDF spy on a demo vault | Save | Exactly one KDF run during the save, on a worker thread |
| T5 CRY-03.4 salt length (LD-15) | Demo vault read with a 16-byte Argon2 salt | Save, parse | `S` is 32 bytes; the file opens in App and with the reference command line tool (installed version) |
| T6 CRY-03.5 field stream key | Demo vault with a protected password `demo-secret-1` | Save twice; decrypt both payloads with the test key | Inner stream id 3 both times; 64-byte keys differ; protected ciphertexts differ; both decrypt to `demo-secret-1` |
| T7 CRY-03.6 challenge | Demo vault with a mock hardware key that records challenges | Save twice | Two different 32-byte challenges, each equal to that save's `S` (version 4) |
| T8 CRY-03.7 padding item (LD-16) | Demo vault | Save 30 times; read the item each time | Item present with the encoded key; value lowercase hex of even length 128 to 1,022; value differs every time |
| T9 CRY-03.7 length spread | App's function that turns raw random draws into L | Feed it every possible raw input value of one draw (exhaustive, for example all 65,536 values if it draws 2 bytes and rejects some), with no real random source | Every accepted input gives an L in 64 to 511; every L from 64 to 511 comes from exactly the same number of accepted inputs (unbiased); rejected inputs give no L and lead to a new draw |
| T10 CRY-03.8 AT-B03 | Demo vault | Save 10,000 times, collect field 4, field 7, `S`, the field stream key | No value repeats within any of the four sets, and no value appears in two sets |
| T11 CRY-03.9 one source | Code search of the workspace | Search for random generators outside `app-crypto::random` | None (AT-B04) |
| T12 CRY-03.9 source failure | Test build with a failing random source | Save | Save fails; old file byte-for-byte unchanged; no temp file left |
| T13 CRY-03.10 order | Test build where the third random draw fails | Save | Nothing written; the vault in memory still marked changed |
| T14 CRY-03.11 new vault | Create a vault with defaults | Parse the first saved file | Root group id has version nibble `4` and variant bits `10`; salt 32 bytes; all CRY-03.1 to CRY-03.7 values present |
| T14b CRY-03.11 attachment rename, version 4 | Version 4 demo vault with one entry holding two inline `Binary` values both named `f.txt`, contents `AAA` and `BBB` | Open twice | Each time: `f.txt` = `AAA` and one more attachment named 8 lowercase hex digits, `_`, `f.txt` with `BBB` (FMT-13.13); the two opens give different prefixes |
| T15 CRY-03.12 kept values | Demo vault with Argon2id m = 65,536, I = 7, P = 4, a custom data item `demo-key` = `demo-value`, and the public vault id item (FMT-03.23) in the outer header | Save | Those settings, that item and that public id are unchanged; apart from the CRY-03.1 to CRY-03.7 values, only time values changed: the vault custom data's last-modified item (FMT-14.18) and, in version 4.1, the padding item's `LastModificationTime` (FMT-14.21) |
| T16 CRY-03.13 gzip | Demo vault with compression on | Save; decrypt; read the first 10 payload bytes | Bytes 4 to 7 (modification time) are zero |
| T17 CRY-03.14 one kind only (LD-31) | Create key files in App named `demo.appkey`, `demo.bin`, `demo` and one ending in the reference's XML key file extension (the encoded bytes in CRY-03.14), also with that extension in uppercase | Read each | Every file is XML 2.0 with 32 random key bytes and a check value (FMT-18.20); none is a 128-byte plain file; the key bytes of all five differ; file mode 0400 (FMT-18.22) |
| T18 CRY-03.14 XML key file (LD-31) | Create a structured key file in App twice | Parse both | 32 key bytes as uppercase hex, different in the two files; check value = first 4 bytes of SHA-256 of them, uppercase hex; file mode 0400; the reference opens a vault locked with it |
| T19 CRY-03.15 no time seed | Freeze the clock in a test build | Save twice | Values still differ |
| T21 CRY-03.16 key-change check (SF-07) | Demo vault opened in App with `demo-pass`; a test build whose KDF returns the vault's previous transformed key whatever the salt | Save | Save fails; no temp file was made; the old file is byte-for-byte unchanged; the vault in memory is still changed; the error text holds no key bytes. With the real KDF the same save succeeds and its new transformed key differs from the previous one. Code review: the comparison uses the constant-time compare of `app-crypto` |
| T20 CRY-03.3 reference parity | Reference command line tool, version 3.1 demo vault (password `demo-pass-1`) | Make 30 changes with the tool; parse header fields 4, 5, 7, 8, 9 after each | All five change on every save, none repeats (observed) |

## How this was learned

- Searched the whole reference source for every use of its random module and of the UI toolkit's random UUID function, and read each place that touches saving, vault creation and key files: both file writers (which values, which sizes), the vault object (salt refresh when the key is set during a save, salt refresh when KDF settings change, the random padding item in the save-to-file routine, the public vault id), the KDF base (salt refresh keeps the current length), the key file code (sizes, check value, owner read-only), the command line tool's key file loading (creates a missing file), and the random module itself (system generator, unbiased range draw).
- Compared the installed release tag 2.7.11 with the development source: the save-time random values are the same; the public vault id exists only in the development source.
- Observed with the installed command line tool (2.7.11) on demo vaults in `/tmp`: 30 saves of a version 3.1 vault (all header values fresh, padding item lengths 118 to 510 bytes), saves of version 4 demo vaults built by a scratch writer (master seed, nonce, salt and field stream key all fresh; salt length kept at 16; Salsa20 field stream rewritten as ChaCha20; 8-byte nonce rewritten as 12 bytes), key file creation by the create command (128 bytes, or the XML form, mode 0400), and the gzip header of reference-written payloads (decrypted with the scratch reader).
- Cross-check pass: re-read the document reader's attachment handling; the rename of a clashing inline attachment sits in the reader shared by both versions, so it applies in version 4 too (FMT-13.13).
- Sprint 0 close-out: the lead rulings LD-15, LD-16, LD-17 and LD-31 and the default rule (command line key file creation) were written in. Observed reference behavior is kept as facts.
- Sprint 1 close-out: added CRY-03.16, the key-change check that SF-07 names, with test T21. Read in the reference source, in the development commit and the 2.7.11 tag: the save routine's write step, which keeps the old transformed key only when the composite key is empty, compares after the writer has filled the save target, and returns failure so the save file is not committed, the temp file is not renamed, and the direct-write buffer is not written. The key type there returns an empty value when it was never set.
