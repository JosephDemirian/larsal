# FMT-05 Header integrity and the wrong-key rule

Status: reviewed
Epics: E3-S4
Parity rows: SF-05, SF-04

## What it does

The outer header of a vault file is stored in clear text. This card says how the header is protected and how App tells "the key is wrong" from "the file is damaged".

Version 4 puts two 32-byte values right after the header:

1. A plain SHA-256 hash of the header bytes. It needs no key, so anyone can check it. It finds accidental damage only.
2. An HMAC-SHA-256 of the header bytes. Its key comes from the master seed and the transformed key, so only someone with the right key can make or check it. If this check fails, the key is wrong (or someone changed the header and fixed the plain hash).

Version 3 has neither value. It finds a wrong key by decrypting the first 32 bytes of the payload and comparing them with the "stream start bytes" stored in the header. Its header hash, when present, sits inside the encrypted XML document and is checked only after the document has been read.

App's rule: **`WrongKey` only when the version 4 header HMAC fails.** Version 3 has no HMAC. It has one other `WrongKey` case: the start bytes do not match (FMT-05.11, decided: spec/decisions.md LD-12). Other cards that state the version 3 wrong-key rule point to FMT-05.11. Every other failure is `Corrupt`, or another kind from the step of FMT-05.7 where the failure happens (`Io`, `KeyFile`, `NoCredentials`, `Unsupported`, `TooLarge` or `HardwareKey`; FMT-01.33 lists them all).

The block stream after the header HMAC is in FMT-06. The hashed block stream of version 3 is in FMT-07. How the transformed key is made is in FMT-04.

## Inputs and outputs

Notation used in this card:

- `||` joins byte strings.
- `LE64(x)` is x as an unsigned 64-bit little-endian integer (8 bytes).
- `S` is the 32-byte master seed from header field id 4 (FMT-02).
- `T` is the 32-byte transformed key, the KDF output over the composite key (FMT-04, CRY-02).
- `H` is the length of the header bytes (FMT-05.1).
- Hex bytes are written in file order.

Inputs, version 4:

- The file bytes. App reads the whole input into memory, up to the total file limit in `limits.rs` (FMT-01.31), before it parses anything beyond the 12-byte look of the read step (FMT-05.7).
- `T`, which `app-crypto` derives from the user's credentials. The KDF is slow, so it runs on a worker thread.

Outputs, version 4:

- Success: the header is authentic and the key is right. The block stream starts at offset `H + 64` (FMT-06).
- `Corrupt`: the file is too short for the hash and HMAC, or the plain hash does not match.
- `WrongKey`: the header HMAC does not match.

Inputs, version 3: the file bytes, the final cipher key from FMT-04 (which may include a hardware-key part in version 3), and the IV from the header.

Outputs, version 3:

- Success: the decrypted plaintext after the 32 start bytes goes on to FMT-07.
- `WrongKey`: the start bytes do not match (FMT-05.11, decided: spec/decisions.md LD-12).
- `Corrupt`: anything else.

Sizes: the hash is 32 bytes. The HMAC is 32 bytes. The HMAC base key `K` is 64 bytes. The header HMAC key is 64 bytes. The start bytes are 32 bytes.

## Rules

FMT-05.1 **Header bytes.** The header bytes are the raw file bytes from offset 0 up to and including the last data byte of the end-of-header field (field id 0; field layout in FMT-02). They include the 4+4-byte signature, the 4-byte version, every header field in stored order (unknown fields too), and the end-of-header field's id, length and data. Their length is `H`. The hash and HMAC always cover these bytes exactly as read from the file. App never re-encodes the header to check it. Example: the reference command line tool writes a version 4 header with AES-KDF settings that is 207 bytes long. Its end-of-header field is `00 04 00 00 00 0D 0A 0D 0A`.

FMT-05.2 **Version 4 layout after the header.** Bytes `[H, H+32)` hold the stored header hash. Bytes `[H+32, H+64)` hold the stored header HMAC. The HMAC block stream (FMT-06) starts at offset `H+64`. Nothing else sits between them.

FMT-05.3 **Header hash.** The stored header hash is SHA-256(header bytes). It has no key.

FMT-05.4 **HMAC base key.** `K = SHA-512(S || T || 01)`. That is 32 + 32 + 1 = 65 input bytes, and the last byte is the single byte `01`. `K` is 64 bytes. It is different from the payload cipher key, `SHA-256(S || T)` in version 4 (FMT-04, FMT-08). The same `K` keys the header HMAC and every block of FMT-06.

FMT-05.5 **Header HMAC key.** `K_hdr = SHA-512(FF FF FF FF FF FF FF FF || K)`. This is the per-block key formula of FMT-06.4 with index 2^64 − 1, a value no block can ever use.

FMT-05.6 **Header HMAC.** The stored header HMAC is HMAC-SHA-256 (RFC 2104, FIPS 198-1) with key `K_hdr` (all 64 bytes) over the header bytes. A 64-byte key equals the SHA-256 block size, so HMAC uses it as is, with no hashing and no padding.

FMT-05.7 **Order of an open (App). This rule is the single owner of the whole open order.** When a file, its key file or the user's credentials have more than one fault, App reports only the first one it meets in the order below and stops there. Each step names where its checks and error kinds are defined. Other cards describe only their own step: FMT-01.31 (the read), FMT-18.19 and FMT-04.21 step 1 (credentials), FMT-01.2 to FMT-01.7 (detection and version), FMT-02.30 steps 1 to 4 with FMT-03 (header fields), CRY-02.14 and FMT-04.21 step 2 (cost), FMT-04.21 steps 3 to 5 (hardware key, KDF, check). Where another card's wording puts a step somewhere else, this rule wins. In particular: FMT-04.21 step 1 runs at step 0 below, before any header field is parsed and before the detection result is reported, and FMT-04.21 steps 2 to 5 run at steps 4 and 5. FMT-02.30 step 5 hands over to step 2 below. Version 4 runs every step below. Version 3 runs the read and steps 0 and 1 below, then goes on at FMT-05.13 step 2.

Read (before step 0). Read the vault source into memory (FMT-01.31, FMT-01.32). This step reports only `Io` or `TooLarge`. FMT-01.31 step 1 looks at the first 12 bytes during the read for one purpose only: deciding whether a source over the total file limit is `TooLarge`. When those 12 bytes pass detection and the version check, the result is `TooLarge` here. When they fail (too short, not a vault, old format, unsupported version), the read may stop early with no `TooLarge`. The detection result is not reported here. It is kept and reported at step 1, after step 0. A source within the limit (every source under 12 bytes is) is read whole, and its detection result is likewise reported at step 1.
0. Credentials. Build the password and key file parts of the composite key (FMT-04.21 step 1, FMT-18). Every key file error ends the open here (`KeyFile`, FMT-18.19). Opening with no credential at all is refused with `NoCredentials` at this step, before any key work (FMT-04, decided: spec/decisions.md LD-13). No vault byte has been parsed yet, apart from the 12-byte look of the read step, and no key work has been done. So a key file error always wins over any fault in the vault file that the read step did not report, whatever that fault is.
1. Detection, version and header fields. First detection and the version check on bytes 0 to 11 (FMT-01.2 to FMT-01.7, FMT-02.30 step 1), with the kinds of FMT-01.33. Then the header fields in file order, the required fields and the IV length (FMT-02.30 steps 2 to 4). This includes the full KDF map and the KDF settings checks (FMT-03, CRY-02.5 to CRY-02.13, FMT-04.20). Their kinds are given in those cards (`Corrupt`, `Unsupported`, `TooLarge`). No key work is done. The version picks the layout (FMT-01.8): version 3 goes on at FMT-05.13 step 2.
2. If fewer than 64 bytes follow the header, the result is `Corrupt`.
3. Compute SHA-256 of the header bytes and compare it with the stored hash. On a mismatch the result is `Corrupt`. App does this **before** the cost check, before it sends any hardware-key challenge and before it runs the KDF. So a damaged header gives `Corrupt` and never asks the cost question.
4. Key work, in this order (FMT-04.21 steps 2 to 4):
   a. The KDF cost check (CRY-02.14). Above a refuse ceiling: `TooLarge`. In the ask band: the "ask the user first" decision of FMT-04.21 step 2, with the cost report of CRY-02.14. It is not an error kind. On yes, the caller runs the open again with the approval (CRY-02.14). On no, the open stops here with nothing done and no error.
   b. The hardware key, if the key has one (FMT-04.10). In version 4 the challenge is the KDF seed. A hardware-key error (`HardwareKey`, FMT-04.21 step 3) ends the open here, before the KDF, and is never `WrongKey`.
   c. Derive `T` (FMT-04). A KDF library failure is `Unsupported` (CRY-02.16). Then derive `K` (FMT-05.4) and `K_hdr` (FMT-05.5).
5. Compute the header HMAC (FMT-05.6) and compare it with the stored HMAC in constant time. On a mismatch the result is `WrongKey` (FMT-04.21 step 5).
6. Only after step 5 passes does App read the block stream (FMT-06), decrypt (FMT-08) and parse. Those failures are never `WrongKey` (FMT-05.8). Their kinds are given in those cards.

The reference's order, for comparison. Its command line tool checks that the vault file exists, is a plain file and is readable before it loads the key file (source reading; observed with the installed tool: a vault path that does not exist, given with an empty key file and with a missing key file, gave the vault-not-found message both times). So the read step comes before step 0 in both. Its command line tool and its unlock screen then load the key file and stop on a key file error without reading the vault header (source reading; observed with the installed tool on a version 3.1 demo vault with a damaged master seed, and on a copy cut to 5 bytes, each with an empty key file and with a missing key file: the key file error was shown each time). So step 0 matches the reference. The reference has no total file limit and no cost check (FMT-01.31, CRY-02.14). It does steps 2 and 3 after the KDF: it checks the required fields, derives the keys, then reads the 64 bytes and checks the hash, then the HMAC (source reading). The result is the same for every file where key derivation succeeds, and App saves the KDF time on a damaged file. When key derivation fails (a KDF error, or a hardware key that is missing or fails) on a file whose header is also damaged or cut, the reference reports the key-derivation failure and App reports `Corrupt`. This is an intended known difference (D-05-3).

FMT-05.8 **The wrong-key rule, version 4.** App reports `WrongKey` if, and only if, step 5 of FMT-05.7 fails. No failure after step 5 is ever `WrongKey`, because the key has been proven. That includes block HMAC, padding (decided: spec/decisions.md LD-03), decompression and document errors, and all of them are `Corrupt`. When the stored HMAC itself is damaged, or the header was changed and its plain hash recomputed, App also reports `WrongKey`. The format cannot tell those cases from a wrong key.

FMT-05.9 **Writing version 4.** App writes, in this order: the header bytes, then SHA-256(header bytes), then the header HMAC (FMT-05.6), then the block stream (FMT-06). The HMAC uses the fresh master seed of this save (CRY-03) and the `T` of this save. In version 4 the XML document has no header hash. The reference writes the `HeaderHash` metadata element only in version 3 files, so App never writes it in version 4. On a version 4 read, a `HeaderHash` element in the document is read and ignored: it is never checked, whatever its value (FMT-10.21). It is not kept in the model, so App's next save drops it. The reference does the same on both counts.

FMT-05.10 **Version 3 start bytes.** In version 3 the encrypted payload starts right at offset `H`, with no hash or HMAC in front. After decryption (FMT-08), the first 32 plaintext bytes must equal the 32-byte stream start bytes from header field id 9 (FMT-02, FMT-17). App compares them in constant time. The rest of the plaintext is the hashed block stream (FMT-07), followed by the cipher padding when the cipher is CBC. Nothing after the final hashed block is read, the padding included (FMT-05.13 step 6, FMT-07.11). The reference writes 32 fresh random start bytes on every version 3 save.

FMT-05.11 **The wrong-key rule, version 3 (decided: spec/decisions.md LD-12).** A start-bytes mismatch gives `WrongKey`. This is the only `WrongKey` case in version 3. Hashed block failures (FMT-07), decompression failures, document errors and a header hash mismatch (FMT-05.12) all give `Corrupt`. The padding is never checked (FMT-07.11), so it gives no result at all. FMT-01.21, FMT-07.12, FMT-08.2, FMT-17.13 and CRY-01 state the same version 3 rule by pointing here. plan/architecture.md (`error.rs` row: `WrongKey` only when the header HMAC fails) is read with this version 3 case added.

FMT-05.12 **Version 3 header hash.** The document's metadata may hold a `HeaderHash` element: base64 of 32 bytes (FMT-10.21). App takes its value like this, the same way as the reference (observed):
1. If the element appears more than once, only the last one counts (FMT-10.13). Earlier ones are ignored, even when they are wrong.
2. The text is decoded with the lenient base64 rule of FMT-12.20, which never fails: characters outside the base64 alphabet (spaces, line breaks, `=`, `-`, `_`, `!` and so on) are skipped. If the element carries a true `Protected` attribute, FMT-12.22 applies first.
3. If the element is absent, or the decoded value is zero bytes long (empty text, or text with no alphabet characters, such as `-_`), App does no check.
4. Otherwise the decoded value must be exactly the 32 bytes of SHA-256(header bytes). Any other value gives `Corrupt`, including a value of any other length (for example 31 or 33 bytes).

The value lives inside the document, so App checks it after the document is parsed, and before any vault data reaches `app-core`. The reference accepts files with no value to check. Version 3.0 files made by other writers often lack it (for example the reference test vault `Format300`). The reference checks the element whenever it is present, whatever the minor version.

FMT-05.13 **Version 3 order of checks (App).** This continues the single open order of FMT-05.7, which owns the read and steps 0 and 1. They are repeated here only as pointers.
0. The read and the credentials, exactly as in FMT-05.7 (read step and step 0). Every key file error ends the open here (FMT-18.19), before the header is parsed.
1. Detection, version and header fields, exactly as in FMT-05.7 step 1, with the version 3 field rules of FMT-17.
2. Check the ciphertext length (every byte from `H` to the end of the file). It must be at least 32 bytes, otherwise the result is `Corrupt`. App does this before the KDF. There is no multiple-of-16 rule, for any cipher. For a CBC cipher (AES-256, Twofish), App decrypts whole 16-byte cipher blocks only, and 1 to 15 leftover bytes at the end of the file lie after the logical end and are ignored (step 6). A stream cipher (ChaCha20, which the reference reads and writes in version 3.1, CRY-01) has no padding (FMT-08.4).
3. Key work, in the same sub-order as FMT-05.7 step 4 (FMT-04.21 steps 2 to 4). Check the KDF cost limits (CRY-02.14). If the key has a hardware-key part, send the challenge now (FMT-04.10; in version 3 the challenge is the master seed). A hardware-key error ends the open here, before the KDF, and is never `WrongKey`. Then derive the final cipher key (FMT-04). The reference runs the KDF first and sends the challenge after it in version 3 (FMT-04.10); so when both the KDF and the challenge would fail, App reports the hardware-key error and the reference the KDF error.
4. Decrypt only the first 32 plaintext bytes and compare them with the start bytes. For CBC these are the first two 16-byte cipher blocks. For ChaCha20 they come from the first 32 ciphertext bytes and the first 32 keystream bytes. The padding is not touched. On a mismatch the result is `WrongKey` (FMT-05.11).
5. Decrypt the rest: CBC without removing any padding, ChaCha20 byte for byte. App may decrypt every remaining whole cipher block at once or only as far as the walk reaches; the result is the same. Walk the hashed block stream from plaintext offset 32 (FMT-07). On a failure, including plaintext that ends before the final hashed block, the result is `Corrupt`.
6. Stop at the end of the final hashed block. Every byte after it is ignored and never read as content: the CBC padding (whatever it holds), any other plaintext, further cipher blocks and leftover bytes (FMT-07.11, decided: spec/decisions.md LD-01). So App does not check the PKCS#7 padding in version 3. This step never fails.
7. Decompress and parse the document (FMT-08, FMT-10). On a failure the result is `Corrupt`.
8. Check the header hash (FMT-05.12). On a failure the result is `Corrupt`.

The start-bytes check comes before the walk, so a wrong key always gives `WrongKey` and never `Corrupt`. Since the padding is never checked in version 3, no padding result exists that could act as an oracle (AT-B07, read as spec/decisions.md LD-04 says).

FMT-05.14 **Messages.** `app-format` returns only the error kind. Screen text comes from `app-desktop` and APP-06. The reference's own messages are listed under Edge cases for comparison. App does not need to copy them.

FMT-05.15 **Secret handling.** `T`, `K`, `K_hdr`, the payload cipher key and the decrypted start bytes are secrets. They live in wiped-on-drop types in `app-crypto` (`SecretBytes`) and are dropped as soon as the checks and decryption are done. The header bytes, the stored hash, the stored HMAC and the stored start bytes are public. The debug log may name the check that failed (for example "header hash mismatch"). It must never contain key bytes or decrypted bytes.

## Edge cases and errors

How the reference reports each failure, observed with the installed command line tool version 2.7.11. The tool prints a fixed prefix saying that reading the vault failed, then the message, and exits with status 1. The graphical app shows the same message text in the unlock screen's message bar (from source reading). When the password field is empty, it first offers to retry with an empty password, whatever the failure (APP-06).

| Situation | Reference message (paraphrased) | App kind |
|---|---|---|
| Version 4: fewer than 64 bytes after the header | The header checksum has the wrong size. | `Corrupt` |
| Version 4: plain header hash does not match | The header's SHA-256 does not match. | `Corrupt` |
| Version 4: header HMAC does not match (wrong password, wrong key file, damaged stored HMAC, or header changed with its hash fixed) | The credentials are invalid, try again; if this keeps happening the file may be damaged. A short note naming an HMAC mismatch is added at the end. | `WrongKey` |
| Version 4: a byte flipped in the header, with a wrong password | The header's SHA-256 does not match. The hash is checked before the HMAC. | `Corrupt` |
| Version 3: start bytes do not match (wrong key, or damage to the master seed, transform seed, rounds, IV, start bytes field, or the first two ciphertext blocks) | Same wrong-credentials text as version 4, without the HMAC note. | `WrongKey` (FMT-05.11) |
| Version 3: file ends less than 32 bytes after the header | Same wrong-credentials text (the short read does not match the start bytes). | `Corrupt` (App can tell the file is cut; known difference D-05-4) |
| Version 3: header hash in the document does not match, or decodes to a length other than 0 or 32 | The header and its stored hash differ (observed with 31 and 33 bytes). | `Corrupt` |
| Version 3: a ciphertext byte changed from `H+32` on, or a hashed block damaged | Never reported by name. A later layer fails, for small files usually saying the document has no root group. | `Corrupt`. A change only inside a last cipher block made of padding alone is ignored (FMT-07.11) |
| Version 3: bad padding, hashed blocks intact (rebuilt with the key), last cipher block also holds the end of the final hashed block | The document has no root group (observed with the last padding byte `00` or `n+1`, and with all padding bytes `00` or `41`). The reference checks the padding only when it reads the file's last cipher block | Opens, the padding is not read (FMT-05.13 step 6, LD-01). Known difference: only the key holder can make this file, and its content is intact (FMT-07.11) |
| Version 3: bad padding, hashed blocks intact, last cipher block made only of padding (16 bytes) | Ignored; the file opens (observed with 16 `00` bytes). The final hashed block ends before that block, so the reference never reads it | Opens (FMT-07.11, LD-01) |
| Version 3: extra bytes after the end of the ciphertext | Ignored. The file opens (observed with 1 and 16 extra bytes). | Opens, the bytes are ignored (FMT-05.13 steps 2 and 6, LD-01) |

More edge cases:

- **Signature, version and field-structure bytes.** Flipping these fails before any check in this card: "not a vault", "unsupported version", wrong field lengths, unknown cipher. The kinds are defined in FMT-01 and FMT-02. Flipping the low byte of the minor version gives a valid version, so the hash check catches it: in version 4 the plain hash fails, and in version 3 the `HeaderHash` check fails.
- **Version 4 header with a recomputed plain hash.** The HMAC still fails, so App reports `WrongKey` (observed in the reference with the right password).
- **Version 4 file cut at exactly `H+64`.** With the right key, the header HMAC passes and FMT-06 reports `Corrupt` because there is no block. With a wrong key, the result is `WrongKey`.
- **Version 3 file without `HeaderHash`.** It opens, so a changed protected-stream key, stream id or compression flag goes unnoticed until the document layer fails or protected values decode to garbage. That is the format's weakness. App accepts such files, like the reference (decided: spec/decisions.md LD-11).
- **`HeaderHash` quirks in version 3 (observed, FMT-05.12).** An empty element, or one holding only `-_`, opens with no check. The right value with a space, a line break and a `!` inserted, or with its `=` removed, opens. Two elements, right then wrong: rejected. Wrong then right: opens. Right then empty: opens with no check. The document sits inside the encryption, so only someone who holds the key can write these.
- **Hardware key missing or failing.** The error itself is defined in FMT-04.10 and INT-07. Its place in the order is FMT-05.7 step 4 and FMT-05.13 step 3: after the header, length and plain hash checks, before the KDF. So a damaged or cut version 4 header gives `Corrupt` even when the device is missing (D-05-3), and an intact header with a missing device gives the hardware-key error, never `WrongKey`.
- **Graphical app messages.** Only the command line tool was run. That the graphical unlock screen shows the same text comes from source reading (re-read by Verify in Sprint 2: the shared open routine builds the text, "error while reading the database" (paraphrased) followed by the reader's message, and both the unlock screen's message bar and the command line tool show that text; when the password box was empty, the unlock screen first offers one retry with an empty password. The window was not run).

Decisions:

- **D-05-1** (decided: spec/decisions.md LD-12). A version 3 start-bytes mismatch gives `WrongKey` (FMT-05.11). AT-A01 needs it: for version 3 only the start-bytes check can tell a wrong key. The reference shows its wrong-credentials message there too (observed). History: the option "start-bytes mismatch gives `Corrupt`" was not chosen. AT-B07 and the E2-S4 check are read as LD-04 says: padding is looked at only after integrity passes. In version 4 that is after every block HMAC (FMT-06, FMT-08); in version 3 the padding is never looked at (FMT-07.11, LD-01). So `WrongKey` for a wrong key and `Corrupt` for other damage reveal nothing about padding.
- **D-05-2** (decided: spec/decisions.md LD-11). Version 3 files with no `HeaderHash` are accepted, like the reference.
- **D-05-3** (decided: spec/decisions.md default rule, the card's option). App checks the plain header hash before the KDF. Known difference (list it for AT-A11): a version 4 file with a damaged or cut header whose key derivation also fails gives `Corrupt` in App and the key-derivation error in the reference.
- **D-05-4** (decided: spec/decisions.md default rule, the card's option, narrowed by LD-01). App checks the 32-byte minimum of the version 3 ciphertext before the KDF (FMT-05.13 step 2). Known difference (list it for AT-A11): a version 3 file that ends less than 32 bytes after the header gives `Corrupt` in App and the wrong-credentials message in the reference (observed with a file cut to `H+20`). History: the earlier proposal also refused a CBC ciphertext whose length is not a multiple of 16. LD-01 removes it: such a file (for example with 1 appended byte) opens with the right password and gives `WrongKey` with a wrong one, in App and in the reference (observed).

## Security notes

- The plain header hash proves nothing against an attacker, who can recompute it. Only the HMAC protects the header (SF-05). Never treat a matching plain hash as proof that the header is authentic.
- The HMAC covers every header byte, unknown fields included. In version 4 an attacker cannot add, remove or change any header field, including the cipher, KDF settings or IV, without the HMAC failing. A KDF downgrade (AT-A09) or a cipher swap is therefore found before decryption.
- **Never decrypt, decompress or parse any version 4 payload byte before the header HMAC passes.** After it passes, never report `WrongKey`. This keeps the payload layers from becoming an oracle, and it means a damaged payload can never be blamed on the user's password.
- Every comparison in this card (hash, HMAC, start bytes) uses the constant-time compare in `app-crypto` (Rust rule 6, AT-B05). The plain hash is not secret, but using one compare function everywhere is simpler and safe.
- Checking the plain hash before the KDF (FMT-05.7) means a damaged header never makes App spend a KDF run. KDF settings are still bounded by FMT-03 before any KDF work (AT-A05).
- `WrongKey` also covers "header changed and hash fixed" and "stored HMAC damaged". This is a property of the format, not a bug. Suggestion for APP-06: like the reference, the wrong-key text may mention that a damaged file can cause the same message.
- Bytes after the final hashed block of version 3 are ignored (LD-01). Someone without the key can append bytes, or replace a last cipher block that holds only padding, and the file still opens with the same content. That changes nothing the user sees, and the reference opens such files too.
- Version 3 is weaker. It has no header authentication at all, apart from the optional `HeaderHash` inside the encrypted document. A wrong key cannot be told from damage at the start of the payload or in key-related header fields. Version 3 is read only in App (plan/architecture.md), and FMT-16 decides that App saves as version 4.
- Padding must not become an oracle (AT-B07, read as LD-04 says). In version 4, the block HMACs (FMT-06) cover all ciphertext, so modified ciphertext never reaches the padding check. In version 3, App never checks the padding (FMT-05.13 step 6, LD-01), so there is no padding result to observe.
- Every wrong credential (wrong password, wrong key file, or both) must give exactly the same `WrongKey` result and message (AT-A01).
- Attacks that test this card: AT-A01, AT-A02, AT-A04, AT-A09, AT-A10, AT-A11, AT-B05, AT-B07.

## Test cases

Fixed vectors (computed with python3 hashlib/hmac and cross-checked with the macOS openssl tool):

- `S` = `00 01 02 … 1F` (bytes 0x00 to 0x1F). `T` = `20 21 22 … 3F` (bytes 0x20 to 0x3F).
- `K` = SHA-512(S || T || 01) = `f09af394435628155b2d8ba7af6236610e63c26d6595f5bc508d3e1f2328dd7040c6ce1001efc85f9e7ef54e83df08e2c448fcc47dfd768d7f130de6666c37c3`
- `K_hdr` = SHA-512(FF×8 || K) = `66f79c938c23e8af49bad0f21766830cafb0c73c886cd42acace7407323a4168fa7028853785edb696119ac066b24ce58329eaa72a04bbdba4c09be94f75b03c`
- Synthetic header `HDR` (109 bytes; signature, version 4.1, cipher AES-256, compression gzip, master seed `S`, IV `40 41 … 4F`, end of header). It has no KDF field, so it is not an openable header and is used only for these vectors: `03d9a29a67fb4bb501000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0710000000404142434445464748494a4b4c4d4e4f00040000000d0a0d0a`
- SHA-256(HDR) = `34984c167a5ea4e3e7b565585d76a902207a5294c8d7c33041b6193ca17d51d3`
- HMAC-SHA-256(K_hdr, HDR) = `3cb9a0fdb600461265b8e28ab9452479a12a313e34f4bae0b7b30184b6086989`
- With `T` changed in its first byte only (`21 21 22 … 3F`): HMAC = `a6ad4d0a4ea8ed1dafaa57f55afe29c83576a8f2cdeabc98215dd5bf7614f081`

Demo vault vectors. These vaults were made by the reference command line tool 2.7.11 in a scratch folder, with demo password `demo-pass`. Only the header bytes are given here, which is enough for the header checks.

- Version 4 demo header `D4` (207 bytes; version 4.0, file bytes 8–11 = `00 00 04 00`; AES-256; gzip; AES-KDF with the id `c9d9f39a-628a-4460-bf74-0d08c18a4fea` carried in the version 4 KDF parameter map, 1,000,000 rounds; FMT-03 lists both AES-KDF ids), offsets in decimal:
  - `0000: 03 d9 a2 9a 67 fb 4b b5 00 00 04 00 02 10 00 00 00 31 c1 f2 e6 bf 71 43 50 be 58 05 21 6a fc 5a`
  - `0032: ff 03 04 00 00 00 01 00 00 00 04 20 00 00 00 df 71 ea 4f d2 e9 c9 4f 8e 17 9e 14 44 57 8e 1b 79`
  - `0064: 2c 26 c1 6e 8f 27 af a9 7a b9 42 a9 1d 79 aa 07 10 00 00 00 9e cb 02 07 27 8f 2a c4 e7 a8 99 fc`
  - `0096: 68 42 6e a9 0b 5d 00 00 00 00 01 42 05 00 00 00 24 55 55 49 44 10 00 00 00 c9 d9 f3 9a 62 8a 44`
  - `0128: 60 bf 74 0d 08 c1 8a 4f ea 05 01 00 00 00 52 08 00 00 00 40 42 0f 00 00 00 00 00 42 01 00 00 00`
  - `0160: 53 20 00 00 00 bc ea a2 9c 67 08 58 31 db 1d ad 53 b1 ab e4 6d 43 89 4c 16 40 ab 5a 05 78 d1 70`
  - `0192: 24 2f 5a d6 c1 00 00 04 00 00 00 0d 0a 0d 0a`
  - `T` for `demo-pass` = `3922759997b81034d3c16c77e31649d01c75caba0809da42a782be60d668b33f`
  - Stored hash (file bytes 207..238) = `33a5cc7bbf83bfb2ae447739f18a4780cc0f1477e33b821cf71f6feeec6d61a8`
  - Stored HMAC (file bytes 239..270) = `d4c72728909426d045a25d0005e00dde9b3e94ce828e91fe58a2457f64c551db`
  - `K` = `96aff2c2abaf7917fd4fa58651b2698def0f798c739233cd6671dc19950d70c23eab826cc2387fad37a3aaddc2916dc3eb483a486779a469b3ac72cc1814e8b7`
  - `T` for `wrong-pass` = `cb0bad4e7dfc64bfd769893b8499113fd76b531261f3b6c01ef1b19427066f00`. The HMAC it gives is `9b6cac5696b2cc1f55ab9bc4b319a182748e88ee572806b36c5c782197700f37`.
- Version 3 demo header `D3` (222 bytes; version 3.1, AES-256, gzip, AES-KDF with 30,000,000 rounds):
  - `0000: 03 d9 a2 9a 67 fb 4b b5 01 00 03 00 02 10 00 31 c1 f2 e6 bf 71 43 50 be 58 05 21 6a fc 5a ff 03`
  - `0032: 04 00 01 00 00 00 04 20 00 a8 49 74 eb c6 da 1f 91 8a f2 19 bc f9 2b 5a 71 c0 0e 97 e0 ac 5d f5`
  - `0064: 6f 17 59 fc 81 6e b9 ab 32 05 20 00 13 86 6c af 70 f8 bd 8e bd 73 ad dc 36 8a e4 e0 4b 9a 1d 4f`
  - `0096: 4a c7 ce 64 25 b5 08 ca bd 77 0f d7 06 08 00 80 c3 c9 01 00 00 00 00 07 10 00 63 1c 92 83 ec 7f`
  - `0128: b8 68 ca d1 e0 83 68 17 96 6e 08 20 00 e2 03 3d 85 3d 21 a2 bc c9 58 05 40 6b e2 b9 c4 14 f9 8c`
  - `0160: 40 ee c6 9e b1 a4 33 6a 41 7f 3e 7a 71 09 20 00 80 57 51 54 9e aa cd f9 15 e2 ab 56 82 45 cf 1e`
  - `0192: e5 96 16 7e 84 62 b8 60 d5 85 58 1c 1e a1 12 16 0a 04 00 02 00 00 00 00 04 00 0d 0a 0d 0a`
  - `T` for `demo-pass` = `b8caf4f22b5e734cb76e43d433562910520bf7d3201cbf8b95457b6f2d1fc115`. The final key SHA-256(S || T) = `6a33983cef363ade35dfcb80bf2a5119265359afd53a9bf399a21762a934297b`.
  - IV (header field 7) = `631c9283ec7fb868cad1e0836817966e`. Start bytes (header field 9) = `805751549eaacdf915e2ab568245cf1ee596167e8462b860d585581c1ea11216`.
  - First 32 ciphertext bytes (file bytes 222..253) = `5137fd2c7af22daa60a5fd74d00d7fde9271db1f9ca82a281a8fc9beb29d9389`
  - `T` for `wrong-pass` = `5d25042eeb6e5a25e00bc23a5c2033e91f7a9119783fad652c2b5becb7d65bb5`. Its final key is `3b54593af5284f098bd0c2624fed509c3a78c37e5c9f3b7d4238a4470b570497`, and the first 32 decrypted bytes are `d2e013b8ae66d798904bc82dd9041cdfd3ba3454cadf3580f66ae09f43022e4d`.
- Synthetic version 3 payload: final key `60 61 … 7F`, IV `40 41 … 4F`, start bytes `80 81 … 9F`, followed by the hashed block stream vector of FMT-07, then PKCS#7 padding. Ciphertext (192 bytes, AES-256-CBC) = `23db97b1fbe632c63b581e30a4df5f878944ccc91e52c4bcf08eddcb124d45cc05c62864742e06613053d7b43acdd01c08b99a223dad51457fa85108d13b51acac0dcac179d5a1034d552e84acb5d2af6c74aa4c5a43dfe8aa50fa819d528814913b8621d89cdd585e3e5abe7df4cfe3a89f4344205f0cd2ef265cf88ad050c69cde99b22408528e0395347eca1c89711c4cd05418a1d72f51d6e17697489df42648f79a4d4876cf3f05a19587a1284e17b212b913aff05b2a5dafadbac3e3c5`

In the cases below, password `demo-pass` is used throughout. "Demo vault v4" means a version 4 vault made by our test-data script or by the reference command line tool. "Demo vault v3" means a version 3.1 vault made by the reference command line tool (its default), or by the test-only version 3 builder: test code in `tests/`, built from FMT-17 with FMT-07.7, FMT-05.10 and FMT-05.12, never shipped (FMT-01.26 plan (e), decided: spec/decisions.md LD-35). App's product code never writes version 3. Header bytes are named by their field. The decimal offsets given in brackets are those of `D4` and `D3`, the reference tool's default layouts, and are examples only. Offsets after the header are relative to that file's own `H`. "Rebuilt" means the payload was decrypted with the vault's own key, changed, and encrypted again with the same key and IV (version 3), or with valid block HMACs (version 4).

| Case | Given | When | Then |
|---|---|---|---|
| FMT-05.1 header length | Demo header `D4` | Find the end-of-header field | `H` = 207. The last 9 header bytes are `00 04 00 00 00 0d 0a 0d 0a` |
| FMT-05.1 / FMT-05.3 hash over raw bytes | `HDR` | SHA-256 | `34984c16…7d51d3` as listed |
| FMT-05.4 base key | `S`, `T` as listed | Compute `K` | `f09af394…6c37c3` |
| FMT-05.5 header key | `K` as listed | Compute `K_hdr` | `66f79c93…75b03c` |
| FMT-05.6 header HMAC | `HDR`, `K_hdr` | HMAC-SHA-256 | `3cb9a0fd…086989` |
| FMT-05.6 / FMT-05.8 one-bit key change | `HDR`, `T` with first byte `21` | Compute HMAC, compare with `3cb9a0fd…` | HMAC is `a6ad4d0a…14f081`, no match: `WrongKey` |
| FMT-05.2 / FMT-05.3 / FMT-05.6 end to end | Header `D4`, password `demo-pass` | Derive `T` (FMT-04), hash, HMAC | `T`, stored hash and stored HMAC all equal the listed values |
| FMT-05.8 wrong password | Header `D4`, password `wrong-pass` | Open | HMAC computes to `9b6cac56…`, which differs from `d4c72728…`: `WrongKey`. No payload byte is decrypted (spy on the decrypt call) |
| FMT-05.7 damaged header, hash checked before KDF | Demo vault v4, one bit flipped in the master seed data (offset 50 in `D4`) | Open with `demo-pass` | `Corrupt`. The KDF is never called. Reference: "header SHA-256 does not match" |
| FMT-05.7 damaged header, wrong password | Same flipped file | Open with `wrong-pass` | `Corrupt`, not `WrongKey` (reference agrees) |
| FMT-05.7 key file error comes first | Demo vault v4 with one bit flipped in the master seed data (offset 50 in `D4`); separately, the same vault cut to 5 bytes | Open with `demo-pass` plus an empty (0-byte) key file; then with `demo-pass` plus a key file path that does not exist | The key file error of FMT-18.19 (key file empty; key file cannot be read) each time, never `Corrupt`, `TooShort` or `WrongKey`. The header parser and the KDF are never called (spy). Reference: shows its key file load failure each time (observed on version 3.1 copies; same code path for version 4 by source reading) |
| FMT-05.7 key file error before a header field fault | Demo vault v4 with the compression flag data changed from `01 00 00 00` to `02 00 00 00` (file byte 38 in `D4` changed from `01` to `02`) | Open with `demo-pass` plus an empty key file; then with `demo-pass` and no key file | First: the key file error of FMT-18.19, header parser and KDF never called. Second: `Unsupported` (FMT-02, step 1), KDF never called |
| FMT-05.7 read step before credentials | A vault path that does not exist | Open with `demo-pass` plus an empty key file; then plus a key file path that does not exist | `Io` both times, never `KeyFile`. The key file is never opened (spy). Reference: the vault-not-found message both times (observed) |
| FMT-05.7 12-byte look of the read step | Total file limit lowered to 100 bytes for the test (FMT-01.31). (a) The full demo vault v4 (more than 100 bytes, valid first 12 bytes). (b) 200 bytes of `00`. (c) `D4`'s first 12 bytes with byte 10 changed from `04` to `05` (major version 5), followed by 188 bytes of `00` | Open each with `demo-pass` plus an empty key file; then each with `demo-pass` and no key file | With the empty key file: (a) `TooLarge` (the read step comes first), (b) and (c) the key file error of FMT-18.19. Without a key file: (a) `TooLarge`, (b) the not-a-vault kind of FMT-01.33, (c) `Unsupported`. Never `TooLarge` for (b) or (c). The KDF is never called |
| FMT-05.7 header hash before the cost check | Demo vault v4 with Argon2d (FMT-03) whose KDF map `M` value is set to 2,147,483,648 (2 GiB, in the ask band of CRY-02.14 on a test Mac with more than 2 GiB of memory) and whose stored hash is recomputed over the changed header; separately, the same file with one bit flipped in the master seed data too, the stored hash not recomputed | Open each with `demo-pass`; answer no to the first | First: the "ask the user first" decision of FMT-04.21 step 2 with the cost report of CRY-02.14 (not an error kind), KDF not run (the header HMAC is never reached, because the user has not answered yet); after no, the open stops with nothing done and no error, KDF still not run. Second: `Corrupt`, no ask decision, no hardware challenge, KDF not run. The yes path is tested in CRY-02 T25 and FMT-04.21-b |
| FMT-05.7 hardware key after the hash, before the KDF | Demo vault v4 that needs a hardware key (mock device, FMT-04 test setup), one bit flipped in the master seed data; separately, the same vault undamaged | Open with `demo-pass`, no device answering | Damaged: `Corrupt`, no challenge sent, KDF not run (D-05-3). Undamaged: the hardware-key error of FMT-04.10, KDF not run, never `WrongKey` |
| FMT-05.7 damaged stored hash | Demo vault v4, bit flipped at `H+3` | Open with `demo-pass` | `Corrupt` (reference: hash mismatch) |
| FMT-05.8 damaged stored HMAC | Demo vault v4, bit flipped at `H+38` | Open with `demo-pass` | `WrongKey` (reference: invalid credentials with HMAC note) |
| FMT-05.8 tamper with fixed hash | Demo vault v4, master seed bit flipped, stored hash replaced by SHA-256 of the changed header | Open with `demo-pass` | `WrongKey` (reference agrees, observed) |
| FMT-05.7 cut inside hash or HMAC | Demo vault v4 cut to `H+40` bytes; also cut to `H` bytes | Open | `Corrupt`, KDF not run (reference: checksum has the wrong size) |
| FMT-05.7 / FMT-05.8 cut right after HMAC | Demo vault v4 cut to `H+64` bytes | Open with `demo-pass`; open with `wrong-pass` | `Corrupt` from FMT-06; `WrongKey` |
| FMT-05.7 / FMT-05.8 header byte sweep (AT-A02) | Demo vault v4 | Flip each byte at offsets 0 to `H+63`, one at a time, and open with `demo-pass` | Every file is rejected, with no panic. Bytes in `[H+32, H+64)` give `WrongKey`. Every other byte gives `Corrupt`, or a header error kind from FMT-01/FMT-02 |
| FMT-05.8 errors after the HMAC are never WrongKey | Demo vault v4 with any byte at offset ≥ `H+64` flipped | Open with `demo-pass` | `Corrupt` |
| FMT-05.9 write | Any vault saved by App as version 4 | Read back the bytes | Bytes `[H, H+32)` = SHA-256(header). Bytes `[H+32, H+64)` = HMAC from FMT-05.6 with this file's `S` and `T`. The reference command line tool opens the file (interop, `REF_CLI`) |
| FMT-05.9 no header hash element in version 4 | Any vault saved by App as version 4 | Decrypt and read the document | No `HeaderHash` element in the metadata |
| FMT-05.9 header hash element ignored in version 4 | Demo vault v4 rebuilt with `<HeaderHash>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</HeaderHash>` (32 zero bytes, a wrong value) in its metadata, with a valid header hash, header HMAC and block HMACs | Open with `demo-pass`; save with App; decrypt the saved document | Opens (the reference also opens it, FMT-10.21); the saved document has no `HeaderHash` element |
| FMT-05.10 start bytes match | Synthetic version 3 payload | Decrypt the first 32 bytes with key `60…7F`, IV `40…4F` | Result `80 81 … 9F`, equal to the start bytes |
| FMT-05.11 start bytes mismatch | Same ciphertext, key `61 61 62 … 7F` (first byte changed) | Decrypt the first 32 bytes | `b7396b0c28c6b8c74534315822da9353818598d447e883b0edd8d2826b000272`, no match: `WrongKey` |
| FMT-05.10 demo version 3 | Header `D3`, first 32 ciphertext bytes, password `demo-pass` | Derive the key, decrypt 32 bytes | Equal to the start bytes `80575154…1ea11216` |
| FMT-05.11 demo version 3, wrong password | Same, password `wrong-pass` | Derive the key, decrypt 32 bytes | `d2e013b8…43022e4d`, no match: `WrongKey`. Reference: invalid credentials, without the HMAC note |
| FMT-05.11 version 3 key-field damage | Demo vault v3, a bit flipped in the master seed data (offset 50 in `D3`), the IV data (offset 125 in `D3`) or the first ciphertext byte (offset `H`) | Open with `demo-pass` | `WrongKey` in each case (reference agrees, observed) |
| FMT-05.13 version 3 last byte flipped | Demo vault v3 whose last cipher block also holds the end of the final hashed block (plaintext before the padding not a multiple of 16), last file byte flipped; separately, a demo vault v3 whose last cipher block holds only padding (plaintext before the padding a multiple of 16), last file byte flipped | Open with `demo-pass` | First: `Corrupt` (the garbled block holds the end of the final hashed block, so the walk fails; reference: the document has no root group). Second: opens with the same content, the garbled padding is not read (step 6; the reference also opens it) |
| FMT-05.13 key file error comes first, version 3 | Demo vault v3 with one bit flipped in the master seed data (offset 50 in `D3`); separately, cut to 5 bytes | Open with `demo-pass` plus an empty key file | The key file error of FMT-18.19 both times, KDF not run. Without the key file, the first file gives `WrongKey` (FMT-05.11). Reference: key file load failure both times; without a key file, the wrong-credentials message for the first (observed) |
| FMT-05.13 version 3 short file | Demo vault v3 cut to `H+20` bytes | Open with `demo-pass`, and with `wrong-pass` | `Corrupt` both times, KDF not run (step 2). The reference gives its wrong-credentials message (D-05-4) |
| FMT-05.13 step 6 appended bytes | Demo vault v3 (AES-256) with 1 byte appended; separately with 16 bytes of `00` appended | Open with `demo-pass`, and with `wrong-pass` | `demo-pass`: opens with the same content as the unchanged vault, the extra bytes are never decrypted as content. `wrong-pass`: `WrongKey`. Reference: the same (observed) |
| FMT-05.13 step 5 walk | Demo vault v3 rebuilt with one data byte of hashed block 0 changed (its stored hash kept) and its last padding byte changed from n to n+1 | Open with `demo-pass` | `Corrupt`. The debug log names the hashed block check of block 0 and never the padding |
| FMT-05.13 step 6 padding never checked | Demo vault v3 rebuilt with intact hashed blocks and every padding byte set to `00`, re-encrypted with its own key and IV: once with plaintext before the padding not a multiple of 16, once with it a multiple of 16 (16 padding bytes) | Open with `demo-pass` | Opens both times with the same content. Reference: fails the first with the no-root-group message (known difference, FMT-07.11) and opens the second (observed) |
| FMT-05.13 version 3 stream cipher | Version 3.1 demo vault with the ChaCha20 payload id and a 12-byte nonce (CRY-01 T33), made by the test-only version 3 builder (LD-35) or by a Verify agent with the reference app's window (LD-34) | Open with `demo-pass`; open with `wrong-pass`; open with 1 byte appended | Opens, with a ciphertext length that is not a multiple of 16 and no padding; `WrongKey`; opens with the same content (step 6: the byte after the final block is ignored) |
| FMT-05.12 version 3 header hash | Demo vault v3 with one bit flipped in the protected-stream key data (offset 150 in `D3`) or in the end-of-header data (offset 219 in `D3`) | Open with `demo-pass` | `Corrupt`. Reference: the header and its stored hash differ |
| FMT-05.12 wrong length | Demo vault v3 rebuilt with `HeaderHash` set to base64 of the first 31 bytes of SHA-256(header); separately, of those 32 bytes plus one `00` byte. For `D3`: SHA-256(header) = `39efd4929e1a856bd521ad17b683c88929656b09d4b37998f0ae8dd8561670b0`, its base64 is `Oe/Ukp4ahWvVIa0XtoPIiSllawnUs3mY8K6N2FYWcLA=`, and the 31-byte form is `Oe/Ukp4ahWvVIa0XtoPIiSllawnUs3mY8K6N2FYWcA==` | Open with `demo-pass` | `Corrupt` both times (reference agrees, observed) |
| FMT-05.12 lenient decoding | Demo vault v3 rebuilt with the right `HeaderHash` text, once with a space, a line break and `!` inserted, once with the final `=` removed | Open with `demo-pass` | Opens both times (reference agrees, observed) |
| FMT-05.12 no value to check | Demo vault v3 rebuilt with `HeaderHash` empty; separately, holding only `-_` | Open with `demo-pass` | Opens both times, no check (reference agrees, observed) |
| FMT-05.12 repeated element | Demo vault v3 rebuilt with two `HeaderHash` elements: right then wrong (32 zero bytes); wrong then right; right then empty | Open with `demo-pass` | `Corrupt`; opens; opens with no check (the last one counts; reference agrees, observed) |
| FMT-05.12 version 3 minor version flip | Demo vault v3 (version 3.1), byte 8 changed from `01` to `00` | Open with `demo-pass` | `Corrupt` (`HeaderHash` is checked whatever the minor version) |
| FMT-05.12 reference test vault with a broken header hash | Reference test vault `BrokenHeaderHash` (empty password), read through `REF_TESTDATA` | Open | `Corrupt` (reference: the header and its stored hash differ) |
| FMT-05.12 version 3.0 without header hash | Reference test vault `Format300` (password `a`) | Open | Opens; no header hash check |
| FMT-05.14 kinds only | Every failing case above | Inspect the `app-format` error | Only the error kind is returned; the screen text comes from APP-06 |
| FMT-05.15 no secrets in logs | Demo vault v4 opened with `wrong-pass`, then with `demo-pass` | Search the debug log for the hex of `T`, `K` and `K_hdr` | No match. The log says "header HMAC mismatch" for the first open |

## How this was learned

- Read the reference's version 4 reader (the open routine after the header is parsed), its version 3 reader, the shared header reader, and the top-level reader that dispatches on the version number. Read the version 4 and version 3 save routines, the helper that builds the HMAC base key, and the per-block key helper of the HMAC block stream.
- Read the XML reader and writer for the metadata `HeaderHash` element (how it is decoded, which copy wins, when it is written), and the vault open routine and unlock screen for how messages reach the user.
- Rebuilt a version 3.1 demo vault made by the reference tool with changed `HeaderHash` values (31 and 33 bytes, extra characters, no `=`, empty, `-_` only, two elements in three orders), encrypted it again with its own key and IV, and opened each copy with the reference tool. Results are in FMT-05.12 and the edge cases.
- Ran the installed reference command line tool 2.7.11 on demo vaults it made in a scratch folder under `/tmp` (password `demo-pass`). It made a version 3.1 vault by default, and a version 4 vault when importing an XML document that used per-entry custom data. On copies of those vaults: flipped single header bytes, damaged the stored hash and HMAC, recomputed the plain hash after a header change, cut the file at several points, appended bytes, and tried wrong passwords. Every observed message matched what the source reading predicts.
- Rebuilt a version 3.1 demo vault with bad padding under intact hashed blocks and opened it with the reference tool: rejected when the last cipher block also holds the end of the final hashed block, opened when the last cipher block is all padding (see the edge table and FMT-07.11).
- Read the command line tool's unlock helper and the unlock screen's key-building step: both load the key file before the vault is opened. Ran the installed command line tool on a version 3.1 demo vault with a flipped master seed byte and on a copy cut to 5 bytes, each with an empty key file and with a missing key file: the key file load failure was shown every time. Without a key file the damaged copy gave the wrong-credentials message (FMT-05.7 step 0, FMT-05.13 step 0).
- Cross-check round (open order): read the command line tool's unlock helper again. It checks that the vault file exists, is a plain file and is readable, then reads the password, then loads the key file, then sets up the hardware key, and only then opens the vault. Ran the installed tool with a vault path that does not exist, plus an empty key file and plus a missing key file: the vault-not-found message both times. Read the version 4 reader again: required fields, then key derivation, then the 64 bytes, the hash and the HMAC. Made FMT-05.7 the single owner of the whole open order, so that FMT-01.31, FMT-02.30, FMT-04.21, CRY-02.14 and FMT-18.19 each describe one step of it.
- Recomputed `T`, the hash, `K`, `K_hdr` and the HMAC for the demo vaults with a scratch tool (python3 hashlib/hmac plus an AES-KDF helper), and confirmed they equal the stored values. Opened the reference test vaults `BrokenHeaderHash`, `Format300` and `Format400` (read only) with the reference tool.
- Sprint 0 close-out: wrote in the lead rulings of spec/decisions.md. LD-12 (D-05-1), LD-11 (D-05-2), LD-13 (no credentials), LD-35 (test-only version 3 builder), LD-34 (window-made demo vaults), LD-04 (how AT-B07 and E2-S4 are read), and LD-01, which made every byte after the final hashed block ignored: the version 3 padding check and the multiple-of-16 rule are gone, and the rows for appended bytes and bad padding now expect the file to open. D-05-3 and the 32-byte minimum of D-05-4 follow the default rule. The observed reference results are unchanged.
- The installed tool (2.7.11) and the source (development branch) agreed on every point checked here. No "differs in installed version" items were found for this card.
- Sprint 1 close-out: FMT-05.7 step 4a and its test row now give the ask band the same shape as FMT-04.21 step 2 and CRY-02.14 (a returned decision, not an error; on no the open stops with no error). What it does lists the other error kinds of FMT-05.7. The pointer from FMT-02.30 now names its single step 5.
