# FMT-02 Outer header fields and their limits

Status: reviewed
Epics: E3-S2, E3-S8 (version 3 fields)
Parity rows: SF-01, SF-02, SF-05, SF-07, SF-11, SF-12, SD-06

## What it does

Every vault file starts with a 12-byte preamble (two signatures and the file version, see FMT-01). Right after it comes the outer header: a list of fields stored in the clear. The outer header names the cipher, the compression, the random values used for this save, and the key derivation settings. It ends with an end-of-header field. In version 4 the header is followed by its SHA-256 and its HMAC (FMT-05). In version 3 the encrypted payload follows directly (FMT-07, FMT-08).

This card says how the fields are framed, which field ids exist in versions 3 and 4, which lengths and values are allowed, which fields are required, what happens with unknown, duplicate, missing or malformed fields, in which order the reference writes them, and which size limits apply. Where the reference has no limit or is looser, this card gives App's own rule and names the lead ruling that decided it (spec/decisions.md).

The outer header is read before any key is known. Everything in it is attacker-controlled until the header check in FMT-05 passes. So every check of this card runs on untrusted bytes, before any key derivation.

## Inputs and outputs

Input: the file bytes from offset 12 onward, plus the major version from the preamble (FMT-01). Major version 4 uses the version 4 rules. Every version below 4.0 that FMT-01 accepts (2.x and 3.x) uses the version 3 rules.

Output, on success:
- the parsed header: cipher, compression, master seed, encryption IV, key derivation settings (version 4: from the typed map, FMT-03; version 3: AES-KDF seed and rounds from fields 5 and 6), public custom data (version 4 only), and for version 3 the protected stream key, the stream start bytes and the inner stream id;
- the raw header bytes: every byte from offset 0 up to and including the last data byte of the end-of-header field, exactly as read (input to FMT-05);
- the header length, which is the offset of the first byte after the header.

On failure: one error kind from `app-format/error.rs`: `Corrupt` (malformed), `Unsupported` (well-formed but not something App can read), `TooLarge` (over a limit). This card never produces `WrongKey`.

### Field framing

| Version | One field |
|---|---|
| 4 | id: 1 byte (unsigned) · length: 4 bytes, unsigned, little-endian · data: `length` bytes |
| 3 (and 2) | id: 1 byte (unsigned) · length: 2 bytes, unsigned, little-endian · data: `length` bytes |

Fields follow each other with no padding until the field with id 0.

### Field ids

| Id | Name | v3 | v4 | Data length | Value | Required in App | Reference when absent (observed) |
|---|---|---|---|---|---|---|---|
| 0 | End of header | yes | yes | any; writer: 4 | ignored on read; writer: `0D 0A 0D 0A` | yes (ends the header) | header never ends: truncation error |
| 1 | Comment | unknown | unknown | any | ignored | no | nothing |
| 2 | Cipher id | yes | yes | 16 | cipher UUID, table below | yes | uses AES-256 |
| 3 | Compression | yes | yes | 4 | unsigned 32-bit LE: 0 none, 1 gzip | yes | uses gzip |
| 4 | Master seed | yes | yes | 32 | random bytes (FMT-04, CRY-03) | yes | error: missing header fields |
| 5 | Transform seed | yes | forbidden | 32 | AES-KDF seed (FMT-17) | yes (v3) | random seed, so the open fails with the wrong-key message |
| 6 | Transform rounds | yes | forbidden | 8 | unsigned 64-bit LE AES-KDF rounds | yes (v3) | uses 1,000,000 rounds, so the open fails with the wrong-key message unless the file used exactly that |
| 7 | Encryption IV | yes | yes | 16 for AES-256 and Twofish, 12 for ChaCha20 (CRY-01) | random bytes (CRY-03) | yes | error: missing header fields |
| 8 | Protected stream key | yes | forbidden | 1 or more; writer: 32 | key of the protected-field stream (FMT-09) | yes (v3) | error: missing header fields |
| 9 | Stream start bytes | yes | forbidden | 32 | check bytes (FMT-07, FMT-17) | yes (v3) | error: missing header fields |
| 10 | Inner stream id | yes | forbidden | 4 | unsigned 32-bit LE; 2 = Salsa20 | no (absent means 2) | uses Salsa20 |
| 11 | KDF parameters | unknown | yes | any | typed map, FMT-03 | yes (v4) | default AES-KDF with a random seed, so the open fails with the wrong-key message |
| 12 | Public custom data | unknown | yes | any | typed map, FMT-03 | no | empty |
| 13 to 255 | (not defined) | unknown | unknown | any | ignored | no | nothing |

"Unknown" means: read past and ignored (FMT-02.21). "Forbidden" means: the file is rejected (FMT-02.14). In version 4 the protected stream key and the inner stream id moved into the inner header (FMT-09), and the stream start bytes were replaced by the header HMAC (FMT-05).

### Cipher UUIDs (field 2)

Bytes are in RFC 4122 order: the UUID text read left to right, two hex digits per byte.

| Cipher | UUID | Field 2 data | App |
|---|---|---|---|
| AES-256-CBC | 31c1f2e6-bf71-4350-be58-05216afc5aff | `31 C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A FF` | read and write |
| Twofish-CBC (256-bit key) | ad68f29f-576f-4bb9-a36a-d47af965346c | `AD 68 F2 9F 57 6F 4B B9 A3 6A D4 7A F9 65 34 6C` | read and write |
| ChaCha20 (256-bit key) | d6038a2b-8b6f-4cb5-a524-339a31dbb59a | `D6 03 8A 2B 8B 6F 4C B5 A5 24 33 9A 31 DB B5 9A` | read and write |
| AES-128-CBC | 61ab05a1-9464-41c3-8d74-3a563df8dd35 | `61 AB 05 A1 94 64 41 C3 8D 74 3A 56 3D F8 DD 35` | `Unsupported` (FMT-02.8) |

### Limits

| Limit | Reference | App |
|---|---|---|
| Whole outer header (offset 0 to end of end-of-header data) | none (a 20 MiB unknown field was accepted) | at most 1,048,576 bytes (1 MiB) (decided: spec/decisions.md LD-22) |
| One field, version 4 | up to 2^32 − 1 by the length width | bounded by the header limit |
| One field, version 3 | up to 65,535 by the length width | bounded by the header limit |
| Number of fields | none | bounded by the header limit (each field is at least 5 or 3 bytes) |

### Example A: version 3.1 header made by the reference CLI

Made with the installed reference CLI: `db-create -p -t 100` with password `demo`, then one entry added with `add`. The CLI makes version 3.1 files with AES-KDF. The header is 222 bytes.

```
0000: 03 D9 A2 9A 67 FB 4B B5 01 00 03 00 02 10 00 31
0010: C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A FF 03
0020: 04 00 01 00 00 00 04 20 00 72 3D 68 5D 06 C1 13
0030: 84 89 A4 FA 52 AD D4 13 F9 86 91 76 3F 2B F4 E8
0040: 06 F7 C1 DE B1 A8 7B C3 D8 05 20 00 AB BE 5B 4D
0050: 57 5C F2 93 DC EF 6B 27 9C E5 A7 61 9D 0C AA A4
0060: 40 9E 07 59 92 A8 BF A2 4E CD 7B 81 06 08 00 16
0070: 07 C7 00 00 00 00 00 07 10 00 A1 A7 A0 14 32 FC
0080: C2 76 C6 BE EA 20 72 29 7F 4E 08 20 00 78 14 2C
0090: 81 CF 1E FD 4D 88 2C 82 CB 57 3B AF DD 0A 69 3B
00A0: 4F B6 5C 50 61 4D 9D EF 17 FF 2D AD D5 09 20 00
00B0: 6D 54 64 8E E5 9D 00 67 7B 84 93 1B E8 A2 EF 43
00C0: 00 48 E3 FA 5B B0 D8 7A 6A CA EE 40 DE A5 EE 46
00D0: 0A 04 00 02 00 00 00 00 04 00 0D 0A 0D 0A
```

| Offset | Bytes | Meaning |
|---|---|---|
| 0x0000 | 03 D9 A2 9A | signature 1, see FMT-01 |
| 0x0004 | 67 FB 4B B5 | signature 2, see FMT-01 |
| 0x0008 | 01 00 03 00 | file version 0x00030001 (major 3, minor 1), see FMT-01 |
| 0x000C | 02 | field id 2, cipher id |
| 0x000D | 10 00 | length 16 (2 bytes, version 3) |
| 0x000F | 31 C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A FF | AES-256 |
| 0x001F | 03 | field id 3, compression |
| 0x0020 | 04 00 | length 4 |
| 0x0022 | 01 00 00 00 | 1 = gzip |
| 0x0026 | 04 | field id 4, master seed |
| 0x0027 | 20 00 | length 32 |
| 0x0029 | 72 3D 68 5D 06 C1 13 84 89 A4 FA 52 AD D4 13 F9 86 91 76 3F 2B F4 E8 06 F7 C1 DE B1 A8 7B C3 D8 | master seed |
| 0x0049 | 05 | field id 5, transform seed |
| 0x004A | 20 00 | length 32 |
| 0x004C | AB BE 5B 4D 57 5C F2 93 DC EF 6B 27 9C E5 A7 61 9D 0C AA A4 40 9E 07 59 92 A8 BF A2 4E CD 7B 81 | AES-KDF seed |
| 0x006C | 06 | field id 6, transform rounds |
| 0x006D | 08 00 | length 8 |
| 0x006F | 16 07 C7 00 00 00 00 00 | 13,043,478 rounds |
| 0x0077 | 07 | field id 7, encryption IV |
| 0x0078 | 10 00 | length 16 |
| 0x007A | A1 A7 A0 14 32 FC C2 76 C6 BE EA 20 72 29 7F 4E | IV for AES-256-CBC |
| 0x008A | 08 | field id 8, protected stream key |
| 0x008B | 20 00 | length 32 |
| 0x008D | 78 14 2C 81 CF 1E FD 4D 88 2C 82 CB 57 3B AF DD 0A 69 3B 4F B6 5C 50 61 4D 9D EF 17 FF 2D AD D5 | protected stream key |
| 0x00AD | 09 | field id 9, stream start bytes |
| 0x00AE | 20 00 | length 32 |
| 0x00B0 | 6D 54 64 8E E5 9D 00 67 7B 84 93 1B E8 A2 EF 43 00 48 E3 FA 5B B0 D8 7A 6A CA EE 40 DE A5 EE 46 | stream start bytes |
| 0x00D0 | 0A | field id 10, inner stream id |
| 0x00D1 | 04 00 | length 4 |
| 0x00D3 | 02 00 00 00 | 2 = Salsa20 |
| 0x00D7 | 00 | field id 0, end of header |
| 0x00D8 | 04 00 | length 4 |
| 0x00DA | 0D 0A 0D 0A | end-of-header data |
| 0x00DE | | first payload byte (header length 222) |

In the test cases this header is called **H3demo**.

### Example B: version 4.0 header made by the reference CLI

Made with the installed reference CLI: the vault of example A exported to XML, one custom-data item added to the entry (this forces version 4, see FMT-16), then `import -p -t 100` with password `demo`. The header is 207 bytes. The next 32 bytes of the file are the SHA-256 of these 207 bytes (`8F D8 3B 21 ... 01 67 03 45`, checked), then the header HMAC (FMT-05).

```
0000: 03 D9 A2 9A 67 FB 4B B5 00 00 04 00 02 10 00 00
0010: 00 31 C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A
0020: FF 03 04 00 00 00 01 00 00 00 04 20 00 00 00 B8
0030: D0 5E 01 14 D0 B1 5D AD 0F B6 7D 24 0C C7 A5 2B
0040: 57 97 F5 FF F6 A2 4D A4 33 5D E5 72 C5 7F 99 07
0050: 10 00 00 00 60 6D 84 40 AA C3 95 17 B6 3E AB 8F
0060: D3 1E 76 E2 0B 5D 00 00 00 00 01 42 05 00 00 00
0070: 24 55 55 49 44 10 00 00 00 C9 D9 F3 9A 62 8A 44
0080: 60 BF 74 0D 08 C1 8A 4F EA 05 01 00 00 00 52 08
0090: 00 00 00 C0 E1 E4 00 00 00 00 00 42 01 00 00 00
00A0: 53 20 00 00 00 B4 ED E5 64 F2 76 AF 60 7D 75 0C
00B0: E8 84 D0 18 B9 0E 1C 4F 3C 9E 7C 9B A1 8B 30 C6
00C0: AC 1D 93 17 41 00 00 04 00 00 00 0D 0A 0D 0A
```

| Offset | Bytes | Meaning |
|---|---|---|
| 0x0000 | 03 D9 A2 9A | signature 1, see FMT-01 |
| 0x0004 | 67 FB 4B B5 | signature 2, see FMT-01 |
| 0x0008 | 00 00 04 00 | file version 0x00040000 (major 4, minor 0) |
| 0x000C | 02 | field id 2, cipher id |
| 0x000D | 10 00 00 00 | length 16 (4 bytes, version 4) |
| 0x0011 | 31 C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A FF | AES-256 |
| 0x0021 | 03 | field id 3, compression |
| 0x0022 | 04 00 00 00 | length 4 |
| 0x0026 | 01 00 00 00 | 1 = gzip |
| 0x002A | 04 | field id 4, master seed |
| 0x002B | 20 00 00 00 | length 32 |
| 0x002F | B8 D0 5E 01 14 D0 B1 5D AD 0F B6 7D 24 0C C7 A5 2B 57 97 F5 FF F6 A2 4D A4 33 5D E5 72 C5 7F 99 | master seed |
| 0x004F | 07 | field id 7, encryption IV |
| 0x0050 | 10 00 00 00 | length 16 |
| 0x0054 | 60 6D 84 40 AA C3 95 17 B6 3E AB 8F D3 1E 76 E2 | IV for AES-256-CBC |
| 0x0064 | 0B | field id 11, KDF parameters |
| 0x0065 | 5D 00 00 00 | length 93 |
| 0x0069 | 00 01 ... 00 | typed map, 93 bytes: AES-KDF, rounds 15,000,000, 32-byte seed (annotated in FMT-03) |
| 0x00C6 | 00 | field id 0, end of header |
| 0x00C7 | 04 00 00 00 | length 4 |
| 0x00CB | 0D 0A 0D 0A | end-of-header data |
| 0x00CF | | header SHA-256 starts here (header length 207) |

In the test cases this header is called **H4demo**.

### Test header H4min (synthetic, parse tests only)

Same layout as example B, with fixed values: version 4.1, AES-256, gzip, master seed = 32 × `11`, IV = 16 × `22`, AES-KDF with 1,000,000 rounds and seed = 32 × `4B`. 207 bytes. It has no payload; use it for parser tests.

```
0000: 03 D9 A2 9A 67 FB 4B B5 01 00 04 00 02 10 00 00
0010: 00 31 C1 F2 E6 BF 71 43 50 BE 58 05 21 6A FC 5A
0020: FF 03 04 00 00 00 01 00 00 00 04 20 00 00 00 11
0030: 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
0040: 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 07
0050: 10 00 00 00 22 22 22 22 22 22 22 22 22 22 22 22
0060: 22 22 22 22 0B 5D 00 00 00 00 01 42 05 00 00 00
0070: 24 55 55 49 44 10 00 00 00 C9 D9 F3 9A 62 8A 44
0080: 60 BF 74 0D 08 C1 8A 4F EA 05 01 00 00 00 52 08
0090: 00 00 00 40 42 0F 00 00 00 00 00 42 01 00 00 00
00A0: 53 20 00 00 00 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B
00B0: 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B
00C0: 4B 4B 4B 4B 4B 00 00 04 00 00 00 0D 0A 0D 0A
```

Field offsets in H4min (same as H4demo): cipher id field at 0x000C (data 0x0011), compression at 0x0021 (data 0x0026), master seed at 0x002A (data 0x002F), IV at 0x004F (data 0x0054), KDF parameters at 0x0064 (length 0x0065, map 0x0069 to 0x00C5), end of header at 0x00C6 (data 0x00CB to 0x00CE).

## Rules

FMT-02.1 Version 4 framing: from offset 12, the header is a run of fields. Each field is a 1-byte unsigned id, a 4-byte unsigned little-endian length, then exactly that many data bytes.

FMT-02.2 Version 3 framing: the same, but the length is 2 bytes, unsigned, little-endian. Files with major version 2 or 3 use this framing and the version 3 field rules (the reference reads version 2.0 files with its version 3 reader; their header layout is the same). App does the same (decided: spec/decisions.md LD-06).

FMT-02.3 The field with id 0 ends the header. Its data may have any length (including 0) and its content is ignored when reading. The header ends right after its last data byte. When writing, App writes id 0 with length 4 and data `0D 0A 0D 0A`.

FMT-02.4 The raw header bytes are all bytes from offset 0 through the last data byte of the end-of-header field, exactly as read, including the preamble, unknown fields, comments and the end-of-header data. These raw bytes, never a re-encoding of the parsed values, are the input of the header checks in FMT-05.

FMT-02.5 Readers accept the fields in any order. Example: the reference's version 4.0 test vault (stem Format400), written by a different program, has the order 2, 3, 4, 11, 7, 0, and the reference opens it.

FMT-02.6 When writing version 4, App writes the fields in this order, which is the reference writer's order: 2 (cipher id), 3 (compression), 4 (master seed), 7 (encryption IV), 11 (KDF parameters), 12 (public custom data, only when it has at least one entry), 0 (end of header). For reference only (App does not write version 3): the reference writes version 3 headers in the order 2, 3, 4, 5, 6, 7, 8, 9, 10, 0.

FMT-02.7 Cipher id (field 2): the data must be exactly 16 bytes, otherwise `Corrupt`. The 16 bytes are a UUID in RFC 4122 byte order. App accepts the three ciphers in the cipher table (AES-256-CBC, Twofish-CBC, ChaCha20). Any other value, including 16 zero bytes, is `Unsupported`. CRY-01 defines the ciphers themselves.

FMT-02.8 The AES-128-CBC UUID (`61 AB 05 A1 94 64 41 C3 8D 74 3A 56 3D F8 DD 35`) is `Unsupported` when the header is parsed. The reference accepts it in the header and then fails when it sets up decryption, because the derived key is always 32 bytes. So no file opens in the reference with this id, and App loses nothing by rejecting it early.

FMT-02.9 Compression (field 3): the data must be exactly 4 bytes, otherwise `Corrupt`. Read it as an unsigned 32-bit little-endian number: 0 means no compression, 1 means gzip (FMT-08). Any value of 2 or more is `Unsupported`. When writing, App writes `00 00 00 00` or `01 00 00 00`.

FMT-02.10 Master seed (field 4): the data must be exactly 32 bytes, otherwise `Corrupt`. FMT-04 says how it is used. CRY-03 says it is fresh on every save.

FMT-02.11 Encryption IV (field 7): a length of 0 counts as missing (FMT-02.23). Otherwise the length must equal the nonce size of the cipher named in field 2: 16 bytes for AES-256-CBC and Twofish-CBC, 12 bytes for ChaCha20. Any other length is `Unsupported`. Check this only after the required-field check (FMT-02.30, step 4), because field 7 may come before field 2. This is stricter than the reference (decided: spec/decisions.md default rule, the card's recommendation): the reference accepts any non-empty IV in the header, and its cipher setup then also accepts 8 and 24 bytes for ChaCha20 (observed). The reference never writes those lengths.

FMT-02.12 KDF parameters (field 11, version 4): the data is a typed map (FMT-03) that must describe a supported key derivation (FMT-03.11 to FMT-03.19). Map errors and KDF errors carry the error kind given in FMT-03. The map is parsed and judged completely as soon as field 11 is read, before the next field (FMT-02.30, step 2h).

FMT-02.13 Public custom data (field 12, version 4): optional. The data is a typed map (FMT-03). Any error in this map rejects the whole file, with the error kind given in FMT-03. Like field 11, the map is parsed and judged as soon as field 12 is read (FMT-02.30, step 2h). The reference also rejects the file in this case (observed). Zero data bytes is `Corrupt`, because the map version is missing. The entries are kept and written back on save (FMT-03.22). When the map has no entries, App does not write field 12 (same as the reference).

FMT-02.14 In a version 4 header, the version-3-only ids 5, 6, 8, 9 and 10 are `Corrupt`, whatever their length or content. The reference rejects them too, with a message about old (legacy) header fields.

FMT-02.15 In a version 3 header, ids 11 and 12 are not parsed or checked. They are skipped like unknown ids (FMT-02.21). Observed: the reference skips a field 11 or 12 with any content in a version 3 file.

FMT-02.16 Transform seed (field 5, version 3): the data must be exactly 32 bytes, otherwise `Corrupt`. It is the AES-KDF seed of the version 3 key flow (FMT-04, FMT-17). In version 3 the key derivation is always AES-KDF.

FMT-02.17 Transform rounds (field 6, version 3): the data must be exactly 8 bytes, otherwise `Corrupt`. Read it as an unsigned 64-bit little-endian number. App accepts 1 to 2,147,483,646 (2^31 − 2) rounds. Any other value is `Unsupported`. CRY-02 may add a cost ceiling. The reference cuts the number to a signed 32-bit value and, when that value is out of its range, quietly uses 1 round with no message (observed, see CRY-02.13: rounds 0 and 2^31 opened with 1 round; 2^32 + 5 was read as 5 rounds). App never computes with a number other than the stored one.

FMT-02.18 Protected stream key (field 8, version 3): length 1 or more, any content. A length of 0 counts as missing. FMT-09 says how it is used (it is hashed, so any length works). The reference writes 32 bytes.

FMT-02.19 Stream start bytes (field 9, version 3): the data must be exactly 32 bytes, otherwise `Corrupt`. FMT-07 and FMT-17 say how they are checked.

FMT-02.20 Inner stream id (field 10, version 3): the data must be exactly 4 bytes, otherwise `Corrupt`. Read it as an unsigned 32-bit little-endian number. 2 means Salsa20 (FMT-09). When the field is absent, App uses Salsa20 (same as the reference). Value 3 (ChaCha20) is `Unsupported` (decided: spec/decisions.md LD-10): the reference accepts 3 in a version 3 header but still decrypts protected fields with Salsa20 (observed), so a file that really used ChaCha20 would show garbage. Value 1 (an old RC4-based stream) and every other value are `Unsupported`. The reference rejects those too.

FMT-02.21 Field 1 (comment) and all ids not defined for the file's version (13 to 255, including ids of 128 and above; plus 11 and 12 in version 3) are skipped: App reads and discards their data, and they still count in the raw header bytes (FMT-02.4). App does not write them back on save (decided: spec/decisions.md LD-21). The reference also drops them on save (observed). This is a deliberate exception to SD-06, see Security notes.

FMT-02.22 Duplicate fields (decided: spec/decisions.md default rule, the card's recommendation): if an id defined for the file's version appears more than once, the header is `Corrupt`. The defined ids are 2, 3, 4, 7, 11 and 12 in version 4, and 2 to 10 in version 3. Comments (id 1) and every id that FMT-02.21 skips may repeat. That includes ids 11 and 12 in a version 3 header. In version 4, ids 5, 6, 8, 9 and 10 are already `Corrupt` on their first appearance (FMT-02.14). The first id 0 ends the header, so a second end-of-header can never be seen. The reference instead uses the last copy of each repeated field (observed for cipher id, KDF parameters and public custom data).

FMT-02.23 Required fields: when the end-of-header field has been read (FMT-02.30, step 3), App checks that all required fields are present. Version 4: 2, 3, 4, 7, 11. Version 3: 2, 3, 4, 5, 6, 7, 8, 9. A missing field, or an IV or protected stream key of length 0, is `Corrupt`. The reference uses defaults for some of these (see the field table). App never fills in a default.

FMT-02.24 Truncation: if the input ends inside an id, a length or a data block, or before an end-of-header field has been read, the header is `Corrupt`. App never returns a partly read header.

FMT-02.25 Size limit (decided: spec/decisions.md LD-22): the raw header (FMT-02.4) is at most 1,048,576 bytes. Before reading a field's data, App checks that the field's end offset (field start + 1 + length width + length) is at most 1,048,576. If not, the result is `TooLarge`, and nothing is allocated for that field. This check runs before the truncation check of the same field. The reference has no limit (observed: a 20 MiB unknown field was accepted). For a length of `FF FF FF FF` it did not allocate 4 GiB: peak memory stayed near 25 MB.

FMT-02.26 Order of work: every check in this card and in FMT-03 runs in the order of FMT-02.30, before any key derivation, decryption or decompression starts. Where these checks sit in the whole open (after the read and the credentials, then the header hash, the KDF cost check of CRY-02.14 and the key work) is owned by FMT-05.7. A malformed or unsupported header never makes App spend KDF time.

FMT-02.27 Header-only read: App can parse the outer header without any key, for example to show the file version, cipher and KDF settings before unlock, or to read public custom data. The same rules apply. No secret is involved. The reference's unlock screen also reads the header without a key. Public name, colour and icon values shown before unlock follow FMT-03.23: they are unauthenticated until FMT-05 passes.

FMT-02.28 Version 3 headers may name any of the three ciphers. The reference writes a version 3.1 file whenever the KDF is AES-KDF and no feature needs version 4 (FMT-16). The cipher is whatever the vault has, any of the three, and does not affect the version choice. The IV size follows the cipher: 16 bytes for AES-256 and Twofish, 12 bytes for ChaCha20. FMT-02.11 applies to version 3 too.

FMT-02.29 Values App writes in a version 4 header: field 2 holds the vault's cipher UUID (for new vaults App offers AES-256, the default, ChaCha20 and Twofish-256; decided: spec/decisions.md LD-20). Field 3 holds 0 or 1. Field 4 holds 32 fresh random bytes. Field 7 holds fresh random bytes, 16 for AES-256 or Twofish and 12 for ChaCha20 (CRY-03). Field 11 holds the KDF map with a fresh salt or seed (FMT-03.21). Field 12 holds the public custom data when it is not empty (FMT-03.22). Field 0 holds `0D 0A 0D 0A`. All lengths are 4-byte little-endian. With the same values, App's header is byte-identical to the reference's.

FMT-02.30 Order of checks (decided: spec/decisions.md default rule, the card's recommendation). When a header has more than one fault, App reports only the first one it meets in the order below and stops there. Later bytes are not examined. Each step names the error kind it gives. This order covers the header only. FMT-05.7 owns the whole open: the read and the credentials (key file errors, `NoCredentials`) come before step 1 below, and step 5 below hands over to FMT-05.7 step 2.
1. The preamble (FMT-01).
2. The fields, one at a time in file order. For each field:
   a. The id byte. Input ends here: `Corrupt` (FMT-02.24).
   b. The length (4 bytes in version 4, 2 in version 3). Input ends inside it: `Corrupt` (FMT-02.24).
   c. The size limit. Field end past 1,048,576: `TooLarge` (FMT-02.25).
   d. The data. Fewer than `length` bytes left: `Corrupt` (FMT-02.24).
   e. Id 0: the header ends here. Go to step 3.
   f. Version 4 only: id 5, 6, 8, 9 or 10 is `Corrupt` (FMT-02.14).
   g. A defined id (FMT-02.22) already seen in this header is `Corrupt`, whatever the second copy holds.
   h. The field's own checks, all of them, before the next field is read: first its length, then its value (FMT-02.7 to FMT-02.10, FMT-02.16 to FMT-02.20). In version 4, field 11 or 12 is parsed and judged here as a whole map, in the order of FMT-03.20 (map version, then structure, then for field 11 the KDF settings). Two things wait for later steps: an IV (field 7) or protected stream key (field 8) of length 0 is not a fault here, it counts as missing in step 3; and the IV length is judged in step 4.
   i. A skipped id (FMT-02.21): no check.
3. After the end field: the required fields (FMT-02.23). One or more missing: `Corrupt`.
4. The IV length against the cipher of field 2 (FMT-02.11): `Unsupported`.
5. Then the open goes on at FMT-05.7 step 2 (version 4: the header hash check, then the KDF cost check of CRY-02.14, then the key work) or at FMT-05.13 step 2 (version 3: the ciphertext length check, then the cost check and the key work).

A header-only read (FMT-02.27) runs steps 1 to 4. The reference also judges each field, both maps included, as soon as it reads it, and stops at the first fault. So for every fault that both readers find in step 2, both stop at the same field. The reference differs in the later steps: it has no size limit (2c) and no duplicate check (2g, the last copy wins). It checks required fields after the end field only when a key is given, so its header-only read skips step 3. It checks the IV length only when it sets up decryption, after the header HMAC (source, same in the 2.7.11 tag).

## Edge cases and errors

| Case | App result | Reference (installed 2.7.11, observed unless marked) |
|---|---|---|
| Unknown id (for example 13, 255) | skipped, not saved | skipped with a warning on the error stream; dropped on save |
| Comment field (id 1) | skipped, not saved | same: skipped with a warning, dropped on save |
| Field 11 or 12 in version 3 | skipped | skipped with a warning |
| Field 5, 6, 8, 9 or 10 in version 4 | `Corrupt` | rejected: message about old (legacy) header fields |
| Cipher data not 16 bytes | `Corrupt` | rejected: message about a wrong cipher id length; the message includes the raw bytes |
| Cipher UUID all zero | `Unsupported` | rejected: message says the UUID could not be parsed |
| Cipher UUID unknown | `Unsupported` | rejected: message says the cipher is not supported |
| AES-128 UUID | `Unsupported` | header accepted; after the header check, decryption setup fails with a generic unknown-error message |
| Compression value 2 or more | `Unsupported` | rejected: message says the compression is not supported |
| Compression data not 4 bytes | `Corrupt` | rejected: message about a wrong compression length |
| Master seed not 32 bytes | `Corrupt` | rejected: message about a wrong master seed size |
| IV length wrong for the cipher | `Unsupported` | 0 bytes: missing header fields. ChaCha20 with 8 or 24 bytes: accepted. ChaCha20 with 16 or 32 bytes, or CBC with 12: rejected at decryption setup with an IV size message |
| Required field missing | `Corrupt` | v4: missing seed or IV gives a missing-fields message; missing cipher gives AES-256; missing compression gives gzip; missing KDF gives the wrong-key message. v3: missing protected stream key or start bytes gives a missing-fields message; missing transform seed or rounds gives the wrong-key message; missing inner stream id gives Salsa20 |
| Same defined id twice | `Corrupt` | last copy wins |
| End-of-header data empty or not `0D 0A 0D 0A` | accepted | accepted |
| Input ends inside a field or before id 0 | `Corrupt` | rejected: messages about a wrong header id size, field length or data length |
| Field length past the 1 MiB header limit | `TooLarge` | no limit |
| v3 transform seed or start bytes not 32 bytes | `Corrupt` | rejected: size messages |
| v3 transform rounds not 8 bytes | `Corrupt` | rejected: size message |
| v3 transform rounds 0, or 2^31 − 1 and above | `Unsupported` | cut to 32 bits; out of range quietly becomes 1 round (observed for 0 and 2^31; 2^32 + 5 read as 5; CRY-02.13) |
| v3 inner stream id 3 | `Unsupported` | accepted, but Salsa20 is used anyway |
| v3 inner stream id 1, or 4 and above | `Unsupported` | rejected: message about an invalid inner stream cipher |
| Several faults in one header | the first fault in the order of FMT-02.30 | stops at the first faulty field in file order (source); missing fields are reported only with a key; IV length only at decryption setup |
| v3 protected stream key of another length (for example 5 bytes) | accepted | accepted; protected values then decode to garbage with no error in a version 3.0 file, which has no header hash |

The reference puts a general could-not-read-the-vault prefix in front of each specific header message. App's plain-language messages come from `app-desktop` (APP-06). Error values never include header bytes.

## Security notes

- Everything in the outer header is unauthenticated until FMT-05 passes. A tamperer or a hostile file controls every byte (AT-A02, AT-A04, AT-A10). Parsing must be total: no panic, no unchecked index, every length checked against the remaining input and the limit before allocation (Rust rules 4 and 5).
- The header is public (SF-12). It must never hold a secret. The master seed, IV, KDF salt or seed and public custom data are public by design. App must never put a secret into public custom data, and must never write a new header field that carries user data.
- Wrong-key reporting: the reference turns some structural problems into the wrong-key message (missing KDF field, missing transform seed or rounds), because it fills in defaults. App reports structure problems as `Corrupt` and reports `WrongKey` only when the header HMAC fails (version 4, FMT-05) or the stream start bytes do not match (version 3, FMT-05.11, FMT-17.13; decided: spec/decisions.md LD-12). This keeps AT-A01 honest: only wrong credentials give the wrong-key message.
- No silent defaults and no silent number changes: App never assumes a cipher, a compression, a rounds count or a stream cipher that the file did not state, and never computes with a number cut from what the file stored (FMT-02.17, FMT-02.20, FMT-02.23).
- Duplicate fields are rejected so two readers can never disagree about which copy counts (a parser-differential trick). In version 4 the header HMAC already stops a tamperer without the key from adding copies, so this costs no real file.
- Dropping unknown fields on save (FMT-02.21) departs from SD-06 (keep data we do not understand), on purpose: an unknown outer field might change how the payload must be read. Written back next to a payload App encrypted its own way, it could make a future reader misread the file. The reference drops them too (decided: spec/decisions.md LD-21; keeping and re-writing them was the option not chosen).
- Version 3.0 files have no header check at all. A tamperer can change the header (for example the protected stream key) and the reference still opens the file, showing garbage protected values (observed). Version 3.1 checks a header hash inside the document when it is present (FMT-05, FMT-17); a 3.1 file without it is accepted, as the reference does (decided: spec/decisions.md LD-11). App reads version 3 files only.
- The size limit (FMT-02.25) and the ordering rule (FMT-02.26) stop memory and CPU attacks before any expensive work. The KDF cost bomb (AT-A05) is stopped by FMT-03 and CRY-02 before key derivation.
- Fresh master seed and IV on every save (SF-07, CRY-03, AT-B03).
- Differential fuzzing (AT-A11) will show these intended differences from the reference: duplicates, missing cipher or compression field, AES-128 id, ChaCha20 IV of 8 or 24 bytes, version 3 inner stream id 3, version 3 rounds out of range, the 1 MiB limit, and headers with several faults where FMT-02.30 checks earlier than the reference (required fields in a header-only read, IV length before the header HMAC). List them as expected differences in the differential test.

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| C01 FMT-02.1 | H4min | parse | cipher AES-256-CBC, compression gzip, master seed 32 × `11`, IV 16 × `22`, KDF AES-KDF with 1,000,000 rounds and seed 32 × `4B`, no public custom data; header length 207 |
| C02 FMT-02.2 | H3demo | parse | 2-byte lengths; cipher AES-256-CBC, gzip, master seed `72 3D ... C3 D8`, transform seed `AB BE ... 7B 81`, rounds 13,043,478, IV `A1 A7 ... 7F 4E`, protected stream key `78 14 ... AD D5`, start bytes `6D 54 ... EE 46`, inner stream id 2; header length 222 |
| C03 FMT-02.2 | H3demo with bytes 0x0008 to 0x000B changed to `00 00 02 00` (version 2.0) | parse | same values as C02 (version 3 rules) |
| C04 FMT-02.3 | H4min with the last 9 bytes replaced by `00 00 00 00 00` | parse | accepted; header length 203 |
| C05 FMT-02.3 | H4min with the last 9 bytes replaced by `00 03 00 00 00 61 62 63` | parse | accepted; header length 206 (reference: observed accepted) |
| C06 FMT-02.4 | H4min with `0D 05 00 00 00 68 65 6C 6C 6F` inserted at 0x00C6 | parse | accepted; raw header bytes given to FMT-05 are all 217 bytes, including the inserted field |
| C07 FMT-02.5 | the fields of H4min rewritten in the order 11, 7, 4, 3, 2, 0 (same preamble) | parse | same result as C01 |
| C08 FMT-02.5 | the reference's test vault Format400 (password `t`, field order 2, 3, 4, 11, 7, 0) | open | opens |
| C09 FMT-02.6 FMT-02.29 | the settings of H4min (version 4.1, AES-256, gzip, seed 32 × `11`, IV 16 × `22`, AES-KDF 1,000,000 rounds, KDF seed 32 × `4B`, no public custom data), random source mocked to return those values | write header | output equals H4min byte for byte |
| C10 FMT-02.7 | H4min with field 2 data set to each UUID of the cipher table (Twofish and ChaCha20 with a matching IV) | parse | AES-256-CBC, Twofish-CBC, ChaCha20 |
| C11 FMT-02.7 | H4min with field 2 data `00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F`; again with 16 zero bytes | parse | `Unsupported` both times |
| C12 FMT-02.7 | H4min with field 2 length `0F 00 00 00` and its first 15 data bytes | parse | `Corrupt` |
| C13 FMT-02.8 | H4min with field 2 data `61 AB 05 A1 94 64 41 C3 8D 74 3A 56 3D F8 DD 35` | parse | `Unsupported` (reference: header accepted, later failure observed) |
| C14 FMT-02.9 | H4min with field 3 data `00 00 00 00` / `02 00 00 00` / `FF FF FF FF` | parse | no compression / `Unsupported` / `Unsupported` |
| C15 FMT-02.9 | H4min with field 3 length 3 and data `01 00 00` | parse | `Corrupt` |
| C16 FMT-02.10 | H4min with field 4 length 31 (first 31 bytes); again with length 33 (one `11` added) | parse | `Corrupt` both times |
| C17 FMT-02.11 | H4min (AES-256) with field 7 length 12 | parse | `Unsupported` |
| C18 FMT-02.11 | H4min with ChaCha20 UUID and IV lengths 8, 12, 16, 24, 32 | parse | 12 accepted; 8, 16, 24, 32 `Unsupported` (reference: 8 and 24 pass its cipher setup, 16 and 32 fail there) |
| C19 FMT-02.11 FMT-02.23 | H4min with field 7 length 0 | parse | `Corrupt` (missing IV) |
| C20 FMT-02.11 | H4min with field 7 placed before field 2, ChaCha20 UUID, 12-byte IV | parse | accepted (IV size checked after the whole header) |
| C21 FMT-02.12 | H4min with the KDF map's version bytes (0x0069) set to `00 02` | parse | `Unsupported` (FMT-03.2) |
| C22 FMT-02.13 | H4min with field `0C 46 00 00 00` + the 70-byte public custom data vector of FMT-03 (case D10) inserted at 0x00C6 | parse, then write | 4 entries read; the written header has field 12 right after field 11 with the same 70 data bytes |
| C23 FMT-02.13 | H4min with `0C 0F 00 00 00 00 01 03 01 00 00 00 58 02 00 00 00 01 00 00` inserted at 0x00C6 (entry of type 03) | parse | `Corrupt` (reference: file rejected, observed) |
| C24 FMT-02.13 | H4min with `0C 00 00 00 00` inserted at 0x00C6 | parse | `Corrupt` (reference: map version error, observed) |
| C25 FMT-02.13 | H4min with `0C 03 00 00 00 00 01 00` inserted at 0x00C6 | parse, then write | accepted, no entries; written header has no field 12 (reference: same, observed) |
| C26 FMT-02.14 | H4min with `05 20 00 00 00` + 32 × `00` inserted at 0x00C6; again with `06 08 00 00 00` + 8 × `00`, `08 20 00 00 00` + 32 × `00`, `09 20 00 00 00` + 32 × `00`, `0A 04 00 00 00 02 00 00 00` | parse | `Corrupt` each time (reference: rejected, observed for 5, 8, 10) |
| C27 FMT-02.15 | H3demo with `0B 03 00 00 01 00` inserted at 0x00D7; again with `0C 03 00 FF FF FF` | parse | accepted; field skipped; raw header bytes 228 long |
| C28 FMT-02.16 | H3demo with field 5 length `1F 00` and its first 31 bytes | parse | `Corrupt` |
| C29 FMT-02.17 | H3demo with field 6 length `04 00` and data `16 07 C7 00` | parse | `Corrupt` |
| C30 FMT-02.17 | H3demo with field 6 data `00 00 00 00 00 00 00 00` / `FF FF FF 7F 00 00 00 00` / `FE FF FF 7F 00 00 00 00` / `16 07 C7 00 01 00 00 00` | parse | `Unsupported` / `Unsupported` / accepted (2,147,483,646) / `Unsupported` (reference uses 13,043,478 after cutting, by the same cut observed in CRY-02.13 for 2^32 + 5) |
| C31 FMT-02.18 | H3demo with field 8 length `05 00` and its first 5 bytes | parse | accepted |
| C32 FMT-02.18 FMT-02.23 | H3demo with field 8 length `00 00` and no data | parse | `Corrupt` |
| C33 FMT-02.19 | H3demo with field 9 length `1F 00` and its first 31 bytes | parse | `Corrupt` |
| C34 FMT-02.20 | H3demo with field 10 data `02 00 00 00`; again with field 10 removed | parse | Salsa20 both times |
| C35 FMT-02.20 | H3demo with field 10 data `03 00 00 00` / `01 00 00 00` / `04 00 00 00` | parse | `Unsupported` each time (reference: 3 accepted with Salsa20 used anyway; 1 and 4 rejected; observed) |
| C36 FMT-02.20 | H3demo with field 10 length `02 00` and data `02 00` | parse | `Corrupt` |
| C37 FMT-02.21 | H4min with `01 0C 00 00 00 64 65 6D 6F 20 63 6F 6D 6D 65 6E 74` ("demo comment") inserted at 0x000C | parse, then write | accepted; comment not kept; written header has no field 1 (reference: dropped on save, observed) |
| C38 FMT-02.21 | H4min with `FF 03 00 00 00 00 00 00` inserted at 0x0021 | parse | accepted; field skipped |
| C39 FMT-02.22 | H4min with `02 10 00 00 00 AD 68 F2 9F 57 6F 4B B9 A3 6A D4 7A F9 65 34 6C` inserted at 0x000C | parse | `Corrupt` (reference: last copy wins, the file opens, observed) |
| C40 FMT-02.22 | H4min with a second copy of field 11 (bytes 0x0064 to 0x00C5) inserted at 0x00C6; again with field 12 twice | parse | `Corrupt` both times |
| C41 FMT-02.22 | H4min with `0D 01 00 00 00 41` inserted twice at 0x00C6 | parse | accepted |
| C41b FMT-02.22 FMT-02.15 | H3demo with `0B 03 00 00 01 00` (field 11 in version 3) inserted twice at 0x00D7 | parse | accepted; both copies skipped; raw header bytes 234 long (reference: skips each copy by the same path as C27; not run with two copies) |
| C42 FMT-02.23 | H4min with field 2 removed; again with 3, 4, 7 and 11 each removed | parse | `Corrupt` each time |
| C43 FMT-02.23 | H3demo with field 2 removed; again with 3, 4, 5, 6, 7, 8 and 9 each removed | parse | `Corrupt` each time |
| C44 FMT-02.24 | the first 12 bytes of H4min; the first 14 bytes; the first 20 bytes; H4min without its last 9 bytes (no end-of-header) | parse | `Corrupt` each time |
| C45 FMT-02.24 | the first 14 bytes of H3demo | parse | `Corrupt` |
| C46 FMT-02.25 | H4min cut before 0x00C6, then `0D FF FF FF FF` and 100 bytes of `78` | parse | `TooLarge`; no allocation over the limit |
| C47 FMT-02.25 | H4min with an unknown field `0D` holding 1,048,364 zero bytes inserted at 0x00C6 (header exactly 1,048,576 bytes); again with 1,048,365 bytes | parse | first accepted; second `TooLarge` |
| C48 FMT-02.26 | H4min with field 3 data `02 00 00 00`, KDF wrapped in a counting test double | open with any password | `Unsupported`; the KDF was called 0 times |
| C49 FMT-02.27 | H4demo, no key | header-only read | AES-256, gzip, AES-KDF with 15,000,000 rounds and seed `B4 ED ... 17 41`; no KDF call |
| C50 FMT-02.28 | H3demo with field 2 set to the ChaCha20 UUID and field 7 of 12 bytes; again with field 7 of 16 bytes | parse | first accepted; second `Unsupported` |
| C51 FMT-02.29 | one demo vault saved twice by App | compare the two headers | master seeds differ, IVs differ, KDF salts or seeds differ; lengths 32, 16 or 12, and 32 |
| C52 FMT-02.30 | H4min with the `$UUID` value of field 11 (0x0079 to 0x0088) set to `00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F`, field 3 (0x0021 to 0x0029) removed, and `03 03 00 00 00 01 00 00` (field 3 with 3 data bytes) inserted right before the end-of-header field; 206 bytes. Again with the same `$UUID` change but the 3-byte field 3 left in its place (0x0021 to 0x0029 replaced by `03 03 00 00 00 01 00 00`); 206 bytes | parse | first `Unsupported` (field 11 comes first in the file); second `Corrupt` (field 3 comes first) (reference: stops at the first faulty field, observed on a Format400 copy with the same two faults: the KDF message first in one order, the compression-length message first in the other) |
| C53 FMT-02.30 FMT-02.23 FMT-02.11 | H4min (AES-256) with field 4 (0x002A to 0x004E) removed and field 7 replaced by `07 0C 00 00 00` + 12 × `22`; 166 bytes | parse | `Corrupt` (the missing master seed is found before the IV length) |
| C54 FMT-02.30 FMT-02.22 | H4min with `03 04 00 00 00 02 00 00 00` (a second field 3 holding the unsupported value 2) inserted at 0x00C6 | parse | `Corrupt` (the duplicate check comes before the value check) (reference: no duplicate check, so it rejects with the unsupported-compression message, observed) |
| C55 FMT-02.30 FMT-02.24 | the first 48 bytes (0x0000 to 0x002F) of H4min with field 3 data `02 00 00 00` (input ends inside field 4's data); again the same 48 bytes with field 3 data `01 00 00 00` | parse | first `Unsupported` (field 3 comes before the truncation); second `Corrupt` |
| C56 FMT-02.30 FMT-02.25 | H4min with field 3 data `02 00 00 00` and `0D FF FF FF FF` + 100 × `78` inserted at 0x000C (before field 2) | parse | `TooLarge` (the oversized field comes first in the file) |
| C57 FMT-02.30 FMT-02.27 | H4min with field 7 (0x004F to 0x0063) removed | header-only read | `Corrupt` (step 3 runs in a header-only read; the reference's header-only read accepts it, source) |

## How this was learned

- Read in the reference source (development branch, commit 09e34ba8): the shared header reading routine and its field setters, the version 3 and version 4 header readers, the version dispatcher that picks a reader by file version, the version 3 and version 4 save routines (field order, lengths, end-of-header value), the field-id and cipher-id constants, the cipher-id-to-mode lookup and cipher setup (IV checks), the database defaults (cipher, compression and KDF used when fields are absent), and the routine that reads the header without a key for the unlock screen. Also read the reference's tests for version 2, 3 and 4 files and the test vaults (stems Format200, Format300, Format400, NewDatabase, Compressed, NonAscii), whose headers were dumped with a small script.
- Compared the source with the release tag of the installed version (2.7.11). The header reading and writing code is the same in both for this card.
- Ran the installed reference CLI (2.7.11) on demo vaults in a scratch folder: one made with `db-create` (password `demo`, example A), one made with `import` (example B), and a scratch copy of the Format400 test vault re-saved with `db-edit` to password `demo` (a reference-written version 4 header with Argon2d and ChaCha20). Changed version 4 headers were re-signed so the header HMAC stayed valid: composite key = SHA-256(SHA-256(password)), then the KDF (Argon2 through a command-line crypto tool; AES-KDF as many chained AES-256 block encryptions), then HMAC key = SHA-512(master seed ‖ transformed key ‖ `01`), then header HMAC per FMT-05. That made it possible to see what the reader accepts and not only what fails. Version 3 changes were tested on a scratch copy of Format300 (version 3.0, no header hash) and on example A (version 3.1, where an accepted change shows up as a header-hash mismatch inside the document). Every "observed" in this card comes from these runs. Peak memory was measured with the system `time -l`.
- Cross-check round, read in the source (dev commit and the 2.7.11 tag): the shared header loop stops at the first field that raises an error; both readers run each field's checks, including the full parse of fields 11 and 12, when the field is read; the required-field check runs after the end field and only on the path with a key; the IV length is checked at cipher setup after the header HMAC (FMT-02.30). Observed with the installed CLI (2.7.11, `ls`, password `t`) on scratch copies of Format400: a bad `$UUID` in field 11 followed by a 3-byte field 3 gave the KDF message, the reverse order gave the compression-length message (C52); a second field 3 of value 2 gave the unsupported-compression message (C54); no master seed gave the missing-headers message.
- The quiet fallback to 1 round for out-of-range version 3 rounds (FMT-02.17) was observed in the runs reported in CRY-02.13 (rounds 0, 2^31 and 2^32 + 5). Nothing in this card is left marked "check with Verify".
- Sprint 1 close-out: FMT-02.26 and FMT-02.30 no longer give their own order for the cost check and the key work; they point to FMT-05.7, which puts the header hash check before the cost check. The wrong-key bullet now cites FMT-05.11.
