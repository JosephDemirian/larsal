# FMT-03 The KDF settings map

Status: reviewed
Epics: E3-S2
Parity rows: SF-02, SF-07, SF-12, SF-14, SD-06

## What it does

Version 4 files store two outer header fields as a small typed key-value map: the KDF parameters (field 11) and the public custom data (field 12), see FMT-02. The map is a version number, a list of entries, and an end byte. Each entry has a type byte, a name and a value.

This card defines the map's byte layout, how its version is checked, every type byte, the length encodings, the terminator, and what happens with duplicate names, unknown types and empty maps. It then lists the keys of each key derivation (Argon2d, Argon2id, AES-KDF): which keys are required, which types and ranges they take, and exactly how the reference writes them. Last, it says how public custom data is kept and written back.

Version 3 files have no map. Their AES-KDF settings are header fields 5 and 6 (FMT-02.16, FMT-02.17).

The KDF algorithms, their defaults, the benchmark and the cost ceilings are in CRY-02. How the derived key is used is in FMT-04.

## Inputs and outputs

Input: the data bytes of one header field (11 or 12). The field length bounds the map, and the field is bounded by the header limit (FMT-02.25).

Output, on success:
- for field 11: KDF settings, one of
  - Argon2d or Argon2id: salt (8 to 32 bytes), iterations, memory in KiB, parallelism, version (0x10 or 0x13);
  - AES-KDF: seed (32 bytes) and rounds;
- for field 12: an ordered list of entries (type byte, name bytes, value bytes), kept exactly for writing back.

On failure (FMT-03.20 gives the full split, which is the same as CRY-02.5 and CRY-02.16):
- `Corrupt`: the map's structure is broken (FMT-03.1 to FMT-03.6, FMT-03.9);
- `Unsupported`: the structure is fine but Larsal cannot use it: a map version that is too new, or any problem with the KDF settings themselves (unknown KDF, a missing, wrongly typed, negative, zero or out-of-range key);
- `TooLarge`: only through FMT-02.25.

### Map layout

| Part | Size | Content |
|---|---|---|
| Version | 2 bytes | unsigned 16-bit little-endian. High byte = major, low byte = minor. Written as `00 01` (version 1.0) |
| Entry | repeated | see below |
| Terminator | 1 byte | `00` |

One entry:

| Part | Size | Content |
|---|---|---|
| Type | 1 byte | type byte, table below (never `00`, which is the terminator) |
| Name length | 4 bytes | unsigned 32-bit little-endian, may be 0 |
| Name | name length | bytes, meant as UTF-8 |
| Value length | 4 bytes | unsigned 32-bit little-endian |
| Value | value length | bytes, read by type |

### Type bytes

| Type | Name | Value length | Value |
|---|---|---|---|
| `00` | end | (no name, no value) | ends the map |
| `04` | UInt32 | exactly 4 | unsigned, little-endian |
| `05` | UInt64 | exactly 8 | unsigned, little-endian |
| `08` | Bool | exactly 1 | `00` = false, any other byte = true. A Bool that Larsal creates is written as `00` or `01`. A Bool read from public custom data keeps its raw byte (FMT-03.8), so `02` is written back as `02`; the reference writes it back as `01` (observed) |
| `0C` | Int32 | exactly 4 | signed two's complement, little-endian |
| `0D` | Int64 | exactly 8 | signed two's complement, little-endian |
| `18` | String | any (0 or more) | text bytes, meant as UTF-8, no terminator |
| `42` | ByteArray | any (0 or more) | raw bytes |

No other type byte is valid. Some type numbers belong to a wider numbering scheme but are never used in this format (for example `02` byte, `03` 16-bit unsigned, `0A` signed byte, `0B` 16-bit signed, `10` float, `11` double, `12` decimal, `17` character). The reference rejects them, and so does Larsal.

### KDF UUIDs (key `$UUID`)

Bytes in RFC 4122 order.

| KDF | UUID | `$UUID` value bytes |
|---|---|---|
| AES-KDF (older id, the one the reference writes) | c9d9f39a-628a-4460-bf74-0d08c18a4fea | `C9 D9 F3 9A 62 8A 44 60 BF 74 0D 08 C1 8A 4F EA` |
| AES-KDF (newer id) | 7c02bb82-79a7-4ac0-927d-114a00648238 | `7C 02 BB 82 79 A7 4A C0 92 7D 11 4A 00 64 82 38` |
| Argon2d | ef636ddf-8c29-444b-91f7-a9a403e30a0c | `EF 63 6D DF 8C 29 44 4B 91 F7 A9 A4 03 E3 0A 0C` |
| Argon2id | 9e298b19-56db-4773-b23d-fc3ec6f0a1e6 | `9E 29 8B 19 56 DB 47 73 B2 3D FC 3E C6 F0 A1 E6` |

### Keys per KDF

Names are case-sensitive ASCII, compared as bytes.

| KDF | Key | Meaning | Written type | Required | Accepted values (Larsal) | Reference accepts |
|---|---|---|---|---|---|---|
| all | `$UUID` (`24 55 55 49 44`) | which KDF | ByteArray, 16 bytes | yes | the four UUIDs above | same |
| Argon2 | `S` | salt | ByteArray | yes | 8 to 32 bytes | 8 to 32 bytes; also a String, when the bytes it keeps are 8 to 32: the installed 2.7.11 keeps only the bytes before the first `00` byte (observed), the newer source all of them (source, check with Verify); FMT-03.17 |
| Argon2 | `V` | Argon2 version | UInt32 | yes | 0x10 (version 1.0) or 0x13 (version 1.3) | 0x10 to 0x13, after an unsigned 32-bit conversion: a UInt64 or Int64 value is cut to its low 32 bits (observed in 2.7.11: `V` = 2^32 + 0x13 as UInt64 was read as 0x13); a Bool becomes 0 or 1, a String or ByteArray is read as decimal text (source) |
| Argon2 | `P` | parallelism (lanes) | UInt32 | yes | 1 to 16,777,215 (2^24 − 1) | 1 to 16,777,215, after the same unsigned 32-bit conversion as `V` (observed in 2.7.11: `P` = 2^32 + 2 as UInt64 was read as 2) |
| Argon2 | `M` | memory in **bytes** | UInt64 | yes | floor(M / 1024) from 8 to 4,294,967,295 KiB | same |
| Argon2 | `I` | iterations | UInt64 | yes | 1 to 2,147,483,646 (2^31 − 2) | low 32 bits, read as signed, from 1 to 2^31 − 2; a Bool true is read as 1, a String or ByteArray as decimal text (source) |
| Argon2 | `K` | secret key | ByteArray | no | absent or empty | ignored |
| Argon2 | `A` | associated data | ByteArray | no | absent or empty | ignored |
| AES-KDF | `R` | rounds | UInt64 | yes | 1 to 2,147,483,646 (2^31 − 2) | low 32 bits, read as signed, from 1 to 2^31 − 2; a Bool true is read as 1 round, a String or ByteArray as decimal text (source) |
| AES-KDF | `S` | seed (the AES-256 key used for the rounds) | ByteArray | yes | exactly 32 bytes | 8 to 32 bytes, but only 32 works; also a String, with the same `00` byte cut in 2.7.11 as the Argon2 `S` (FMT-03.17) |

### Example 1: Argon2d map written by the reference

The KDF field of a version 4 vault written by the installed reference CLI: a scratch copy of the reference's test vault Format400, re-saved with `db-edit` and the new password `demo`. Argon2d, 2 iterations, 1 MiB, 2 lanes, version 1.3. The field is 139 bytes.

| Map offset | Bytes | Meaning |
|---|---|---|
| 0 | 00 01 | version 0x0100 (major 1, minor 0) |
| 2 | 42 | type ByteArray |
| 3 | 05 00 00 00 | name length 5 |
| 7 | 24 55 55 49 44 | name `$UUID` |
| 12 | 10 00 00 00 | value length 16 |
| 16 | EF 63 6D DF 8C 29 44 4B 91 F7 A9 A4 03 E3 0A 0C | Argon2d |
| 32 | 05 | type UInt64 |
| 33 | 01 00 00 00 | name length 1 |
| 37 | 49 | name `I` |
| 38 | 08 00 00 00 | value length 8 |
| 42 | 02 00 00 00 00 00 00 00 | 2 iterations |
| 50 | 05 | type UInt64 |
| 51 | 01 00 00 00 | name length 1 |
| 55 | 4D | name `M` |
| 56 | 08 00 00 00 | value length 8 |
| 60 | 00 00 10 00 00 00 00 00 | 1,048,576 bytes = 1,024 KiB |
| 68 | 04 | type UInt32 |
| 69 | 01 00 00 00 | name length 1 |
| 73 | 50 | name `P` |
| 74 | 04 00 00 00 | value length 4 |
| 78 | 02 00 00 00 | 2 lanes |
| 82 | 42 | type ByteArray |
| 83 | 01 00 00 00 | name length 1 |
| 87 | 53 | name `S` |
| 88 | 20 00 00 00 | value length 32 |
| 92 | 64 01 68 F0 F1 84 3B CF 2F 8E 77 DC 73 EF BB 6C 1E 05 AC AD 54 C9 B9 C3 47 43 8B D5 B0 FC FB 47 | salt (fresh on each save) |
| 124 | 04 | type UInt32 |
| 125 | 01 00 00 00 | name length 1 |
| 129 | 56 | name `V` |
| 130 | 04 00 00 00 | value length 4 |
| 134 | 13 00 00 00 | version 0x13 |
| 138 | 00 | terminator |

The original Format400 test vault, written by a different program, holds the same keys in the order `$UUID`, `V`, `I`, `M`, `P`, `S`. Readers must accept any order.

### Example 2: AES-KDF map written by the reference

The KDF field of H4demo (FMT-02, example B), made by the installed reference CLI with password `demo`. AES-KDF, 15,000,000 rounds. The field is 93 bytes. Note that a version 4 file carries the **older** AES-KDF UUID.

| Map offset | Bytes | Meaning |
|---|---|---|
| 0 | 00 01 | version 0x0100 |
| 2 | 42 | type ByteArray |
| 3 | 05 00 00 00 | name length 5 |
| 7 | 24 55 55 49 44 | name `$UUID` |
| 12 | 10 00 00 00 | value length 16 |
| 16 | C9 D9 F3 9A 62 8A 44 60 BF 74 0D 08 C1 8A 4F EA | AES-KDF (older id) |
| 32 | 05 | type UInt64 |
| 33 | 01 00 00 00 | name length 1 |
| 37 | 52 | name `R` |
| 38 | 08 00 00 00 | value length 8 |
| 42 | C0 E1 E4 00 00 00 00 00 | 15,000,000 rounds |
| 50 | 42 | type ByteArray |
| 51 | 01 00 00 00 | name length 1 |
| 55 | 53 | name `S` |
| 56 | 20 00 00 00 | value length 32 |
| 60 | B4 ED E5 64 F2 76 AF 60 7D 75 0C E8 84 D0 18 B9 0E 1C 4F 3C 9E 7C 9B A1 8B 30 C6 AC 1D 93 17 41 | seed (fresh on each save) |
| 92 | 00 | terminator |

### Test vectors

**M1** (Argon2id, 2 iterations, 64 MiB, 4 lanes, version 0x13, salt `00 01 ... 1F`), 139 bytes, in the reference writer's key order:

```
00 01 42 05 00 00 00 24 55 55 49 44 10 00 00 00 9E 29 8B 19 56 DB 47 73 B2 3D FC 3E C6 F0 A1 E6
05 01 00 00 00 49 08 00 00 00 02 00 00 00 00 00 00 00
05 01 00 00 00 4D 08 00 00 00 00 00 00 04 00 00 00 00
04 01 00 00 00 50 04 00 00 00 04 00 00 00
42 01 00 00 00 53 20 00 00 00 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
04 01 00 00 00 56 04 00 00 00 13 00 00 00
00
```

Entry offsets in M1: `$UUID` entry at 2, `I` entry at 32 (value at 42), `M` at 50 (value at 60), `P` at 68 (value at 78), `S` at 82 (value at 92), `V` at 124 (value at 134), terminator at 138.

**M2** (AES-KDF, 1,000,000 rounds, seed 32 × `4B`), 93 bytes. This is the KDF field of H4min (FMT-02):

```
00 01 42 05 00 00 00 24 55 55 49 44 10 00 00 00 C9 D9 F3 9A 62 8A 44 60 BF 74 0D 08 C1 8A 4F EA
05 01 00 00 00 52 08 00 00 00 40 42 0F 00 00 00 00 00
42 01 00 00 00 53 20 00 00 00 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B 4B
00
```

Entry offsets in M2: `$UUID` entry at 2, `R` entry at 32 (value at 42), `S` entry at 50 (value at 60), terminator at 92.

**M3** (public custom data from the reference's own test: `CD1` Int32 123, `CD2` Bool true, `CD3` String "abcäöü", `CD4` ByteArray `AB AB A1 23 FF`), 70 bytes:

```
00 01
0C 03 00 00 00 43 44 31 04 00 00 00 7B 00 00 00
08 03 00 00 00 43 44 32 01 00 00 00 01
18 03 00 00 00 43 44 33 09 00 00 00 61 62 63 C3 A4 C3 B6 C3 BC
42 03 00 00 00 43 44 34 05 00 00 00 AB AB A1 23 FF
00
```

## Rules

FMT-03.1 A map is: a 2-byte version, zero or more entries, and one terminator byte `00`. An entry is: type (1 byte), name length (4 bytes, unsigned, little-endian), name bytes, value length (4 bytes, unsigned, little-endian), value bytes. There is no padding.

FMT-03.2 Version check: read the first 2 bytes as an unsigned 16-bit little-endian number. The high byte is the major version and the low byte is the minor version. Majors 0 and 1 are accepted, with any minor (so `00 00`, `01 00`, `00 01` and `FF 01` all pass). Major 2 or more is `Unsupported`. Fewer than 2 bytes is `Corrupt`. Larsal always writes `00 01`.

FMT-03.3 Before reading a name or a value, Larsal checks that its declared length is no larger than the bytes left in the field. If it is larger, the map is `Corrupt` and nothing is allocated for that length. A length field cut short by the end of the field is also `Corrupt`.

FMT-03.4 Each type byte has the value length given in the type table. UInt32 and Int32 need exactly 4 bytes, UInt64 and Int64 exactly 8, Bool exactly 1. Any other length for these types is `Corrupt`. String and ByteArray take any length, including 0.

FMT-03.5 A type byte not in the type table makes the whole map `Corrupt`, even when its name and value are well formed. The reference checks the type after reading the name and value, and rejects the map too (observed for types `03` and `FF`).

FMT-03.6 The type byte `00` ends the map. No name or value follows it. If the field ends before a terminator, the map is `Corrupt`. Bytes after the terminator inside the same field are ignored and not kept (the reference ignores them too, observed). A write never produces them.

FMT-03.7 Names are byte strings, meant as UTF-8. The empty name is allowed. Larsal compares names as exact bytes (case-sensitive) and keeps them as raw bytes, with no decoding, so a save writes back exactly what was read. The reference decodes names and String values as UTF-8 and replaces invalid sequences, so it may change such bytes on save (observed by Verify in Sprint 2 with the installed 2.7.11, through public custom data (field 12), which the reference writes back: after a re-save with `mkdir`, the name `6E FE` came back as `6E EF BF BD`, the String value `41 FF 42` as `41 EF BF BD 42`, and the String value `EF BB BF 68 69` as `68 69`). The installed 2.7.11 also stops that decoding at the first `00` byte and drops the rest (observed for a String `S`, FMT-03.17, and by Verify in field 12: the name `78 00 79` came back as `78` and the String value `41 42 00 43 44` as `41 42`); the newer source keeps `00` bytes (source reading only: it needs the newer toolkit generation, which is not on this Mac; check with Verify).

FMT-03.8 Values are read by type: integers little-endian (Int32 and Int64 as two's complement), Bool false only for `00`, String and ByteArray as raw bytes. In public custom data Larsal keeps the raw value bytes and writes them back unchanged, including a Bool byte other than `00` or `01`. The reference re-encodes on save instead: a Bool is written as `01` or `00` from its truth value (observed: `02` came back as `01`), and String values are re-encoded from decoded text (FMT-03.7).

FMT-03.9 Duplicate names (decided: spec/decisions.md default rule, the card's recommendation): if two entries in one map have the same name bytes, the map is `Corrupt`. The reference instead keeps the last one (observed: a KDF map with `I` twice used the second value).

FMT-03.10 The empty map `00 01 00` (version plus terminator) is valid structure. As public custom data it means "no entries". As KDF parameters it fails FMT-03.11 because `$UUID` is missing.

FMT-03.11 In field 11 the key `$UUID` picks the KDF. Its value must be a ByteArray of exactly 16 bytes, otherwise `Unsupported`. A missing `$UUID` is `Unsupported`. One of the four KDF UUIDs selects that KDF. Any other UUID is `Unsupported`. In a version 4 file both AES-KDF UUIDs select the same AES-KDF, and the key flow treats it as version 4 AES-KDF (FMT-04).

FMT-03.12 Argon2d and Argon2id need all of `S`, `V`, `P`, `M` and `I`. A missing key is `Unsupported`. Range checks, after the type rules of FMT-03.17. Each value outside its range is `Unsupported`:
- `S`: 8 to 32 bytes.
- `P`: 1 to 16,777,215.
- `I`: 1 to 2,147,483,646.
- `M`: 8,192 bytes (8 KiB after the floor of FMT-03.13) up to, but not including, 4,398,046,511,104 bytes (2^32 KiB).
- `V`: 0x10 or 0x13 (FMT-03.14).

These are the same ranges as CRY-02.7 to CRY-02.11.

FMT-03.13 `M` is stored in bytes. The memory cost is floor(M / 1024) KiB. A value that is not a multiple of 1024 is accepted and rounded down, as the reference does (observed: `M` = 1,048,581 opened as 1,024 KiB). When writing, Larsal stores KiB × 1024, so such a value becomes a clean multiple after a save (the reference does the same, observed).

FMT-03.14 `V` = 0x13 means Argon2 version 1.3 (RFC 9106). `V` = 0x10 means the older version 1.0, which Larsal supports for reading. 0x11 and 0x12 are not Argon2 versions and are `Unsupported` (decided: spec/decisions.md default rule, the card's recommendation). The reference accepts 0x10 to 0x13. The installed reference (2.7.11) computes with the stored version (observed: a header signed with a version 1.0 key passed its HMAC check). The newer reference source ignores `V` and always computes version 1.3 (differs in installed version). So a file with `V` = 0x10 opens in the installed reference but not in the newer source. Larsal reads such a file with version 1.0 and saves it as 0x13 (FMT-03.21; decided: spec/decisions.md LD-17), so after one Larsal save it opens in both.

FMT-03.15 `K` (secret key) and `A` (associated data) are optional Argon2 inputs. When either is present with a non-empty value, the map is `Unsupported` (decided: spec/decisions.md default rule, the card's recommendation). The reference ignores both keys (observed: a file with `K` = "secret" opened with `K` left out of the computation), so such a file was not really made for the reference. An empty `K` or `A` is ignored. Larsal never writes `K` or `A`.

FMT-03.16 AES-KDF needs `R` and `S`. A missing key is `Unsupported`. `R` must be 1 to 2,147,483,646, otherwise `Unsupported`. `S` must be exactly 32 bytes, otherwise `Unsupported` (decided: spec/decisions.md LD-14, decision D-04-2 option (a); the other option, copying the reference's zero-round derivation, was not chosen). FMT-04.20 and CRY-02.12 follow this rule. The reference accepts 8 to 32 bytes, but with fewer than 32 its AES setup fails without reporting it, and it then derives the key with **no rounds at all**: transformed key = SHA-256(composite key) (observed: a header signed with that key passed its HMAC check).

FMT-03.17 Value types for KDF keys: `$UUID`, `S`, `K` and `A` must be ByteArray, otherwise `Unsupported`. The numeric keys `V`, `P`, `M`, `I` and `R` accept any of UInt32, UInt64, Int32 and Int64, as long as the value is not negative and is in range. A negative value is `Unsupported`. Any other type (String, Bool, ByteArray) for a numeric key is `Unsupported`. The reference converts more freely (observed accepted: `P` as UInt64, `I` as UInt32 or Int64, `V` as the String "19", `M` as the String "1048576"). From the source it also reads a number stored as ByteArray as decimal text, reads a Bool as 0 or 1 (so `I` or `R` = Bool true means 1 iteration or 1 AES round), and takes an `S` stored as a String as the UTF-8 bytes of the decoded text. Because the reader replaces invalid UTF-8 (FMT-03.7), a String `S` that is not valid UTF-8 grows and usually fails the length check (observed: an `S` String of 32 random bytes was rejected with the generic KDF message). A `00` byte is handled differently by the two versions. The installed 2.7.11 stops the text at the first `00` byte, so only the bytes before it become the salt or seed (observed: an Argon2 `S` String of 32 bytes of `41` opened as that 32-byte salt; 10 bytes of `42`, then `00`, then 21 bytes of `43` opened only when derived with the 10-byte salt, and with all 32 bytes it gave the wrong-key message; the bytes `00` to `1F` gave an empty salt and the generic KDF message). The newer source keeps `00` bytes, so a valid UTF-8 String of 8 to 32 bytes, `00` bytes included, is used whole (source, check with Verify). The reference does not read `K` or `A` at all (FMT-03.15). Larsal deliberately rejects text, ByteArray and Bool for numbers and anything but ByteArray for `S`.

FMT-03.18 Larsal reads every numeric key at its full stored width and checks the range on that value. It never computes with a cut-down number. The reference cuts `I` and `R` to signed 32-bit numbers before its range check (observed: `I` = 4,294,967,298 (2^32 + 2) opened as 2 iterations; `R` = 2^32 + 15,000,000 opened as 15,000,000 rounds; `I` = 2^63 cut to 0 and was rejected). It also reads `P` and `V` with an unsigned 32-bit conversion, so a 64-bit value loses its high bits (observed in 2.7.11: `P` = 2^32 + 2 as UInt64 was read as 2; `V` = 2^32 + 0x13 as UInt64 was read as 0x13).

FMT-03.19 Keys that the selected KDF does not use (for example `X`, the empty name, `R` in an Argon2 map, or `I` and `P` in an AES-KDF map) are ignored when reading and not written back. The reference does the same (observed).

FMT-03.20 These structure and range checks only decide whether the map is readable. The cost ceilings and safe minimums (memory, iterations, rounds, parallelism) are in CRY-02. Every check of this card and CRY-02 runs before any key derivation (FMT-02.26, AT-A05). Error kinds, the same split as CRY-02.5, CRY-02.12 and CRY-02.16:
- A broken structure is `Corrupt`: a version field cut short, a length past the end, a fixed-size type with the wrong length, an unknown type byte, no terminator, or a duplicate name (FMT-03.1 to FMT-03.6, FMT-03.9).
- A map version with major 2 or more is `Unsupported` (FMT-03.2).
- In field 11, every problem with the settings themselves is `Unsupported`: `$UUID` missing, not a ByteArray, not 16 bytes or unknown; a required key missing; a key of the wrong type; a negative, zero or out-of-range value; a non-empty `K` or `A`; an AES-KDF seed that is not 32 bytes (FMT-03.11 to FMT-03.17).

Order of checks inside one map. The map is judged as soon as its header field is read (FMT-02.30, step 2h). When it has more than one fault, only the first one met in this order is reported:
1. The version (FMT-03.2): fewer than 2 bytes is `Corrupt`; major 2 or more is `Unsupported`, and no entry is read.
2. The entries in file order, then the terminator (FMT-03.3 to FMT-03.6). A duplicate name (FMT-03.9) is found when its second copy is read. The first structure fault is `Corrupt`.
3. Field 11 only, and only once the whole map is well formed: the KDF settings (FMT-03.11 to FMT-03.17), all `Unsupported`. Their order among themselves does not change the error kind.

So a map with a broken entry is `Corrupt` even when its `$UUID` is unknown, and a map of major version 2 is `Unsupported` even when its entries are broken. The reference also checks the version first and stops there, and reads every entry before it looks at the KDF settings (source); it rejects both kinds of map.

FMT-03.21 Writing field 11: version `00 01`, then the entries sorted by name bytes in ascending order (`$UUID` is first because `24` sorts before letters), then `00`.
- Argon2: `$UUID` (ByteArray, 16), `I` (UInt64), `M` (UInt64, KiB × 1024), `P` (UInt32), `S` (ByteArray, 32 fresh random bytes), `V` (UInt32, always 0x13: a vault read with 0x10 is written as 0x13, and the save derives its new key with Argon2 version 1.3; decided: spec/decisions.md LD-17). Always 139 bytes.
- AES-KDF: `$UUID` (ByteArray, the older id `C9 D9 F3 9A ...`), `R` (UInt64), `S` (ByteArray, 32 fresh random bytes). Always 93 bytes.

The key order, the types and the byte layout match the reference writer. Differences from the reference:
- The reference makes the new salt or seed with the same length as the one it read (source: the new random seed takes the length of the current one). So its Argon2 map is 139 bytes only when the salt it read was 32 bytes, and an AES-KDF seed it read short stays short (FMT-03.16, CRY-02.12). Larsal always writes 32 bytes (decided: spec/decisions.md LD-15; CRY-02.19, CRY-03.4).
- `V`: the reference writes back the version it read, 0x10 to 0x13 (source, same in 2.7.11 and the newer source). Larsal always writes 0x13 (decided: spec/decisions.md LD-17). This costs nothing extra, because every save runs the KDF again with a fresh salt (CRY-03), and the newer reference source computes 1.3 whatever `V` says (FMT-03.14), so the saved vault opens there too. History: keeping 0x10 was the card's earlier default; CRY-02.19 must follow the same ruling.

FMT-03.22 Public custom data (field 12): every entry of every valid type is accepted, whatever its name. Larsal keeps each entry exactly (type byte, name bytes, value bytes). On save it writes them back as one map: version `00 01`, the entries sorted by name bytes ascending, terminator `00`. Larsal writes field 12 only when there is at least one entry. The reference also sorts on save, and keeps each value's type (observed: entries `zeta` UInt64, `Alpha` UInt32, `beta` Int64, `_x` String were written back as `Alpha`, `_x`, `beta`, `zeta` with the same types). The reference sorts by 16-bit text code units, which differs from byte order only when names hold characters at U+E000 or above next to characters above U+FFFF. Readers accept any order.

FMT-03.23 Public custom data keys that the reference writes. The names are ASCII and are stored encoded (name rule). They all share the same 12-byte prefix `4B 50 58 43 5F 50 55 42 4C 49 43 5F`.

| Name bytes (stored encoded, name rule) | Type written | Value | Written by | When cleared |
|---|---|---|---|---|
| prefix + `4E 41 4D 45` (16 bytes) | String | the vault's public name: free text the user types in the vault settings | installed 2.7.11 and newer source | entry removed |
| prefix + `43 4F 4C 4F 52` (17 bytes) | String | a colour, written as `#` plus 6 lowercase hex digits (`#rrggbb`), picked with a colour dialog | installed 2.7.11 and newer source | entry removed |
| prefix + `49 43 4F 4E` (16 bytes) | Int32 | index of one of the reference's built-in vault icons, 0 or more | installed 2.7.11 and newer source | entry removed (the reference holds "no icon" as −1 and does not store it) |
| prefix + `55 55 49 44` (16 bytes) | ByteArray, 16 bytes | a random UUID used as a public id. Created the first time quick unlock looks up, checks, stores or resets a key for this version 4 vault (a plain check on the unlock screen whether a quick unlock key exists is enough); creating it marks the vault changed (APP-04.8 describes the reference's trigger; Larsal never adds or uses this key, D-A04-3) | newer source only | never removed |

More facts about these keys:
- Public custom data exists only in version 4 files. When it is not empty, the reference writes version 4 (FMT-16).
- When reading, the reference converts loosely: the name and colour as text from any type, the icon as an integer from any type (source).
- The reference's unlock screen opens the file with no key. This parses the whole outer header, field 12 included, and stops before the header HMAC check (FMT-05). The screen then puts the name into its title, draws a border by inserting the colour text into a style rule, and shows the icon when the index is inside its icon list (source, same in the 2.7.11 tag and the newer source). So the reference shows these values before anything has authenticated them.
- Observed keep-on-save: a demo vault with the name `Demo vault`, the colour `#1a2b3c` and the icon 5, re-saved by the installed CLI, came back with the same three entries and types, sorted (test D50).

Larsal keeps every one of these entries unchanged on save (FMT-03.22), like any other entry. If Larsal shows any of them before unlock (FMT-02.27), these rules apply (decided: spec/decisions.md default rule, the card's recommendation):
- **Name:** used only when its type is String and its bytes are valid UTF-8. Shown as plain text only, never as markup or a link, with control characters left out.
- **Colour:** used only when its type is String and its bytes are exactly `#` followed by 6 hex digits (`0`–`9`, `a`–`f`, `A`–`F`). Larsal turns it into three numbers before use and never puts the text itself into a style rule or markup.
- **Icon:** used only when its type is Int32 and the value is a valid index in Larsal's own vault icon set.
- **Invalid values:** an invalid value is not shown. It never fails the open, and it is still written back unchanged.
- **Before unlock:** these values are not verified until FMT-05 passes. After unlock, Larsal uses them only from the authenticated header.

If Larsal lets the user set them, Larsal writes the same names and types as the reference (String, lowercase `#rrggbb` String, Int32 of 0 or more), removes an entry when it is cleared, and warns that anyone with the file can read the name (SF-12). Larsal offers these three settings, as the reference does (decided: spec/decisions.md default rule; the card gave no recommendation, so the reference behavior holds). The settings screen itself belongs to MOD-12.

Lowercase is the one case for every colour Larsal creates, so Larsal's bytes match the reference's and AT-A11 shows no needless differences. The reference's colour dialog writes lowercase, and saving its vault settings page rewrites the stored public colour in that form (an uppercase `#1A2B3C` becomes `#1a2b3c`; text it cannot read as a colour is removed; source). The colours inside the XML document are owned by FMT-12.18 and FMT-11; they follow the same lowercase rule.

FMT-03.24 Version 3 files have no typed map. Their KDF is always AES-KDF, with the seed from field 5 and the rounds from field 6 (FMT-02.16, FMT-02.17). A field 11 or 12 in a version 3 header is never parsed (FMT-02.15).

## Edge cases and errors

| Case | Larsal | Reference (installed 2.7.11, observed unless marked) |
|---|---|---|
| Map version major 2 or more | `Unsupported` | rejected; KDF field: generic message that the KDF is unsupported or its parameters invalid; public custom data: message that the map version is unsupported |
| Map version `00 00`, `01 00`, `FF 01` | accepted | accepted |
| Field shorter than 2 bytes | `Corrupt` | rejected (map version message) |
| Name or value length past the end of the field | `Corrupt`, no allocation | rejected |
| Fixed-size type with wrong length | `Corrupt` | rejected |
| Unknown type byte | `Corrupt` | rejected |
| No terminator | `Corrupt` | rejected |
| Bytes after the terminator | ignored, not kept | ignored |
| Same name twice | `Corrupt` | last one wins |
| Empty name | accepted | accepted |
| Empty map as KDF parameters | `Unsupported` (no `$UUID`) | rejected (generic KDF message) |
| Empty map as public custom data | accepted, not written back | same |
| `$UUID` missing, not a ByteArray or not 16 bytes | `Unsupported` | rejected |
| `$UUID` unknown | `Unsupported` | rejected |
| A required KDF key missing | `Unsupported` | rejected |
| `I` or `R` above 2^31 − 2 in full width | `Unsupported` | cut to 32 bits; may open with a different number |
| `M` below 8 KiB; `P`, `I` or `R` of 0; a negative number | `Unsupported` | rejected |
| `M` of 2^32 KiB or more (4 TiB) | `Unsupported` | rejected |
| `M` from 2^42 − 1,024 bytes down to the CRY-02 ceiling | stopped by CRY-02 before work | accepted by the map check; the reference would try to allocate it (not run) |
| `V` 0x11 or 0x12 | `Unsupported` | accepted; installed version computes a nonstandard variant |
| `V` 0x10 | accepted, Argon2 1.0 used to open; written as 0x13 on save (FMT-03.21, decided: spec/decisions.md LD-17) | installed: honoured; newer source: ignored (computes 1.3); both write back the version read (source) |
| `K` or `A` non-empty | `Unsupported` | ignored |
| AES-KDF `S` of 8 to 31 bytes | `Unsupported` (decided: spec/decisions.md LD-14) | accepted; KDF silently does zero rounds |
| Numeric key given as String, ByteArray or Bool | `Unsupported` | converted from text (observed for String `V` and `M`; ByteArray read as decimal text, source); a Bool becomes 0 or 1, so `I` or `R` = true means 1 iteration or 1 round (source) |
| `S` given as String | `Unsupported` | used as the UTF-8 bytes of the decoded text when those are 8 to 32 bytes; 2.7.11 keeps only the bytes before the first `00` byte (observed), the newer source all of them (source, check with Verify); a String of 32 random bytes was rejected (observed); FMT-03.17 |
| `P` or `V` stored as a 64-bit type above 2^32 − 1 | `Unsupported` (out of range at full width) | cut to the low 32 bits (observed: `P` = 2^32 + 2 read as 2, `V` = 2^32 + 0x13 read as 0x13) |
| Public custom data Bool byte other than `00` or `01` | kept and written back as read | true; written back as `01` (observed) |
| Public name, colour or icon key (FMT-03.23) with an invalid value | kept and written back; not shown | converted loosely; the colour text goes into a style rule (source) |
| Public custom data with any map error | file rejected (`Corrupt` or `Unsupported`) | file rejected with a specific map message |

The reference uses one generic message for every problem in the KDF field (the KDF is unsupported or its parameters are invalid). For public custom data it uses specific messages about the map's version, entry type or lengths. Larsal's plain-language messages come from `larsal-desktop` (APP-06). Error values never include map bytes.

## Security notes

- The KDF map sets how much work an attacker must do per password guess (SF-02). Read naively, it is also an attack tool:
  - a cost bomb (AT-A05: huge memory, iterations or lanes), stopped by the ranges here and the CRY-02 ceilings before any work;
  - a silent downgrade (AT-A09).
- Downgrade paths in the reference that Larsal closes:
  - An AES-KDF seed shorter than 32 bytes makes the reference skip every round. The vault then has no key stretching at all, while the settings still show millions of rounds. Worse, the reference makes a new seed of the same short length on each save, so the weakness stays. Larsal rejects such seeds (FMT-03.16).
  - Cutting `I` and `R` to 32 bits means the stored number and the number used differ (FMT-03.18). Larsal rejects them, so the cost shown is always the cost paid (AT-B06: stored settings equal the ones used).
  - Ignoring `K` or `A` means the reference computes something other than what the file's writer asked for. Larsal refuses (FMT-03.15).
- Silent type conversion (text to number) is a parser-differential risk (AT-A11). Larsal accepts only integer types for numbers (FMT-03.17).
- Differential fuzzing (AT-A11) will show these intended differences from the reference. List them as expected differences in the differential test:
  - duplicate names;
  - `V` of 0x11 or 0x12 (FMT-03.14);
  - non-empty `K` or `A`;
  - AES-KDF seed shorter than 32 bytes;
  - numbers given as String, ByteArray or Bool (including `I` or `R` = Bool true, which the reference reads as 1);
  - `S` given as String;
  - `I`, `R`, `P` or `V` above 2^32 − 1 in a 64-bit type, which the reference cuts to 32 bits;
  - names or String values that are not valid UTF-8 (FMT-03.7);
  - a public custom data Bool byte other than `00` or `01` (FMT-03.8).
- Duplicate names are rejected so no two readers can disagree about which value counts (FMT-03.9). In version 4 a tamperer without the key cannot add duplicates anyway, because the header HMAC covers the map (FMT-05).
- Public custom data is stored in the clear (SF-12). Larsal never writes secrets there. The public id of FMT-03.23 is random and holds no secret, but it is a stable marker that links copies of the same vault. Treat it as public metadata. Whether Larsal's own quick unlock (APP-04) uses such an id is APP-04's decision.
- Public name, colour and icon (FMT-03.23):
  - **Not authenticated before unlock.** The reference shows them before the header HMAC is checked, so a tamperer without the key can change what the unlock screen shows. An example is a fake name that tricks the user into thinking they are opening a different vault. Larsal must not present these values as trusted before FMT-05 passes. It must never take them from an unverified header after unlock.
  - **Injection (AT-E01).** The name is attacker text. Show it as plain text only. The colour goes into a style rule in the reference, so a crafted String could inject style. Larsal accepts only the exact `#` + 6 hex digits form and uses the parsed numbers, never the text. A bad icon index must not index out of bounds.
  - **Privacy (SF-12).** Users may type something private into the public name, such as a bank name or their own name. Anyone with the file can read it without the password. If Larsal lets users set it, Larsal warns that it is public.
- Fresh salt or seed on every save (SF-07, CRY-03, AT-B03).
- Changing the KDF or its cost later (SF-14) rewrites this map on the next save, per FMT-03.21.
- Fuzz target `kdf_params` (architecture: fuzz/) covers this card. Every length is checked against the remaining bytes before allocation (Rust rule 5).

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| D01 FMT-03.1 FMT-03.12 | M1 | parse as field 11 | Argon2id; salt `00 01 ... 1F`; iterations 2; memory 65,536 KiB; parallelism 4; version 0x13 |
| D02 FMT-03.1 FMT-03.16 | M2 | parse as field 11 | AES-KDF; rounds 1,000,000; seed 32 × `4B` |
| D03 FMT-03.1 | the 139-byte map of example 1 | parse | Argon2d; iterations 2; memory 1,024 KiB; parallelism 2; version 0x13; salt `64 01 ... FB 47` |
| D04 FMT-03.1 FMT-03.11 | the 93-byte map of example 2 | parse | AES-KDF (older id); rounds 15,000,000; seed `B4 ED ... 17 41` |
| D05 FMT-03.21 | Argon2id settings: 2 iterations, 65,536 KiB, 4 lanes, salt `00 01 ... 1F` (random source mocked) | write field 11 | exactly M1 (139 bytes) |
| D06 FMT-03.21 | AES-KDF settings: 1,000,000 rounds, seed 32 × `4B` (random source mocked) | write field 11 | exactly M2 (93 bytes) |
| D07 FMT-03.2 | M2 with bytes 0 to 1 set to `00 00`; again `01 00`; again `FF 01` | parse | accepted each time; same result as D02 (reference: observed for all three) |
| D08 FMT-03.2 | M2 with bytes 0 to 1 set to `00 02`; again `FF FF` | parse | `Unsupported` |
| D09 FMT-03.2 | the single byte `00` | parse | `Corrupt` |
| D10 FMT-03.22 FMT-03.8 | M3 | parse as field 12, then write | 4 entries: `CD1` Int32 123; `CD2` Bool true; `CD3` String `61 62 63 C3 A4 C3 B6 C3 BC`; `CD4` ByteArray `AB AB A1 23 FF`; written bytes equal M3 |
| D11 FMT-03.3 | M2 with the `R` name length (offset 33) set to `FF FF 00 00` | parse | `Corrupt`; no 64 KiB allocation |
| D12 FMT-03.3 | M2 with the `S` value length (offset 56) set to `22 00 00 00` (34; only 33 bytes remain from offset 60) | parse | `Corrupt`; no allocation of 34 bytes past the field |
| D12b FMT-03.6 | M2 with the `S` value length (offset 56) set to `21 00 00 00` (33: the value swallows the terminator byte) | parse | `Corrupt` (no terminator) |
| D13 FMT-03.4 | M2 with `08 01 00 00 00 42 02 00 00 00 01 00` inserted at 92 (Bool of length 2) | parse | `Corrupt` |
| D14 FMT-03.4 | M2 with one of these inserted at 92: `0C 01 00 00 00 58 08 00 00 00` + 8 × `00`; `04 01 00 00 00 58 03 00 00 00 00 00 00`; `05 01 00 00 00 58 04 00 00 00 00 00 00 00`; `0D 01 00 00 00 58 09 00 00 00` + 9 × `00` | parse | `Corrupt` each time (reference: rejected, observed) |
| D15 FMT-03.8 | M2 with `08 01 00 00 00 42 01 00 00 00 02` inserted at 92 | parse | accepted; `B` is Bool true; ignored as an unused KDF key |
| D16 FMT-03.5 | M2 with `03 01 00 00 00 58 02 00 00 00 01 00` inserted at 92; again with `FF 01 00 00 00 58 00 00 00 00` | parse | `Corrupt` both times |
| D17 FMT-03.6 | M2 without its last byte (92 bytes) | parse | `Corrupt` |
| D18 FMT-03.6 | M2 followed by `47 41 52 42 41 47 45` inside the same field | parse | accepted; same result as D02; the extra bytes are not kept |
| D19 FMT-03.7 FMT-03.19 | M2 with `04 00 00 00 00 04 00 00 00 01 00 00 00` (empty name) inserted at 92 | parse | accepted; entry ignored |
| D20 FMT-03.7 FMT-03.22 | field 12 = `00 01 04 00 00 00 00 04 00 00 00 01 00 00 00 00` | parse, then write | one entry with an empty name, UInt32 1; written back unchanged |
| D21 FMT-03.9 | M1 with `05 01 00 00 00 49 08 00 00 00 63 00 00 00 00 00 00 00` (`I` = 99) inserted at 2; again inserted at 138 | parse | `Corrupt` both times (reference: inserted at 2, the later `I` = 2 won and the file opened; inserted at 138, `I` = 99 won and the open failed with the wrong-key message; both observed) |
| D22 FMT-03.10 FMT-03.20 | `00 01 00` | parse as field 11 | `Unsupported` (no `$UUID`) |
| D23 FMT-03.10 FMT-03.22 | `00 01 00` | parse as field 12, then write the header | no entries; no field 12 written |
| D24 FMT-03.11 | M1 with the `$UUID` value (offset 16) set to `00 01 02 ... 0F` | parse | `Unsupported` |
| D25 FMT-03.11 FMT-03.20 | M1 with the `$UUID` value length set to 15 and one value byte removed | parse | `Unsupported` |
| D26 FMT-03.11 | M2 with the `$UUID` value set to `7C 02 BB 82 79 A7 4A C0 92 7D 11 4A 00 64 82 38` | parse | AES-KDF, same as D02 (reference: file opened, observed) |
| D27 FMT-03.11 FMT-03.12 | M1 with the `$UUID` entry removed; again with each of the `S`, `V`, `P`, `M`, `I` entries removed | parse | `Unsupported` each time (reference: rejected, observed for all six) |
| D28 FMT-03.12 | M1 with `P` (offset 78) = `00 00 00 00`; = `00 00 00 01` (2^24); = `FF FF FF 00` (2^24 − 1) | parse | `Unsupported`; `Unsupported`; accepted by this card (CRY-02 then judges the cost) |
| D29 FMT-03.12 | M1 with the `S` entry holding 7 bytes; again with 33 bytes (value length adjusted) | parse | `Unsupported` both times |
| D30 FMT-03.12 FMT-03.18 | M1 with `I` (offset 42) = `00 00 00 00 00 00 00 00`; = `FE FF FF 7F 00 00 00 00`; = `FF FF FF 7F 00 00 00 00`; = `02 00 00 00 01 00 00 00` (2^32 + 2); = `00 00 00 00 00 00 00 80` (2^63) | parse | `Unsupported`; accepted; `Unsupported`; `Unsupported` (reference opens it as 2 iterations, observed); `Unsupported` |
| D31 FMT-03.13 | M1 with `M` (offset 60) = `05 00 10 00 00 00 00 00` (1,048,581) | parse, then write | memory 1,024 KiB; written `M` = `00 00 10 00 00 00 00 00` |
| D32 FMT-03.12 FMT-03.13 | M1 with `M` = `FF 1F 00 00 00 00 00 00` (8,191); = `00 20 00 00 00 00 00 00` (8,192); = `00 00 00 00 00 04 00 00` (2^42) | parse | `Unsupported`; accepted by this card as 8 KiB, then CRY-02.10 rejects it with `Unsupported` because M1 has `P` = 4 (m = 8 < 8 × P = 32 KiB); `Unsupported`. Sub-case: 8,192 with `P` (offset 78) = `01 00 00 00` passes both this card and CRY-02.10 (reference: first and third rejected, observed) |
| D33 FMT-03.14 | M1 with `V` (offset 134) = `10 00 00 00` | parse | accepted; Argon2 version 1.0 is used for the key (installed reference: observed honoured) |
| D34 FMT-03.14 | M1 with `V` = `11 00 00 00`; = `12 00 00 00`; = `0F 00 00 00`; = `14 00 00 00` | parse | `Unsupported` each time (reference: 0x0F and 0x14 rejected, observed; 0x11 and 0x12 accepted) |
| D35 FMT-03.15 | M1 with `42 01 00 00 00 4B 06 00 00 00 73 65 63 72 65 74` (`K` = "secret") inserted at 138 | parse | `Unsupported` (reference: `K` ignored, file opened, observed) |
| D36 FMT-03.15 | M1 with `42 01 00 00 00 41 00 00 00 00` (`A` empty) inserted at 138 | parse | accepted; ignored |
| D37 FMT-03.16 | M2 with `R` (offset 42) = `00 00 00 00 00 00 00 00`; = `FF FF FF 7F 00 00 00 00`; = `00 00 00 80 00 00 00 00`; = `FE FF FF 7F 00 00 00 00` | parse | `Unsupported`; `Unsupported`; `Unsupported`; accepted (reference: the first three rejected, observed) |
| D38 FMT-03.16 | M2 with the `S` entry holding 16 bytes (value length `10 00 00 00`); again 7 bytes | parse | `Unsupported` both times (reference: 7 rejected; 16 accepted and zero rounds used, observed) |
| D39 FMT-03.16 FMT-03.18 | M2 with `R` = `40 42 0F 00 01 00 00 00` (2^32 + 1,000,000) | parse | `Unsupported` (reference: uses 1,000,000; observed with 2^32 + 15,000,000) |
| D40 FMT-03.17 | M1 with the `P` entry replaced by `05 01 00 00 00 50 08 00 00 00 04 00 00 00 00 00 00 00` (UInt64) | parse | accepted; parallelism 4 |
| D41 FMT-03.17 | M1 with the `I` entry replaced by `04 01 00 00 00 49 04 00 00 00 02 00 00 00` (UInt32); again by `0D 01 00 00 00 49 08 00 00 00 02 00 00 00 00 00 00 00` (Int64) | parse | accepted; iterations 2 both times |
| D42 FMT-03.17 | M1 with the `I` entry replaced by `0D 01 00 00 00 49 08 00 00 00 FF FF FF FF FF FF FF FF` (Int64 −1) | parse | `Unsupported` |
| D43 FMT-03.17 | M1 with the `V` entry replaced by `18 01 00 00 00 56 02 00 00 00 31 39` (String "19") | parse | `Unsupported` (reference: accepted, observed) |
| D44 FMT-03.17 FMT-03.20 | M1 with the `S` entry type changed from `42` to `18` (String); separately, the same with the `S` value replaced by 10 bytes of `42`, `00`, 21 bytes of `43` | parse | `Unsupported` both times. Reference, installed 2.7.11 (observed): the first gives an empty salt (the text stops at the first byte, `00`) and the generic KDF message; the second opens a demo vault derived with the 10-byte salt `42` × 10. Newer source: both are valid UTF-8 and are used whole, 32 bytes (source, check with Verify) |
| D44b FMT-03.17 | M1 with the `V` entry replaced by `42 01 00 00 00 56 02 00 00 00 31 39` (ByteArray "19"); again the `I` entry replaced by `08 01 00 00 00 49 01 00 00 00 01` (Bool true) | parse | `Unsupported` both times (reference: reads `V` = 0x13 and 1 iteration; source) |
| D45 FMT-03.19 FMT-03.21 | M1 with `04 01 00 00 00 58 04 00 00 00 07 00 00 00` (`X` = 7) inserted at 138 | parse, then write with the same settings | accepted; written map has M1's layout, no `X` (reference: `X` ignored on read, observed; unused keys dropped on save, observed for `K`) |
| D46 FMT-03.20 | M1 with `M` = `00 FC FF FF FF 03 00 00` (2^42 − 1,024 bytes) | open with a counting test double for the KDF | this card accepts it; CRY-02 refuses it or asks the user with the cost shown; the KDF was called 0 times before that |
| D47 FMT-03.22 | field 12 = `00 01 05 04 00 00 00 7A 65 74 61 08 00 00 00 05 00 00 00 00 00 00 00 04 05 00 00 00 41 6C 70 68 61 04 00 00 00 01 00 00 00 0D 04 00 00 00 62 65 74 61 08 00 00 00 FE FF FF FF FF FF FF FF 18 02 00 00 00 5F 78 00 00 00 00 00` | parse, then write | written field 12 = `00 01 04 05 00 00 00 41 6C 70 68 61 04 00 00 00 01 00 00 00 18 02 00 00 00 5F 78 00 00 00 00 0D 04 00 00 00 62 65 74 61 08 00 00 00 FE FF FF FF FF FF FF FF 05 04 00 00 00 7A 65 74 61 08 00 00 00 05 00 00 00 00 00 00 00 00` (the reference wrote exactly these bytes, observed) |
| D48 FMT-03.23 | field 12 = `00 01 42 10 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 55 55 49 44 10 00 00 00 A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF 00` | parse, then write | one ByteArray entry; written back byte for byte |
| D49 FMT-03.24 | H3demo (FMT-02) | parse | AES-KDF with the seed from field 5 (`AB BE ... 7B 81`) and 13,043,478 rounds from field 6; no map parsed |
| D50 FMT-03.23 FMT-03.22 | field 12 (100 bytes, unsorted) = `00 01 18 10 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 4E 41 4D 45 0A 00 00 00 44 65 6D 6F 20 76 61 75 6C 74 0C 10 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 49 43 4F 4E 04 00 00 00 05 00 00 00 18 11 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 43 4F 4C 4F 52 07 00 00 00 23 31 61 32 62 33 63 00` (name String `Demo vault`, icon Int32 5, colour String `#1a2b3c`) | parse, then write | three entries kept with their types; written field 12 (100 bytes) = `00 01 18 11 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 43 4F 4C 4F 52 07 00 00 00 23 31 61 32 62 33 63 0C 10 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 49 43 4F 4E 04 00 00 00 05 00 00 00 18 10 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 4E 41 4D 45 0A 00 00 00 44 65 6D 6F 20 76 61 75 6C 74 00` (the installed reference CLI wrote exactly these bytes on re-save, observed) |
| D51 FMT-03.21 FMT-03.14 | M1 with `V` (offset 134) = `10 00 00 00`, read; same settings written with the random source mocked to `00 01 ... 1F` | parse, then write field 11 | parse gives version 0x10; written map is exactly M1 (offset 134 = `13`, LD-17); the new key is derived with Argon2 version 1.3 (the reference writes back `10`, source) |
| D52 FMT-03.8 | field 12 = `00 01 08 01 00 00 00 42 01 00 00 00 02 00` (Bool `B` with byte `02`) | parse, then write | `B` is true; written back unchanged as `00 01 08 01 00 00 00 42 01 00 00 00 02 00` (the reference wrote `... 01 00`, observed) |
| D53 FMT-03.18 FMT-03.12 | M1 with the `P` entry replaced by `05 01 00 00 00 50 08 00 00 00 04 00 00 00 01 00 00 00` (UInt64 2^32 + 4) | parse | `Unsupported` (reference reads 4 lanes; observed in 2.7.11 with the same cut: `P` = 2^32 + 2 opened as 2 lanes) |
| D54 FMT-03.23 | field 12 (97 bytes) = `00 01 18 11 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 43 4F 4C 4F 52 09 00 00 00 23 31 61 32 62 33 63 3B 7D 18 10 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 49 43 4F 4E 01 00 00 00 35 18 10 00 00 00 4B 50 58 43 5F 50 55 42 4C 49 43 5F 4E 41 4D 45 08 00 00 00 3C 62 3E 78 3C 2F 62 3E 00` (colour String `#1a2b3c;}`, icon as String `5`, name String `<b>x</b>`) | header-only read (FMT-02.27), then open with the right key and save | before unlock: no colour used, no icon used (wrong type), name shown as the literal text `<b>x</b>`; the open does not fail; after save, field 12 is written back byte for byte |
| D55 FMT-03.21 | M1 with the `S` entry holding the 16 bytes `00 01 ... 0F` (value length `10 00 00 00`, map 123 bytes), read; written with the random source mocked to `00 01 ... 1F` | parse, then write field 11 | written map is exactly M1 (139 bytes, 32-byte salt) (the reference would write a fresh 16-byte salt and a 123-byte map; source) |
| D56 FMT-03.20 | M1 with the `$UUID` value (offset 16) set to `00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F` and `03 01 00 00 00 58 02 00 00 00 01 00` (an entry of unknown type `03`) inserted at 138 | parse as field 11 | `Corrupt` (structure is judged before the settings) |
| D57 FMT-03.20 FMT-03.2 | M2 with bytes 0 to 1 set to `00 02` and without its last byte (92 bytes, no terminator) | parse | `Unsupported` (the version is judged before the structure) |
| D58 FMT-03.23 | Larsal creates a public colour from the user's pick red 0x1A, green 0x2B, blue 0x3C | write field 12 | the value is the String `23 31 61 32 62 33 63` (`#1a2b3c`, lowercase), as in D50 |

## How this was learned

- Read in the reference source (development branch, commit 09e34ba8): the typed map reader and writer inside the version 4 header reader and save routine, the map version and type constants, the KDF key-name constants, the routine that builds a KDF from a map and its reverse, the AES-KDF and Argon2 classes (their range setters, how they read map values, how they write them), the AES-KDF primitive (an AES failure is caught but not reported to the caller), the database routine that adds the public id to public custom data, and the reference's version 4 tests (including its public custom data test with keys `CD1` to `CD4`, used for M3).
- Compared with the release tag of the installed version (2.7.11). Differences for this card: the Argon2 computation moved from the Argon2 reference library (which takes the version) to a general crypto library call that does not take the version (FMT-03.14); the public id in public custom data exists only in the newer source (FMT-03.23); the map writer's length width was pinned to 4 bytes in the newer source (no change in the bytes written).
- Ran the installed reference CLI (2.7.11) on demo vaults in a scratch folder: a scratch copy of the Format400 test vault re-saved with `db-edit` to password `demo` (Argon2d), and a vault made with `import` (AES-KDF, example 2). Each test map was put into the header, and the header was re-signed so the header HMAC stayed valid (composite key from the password, then Argon2 through a command-line crypto tool or AES-KDF as chained AES-256 block encryptions, then the HMAC key and header HMAC per FMT-04 and FMT-05). Opening then shows whether the reader accepted the map, and with which values: a header signed with a key from different parameters only passes if the reader computed exactly those parameters. Re-saves with `mkdir` showed the writer's order, types and normalisation.
- Review round 2, read in the source (dev commit and the 2.7.11 tag): the Argon2 write step stores the version as read, and its setter keeps 0x10 to 0x13 (FMT-03.21). A new salt or seed takes the length of the current one (FMT-03.21). `P` and `V` are read with an unsigned 32-bit conversion (FMT-03.18). The map writer encodes a Bool from its truth value (FMT-03.8). The database getters and setters for the public name, colour and icon, and their removal when cleared (FMT-03.23). The unlock screen opens the file with no key and then uses those three values, the colour inside a style rule (FMT-03.23). The version-choice routine raises the version to 4 when public custom data is not empty.
- Review round 2, observed with the installed CLI (2.7.11) in a scratch folder: field 12 was added to the AES-KDF demo vault of example 2, leaving field 11 unchanged. The transformed key was computed with the `openssl` tool (AES-256 rounds through CBC with a zero IV over zero blocks) and checked against the original header HMAC. The header SHA-256 and HMAC were then recomputed, so the file opened fully. A re-save with `mkdir` showed the written field 12: the three public keys came back sorted with the same types (D50), and a Bool byte `02` came back as `01` (D52).
- Review round 3, observed with the installed CLI (2.7.11) in a scratch folder: two scratch copies of the Argon2d demo vault (example 1, password `demo`), one with `P` stored as UInt64 2^32 + 2 and one with `V` stored as UInt64 2^32 + 0x13, each header re-signed with the unchanged transformed key (Argon2d computed with the `openssl` tool, first checked against the original header HMAC). Both listed with exit 0, so the reader used `P` = 2 and `V` = 0x13 (FMT-03.18). Read in the source: the KDF reader takes `S` through a byte-array conversion (a String gives its UTF-8 bytes), the numbers through integer conversions that also parse text and byte arrays and turn a Bool into 0 or 1, and does not read `K` or `A` (FMT-03.17). The public id getter adds the key and marks the vault changed when the key is absent; the unlock screen calls it in its quick-unlock availability check, its key lookup, its store after a successful unlock and its reset, and the key settings page calls it on reset (FMT-03.23).
- Closed by Verify in Sprint 2, observed with the installed CLI 2.7.11 on scratch demo vaults: how the reference changes names and String values that are not valid UTF-8 or hold `00` (FMT-03.7, through field 12); the reference writing back `V` = 0x10 and a short salt length on save (FMT-03.21: an Argon2d vault with `V` = 0x10 and a 16-byte salt, built with a re-encrypted payload, opened in the CLI and was re-saved with `mkdir`; the new file kept `V` = 0x10 and had a new 16-byte salt). Source, re-read by Verify: the newer source reads `I` as a 64-bit number and then passes it to the round setter, which takes a signed 32-bit number, so it cuts `I` to 32 bits as 2.7.11 does. Still marked check with Verify, because they need a build of the source on the newer toolkit generation, which is not on this Mac: whether the newer source cuts `R` to 32 bits (it reads `R` through the toolkit's 32-bit conversion), how it handles `00` bytes in names and String values, and an `S` given as a valid UTF-8 String being used whole, `00` bytes included (FMT-03.17). Larsal's own save rules for `V` and the salt length are decided (LD-15, LD-17) and do not depend on these checks.
- Sprint 1 close-out: observed with the installed CLI (2.7.11) on Argon2d demo vaults in a scratch folder (password `demo-pw`) with `S` stored as a String: 32 bytes of `41` opened; 10 bytes of `42`, `00`, 21 bytes of `43` opened when derived with the 10-byte salt and gave the wrong-key message when derived with all 32 bytes; the bytes `00` to `1F` gave the generic KDF message. Source reading: both versions convert the String value to text and back; the installed build uses an older UI toolkit whose conversion stops at a `00` byte, the newer source a toolkit version that keeps it. The public id row of FMT-03.23 now points to APP-04.8.
