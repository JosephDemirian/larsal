# E13-S2 attack group AT-A: vault file attacks (Red team proof)

Story: E13-S2 (attack campaign), group AT-A, rows AT-A01 to AT-A12 of plan/attacks-and-checks.md.
Date: 2026-10-29. Role: Red team (reference CLI run read-only, with a throwaway home folder under /tmp; nothing from the reference was copied into this folder).

Result: **all 12 rows passed on today's tree. No new finding.** Four notes (N1 to N4 at the end) for the lead; none is a defect against a row or a card.

Earlier proof (history only, every attack was re-run here): E3-S10-E3-S11-fuzz.md (AT-A10, AT-A11), E4-S13-import-export.md, E5-S10-saving.md, E12-S1-command-line.md.

## Setup

- Larsal's tool: `larsal` release build of today's tree, `CARGO_TARGET_DIR=/tmp/e13s2-target`, `cargo build --release -p larsal-cli` (up to date at 20:35).
- `larsal-format` test suite: `cargo test -p larsal-format --no-fail-fast` on today's tree, same target folder.
- Hostile files: a throwaway probe crate in `/tmp/e13s2-AT-A/probe` (own target folder) that includes the project's test builder `crates/larsal-format/tests/format_common/mod.rs` by path (our own code, read only) and writes demo vaults: any XML document, any raw plaintext, any KDF map, under a valid encryption with password `demo-pass`, a demo key file and a demo HMAC secret. Every attack then goes to the `larsal` tool as a black box (`export`, `db-info`, `ls`, `mkdir`), password on stdin. One extra probe command (`trunc`) opens in process through `larsal_format::open` with the test host.
- Demo data only: `testdata/` vaults and key files (copied to /tmp), vaults made by the probe or by `larsal` itself under /tmp.
- Reference CLI (`REF_CLI`, version 2.7.11): AT-A11 and AT-A12 only, `HOME=/tmp/e13s2-AT-A/refhome`, `PATH=/usr/bin:/bin`.
- No window, no pasteboard, no keychain, no ssh-agent. Only processes this agent started; all ended on their own or by the harness timeout of the child it started.
- Machine load was very high during the run (load average 140 to 400 on 14 cores: other agents' builds). Wall times below are inflated by that; CPU times are the honest cost.
- Files changed in this folder: this file. `fuzz/Cargo.lock` gained one line (`"larsal-platform"` under `larsal-core`) when `cargo fuzz build` ran; that follows another agent's change to `crates/larsal-core/Cargo.toml` (20:46) and any fuzz build adds it (N3).

`larsal-format` suite, today: every test binary `ok`, 0 failed (attacks 13, header 78, keyfile 154, keys 40, open 68, version3 51, document_read 114, redteam_s2 8, testdata 4, write_* 268, property 1, unit 24; ignored ones are the long or helper tests). `real 440.83 user 208.69 sys 25.04` (build included).

## AT-A01 Wrong credentials

Method: every combination of right, wrong and missing password and key file, on a reference-made 3.1 vault (`password-and-keyfile`, `demo-pass-2` + `key-hex64`), a probe 4.1 vault (password + raw 32-byte key file), and probe 4.1 and 3.1 vaults that also need a hardware key (HMAC secret); plus a key file given to a password-only vault, an empty password, a wrong key file alone. Command per case: `larsal export -q [--key-file K] [--no-password] VAULT`.

Output (`/tmp/e13s2-AT-A/logs/a01.log`, 40 cases):
```
right pw + right kf | password-and-keyfile.larsalvault | accept | 4003 | ...
right pw + wrong kf | password-and-keyfile.larsalvault | reject | 0 | larsal: Wrong password, key file or security key. Check them and try again.
...
right pw + right kf | hw-v4.larsalvault | reject | 0 | larsal: Wrong password, key file or security key. ...   (hardware part missing)
right pw + right kf | hw-v3.larsalvault | reject | 0 | larsal: Wrong password, key file or security key. ...
right pw + right kf + --hw-key 1 | ... | reject | 0 | larsal: Your security key is not connected. Plug it in, then try again.
distinct wrong-case messages: 1
```
- Every wrong or missing part, alone and combined, on version 3 and 4, with and without a hardware part: exit 1, stdout empty, the one wrong-key message. Only the two controls open.
- "Nothing is decrypted": `attacks::at_a01_wrong_credentials` (all 26 wrong combinations of password, key file and software hardware key on v4 and v3: `WrongKey`, 0 inflate) and `at_a01_version_4_wrong_password_decrypts_nothing` (0 decrypt) pass today.
- `--hw-key` in the tool answers "not connected" (the tool has no security key support yet, M06-17, E10); a test with a real key needs the owner's hardware: needs Mac QA (owner's go).

Result: **passed.**

## AT-A02 Header tampering

Method: copy the file, XOR one header byte, run `larsal export -q`, for every byte of the outer header (version 4: also the 32-byte SHA-256 and the 32-byte HMAC after it). Three sweeps through the tool; plus the in-process sweeps of the suite.

| File | Bytes | Flip | Files | Results |
|---|---|---|---|---|
| `default-time` (reference-made 3.1, 1,000,000 AES-KDF rounds) | 0 to 221 | XOR FF | 222 | 116 wrong key, 67 damaged, 31 not supported, 8 not a vault (bytes 0 to 7) |
| `default-time` | 0 to 221 | XOR 01 | 222 | 118 wrong key, 68 damaged, 28 not supported, 8 not a vault |
| `option-a-personal` (4.1, Argon2id) | 0 to 386 | XOR FF | 387 | 264 damaged, 66 not supported, 32 wrong key (the HMAC bytes), 17 "holds more than Larsal can open safely", 8 not a vault |

- 831 files: 831 rejected, 0 opened, stdout empty in every case, 0 panics, exit 1 only (`logs/a02-v3ff.log`, `a02-v3x01.log`, `a02-v4ff.log`).
- Version 3 has no header check before decryption, so flips in the seeds, IV and start bytes give the wrong-key message; the document's HeaderHash catches the rest (FMT-17.19).
- The 17 "holds more than" cases are flipped header field lengths that would end past the 1 MiB header limit: TooLarge before Corrupt, as FMT-01.22 and FMT-02.25 decide.
- In process, passed today: `at_a02_version_4_header_byte_sweep`, `at_a02_rich_v4_header_byte_sweep` (reference-made 4.1, XOR 01 on every byte up to the HMAC: no KDF ran), `at_a02_version_3_header_byte_sweep`.

Result: **passed.**

## AT-A03 Payload tampering

Method, version 4: `multi-v4.larsalvault` made by `larsal attachment-import` of 2.6 MB random bytes into a copy of `option-a-personal`: 3 data blocks (1,048,576 + 1,048,576 + 514,768 bytes) and the final block. Flips (XOR 01, 80, FF) in every block's HMAC (first and last byte), size field (low and high byte), first and last data byte and 6 random data bytes; swap blocks 0 and 1, 1 and 2; repeat block 0, repeat the last data block; cut block 0, cut the middle block, cut the final block, cut one byte more, cut in the middle of block 1; final block moved first; data blocks replaced by the final block. Then appends after the final block.

```
v4 tampered: 131 files
    131  reject  larsal: VAULT is damaged and cannot be unlocked. If you have a backup copy, open that instead.
v4 appended after final block (LD-01 ignores trailing bytes): 3 files
      3  accept  same content
```

Method, version 3: a probe 3.1 vault whose plaintext is built by hand (start bytes, 8 hashed blocks of 512 bytes, final block), each variant encrypted under the right key: hashed blocks swapped (indexes kept, or renumbered with valid hashes), repeated, cut (both ways), final block cut, final block first, final block with a wrong index, a block appended after the final one. On the ciphertext: flips in 45 cipher blocks (first run) and in the first 3 and last 2 cipher blocks (re-check), two 16-byte cipher blocks swapped (neighbours, and 10 with 60), one repeated, one deleted, the last one cut, 16 and 4,096 bytes appended.

```
first run, 108 files: 100 damaged, 4 wrong key (flips in cipher blocks 0 and 1, the start bytes), 4 opened
re-check (time values masked in the compare), 28 files:
     20  reject  larsal: VAULT is damaged ...
      4  accept  same content     (control, block after the final one, 16 and 4,096 bytes appended)
      4  reject  larsal: Wrong password, key file or security key. ...
```

- Every cut, swap, repeat and flip inside the checked data: rejected as damaged (or wrong key where the start bytes are hit), stdout empty: no partial data.
- Bytes after the final block open with exactly the original content and are never read as content: the decided behaviour (LD-01, FMT-06.12, FMT-07.11; "cuts and swaps inside the block stream still fail").
- The first run compared exports byte for byte and called all 4 openings "different": the probe's document has no time values, so each open fills in the current time. Masking the time values (re-check) shows the same content. Not a fault.
- In process, passed today: `at_a03_version_4_payload` (every byte of a 512-byte-block file flipped, swap, repeat, drop, cut final) and `at_a03_version_3_payload`.

Result: **passed.**

## AT-A04 Truncation

Method: cut each file at every 1 KB step (0, 1024, 2048, ...).
- In process (`probe trunc FILE PASSWORD 1024`, through `larsal_format::open`, panics caught):
```
multi-v4.larsalvault: 2612451 bytes, full file: ACCEPTED   2551 Corrupt, 1 NotAVault (cut 0)
big-v3.larsalvault: 457934 bytes (probe 3.1, 1,000 rounds)  447 Corrupt, 1 NotAVault
rich-v4.larsalvault  4 Corrupt, 1 NotAVault      rich-v3.larsalvault  3 Corrupt, 1 NotAVault
option-a-personal  9 Corrupt, 1 NotAVault     default-time  1 Corrupt, 1 NotAVault
```
- Through the tool (`larsal export -q`): every 1 KB step of rich-v4, rich-v3, option-a-personal, default-time, password-only; multi-v4 at every 1 KB to 16 KB, every 64 KB after, and 36 and 1 bytes before the end: 82 cuts, 82 rejected (cut 0 "not a vault file", all others "damaged"), stdout empty.
- In process, passed today: `at_a04_truncation`, `at_a04_rich_v4_truncation`.

Result: **passed.** 3,103 cuts, 0 accepted, 0 panics.

## AT-A05 KDF cost bomb

Method: probe version 4 files with a valid header SHA-256 and the KDF map under test (`probe hdr --kdf ...`); version 3: the rounds field of `default-time` patched. Each run under `/usr/bin/time -l larsal export -q` (`logs/a05.log`):

| Settings | Time, peak memory | Larsal says |
|---|---|---|
| Argon2id M = 4 TiB; I = 2^63; P = 2^24 (M 8 MiB or 128 GiB); all three together; Argon2d M = 4 TiB; Argon2d I = 2^63; Argon2id I = 2^32; P = 2^24 - 1 | 0.00 to 0.01 s, 9 MiB | "This vault uses a file version or setting that Larsal does not support yet..." (out of the format's range) |
| AES-KDF R = 2^63, 2^64 - 1 (version 4); R = 2^63, 2^64 - 1, 2^31 (version 3) | 0.00 to 0.01 s, 9 MiB | same |
| Argon2id I = 1,000,000,001; M = (2^32 - 1) KiB; M = 49 GiB (this Mac has 48 GiB) | 0.01 s, 9 MiB | "This vault's unlock settings ask for more than this Mac can do..." |
| Argon2id M = 40 GiB, I = 1 | 0.26 s CPU, 73 MiB | "unlocking VAULT needs about 40.0 GiB of memory and about 3 minutes on this Mac. Nothing was done. Run the command again with --allow-slow-unlock to go ahead." |
| Argon2id P = 129 | 0.14 s CPU, 73 MiB | "... about 8 MiB of memory and about 0.0 seconds on this Mac and 129 parallel lanes. Nothing was done. ..." |
| AES-KDF R = 2^31 - 2 (version 4 and version 3) | 0.06 and 0.03 s CPU, 9 MiB | "unlocking VAULT needs about 56 seconds / 19 seconds on this Mac. Nothing was done. ..." |

- Every bomb is refused before any key work (9 MiB peak, no time), or the user is asked with the memory, time and lanes shown and nothing is done. The only work before asking is the bounded speed check (CRY-02.14; at most 0.26 s CPU, 73 MiB).
- `--allow-slow-unlock` was not run on the ask cases: that is the user's choice after seeing the cost.
- In process, passed today: `at_a05_kdf_cost_bomb` (no KDF ran for any of them).

Result: **passed.**

## AT-A06 Decompression bomb

Method: probe vaults whose gzip payload is the inner header, then repeated byte-aligned deflate blocks, valid CRC and size (`probe stream`), under valid encryption. `/usr/bin/time -l larsal export -q`:

| File | Size | Inflates to | CPU | Peak memory | Larsal says |
|---|---|---|---|---|---|
| bomb8g-zero-v4 | 8.5 MB | 8 GiB of 00 | 0.19 s | 50 MiB | "holds more than Larsal can open safely ..." |
| bomb8g-space-v4 | 8.5 MB | XML start, 8 GiB of spaces, end | 0.21 s | 50 MiB | same |
| bomb8g-zero-v3 | 8.5 MB | 8 GiB of 00 (version 3, hashed blocks) | 0.37 s | 58 MiB | same |
| bomb1100m-v4 | 1.1 MB | 1,100 MiB of `A` inside a name | 0.23 s | 15 MiB | same |

- Stopped at the 1 GiB `total` limit; memory flat (no output buffer before the member is counted). stdout empty.
- In process, passed today: `at_a06_decompression_bomb_lowered_limit`, `at_a06_decompression_bomb_default_limit`.

Result: **passed.**

## AT-A07 XML attacks

Method: probe version 4 vaults (valid encryption, password `demo-pass`) around hostile documents; `/usr/bin/time -l larsal export -q` (`logs/a07.log`).

| Document | Larsal | Peak memory |
|---|---|---|
| DOCTYPE | damaged | 10 MiB |
| entity expansion (9 levels of 10, "billion laughs"), used in the database name | damaged | 10 MiB |
| external entity `SYSTEM "file:///etc/hosts"`; external DTD file under /tmp holding an entity | damaged; the text of neither file appears | 10 MiB |
| reference to an undeclared entity | damaged | 10 MiB |
| 100,000 nested unknown elements in Meta; 100,000 nested groups; 100,000 unclosed elements | "holds more than Larsal can open safely" (depth limit) | 11 to 12 MiB |
| 1,024 MiB text node (1.0 MB file) | "holds more than" (`total`) | 15 MiB |
| 1,000 MiB text node | "holds more than" (`document`) | 1,013 MiB (N2) |
| 600 MiB text node | "holds more than" (`document`) | 612 MiB (N2) |
| 100 MiB text node | "holds more than" (`text`) | 110 MiB |
| 60 MiB text node (under every limit) | opens, 63 MB exported | 226 MiB |
| predefined entities and character references only; CDATA and a processing instruction in a value; a second document after the root's end tag | open | 14 MiB |

- DTDs and entities are refused before any entity work (FMT-10.9, FMT-11.42); nothing outside the vault is read. The two openings are valid XML or trailing content that FMT-10.5 and FMT-11.5 say to ignore, as the reference does.

Result: **passed.**

## AT-A08 Hostile document inside valid encryption

Method: 48 probe version 4 vaults (password `demo-pass`). For each: `larsal export`; when it opens also `larsal db-info`, a save (`larsal mkdir` on a copy) and a re-open (`logs/a08.log`, `a08b.log`).

- Refused with a clear message, no crash:
  - damaged: no root group, no Root, two root groups, a String without Key or Value, two values for one key, a History inside a History item, a bad time value, a bad compressed Meta binary;
  - damaged, groups inside themselves (FMT-11.36): self-nesting, the root's id inside the root, cross-nested duplicates, a chain of 3, self-nesting 400 levels down. All in under 0.2 s CPU, no hang;
  - "holds more than Larsal can open safely": 1,000,001 entries (peak 1,109 MiB), 1,000,001 groups (589 MiB), 100,001 history items (166 MiB), 100,001 fields in one entry (42 MiB), 1,000,001 deleted objects (216 MiB), 100,001 custom data items (48 MiB).
- Opened, read leniently as the cards say, then saved and re-opened without error: duplicate entry ids and duplicate group ids (merged, FMT-11.35), an entry id equal to a group id or the root id (FMT-11.33), duplicate ids across history, a history item with another id, recycle bin pointing at an entry or the root, a missing templates group, previous parent pointing at itself or a child, a top-visible reference to a group id, a missing Meta, an entry or group without id, ids of 15 bytes, all zero or bad base64 (new ids, FMT-11.34), a negative usage count, attachment refs missing, negative, text, 2^32 and empty (FMT-13.11, 0 bytes), two attachments with one name (renamed, FMT-13.13), a bad custom icon ref (kept, FMT-11.38), a deleted object naming a live entry, 2,000,000 tags (219 MiB).
- 0 crashes, 0 panics, exit codes 0 and 1 only, every save and re-open exit 0.

Result: **passed.**

## AT-A09 Downgrade

Method: open, save with `larsal mkdir -q FILE "A09 saved"`, read the header before and after (`logs/a09.log`); every saved file re-opened with its password (`larsal ls`).

| File | Before | After the save |
|---|---|---|
| probe file stamped 2.0 (version 3 layout) | 2.0, AES-256, AES-KDF 1,000 | 4.0, AES-256, AES-KDF 1,000 |
| probe 3.0; probe 3.4 | 3.0 / 3.4, AES-256, AES-KDF 1,000 | 4.0, same cipher and rounds |
| probe 3.1 Twofish; probe 3.1 without gzip | 3.1 | 4.0, Twofish kept; gzip 0 kept |
| reference-made default-time; rich-v3 | 3.1, AES-KDF 1,000,000 / 13,043,478 | 4.0, same rounds |
| probe 4.1, AES-KDF 1 round | 4.1, R = 1 | 4.0, R = 1 |
| probe 4.1, Argon2id / Argon2d 8 KiB, 1 iteration, 1 lane | 4.1 | 4.0, same settings |
| probe 4.0 ChaCha20; 4.0 Twofish | 4.0 | 4.0, cipher kept |
| probe file stamped 4.0 whose content needs 4.1 (group tags) | 4.0 | 4.1 |
| rich-v4; option-a-personal; option-a-work | 4.1; 4.1; 4.0 | 4.1 (13,043,478 rounds); 4.1 (Argon2id 1 MiB, 2, 1); 4.0 |

- No save lowered the cipher or the key derivation; weak settings are kept as they were (the row allows "keeps"), version 2 and 3 files are raised to version 4, and a file whose content needs 4.1 is raised to 4.1.
- 4.1 files without 4.1 content are written as 4.0: the version comes from the content (FMT-16), 4.0 and 4.1 have the same crypto, so this is no lower security level.
- In the suite, passed today: `write_version` (32 tests).

Result: **passed.**

## AT-A10 Fuzzing (smoke only)

The 24-hour runs per target are E13-S3 and wait for the owner (OD-05). Smoke here: `cargo +nightly fuzz build --target-dir /tmp/e13s2-target` (all 22 targets), then each binary once on its seed folder `fuzz/corpus/<target>` (read only), new units and artifacts under `/tmp/e13s2-AT-A/fuzz`, `-timeout=10`. The six vault file parsers 60 s each, the other 16 targets 20 s each, four at a time.

| Target | Seconds | Units | Slowest | Peak RSS | Error lines |
|---|---|---|---|---|---|
| vault_open | 60 | 15,912 | 0 s | 370 MB | 0 |
| vault_header | 60 | 227,277 | 0 s | 197 MB | 0 |
| key_file | 60 | 100,518 | 0 s | 407 MB | 0 |
| kdf_map | 60 | 218,048 | 0 s | 196 MB | 0 |
| document | 60 | 36,522 | 0 s | 274 MB | 0 |
| inner_header | 60 | 34,597 | 0 s | 399 MB | 0 |
| references, icon_decode, search_query, totp_link, word_list, breach_lines, csv_import, json_import, onepux_import, opvault_import, v1_import, autotype_sequence, autotype_match, ssh_key_read, ssh_settings_read | 20 each | 81 to 31,883 | 0 s | 63 to 497 MB | 0 |
| strength_estimate | 20 | 308 | 10 s (wall) | 161 MB | 0 crash, 1 slow-unit file (N1) |

- 22 targets, exit 0 each, 0 crashes, 0 timeouts (the 10 s limit never fired), memory under the 2,048 MB default limit everywhere.
- The first build failed in `larsal-core` (`larsal_platform` not found in `storage.rs`) while another agent was changing `crates/larsal-core/Cargo.toml` (20:46) and `storage.rs` (20:55). Built again a few minutes later: `Finished`, no error. A half-done edit, not a fault (N3).

Result: **passed (smoke).** Units per target are low because each fuzzer got about a quarter of a core under the load average of 200 or more.

## AT-A11 Differential fuzzing

Method: 420 files from 5 seeds that both readers open with the same content (reference-made default-time 3.1 and rich-v4 4.1; Larsal-made option-a-personal 4.1 Argon2id; Larsal-saved 4.0 ChaCha20 and 4.0 Twofish from AT-A09). Per seed 50 to 120 random mutations (fixed random seed 20261029: 1 to 4 bit flips, 1 to 4 bytes set, truncation, delete or insert 1 to 64 bytes, a splice from another seed, a repeated chunk; 40 % in the first 350 bytes, 20 % in the last 128, 40 % anywhere), plus 3 end cuts and 3 appends. Each file to `larsal export -q` (30 s limit) and to `REF_CLI export -q -f xml` (10 s limit). Content compare: database name, every group (id, name), every live entry (id, every field name and value). A cost guard keeps files with Argon2 memory over 512 MiB, more than 100 iterations or 64 lanes, or more than 30,000,000 AES-KDF rounds away from the reference.

```
files: 420
   388  app rejects  ref rejects  same=None
    27  app opens    ref opens    same=True
     5  app rejects  ref skipped  same=None
app crashes: 0
```

- 415 compared files: 415 pass (both reject, or both open with the same content), 0 differences, 0 files kept. The 5 guarded files (mutated KDF settings) were rejected by Larsal, exit 1, no output.
- The known differences of the row (LD-84, FMT-02.20, FMT-09.15) were not hit by these mutations; the E3-S10 run keeps its two files in `fuzz/target/differential/`.

Result: **passed.**

## AT-A12 Key file attacks

Method: `larsal export -q --no-password -k KEY keyfile-xml-v2.larsalvault` under `/usr/bin/time -l` for each key file; the same regular files also to `REF_CLI export -q -f xml --no-password -k KEY` for the outcome (`logs/a12.log`).

| Key file | Larsal | Reference |
|---|---|---|
| 1 GiB file (sparse, zeros) | wrong-key message, 3.2 s wall, 9 MiB peak | rejects |
| version 2 with check value `00000000`; data of 31 or 33 bytes; no Hash attribute; an undefined entity in the data | "The key file ... is damaged: its built-in check failed. Use a backup copy of the key file." | rejects |
| version 2 with a bad hex digit; version 1 with bad base64 | "... is damaged: Larsal cannot read the key in it. ..." | rejects |
| version 3.0 | "... has version 3.0, which Larsal cannot read. ..." | rejects |
| DOCTYPE with an external entity | "Larsal does not accept the key file ... because it declares a document type. ..." (LD-30) | opens |
| 300 nested elements; 2,000 attributes on Data; 2 MiB of data text | "... is too complex for Larsal to read safely. ..." (LD-83, D-18-3) | opens, opens, rejects |
| half a document; invalid UTF-8; 64 non-hex characters; 32 wrong raw bytes; version 1 of 31 bytes | read as a hashed or raw key, then the wrong-key message | rejects |
| empty file | "The key file ... is empty. ..." | rejects |
| a folder; a FIFO; /dev/zero | "... is a folder or a special file. ..." in 0.00 s (no read, no block) | not run |
| a link to the vault itself | "This is the vault file itself, so it cannot also be its key file. ..." | not run |
| right key file, UTF-16 with BOM; two Data elements | opens | opens |

- Every case: exit 0 or 1, no crash, at most 17 MiB, a clear message naming the key file. Larsal is stricter than the reference only where LD-30 and LD-83 decide it.
- In process, passed today: `at_a12_key_file_attacks` and the 154 tests of `tests/keyfile.rs` (`fmt_18_5_b` hashes 1 GiB with flat memory).

Result: **passed.**

## CPU used (owner's rule: at most 30 minutes for the group)

| Run | CPU (user + sys) |
|---|---|
| `larsal-format` test suite, build and run | 234 s |
| probe crate builds (4) | about 94 s |
| fuzz builds (failed one 139 s, good one 74 s) | 213 s |
| fuzz smoke runs, 22 targets, and the slow-unit re-run | 129 s |
| AT-A01 to AT-A09, AT-A12 runs and file making | about 197 s |
| AT-A11 differential, 420 files, both readers | 76 s |
| **total** | **about 943 s (15.7 min)** |

## Findings

None. No row failed; nothing to file in `security/findings.md`.

Notes for the lead (not defects):

- **N1 (AT-A10, strength_estimate).** libFuzzer wrote one `slow-unit` file (slowest unit 10 s wall). Run alone twice: 3.8 s CPU (`Executed ... in 13827 ms`, `user 3.89`; then `8982 ms`, `user 3.81`) at a load average of 212, so the wall time is the machine, not a hang. The target's own notes give 3.2 to 3.7 s for its slowest seed under the sanitizer, and its guard is 30 s. Worth a look in the E13-S3 long runs on a quiet Mac. Not an AT-A parser.
- **N2 (AT-A07).** A text node just under the 1 GiB `total` limit (1,000 MiB, from a 1.0 MB file) is decompressed in full before the 512 MiB `document` limit refuses it: about 1 GB peak, for a moment. That is inside the ceilings already accepted (LD-22, LD-85, LD-89, LD-90; F-041's 3.2 GiB bound). A text of 1,024 MiB or more stops at 15 MiB.
- **N3 (tree state).** The fuzz build broke for a few minutes while another agent changed `larsal-core` (the `larsal-platform` dependency for F-047), then built cleanly. `fuzz/Cargo.lock` now lists `larsal-platform` under `larsal-core`; that is cargo's sync for the new dependency, not reverted.
- **N4 (AT-A05 wording).** Settings outside the format's range (4 TiB, 2^63 iterations, 2^24 lanes, AES-KDF rounds of 2^31 or more) get the "not supported yet. A Larsal update may open it." text, because FMT-03 makes them Unsupported. Correct per the card; the KDF cost text ("ask for more than this Mac can do") would say more to a user. Wording only.

Scratch files, scripts and logs were in `/tmp/e13s2-AT-A` and were deleted at the end; the shared `/tmp/e13s2-target` was left for the other red team agents.
