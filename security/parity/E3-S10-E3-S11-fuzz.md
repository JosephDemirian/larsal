# E3-S10 and E3-S11 Fuzzing, differential fuzzing, property tests: Verify proof

Stories: E3-S10 Fuzzing and differential fuzzing (AT-A10, AT-A11), E3-S11 Property tests.
Date: 2026-10-27.
Role: Verify (reference access allowed, read only; nothing from the reference was copied into this folder).
Result: **E3-S10 signed. E3-S11 signed.** AT-A10 stands on the recorded runs the owner accepted (OD-05): 13 targets, 0 crashes, 0 slow units, no crash files. AT-A11: 3,655 files, every one rejected by both readers or opened by both with the same content, except two files whose difference is already written in the cards as intended (FMT-02.20 and FMT-09.15). E3-S11: 10,000 random vaults round-trip in release, 43.38 s.

## Setup

- Reference: the installed app 2.7.11 and its command line tool, run with a throwaway home folder `/tmp/verify-diff/home`; the reference source at 09e34ba8 (read only). The reference app's window was not started and its settings folder was not read.
- Larsal's reader: a throwaway probe crate in `/tmp/verify-diff/probe/` (release build, its own target folder, the project's `Cargo.lock`) that depends on `larsal-format`, `larsal-core` and `larsal-crypto` by path. It calls `larsal_format::open` with the password and key file, and on success writes the vault with Larsal's XML export (`export::xml::xml`). When Larsal asks about the key derivation cost (CRY-02.14), the probe answers yes only if the reference finished the same file (so Larsal runs the same work); `larsal-cli` has no open command yet.
- Harness scripts, seeds, mutants and results stay in `/tmp/verify-diff/` (they name the reference). No product code, test or fuzz target was changed. Files changed in this folder: this file, `plan/epics.md` (status lines), and `fuzz/target/differential/` (the two kept files and their index).
- Before the runs: an orphaned test process from an old throwaway check (`/tmp/chk-e3doc/…/fea01-…`, parent process 1, 31 h 35 min at 100 % of one core) was stopped. It broke the owner's CPU rule and would have skewed the timings.

## 1. AT-A10 (E3-S10): recorded fuzz runs

The owner stopped the runs on 2026-10-27 at 04:20 and accepted the stats as proof for now (OD-05). Read from `fuzz/target/logs/*-24h.log` (all 13 logs last written 04:19:03):

| Target | Units run | Slowest unit | Peak RSS | Error lines | End |
|---|---|---|---|---|---|
| breach_lines | 1,679,443,817 | 0 s | 541 MB | 0 | run interrupted |
| document | 76,407,575 | 0 s | 536 MB | 0 | run interrupted |
| icon_decode | 120,403,756 | 0 s | 538 MB | 0 | run interrupted |
| inner_header | 102,891,283 | 0 s | 430 MB | 0 | run interrupted |
| kdf_map | 2,003,277,280 | 0 s | 525 MB | 0 | run interrupted |
| key_file | 193,797,667 | 0 s | 551 MB | 0 | run interrupted |
| references | 1,359,158 | 0 s | 3,074 MB | 0 | run interrupted |
| search_query | 10,938,549 | 0 s | 912 MB | 0 | run interrupted |
| strength_estimate | 934,865 | 0 s | 738 MB | 0 | run interrupted |
| totp_link | 561,902,477 | 0 s | 586 MB | 0 | run interrupted |
| vault_header | 3,930,938,738 | 0 s | 520 MB | 0 | run interrupted |
| vault_open | 54,905,771 | 0 s | 966 MB | 0 | run interrupted |
| word_list | 1,119,020,773 | 0 s | 578 MB | 0 | run interrupted |

- "Error lines" counts `ERROR:`, `SUMMARY:`, `deadly signal`, `Test unit written`, `ALARM`, `timeout after`, `out-of-memory`, and `crash-`/`leak-`/`oom-`/`slow-unit` names: 0 in every log. Each log ends with the fuzzer's own "run interrupted" line and exit status 72, which is the stop, not a fault.
- `references` ran with `-rss_limit_mb=8192 -malloc_limit_mb=2560` (its command line in the log; the reason is in the E3-S10 status: the sanitizer keeps freed memory); 3,074 MB is under that limit and no allocation hit the 2,560 MB cap. Every other target stayed under 1 GB.
- Crash files: `find fuzz/artifacts fuzz/target/artifacts -type f` finds 0 files (the logs show both folders as artifact prefixes; every per-target folder is empty).
- Not covered by these runs: the five import targets added in E4-S13 (`csv_import`, `json_import`, `onepux_import`, `opvault_import`, `v1_import`) ran only in the check.sh smoke. The full 24 hours per target, all 18, is E13-S3 (OD-05).

## 2. AT-A11 (E3-S10): differential fuzzing

### Seeds

| Seeds | Made by | Format | Cipher, key derivation | Credentials |
|---|---|---|---|---|
| 6 | the reference CLI now: `import -p` of its own XML export of `testdata/rich-v3` and `rich-v4` (with and without a key file), and `db-create -p` plus `add` and `mkdir` | 3 × 3.1, 3 × 4.1 | AES-256, AES-KDF 1,000,000 rounds | password `demo-pass`; password plus `key-hex64` (3.1) and `key-binary32` (4.1); `key-xml-v2` only (4.1) |
| 2 | the reference's own test vaults (demo data) | 3.0; 4.0 | AES-256 AES-KDF; ChaCha20 Argon2d (1 MiB, 2 iterations, 2 lanes) | their test passwords |
| 20 | the `vault_open` seed files (whole files only, `fuzz/corpus/vault_open/seed-*-v3-*`, `-v4-*`) | 3.1, 4.0, 4.1; gzip and none | AES-256, ChaCha20, Twofish; AES-KDF 100 rounds | `demo-pass` |

The reference CLI cannot pick the cipher, the key derivation or the version (its `db-create`, `import` and `db-edit` help list only password, key file, decryption time and hardware key options; `-t` must be 100 to 5,000 ms). It writes 3.1 unless the content needs 4.x fields. So ChaCha20, Twofish and Argon2 come from the reference's test vault and the fuzz seeds.

Before mutating, all 28 seeds were opened by both: same content in every one (both the narrow and the broad comparison below).

### Mutated files

3,655 files, made by `/tmp/verify-diff/scripts/mutate.py` (fixed random seed 20261027):

- 150 per reference-made seed and 50 per fuzz seed, one operation each: 1 to 4 bit flips, 1 to 4 bytes set to 00/FF/7F/80/01/random, truncation, deleting or inserting 1 to 64 bytes, a 4 to 256 byte splice from another seed, a repeated chunk. Positions: 40 % in the first 350 bytes (header), 20 % in the last 128 bytes, 40 % anywhere.
- Per seed: the last k bytes cut off for 6 random k from 1 to 64, and 1, 16 and 300 random bytes appended.
- All 1,203 whole-file units (first byte below 0x80) the fuzzer kept in `fuzz/target/corpus/vault_open`, with `demo-pass`.

### Run

`python3 -I /tmp/verify-diff/scripts/run.py`: 4 jobs. Each file goes to the reference CLI (`export -f xml`, password on stdin, `-k` and `--no-password` as needed, 10 s limit) and to Larsal's probe (30 s limit). Pass: both reject, or both open with the same content. A guard kept files with extreme key derivation settings away from the reference (Argon2 memory over 512 MiB could fill this Mac's memory); it skipped 141 files in the first pass. Those 141 were run again through the reference with only the memory guard (`GUARD=mem REF_TIMEOUT=5`): the reference rejected every one within 1 s, and none needed more than 512 MiB. Final numbers are after that run.

Content comparison, two levels:
- Narrow (in the run): database name, every group (path, UUID), every entry (UUID, all string fields with values, tags, attachment names, history string fields).
- Broad (`/tmp/verify-diff/scripts/accept2.py`, every file both opened): the whole `Root` tree and `Meta` element by element, both versions' time forms turned into one form, without only what an export rewrites (`Generator`, the save-time and random custom data items, `SettingsChanged`, header hash) and attachment pool references (the reference's 4.x export has no pool, FEA-09.14).

### Result

| Source | Files | Both reject | Both open, same content | Differ |
|---|---|---|---|---|
| reference CLI seeds | 954 | 931 | 23 | 0 |
| reference test vaults | 318 | 310 | 8 | 0 |
| fuzz seeds | 1,180 | 1,111 | 68 | 1 |
| fuzzer units | 1,203 | 1,198 | 4 | 1 |
| **all** | **3,655** | **3,550** | **103** | **2** |

- Larsal: 0 panics, 0 timeouts, 0 cost questions left open. Larsal's reject kinds: Corrupt 2,407, Unsupported 660, WrongKey 224, TooLarge 138, NotAVault 121, OldFormat 1.
- Reference: 0 timeouts after the second pass. Its most common messages: the key derivation settings are unsupported or invalid, header SHA-256 mismatch, invalid inner header id size, no root group.
- Files both opened: 84 with appended bytes (FMT-06.12, LD-01), 15 with a repeated chunk past the end, 4 fuzzer units. Broad comparison: 103 of 104 identical.
- By operation, all passed except one bit flip and one fuzzer unit: flips 539, set 252, truncation 281, cut end 168, delete 268, insert 315, splice 278, repeat 266, append 84, fuzzer units 1,202.

### The two differences (both intended, written in the cards)

Kept in `fuzz/target/differential/` with `index.tsv` (password `demo-pass` for both):

1. `v3-stream-id-3.vault` (fuzz seed `keyfile-xml-v2` 3.1 without gzip, one bit flipped at offset 0xD3): version 3 header field 10, the inner stream id, is now 3. The reference opens it (its info command lists the vault normally); Larsal gives `Unsupported`. FMT-02.20 (LD-10): the reference accepts 3 in a version 3 header but decrypts with Salsa20 anyway, so Larsal refuses it; FMT-02 lists "version 3 inner stream id 3" among the intended AT-A11 differences.
2. `v3-protected-value-zero-byte.vault` (a fuzzer unit, the 3.1 rich seed with two bytes of field 8, the protected stream key, changed): the vault opens in both, but every protected value decodes to random bytes. Field `otp` of "Full demo entry" then holds a `00` byte at character 14. The installed reference (toolkit 5.15) cuts the value there (`y}` U+FFFD U+FFFD `[5` U+FFFD `8` U+FFFD U+FFFD after its export drops the control characters); Larsal keeps U+0000 and the 68 characters after it (Larsal's decoded value dumped by code point). Every other value in the file is equal. FMT-09.15 says exactly this: Larsal never cuts at a `00` byte; the reference source (toolkit 6) keeps the rest like Larsal, and AT-A11 differs only from the installed version.

Neither is a failure. Proposed for the lead (not blocking): add these two to AT-A11's list of known differences in `plan/attacks-and-checks.md`, next to LD-84.

The LD-84 cases (gzip trailer at a 16 KiB boundary, a 4.x file without its final block at such a boundary, over 128 namespace declarations) were not hit by random mutation: the seeds are small. A cut of exactly the final block of a reference-made 4.1 vault (control file) is rejected by both.

## 3. E3-S11: property test at 10,000 cases

`crates/larsal-format/tests/property.rs`: `ten_thousand_random_vaults_round_trip` has `ProptestConfig { cases: 10_000 }` and is ignored in the normal suite; it runs the same `round_trip` as the 48-case `random_vaults_round_trip` (a random vault saved and opened must equal the original, and a second save and open must equal the first). No `PROPTEST_*` variable was set.

```
$ cargo test --release -p larsal-format --test property -- --ignored
    Finished `release` profile [optimized] target(s) in 12.64s
     Running tests/property.rs (target/release/deps/property-0d0050d77998d0d1)
test ten_thousand_random_vaults_round_trip ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 43.38s
real 56.46  user 53.56  sys 0.68
```

The 48-case test passed in this session's check.sh run (`target/check/test.log`: `random_vaults_round_trip ... ok`).

## 4. CPU used (owner's rule: at most 30 minutes)

| Run | Wall | CPU (user + sys, all cores) |
|---|---|---|
| check.sh (E4-S13 re-check, same session) | 21 min 28 s | 25 min 28 s |
| probe builds and small compiles | about 1 min | about 2 min 30 s |
| differential run, 3,655 files, 4 jobs | 47 s | 2 min 18 s |
| second pass of 141 files, and the broad comparison | about 15 s | about 20 s |
| property test, 10,000 cases (with build) | 56 s | 54 s |
| **total** | **about 24 min 30 s** | **about 31 min** |

No libFuzzer run other than check.sh's smoke (18 targets, 30 s each, one at a time) was started.

## Status

- E3-S10: AT-A10 accepted by the owner on the recorded runs (OD-05), stats confirmed; AT-A11 passes. **Signed.** The 24 hours per target stays in E13-S3.
- E3-S11: **signed.**
