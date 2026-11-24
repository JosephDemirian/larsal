# E13-S2 attack group AT-B: crypto checks (Red team proof)

Story: E13-S2 (attack campaign), group AT-B, rows AT-B01 to AT-B07 of plan/attacks-and-checks.md.
Date: 2026-10-29. Role: Red team. The reference CLI (`REF_CLI`, version 2.7.11) ran read-only with `HOME=/tmp/e13s2-atb/refhome`. Reference sources were read only to learn the passwords of the reference's own demo test vaults (`REF_TESTDATA`). Nothing from the reference was copied into this folder.

Result: **6 of 7 rows passed on today's tree (AT-B04 and AT-B05 each with a Low finding). AT-B06 failed (finding RT-B1, Medium).**

| Row | Result | One line |
|---|---|---|
| AT-B01 | passed | 163 tests passed (154 tests and 9 doc-tests in larsal-crypto, including the startup self-test), plus the NIST 1 GiB long message. Seven public vectors were recomputed with openssl and Python. |
| AT-B02 | passed | 47 vaults made by the reference CLI were checked: 12 in `testdata/`, 28 from `REF_TESTDATA` and 7 made today. 43 open with the reference's content (with two explained differences in form). Both tools refuse the 4 damaged ones and 3 wrong-password cases. |
| AT-B03 | passed | There were 10,000 saves through `larsal_format::save`, using all 3 ciphers and all 3 KDFs. They gave 50,000 distinct values: no repeat within a set or across sets. The existing 10,000-save test also passed. 300 more saves went through the `larsal` tool, checked by an independent header parser. |
| AT-B04 | passed (Low finding RT-B3) | Only `larsal-crypto` `random.rs` names an OS random source, in both Rust and Swift product code. The guards have gaps (RT-B3). |
| AT-B05 | passed (Low finding RT-B2) | Header HMAC, block HMAC, HMAC verify and the version 3 start bytes all stayed within noise (largest \|t\| 1.5). The bare 32-byte `subtle` compare shows a bias under one cycle (RT-B2). |
| AT-B06 | **failed** (Medium finding RT-B1) | At today's load, both the window app's tuning (thread CPU clock) and `larsal db-create` reach the target. With 28 busy threads, `larsal db-create` tuned 11 Argon2id iterations instead of about 40. The KDF then took 330 to 351 ms of CPU, 0.33 times the 1,000 ms target. Stored settings equal the ones used. |
| AT-B07 | passed | The cipher API gives one error for every failure. Version 4 checks padding only after both HMAC checks; version 3 never checks it. No timing difference beyond noise (largest \|t\| 4.3). |

Earlier proof, cited as history only (every row was re-run here): E3-S10-E3-S11-fuzz.md, SF-07.md (AT-B03 history), E5-S10-saving.md, E13-S5-inventory.md (AT-B04 note 5 and C-05), findings F-026 and F-033 (AT-B06).

## Setup

- **Tree:** today's shared tree, read only. `CARGO_TARGET_DIR=/tmp/e13s2-target`. I ran `cargo test --release -p larsal-crypto -p larsal-format -p larsal-cli --no-run` at 20:28, finished 20:35, exit 0. The `larsal` tool used is `/tmp/e13s2-target/release/app` from that build.
- **Red team tests:** I wrote them in a private copy: `rsync -a --exclude target --exclude larsal-shots --exclude fuzz/target` to `/tmp/e13s2-atb-copy`, with its own target `/tmp/e13s2-atb-target`. The new file is `crates/larsal-format/tests/redteam_atb.rs` (ignored tests). It reuses the project's test builders `format_common` and `write_common`. No product code was changed in either tree.
  - Run with: `redteam_atb --ignored --nocapture --test-threads=1 <name>`.
- **Demo data only:**
  - `testdata/`;
  - copies of `REF_TESTDATA` vaults and key files in `/tmp/e13s2-atb/ref*`;
  - vaults made today by `REF_CLI` from `scripts/testdata/make_inputs.py` documents (`/tmp/e13s2-atb/fresh`);
  - vaults made by `larsal` under `/tmp/e13s2-atb`.
  - `larsal` ran with `HOME=/tmp/e13s2-atb/larsalhome`.
- **Owner's session:** no window, no pasteboard, no keychain, no ssh-agent.
- **Processes:** only processes I started. For AT-B06 I started 28 `yes` load processes. My first stop command failed (shell word splitting), so they ran about 15 s. I then stopped each one by PID, and a check with `ps` found none left.
- **Machine load:** high all through the run, from other agents (load average 27 to 63 on 14 cores, Apple M4 Pro, 48 GB). All timing tests interleave their classes, so load hits every class alike.
- **CPU used by attack runs:** about 20 minutes in total, builds not counted. That includes about 7 minutes from the 28 load processes.
- **Files changed in this folder:** this file only.

## AT-B01 Known answers for primitives

**Method.** I ran the RFC and NIST vector tests of `larsal-crypto` in release, including the slow ignored NIST long message. I also checked that the expected values in the tests are the published ones, by recomputing seven of them outside our code.

**Commands.**

```
cargo test --release -p larsal-crypto
/tmp/e13s2-target/release/deps/hash-* --ignored streaming_one_gib_nist_long_message
openssl enc -aes-256-cbc -nopad -K 603deb10...0914dff4 -iv 0001...0e0f   (SP 800-38A F.2.5 block 1)
python3 -I: hashlib sha256/sha1/sha512("abc"), hmac RFC 4231 case 1, RFC 2202 case 1, pbkdf2_hmac RFC 7914 s.11
```

**Output (excerpt).**

```
unittests src/lib.rs   47 passed, 1 ignored     (incl. kdf::tests::rfc9106_5_1_argon2d, rfc9106_5_3_argon2id,
                                                  version_0x10_with_secret_known_answers, ssh::tests::sign_ed25519_rfc8032_test_1,
                                                  sign_p256_rfc6979_sample, selftest::tests::app11_10_d_every_check_passes)
tests/cipher.rs        21 passed  (aes256_cbc_nist_sp800_38a_f25_encrypt, f26_decrypt, chacha20_rfc8439_2_4_2_and_a2_3_encryption,
                                   chacha20_rfc8439_a1_and_2_3_2_blocks, twofish256_authors_table_cry01_t9_t9b,
                                   twofish256_cbc_monte_carlo_encrypt/decrypt_cry01_t10, ...)
tests/hash.rs           6 passed, 1 ignored (sha1/sha256/sha512_fips_180_4_vectors)
tests/kdf.rs           35 passed, 3 ignored (aes_kdf_card_vectors, argon2_no_secret_card_vectors, import::hkdf_expand_rfc_5869_a1_to_a3,
                                   import::pbkdf2_sha256_rfc_7914_section_11, import::pbkdf2_sha512_vectors, import::import_argon2id_published_vector)
tests/mac.rs            8 passed, 1 ignored (hmac_sha256_rfc_4231_cases_1_to_7, hmac_sha1_rfc_2202_cases_1_to_7, hmac_sha512_rfc_4231_cases_1_to_7)
tests/stream.rs        19 passed  (chacha20_rfc8439_vectors, salsa20_estream_vectors_cry01_t24, ...)
tests/random.rs 7, secret.rs 10, ssh_wipe.rs 1 passed; doc-tests 2 + 7 passed
streaming_one_gib_nist_long_message ... ok (SHA-1, SHA-256, SHA-512 of the 1 GiB NIST long message)

AES-256-CBC SP800-38A F.2.5 block1: f58c4c04d6e5f1ba779eabfb5f7bfbd6      (in tests/cipher.rs and src/selftest.rs)
SHA-256(abc): ba7816bf8f01cfea414140de5dae2223...                         (in tests/hash.rs)
SHA-1(abc):   a9993e364706816aba3e25717850c26c9cd0d89d                    (in tests/hash.rs)
SHA-512(abc): ddaf35a193617abacc417349ae204131...                         (in tests/hash.rs)
HMAC-SHA-256 RFC 4231 tc1: b0344c61d8db38535ca8afceaf0bf12b...            (in tests/mac.rs, src/selftest.rs)
HMAC-SHA-1 RFC 2202 tc1:   b617318655057264e28bc0b6fb378c8ef146be00      (in tests/mac.rs)
PBKDF2-SHA256 RFC 7914 s.11: 55ac046e56e3089fec1691c22544b605...          (in tests/kdf.rs)
```

The Argon2 RFC 9106 tags (5.1 `512b391b...`, 5.3 `0d640df5...`), the Ed25519 RFC 8032 test 1 signature (`e5564300...`) and the Twofish all-zero KAT (`57ff739d...`) are present in `src/kdf.rs`, `src/selftest.rs`, `src/ssh.rs` and `tests/cipher.rs`, and pass. The startup self-test (`selftest::run`, called by `larsal-cli` main.rs:101 and `larsal-ffi` start.rs:297) passes its 9 checks.

The other ignored tests are not known-answer tests: the 1 GiB flat-memory streams, a uniformity sweep and the benchmarks. The benchmarks are covered in AT-B06.

**Result: passed.**

## AT-B02 Known answers for whole files

**Method.** For every vault made by the reference CLI, both tools export it as XML: `REF_CLI export -f xml` and `larsal export -f xml`. Both exports go through `scripts/testdata/to_json.py`. A comparer then compares every field: groups, entries, history, strings with their protection flags, custom data, icons, deleted objects and times.

- The comparer is `/tmp/e13s2-atb/b02/compare.py`, written for this run.
- Form-only rules:
  - times are compared as seconds since year 1, whatever their form;
  - `Meta/Binaries` and attachment `Ref` numbers are dropped;
  - Larsal's `SettingsChanged` is ignored when the original has none (FMT-10.10).
- Every current entry's attachment is exported by both tools with `attachment-export` and compared byte for byte.
- Vaults that must fail (broken header hash, broken key files, wrong password) must be refused by both tools.
- Positive control: a changed database name in Larsal's JSON gives a `DIFF` line.

The Rust suite that checks `testdata/` against its JSON was run too.

**Commands.**

```
cargo test --release -p larsal-format --test testdata --test version3 --test open
/tmp/e13s2-atb/b02/run.sh < cases-testdata.txt   # the 12 vaults of testdata/
/tmp/e13s2-atb/b02/run.sh < cases-ref.txt        # 24 REF_TESTDATA vaults; 4 damaged ones and 2 wrong passwords must be refused
/tmp/e13s2-atb/b02/run.sh < cases-fresh.txt      # 7 vaults made today by REF_CLI + 1 must-refuse
```

Today's vaults were made under `/tmp/e13s2-atb/fresh` with `REF_CLI`:

- `import` of the `make_inputs.py` documents: basic, rich-v3, rich-v4 and big, with the default rounds and with `-t 100` and `-t 200`;
- a password plus an XML v2 key file;
- a key file only, made new by `REF_CLI`;
- one vault built step by step with `db-create`, `mkdir`, `add`, `attachment-import`, `edit` (which makes history) and `db-edit` (new password).

**Output (excerpt).**

```
testdata.rs: export_documents_round_trip ok, every_vault_opens_and_matches_its_json ok,
             every_vault_round_trips_as_version_4 ok, ld88_debug_holds_no_demo_text ok    (4 passed)
version3.rs: 51 passed; open.rs: 68 passed

PASS password-only ... PASS big-10000: exports equal (10000 entry records)
PASS rich-v3: exports equal (13 entry records), 5 attachments byte-equal
PASS rich-v4: exports equal (13 entry records), 5 attachments byte-equal
AT-B02: 12 pass, 0 fail                                   (testdata/)

PASS Format400: exports equal (1 entry records), 1 attachments byte-equal    (ChaCha20, Argon2d, version 4.0)
PASS NewDatabase ... PASS SyncDatabaseDifferentPassword ... PASS NonAscii (password in Greek, Latin-1 and Arabic letters)
PASS BrokenHeaderHash: both refuse (app: "... is damaged and cannot be unlocked ...")
PASS the XML v2 key file vault with a failing check value: both refuse (app: "The key file ... is damaged: its built-in check failed ...")
PASS Format400-wrong-password / NewDatabase-wrong-password: both refuse (app: "Wrong password, key file or security key ...")
AT-B02: 28 pass, 2 fail                                   (REF_TESTDATA: both "fails" explained below)

PASS f-basic-default, f-rich-v3, f-rich-v4 (5 attachments byte-equal), f-pw-xmlkey2, f-keyonly-new, f-big (10000),
     f-created (3 entry records incl. history, 1 attachment byte-equal); f-created-old-password: both refuse
AT-B02: 8 pass, 0 fail                                    (made today)
```

The two differences in `REF_TESTDATA` are in form or runtime only; no content differs:

- **Format200 (version 2.0):** Larsal's export keeps `Meta/MemoryProtection/AutoEnableVisualHiding` = `False`. The reference's export leaves it out. The element is in the file: `REF_CLI` prints `skip element "AutoEnableVisualHiding"` while reading it, and no Larsal source names that element. Larsal keeps an element the reference drops.
- **KeyFileProtected:** the reference's export has a `_LAST_MODIFIED` custom data item that Larsal's lacks. Its value is the time of the export run: `20:05:44` on the first run and `20:06:57` on a second run a minute later. The reference stamps it at load; it is not in the file.

Coverage note: every vault the reference CLI can make uses AES-256 and AES-KDF, because the CLI has no option to pick others. Format400 brings ChaCha20 with Argon2d. No reference-made demo vault with Twofish or Argon2id exists in `REF_TESTDATA`; those primitives are covered by AT-B01 and by AT-B03's save and open round trips.

**Result: passed.** 47 vault files were checked: 43 open with the reference's content. Both tools refuse the 4 damaged files and 3 wrong-password cases. One `REF_TESTDATA` vault needs a hardware key and was not run; that check needs the owner's hardware.

## AT-B03 Fresh randomness

**Method.**

1. My test made 10,000 saves through the real `larsal_format::save`. It rotated AES-256, Twofish-256 and ChaCha20 against AES-KDF, Argon2id and Argon2d (all cheap settings), about 1,111 saves of each of the 9 pairs. After each save it decrypted the file and collected 5 values: master seed, IV or nonce, KDF salt or seed, inner stream key and the CRY-03.7 padding item value. No value may repeat within its set or appear in two sets.
2. The project's own test `cry_03_t10_at_b03_ten_thousand_saves`, with the other CRY-03 tests.
3. 300 saves through the product command line: `larsal edit` on a vault made by `larsal db-create -t 100`. An independent Python header parser (`/tmp/e13s2-atb/b03cli/hdr.py`, no Larsal code) read the master seed, IV and KDF salt after each save.

**Commands.**

```
redteam_atb --ignored --nocapture at_b03_ten_thousand_saves_all_ciphers_and_kdfs
cargo test --release -p larsal-format --test write_version -- cry_03
for i in 1..300: printf 'demo-b03\n' | larsal edit -q -u demo-user-$i v.larsalvault "Demo b03"; python3 -I hdr.py v.larsalvault
```

**Output (excerpt).**

```
AT-B03: master seed: 10000 distinct of 10000, lengths "[32]"
AT-B03: IV or nonce: 10000 distinct of 10000, lengths "[12, 16]"
AT-B03: KDF salt or seed: 10000 distinct of 10000, lengths "[32]"
AT-B03: inner stream key: 10000 distinct of 10000, lengths "[64]"
AT-B03: padding item value: 10000 distinct of 10000, lengths "128..1022 (448 lengths)"
AT-B03: saves per cipher/KDF: Aes256 1112+1111+1111, ChaCha20 1111x3, Twofish256 1111x3
AT-B03: 50000 distinct values over all five sets; 6.9 s
cry_03: 14 passed (incl. cry_03_t10_at_b03_ten_thousand_saves, cry_03_t11_one_random_source, cry_03_t2_chacha20_nonce)
CLI: saves: 300; master seed / IV / KDF salt distinct: 300 / 300 / 300; values seen twice across all columns: 0
```

**Result: passed.**

## AT-B04 One random source

**Method.**

- **Code search** of every product source: `crates/*/src` (Rust) and `macos/` (Swift, C, Objective-C). The search used a wider word list than the project's own guards: `getrandom`, `rand_core`, `rand::`, `OsRng`, `thread_rng`, `StdRng`, `SmallRng`, `SysRng`, `fastrand`, `RandomState`, `arc4random`, `SecRandomCopyBytes`, `CCRandom`, `/dev/urandom`, `getentropy`, `new_v4`, `SystemRandomNumberGenerator`, `.random(`, `UUID()`, `SecKeyCreateRandomKey`, `CryptoKit`, `srand` and `rand()`.
- **Dependency trees:** `cargo tree -e normal -i` for getrandom, rand_core, rand and fastrand, for `larsal-cli` and `larsal-ffi`.
- **Callers:** the list of every caller of `larsal_crypto::random`.
- **The project's guards:** `cry_03_t11_one_random_source`, `only_random_rs_reaches_the_os_source`, `fea02_06_no_random_source_outside_larsal_crypto` and `int10_3_crypto_list_matches_larsal_crypto`.
- **Review:** `random.rs` itself.

**Output (excerpt).**

```
crates/larsal-crypto/src/random.rs:14: use getrandom::SysRng;   (+ rand_core; the only Rust hits)
macos/LarsalTests/*.swift: UUID() x4 (test-only pasteboard names and temp paths); no hit in macos/Larsal or macos/LarsalCore
callers of larsal_crypto::random: larsal-cli main.rs, larsal-core (attachments, generator x4, import, settings, storage, tree),
  larsal-ffi (cli, edit x2), larsal-format (document/read x2, keyfile, lib x2), larsal-hwkey lib
cargo tree -p larsal-cli  -i getrandom: only larsal-crypto
cargo tree -p larsal-ffi  -i getrandom: larsal-crypto, and tempfile 3.27.0 <- uniffi_pipeline 0.32.2 <- uniffi
cargo tree -p larsal-ffi  -i fastrand:  fastrand 2.5.0 <- tempfile 3.27.0 <- uniffi_pipeline
rand_core is also a trait dependency of crypto-bigint / elliptic-curve (p256); signing is deterministic
  (RFC 6979, Ed25519), no RNG call in ssh.rs
fea02_06_no_random_source_outside_larsal_crypto ok; int10_3_crypto_list_matches_larsal_crypto ok;
  cry_03_t11_one_random_source ok; only_random_rs_reaches_the_os_source ok
```

`random.rs` review: `SysRng` only, no seed, no state and no fallback. A failed source gives `RandomSource` and no value. `below` is unbiased by rejection and fails closed after 64 rejected draws. `uuid_v4` sets the version and variant bits.

Temp file names (`larsal-core` `storage.rs:398`) and generated key files also come from `random::`. The `getrandom` 0.2.17 under `ring` exists only with feature `net` (TLS handshake); that feature is off in product builds.

Guard probe in the private copy (text scan, run directly from the built test binary):

```
0: unchanged                                         test cry_03_t11_one_random_source ... ok
1: + libc::arc4random_buf in larsal-platform/src/lib.rs test cry_03_t11_one_random_source ... ok     <- not caught
2: + fastrand::u64(..) (control)                     test cry_03_t11_one_random_source ... FAILED (rand:: in .../larsal-platform/src/lib.rs)
```

**Result: passed.** Larsal's own code (Rust and Swift) takes random values only from `larsal_crypto::random`.

- A random path in third-party code that Larsal never calls (`tempfile` through UniFFI) is linked into `larsal-ffi`. Nothing calls it today.
- The guards would not catch a future `libc::arc4random_buf`, `SecRandomCopyBytes` or any Swift random call.

Both are recorded as finding RT-B3 (Low).

## AT-B05 Constant time

**Method.**

1. **Review** of every compare of a tag, hash or check value in product code. There are 17 call sites, and every one goes through `secret::ct_eq` or `mac::verify_hmac_*`, both on `subtle` 2.6.1:
   - `integrity.rs`: header hash, header HMAC and block HMAC;
   - `hashed_blocks.rs`: the version 3 block hash;
   - `payload.rs:385`: the version 3 start bytes;
   - `document/read.rs:1857`: the version 3 HeaderHash;
   - `keyfile.rs:1703`: the XML v2 check value;
   - `keys.rs:256`: the CRY-03.16 transformed-key check;
   - imports: `v1.rs:128`, `bitwarden.rs:139` and `:142`, `opvault.rs:170`, `:412` and `:439`;
   - password repeats: `commands.rs:989`, `settings.rs:379`, `wizard.rs:615`.

   `mac.rs` has a probe test that every verify runs the one compare, and a source scan that finds no `==` there. `subtle`'s slice `ct_eq` is branch-free: a length check (public), then an AND over per-byte `ct_eq` results, each passed through a volatile read.
2. **Timing tests**, Welch t between classes, dudect bound \|t\| < 10. Each test prints raw t and t after cropping the slowest 10%.
   - (a) the file-level MAC checks: `header_hmac_ok` with the right tag, byte 0 wrong and byte 31 wrong; `read_blocks` with the block tag wrong at byte 0 against byte 31; version 3 `open_payload` with start byte 0 wrong against 31 wrong;
   - (b) the project's own `verify_time_does_not_depend_on_the_tag`;
   - (c) the bare `ct_eq` on 32-byte tags. It was run with a positive control (an early-exit compare in the same harness, which must be caught) and an A/A null test (two classes with the same tag).

**Commands.**

```
redteam_atb --ignored --nocapture at_b05_header_and_block_hmac_checks at_b05_version_3_start_bytes
cargo test --release -p larsal-crypto --test mac -- --ignored --nocapture verify_time_does_not_depend_on_the_tag
redteam_atb --ignored --nocapture at_b05_ct_eq_and_positive_control at_b05_ct_eq_refined at_b05_ct_eq_positions   (twice)
```

**Output (excerpt).**

```
header HMAC: median 3567.8 / 3570.3 / 3567.8 ns (right, byte 0 wrong, byte 31 wrong), n = 40000 each
header HMAC: byte 0 wrong vs byte 31 wrong: t = 1.48 (cropped 0.53); right vs byte 0: t = -0.09 (0.19); right vs byte 31: t = 0.99 (0.72)
block HMAC: byte 0 wrong vs byte 31 wrong: t = 0.07 (cropped -1.27)
v3 start bytes: byte 0 wrong vs byte 31 wrong: t = 1.10 (cropped 0.31)      (both WrongKey, n = 10000 each)
existing test: classes 0 and 1: t = 0.30; 0 and 2: t = 0.90; 1 and 2: t = 0.58

bare ct_eq, fixed buffer, random class order, 100,000 batches of 256 calls per class:
A/A null (equal vs equal): t = -0.83 (cropped -0.32); second run -0.45 (0.49)
equal vs byte 0 wrong: t = 0.80 (cropped -2.83); equal vs all bytes wrong: t = 1.18 (cropped -0.19)
equal vs byte 31 wrong: t = 0.13 (cropped -36.14); second run -0.26 (cropped -11.00)
positions (60,000 batches): byte 0 / 1 wrong: cropped |t| <= 2.2; byte 8 / 16 / 24 / 30 / 31 wrong: cropped t -5.9 to -8.3 (run 1), -19.8 to -24.6 (run 2);
  raw t always within +-3; medians 28.8 vs 29.0 ns per compare (a 0.2 ns step)
or-fold compare in the same harness: all positions cropped |t| <= 2.5
positive control (early exit): byte 0 vs byte 31 wrong: medians 1.0 vs 14.0 ns, cropped t -4640 to -12346
```

All four MAC checks show no timing difference beyond noise. The largest \|t\| over every MAC-check pair is 1.48, which is under 10 by a wide margin.

The bare compare shows something else: a mismatch at byte 8 or later costs about 0.2 ns more (about one CPU cycle) than a mismatch at byte 0 or 1, or equal tags. This shows only after cropping, and only with a fixed buffer and 15 to 26 million calls per class. The A/A null test and an OR-fold compare in the same harness show nothing, so the effect is real. It points to `subtle`'s per-byte volatile reads on this CPU. Inside a MAC check it is about 1/18,000 of the check's own time and does not show.

**Result: passed** (the row's timing test is on MAC checks). Finding RT-B2 (Low) records the bare-compare effect.

## AT-B06 KDF cost is real

**Method.**

- **Command line default:** I made a vault with the default settings of the command line (`larsal db-create -p`, no `-t`, so the target is 1,000 ms). I timed its unlock with `/usr/bin/time` (user CPU = KDF, which is single-threaded in Larsal), and its KDF alone with both clocks: a harness reads the header and runs `kdf::derive` with the stored settings.
- **Window app path:** the window app's wizard calls `kdf::benchmark(template, 1_000, host, thread_cpu_time)`, `larsal-ffi` `wizard.rs:250`. My harness made that same call with the default template (Argon2id, 64 MiB, 4 lanes, CRY-02.23), and once with a wall clock for comparison. Each result was then timed.
- **Busy Mac:** the same was done while 28 CPU-bound load processes ran (my own `yes` processes, stopped by PID).
- **Stored equals used:** an independent Python parse of the header's KDF map, `REF_CLI db-info` unlocking each vault, and Larsal's own `db-info`.

**Commands.**

```
printf 'demo-b06\ndemo-b06\n' | larsal db-create -p cli-default.larsalvault
/usr/bin/time -p sh -c "printf 'demo-b06\n' | larsal db-info -q cli-default.larsalvault"      (3 times)
AT_B06_VAULTS=... redteam_atb --ignored --nocapture at_b06_kdf_cost_is_real
28 x (yes > /dev/null &), then: larsal db-create -q -p load1.larsalvault; larsal db-create -q -p load2.larsalvault;
   AT_B06_NO_RUNS=1 redteam_atb ... at_b06 ; kill <each PID>
REF_CLI db-info -q cli-default.larsalvault / load1.larsalvault
```

**Output (excerpt).**

```
normal load (load average 30-50):
  larsal db-create default:  Key derivation: Argon2id, 64 MiB, 41 iterations, 4 lanes
  larsal db-info unlock:     real 1.48 user 1.41 | real 2.82 user 1.51 | real 3.51 user 1.58
  KDF alone (wall/CPU ms) with the stored settings: 1185/1158, 1202/1185, 1214/1188
  wizard path (thread CPU clock): 38 iterations; runs 1227/1168, 1259/1201, 1149/1137
  wall clock tune: 40 iterations; runs 1148/1140, 1160/1150, 1202/1164
  nice -n 20 larsal db-create (x2): 40 and 40 iterations

28 busy threads during tuning:
  wizard path (thread CPU clock): 40 iterations
  larsal db-create load1.larsalvault:   11 iterations   <- wall clock
  larsal db-create load2.larsalvault:   41 iterations
  load1 KDF alone (wall/CPU ms) at normal load: 1005/351, 1278/333, 1292/330
  load1 unlock with app:          real 0.57 user 0.51 | 0.54 0.50 | 0.52 0.49

stored = used:
  cli-default header KDF map: {'$UUID': '9e298b19...', 'I': 41, 'M': 67108864, 'P': 4, 'V': 19, 'S': 32 bytes}
  REF_CLI db-info: Cipher: AES 256-bit; KDF: Argon2id (41 rounds, 65536 KB)   (unlocked; real 0.56 s, user 1.20 s)
  load1 header: I 11, M 67108864, P 4, V 19; REF_CLI db-info: KDF: Argon2id (11 rounds, 65536 KB)
existing ignored tests: benchmark_aes_kdf_lands_in_band ok (135,499,160 rounds, median unlock 1196 ms);
  benchmark_argon2id_default_lands_in_band FAILED on its upper bound only: 42 iterations, median 1238 ms > 1200
  (wall-clock unlock under load: slower, not weaker; same kind as F-033)
```

What passes:

- Stored settings equal the ones used: the header, Larsal's `db-info` and the reference's unlock all agree.
- The window app path reaches the target, with load and without: 38 to 40 iterations, 1,137 to 1,201 ms of CPU.
- Today's `larsal db-create` at normal load: 41 iterations, 1.16 to 1.19 s.

What fails: `larsal db-create` and `larsal import` tune with a wall clock. `crates/larsal-cli/src/commands.rs:1024-1030` holds a `clock()` built on `Instant` and a stale note: "larsal-platform has no thread CPU-time clock yet (LD-72)". That clock is passed to `settings::tune` at line 1037.

`larsal_platform::macos::thread_cpu_time` has existed since F-026, and larsal-cli already depends on `larsal-platform` with `appkit`. On a busy Mac, one of two creates tuned 11 iterations where the CPU clock picked 40 at the same moment. The resulting vault's KDF costs 330 to 351 ms of CPU, 0.33 times the target. LD-72 decided that Larsal passes the thread CPU clock so that "other work cannot make the tuned KDF weaker"; the command line does not.

**Result: failed.** The command line path is weaker than the target under load (finding RT-B1, Medium). The window app's path and stored-equals-used pass.

## AT-B07 No padding oracle

**Method.**

1. **Cipher API, one error.** 208,192 last blocks per cipher, AES-256-CBC and Twofish-256-CBC (416,384 decrypts in total): every value of n with one wrong byte at each position, every all-n block, and 200,000 random blocks biased toward short paddings. They were decrypted with `cipher::decrypt`, and each result was compared with a naive PKCS#7 rule written from RFC 5652 section 6.3. Every failure was collected as `Debug|Display`, along with empty, 15, 17 and 31-byte inputs and a wrong key.
2. **Cipher API timing:** a wrong key against four kinds of bad padding under the right key: last byte 0, last byte 17, n = 16 with the 16th byte from the end wrong, and n = 2 with the 2nd byte from the end wrong. Each is one block, and all give `Decrypt`. A valid padding was included for reference.
3. **Version 4 files** (the project's `Demo` builder, password `demo-pass`): a file sealed with valid HMACs around a bad padding, which only a key holder can make, and the good file tampered so the padding would become valid or invalid, without fixing the HMACs. Each was opened with the right and the wrong password, counting decrypts with the `payload::probe`, and timed within each pair.
4. **Version 3 files** (`DemoV3`): a file whose padding, which lies after the logical end, is invalid. It was opened, and timed under a wrong key against the good file.
5. **Reference comparison**, with real content: `testdata/password-only` re-encrypted with its own key and an invalid last padding byte, and rich-v4's content sealed with a bad padding. Both CLIs opened both.

**Commands.**

```
redteam_atb --ignored --nocapture at_b07_one_error_and_exact_padding_rule at_b07_cipher_api_timing_bad_padding_vs_wrong_key
redteam_atb --ignored --nocapture at_b07_version_4_padding_only_after_integrity at_b07_version_3_no_padding_check
redteam_atb --ignored --nocapture at_b07_write_real_content_files; then larsal ls / REF_CLI ls on /tmp/e13s2-atb/b07/real-*.v
cargo test --release -p larsal-crypto (every_decrypt_failure_is_the_same_error_ld04, wrong_key_and_bad_padding_give_one_error_cry01_t38,
   garbage_gives_ok_or_the_one_error, unpad_accepts_exactly_the_valid_paddings, length_check_is_not_hidden_by_the_padding_check: ok)
```

**Output (excerpt).**

```
AT-B07 cipher API: 416384 decrypts, 24370 accepted, error values seen: {"Decrypt|decryption failed"}
cipher decrypt (n = 40000 each, ~3.7 us per call): wrong key vs pad byte 0: t = 0.78 (cropped 3.41); vs pad byte 17: -0.75 (4.33);
   vs n16 wrong at 16: 0.12 (4.15); vs n2 wrong at 2: -0.34 (4.13); bad paddings among themselves: |t| <= 1.46 (cropped <= 0.92)
   valid n16 vs pad byte 0 (the Ok/Err result is public anyway): t = 0.05 (cropped 9.61)
AT-B07 v4 sealed bad padding, right key: Some(Corrupt), decrypts 1
AT-B07 v4 tampered, padding would be valid, right key: Some(Corrupt), decrypts 0
AT-B07 v4 tampered, padding would be invalid, right key: Some(Corrupt), decrypts 0
AT-B07 v4 good file / sealed bad padding / tampered, wrong key: Some(WrongKey), decrypts 0 (each)
v4 open: tampered valid-pad vs tampered invalid-pad (right key): t = 0.53 (cropped 0.42)
v4 open: good file vs bad-padding file (wrong key): t = -0.96 (cropped -0.64)
AT-B07 v3 sealed bad padding, right key: Ok(65)   (same document as the good file)
v3 open, wrong key: good padding vs bad padding: t = 0.13 (cropped -0.01)
real content: password-only re-encrypted with padding byte 0 (was 6):
   larsal ls: "Demo login" (opens: padding after the logical end is never read, FMT-01.20, LD-01)
   REF_CLI ls: "Error while reading the database: No root group"
real content: rich-v4 sealed with a bad padding:
   larsal ls: "... is damaged and cannot be unlocked ..." (Corrupt after both HMAC checks, FMT-08.5, LD-03)
   REF_CLI ls: lists the entries (opens it)
wrong password on every one of these files, both tools: wrong-key message
```

Imports were reviewed too. The version 1 import maps a padding failure and a content-hash failure to the same `WrongCredentials` (`v1.rs:127-131`). Bitwarden and OPVault check the HMAC before any decrypt, and OPVault uses no padding.

**Result: passed.** The cipher API has one error. Padding is reached only after both HMAC checks pass in version 4 (decrypt count 0 for every tampered or wrong-key file), and never in version 3. No timing difference beyond noise: largest \|t\| 4.33 among failures, 0.96 in files.

The two reference differences are both on purpose (LD-01, LD-03), fail closed or affect only bytes outside the logical end, and need someone who holds the key. They are listed as notes for AT-A11 below, not as findings.

## Findings

Proposed for `security/findings.md` (the filer assigns the F numbers). All steps use demo data only.

### RT-B1 Medium: the command line tunes the KDF with a wall clock (AT-B06, LD-72, F-026)

**Area:** larsal-cli `write_vault` (`db-create`, `import`), `crates/larsal-cli/src/commands.rs:1024-1037`.

**Steps to reproduce.**

1. Build `larsal` (`cargo build --release -p larsal-cli`). Use `HOME=/tmp/x`.
2. Start 28 CPU-bound processes (`yes > /dev/null &`, 28 times) and note their PIDs.
3. `printf 'demo-b06\ndemo-b06\n' | larsal db-create -q -p /tmp/x/load.larsalvault`. Repeat 2 or 3 times with new names.
4. Stop the 28 processes by PID.
5. `printf 'demo-b06\n' | larsal db-info -q /tmp/x/load.larsalvault`, then time the unlock.

**Observed:** one of two creates got `Argon2id, 64 MiB, 11 iterations` and a KDF of 330 to 351 ms CPU. In the same window, the window app's call (`kdf::benchmark` with `thread_cpu_time`) picked 40 iterations. The KDF was 0.33 times the 1,000 ms target, a weaker KDF than promised (LD-19, LD-40, LD-72).

**Smallest fix:** in `write_vault`, pass `larsal_platform::macos::thread_cpu_time` to `settings::tune`, and delete the `clock()` function and its stale note. Larsal-cli already depends on `larsal-platform` (appkit), and the function is exported without a feature gate.

**Re-test:** the steps above under 28 busy threads. Expect 38 to 44 iterations (the CPU-clock band measured here) and a KDF of at least 1,000 ms CPU.

### RT-B2 Low: the bare `subtle` slice compare shows a timing step under one cycle on Apple M4 Pro (AT-B05)

**Area:** `larsal-crypto` `secret::ct_eq`, which is `subtle` 2.6.1 `<[u8]>::ct_eq`.

**Steps to reproduce:** the private-copy test `at_b05_ct_eq_positions` (code in this file's AT-B05 section).

- Want: 32 bytes of `5A`. Each class is the same tag with one byte flipped, at byte 0, 1, 8, 16, 24, 30 or 31.
- The tag is copied into one fixed buffer before each batch.
- Each class is chosen at random.
- Batches of 256 calls, 60,000 per class, Welch t after cropping the slowest 10%.

**Observed:** byte 0 and byte 1 sit at the level of equal tags. Byte 8 and later are about 0.2 ns slower: cropped t -5.9 to -8.3 in the first run and -19.8 to -24.6 in the second. In the 100,000-batch runs, byte 31 alone gave -36.1 and -11.0. Raw t is always within ±3. The A/A null test and an OR-fold compare in the same harness show nothing.

No MAC check shows it (largest \|t\| 1.48). An attacker would have to make Larsal verify chosen tags many millions of times, behind a KDF of at least 1 s each, and time a 0.2 ns step inside about 3.6 µs of HMAC work. That is not practical.

**Smallest fix:** no code change. Record in CRY-01 or LD-72's neighbour (or in the AT-B05 row) that AT-B05 is judged on the MAC checks, and that the bare compare's step is below one cycle (a hardware effect of the per-byte volatile reads). If the lead wants it gone, change `secret::ct_eq` to OR-fold `a[i] ^ b[i]` into one byte and run one `subtle` `u8::ct_eq` against 0 (one volatile read). Lengths stay public as today. Re-run `at_b05_ct_eq_positions`.

### RT-B3 Low: the one-random-source guards miss Swift and third-party paths (AT-B04, E13-S5 note 5 / C-05)

**Area:** `deny.toml`, `crates/larsal-format/tests/write_version.rs` `cry_03_t11_one_random_source`, `crates/larsal-core/tests/fea02.rs` and `crates/larsal-crypto/tests/random.rs`.

**Steps to reproduce:**

1. `cargo tree -p larsal-ffi -e normal -i getrandom` and `-i fastrand`. Both show `tempfile 3.27.0 <- uniffi_pipeline 0.32.2 <- uniffi`.
2. In a private copy, append `pub fn rt_b3_probe(buf: &mut [u8]) { unsafe { libc::arc4random_buf(buf.as_mut_ptr().cast(), buf.len()) } }` to `crates/larsal-platform/src/lib.rs`.
3. Run the workspace guard `cry_03_t11_one_random_source`.

**Observed:** the guard still passes (`test cry_03_t11_one_random_source ... ok`). The control line `fastrand::u64(..)` is caught by its `rand::` word (`panicked ... rand:: in .../larsal-platform/src/lib.rs`).

The guards' word lists hold only `getrandom`, `rand_core`, `rand::`, `OsRng` and `thread_rng` (plus `SysRng`, `StdRng`, `SmallRng`, `ThreadRng` and `SystemTime` in the per-crate scans). They do not cover `arc4random`, `getentropy`, `SecRandomCopyBytes` or `RandomState`, and no guard scans the Swift code in `macos/` (`UInt64.random(in:)`, `SystemRandomNumberGenerator`, `SecRandomCopyBytes`). `deny.toml` only stops a second version of `getrandom` or `rand_core`, not a new caller.

Today no product code makes such a call: my wider search of Rust and Swift found none. Only third-party code that Larsal never calls links a second source.

**Smallest fix:**

- Add `arc4random`, `getentropy`, `SecRandomCopyBytes` and `RandomState` to the word list of `cry_03_t11_one_random_source`.
- Add a scan of `macos/Larsal` and `macos/LarsalCore` (LarsalTests excluded) for `.random(`, `SystemRandomNumberGenerator`, `SecRandomCopyBytes` and `arc4random`.
- In `deny.toml` `bans.deny`, give `getrandom` `wrappers = ["larsal-crypto", "tempfile", "ring"]`, and add `{ crate = "fastrand", wrappers = ["tempfile"] }`.

## Notes for the lead (not findings)

- **N1 (AT-A11 known differences):** the AT-B07 reference comparison found two crafted-file differences that LD-84's list does not name. Both are decided and both need the key:
  - a version 3 file with an invalid CBC padding after the logical end: Larsal opens it (LD-01, FMT-01.20); the reference refuses it ("No root group");
  - a version 4 file with valid HMACs around an invalid padding: Larsal says damaged (LD-03, FMT-08.5); the reference opens it.

  Add them to the AT-A11 row if the lead wants that list complete.
- **N2:** the project's ignored `benchmark_argon2id_default_lands_in_band` failed its upper bound under today's load: median wall-clock unlock 1,238 ms, above 1,200. The test times unlocks by wall clock. It is not a weakness (slower, not faster), but the test will keep failing on a busy Mac; timing unlocks with the thread CPU clock would make it stable.
- **N3:** the reference-made demo vaults cover AES and AES-KDF everywhere, and ChaCha20 with Argon2d only through `REF_TESTDATA` Format400. Twofish and Argon2id reach whole-file checks only through Larsal's own round trips (AT-B03) and earlier interop runs.

## Cleanup

All work folders were deleted at the end:

- `/tmp/e13s2-atb` (work, homes, vaults);
- `/tmp/e13s2-atb-copy` (private copy);
- `/tmp/e13s2-atb-target` (private target).

The shared `/tmp/e13s2-target` was left for the other red team agents. No process of mine is left running.
