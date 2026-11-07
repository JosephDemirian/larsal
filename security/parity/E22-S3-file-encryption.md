# E22-S3 File encryption in Rust: Verify sign-off

Story: E22-S3 (plan/epics.md). Cards: FIL-01, FIL-03. Decisions: LD-366 to LD-371, LD-379, LD-429. Checkers: C1 and Sensitive C2, round 3.
Date: 2026-11-07.
Role: Verify. I ran probes and mutants in a private copy of the tree. I changed no product code. I did not run the downloaded tool, its keygen or its plugin, and `LARSAL_AGE_TOOL` stayed unset in everything I ran. The logs and scripts named here lived in private folders under /private/tmp that do not last, so this page copies what must survive.

**Result: signed with limits.** Commit `109ef3660c656e47beaac581898066fcbffd9a8f`, five commits on 8403aad: 88df65f (the check tool), 385835a (the published vectors), 6e04189 (the engine), ed1947d (the name guard), 109ef36 (the tables). All 7 story checks hold, and the guarded tool's run of this commit reads PASS. The 128 published rows in profile age-classic-1 pass by their own stage and hash, and the 19 hybrid rows are recorded by name and never counted (LD-366). Of my 30 mutants 28 went red, and the 2 that stayed green are explained below.

Nothing but tests and the fuzz target calls this crate. No CLI, no Swift and no FFI reach it, so no person can meet what stays open. Three things must close before the first caller lands, which by the plan can be E22-S4 or E22-S5:

- FIL-03.9: output cleanup looks at the name and then unlinks it. That is two calls. It blocks that story's close.
- C1-R3-01: a write that fills an APFS disk can report `Cleanup` when nothing is left, and the cause `Space` is lost.
- C2R3-01: the wipe walk has no ending for a full chunk under the other flag.

Story check 2 rests on the lead's run, not on mine.

## The run

The guarded tool ran the full check of this commit once, started by the lead at 08:37. I read its results and did not rerun it.

| Item | Result |
|---|---|
| Overall | PASS, 2766.1 s. Hold wait 0.0 s, not partial, no failures |
| Commit and tree | Run commit is this commit. Run tree equals the commit's tree, 0f05792ba2dde4ad9f4a5392bfe1dde5b7bf4d8c |
| Tool | 23 files, none differs from the commit's `scripts/guarded`, and the run's own copy holds the same bytes, before and after the run |
| Tables | `pins.json` f6ba13e4538e4ffce043b2cbca77ec3960182d720e40df6fe96c8ecacbf2a515 and `routes.json` 51e7fbf12970385f5e07991a1969bb60ab6868815766f59868140a60e4283126, both equal to this commit |
| `scripts/check.sh` | 04ebc025ea433f09b5b6e8d817947c647adee106d732f3a9b07e0eddd6479ade, equal to `routes.json` |
| `scripts/check-names.sh` | 364b0f7a6d33a4ace77ef2ae5fed8d41391fc886756cba88621ed677ed486fc3, equal to `routes.json` |
| Grants | 55 read, 0 withheld. Reviewed commit ed1947d; the only commit after it changes the two tables alone |
| Custody | 0 changed, 19 executables, 23 tool files |
| Lanes | source exit 0; static exit 0, 710.5 s; rust exit 0, 997.1 s; native exit 0, 504.7 s; docs exit 0, 198.6 s; fuzz exit 0, 341.2 s |
| Static | 18 of 18 steps. Names PASS, 12178 files, 19 vault files by name only. Unsafe count 438 in 19 crates. Advisories, bans, licenses and sources ok |
| Rust | 4265 passed, 0 failed, 92 ignored, 154 of 154 programs. Workspace 3356/0/76 (130 programs), sync 518/0/9 (15), net 71/0/7 (2), release 275/0/0 (6), release-browser 45/0/0 (1). Guard library requests 0 in all lanes |
| Swift | 399 tests in 57 suites passed, 0 failed, 0 skipped. The APP-09 lane: 18 passed |
| Docs | 15 passed, 0 failed |
| Fuzz | 30 routes, all exit zero, fewest runs 2511, no artifacts and no marks, no route new to the tool |
| Test names against the earlier run | Baseline from 2a0392c. 4638 compared, 0 lost, 0 newly ignored, 0 waived, 151 new |
| Crash reports | 5 new while the run went. 4 are on purpose, from the guard's own test children. 1 is not this run's, see below |
| Limit the run states | Yanked status not proven for 11 crates, as the index is offline: aes-kw, aes-siv, bech32, chacha20poly1305, cmac, dbl, hpke, httpdate, scrypt, x25519-dalek, zeroize_derive. Advisories 1395, newest 2026-10-30, allowed warning RUSTSEC-2026-0374 |

The 151 new test names are larsal-files 124, larsal-crypto 13, doc tests 6 and larsal-platform 8. Of them only 4 are not ok, and all 4 are ignored with their reason: `write_file_decrypt_seeds`, `fil03_t22_measured_costs_for_the_report`, `fil01_t01_fil03_t18_files_open_both_ways_with_the_reference_tool` and `fil03_t08_t09_real_volumes`.

In the run's own program logs I found every story test by name, and no test reads FAILED in any of the 154 logs. The program `larsal_files` reads 114 passed. Its stderr holds the heading `age-testkit: 19 rows OPEN, outside profile age-classic-1 (LD-366), not passes:` and 19 distinct OPEN lines.

The fifth crash report is `xctest-2026-11-07-092200.ips`: launched 09:18:23, captured 09:21:54, parent `xcodebuild`, breakpoint trap in an AppKit layout path. This run's last native lane ended at 09:14, so by its times it belongs to another private root's Larsal test on this shared Mac. No Swift reaches `larsal-files`, so it does not touch this story. It is a real crash in a Swift test somewhere, and the lead should read it.

## The 7 story checks

Each test ran in the run's own log, with the result in the table. The mutants named here went red in my private copy, and the table says which stayed green.

| # | Check | Test | Mutants that went red |
|---|---|---|---|
| 1 | Every published row passes: 128 in profile by their own stage and hash, 19 hybrid rows named and never counted | `fil03_t17_published_vectors_pass`, `fil03_t17_a_thin_or_foreign_corpus_does_not_pass`, `fil03_t17_a_native_pq_row_is_recorded_open_and_never_a_pass`, `fil03_t17_the_discard_pass_counts_a_full_chunk_under_the_other_flag_and_still_refuses`, all ok | v1, v2, v3, v3b, v5. v4 stayed green, second layer |
| 2 | Files open both ways with the outside tool | `fil01_t01_fil03_t18_files_open_both_ways_with_the_reference_tool`: ignored in the run, ok in the lead's log. `fil03_t18_a_set_tool_path_runs_or_fails_loudly`: ok in both | None: I may not run the tool, so I cannot watch this test go red. The Builder's wrong-path proof: `/no/such/tool`, `/usr/bin/false` and ignored-with-no-tool each exit 101. Rests on the lead's run |
| 3 | One changed, cut or swapped byte gives the one generic error and no plaintext | `check3_every_bit_and_cut_of_a_small_x25519_file`, `..._small_passphrase_file`, `..._small_armored_file`, `check3_every_header_byte_and_chunk_boundary_of_a_larger_file`, `check3_swapped_removed_repeated_and_spliced_chunks`, `check3_final_marker_and_trailing_bytes`, `check3_sampled_changes_across_a_larger_file`, `fil03_t04_bad_first_middle_last_chunk_no_final_marker_and_append`, all ok | t1 to t8, all red |
| 4 | Plaintext never written to a temporary file | `check4_no_plaintext_reaches_scratch_in_a_whole_decrypt`, `check4_a_failed_decrypt_touches_no_output_and_leaves_no_scratch`, `check4_encrypting_uses_no_scratch_and_writes_only_ciphertext`, `check4_only_the_file_system_module_can_reach_the_disk`, all ok | s1, s2, s3, s4, all red. s4's message is `plaintext in scratch at Capture` |
| 5 | Keys and passphrases wiped | `fil01_t18_every_ending_of_a_decrypt_leaves_no_secret_in_a_freed_block`, `fil01_t18_encrypt_leaves_no_key_in_a_freed_block`, `fil01_t18_file_primitives_wipe_stack_and_heap`, all ok | w1 to w6, all red. w7 stayed green, the gap C2R3-01 |
| 6 | A work factor above FIL-03's limit refused at once | `check6_a_cost_above_the_ceiling_is_refused_at_once_with_no_memory_for_it`, `fil03_t02_over_ceiling_or_malformed_means_zero_key_derivations`, `scrypt_refuses_a_cost_out_of_range_at_once`, all ok | c1, c2, c3, c4, all red |
| 7 | Two Checkers (crypto) | C1 and Sensitive C2, round 3, below | Not a test. Both approved with 0 blocking |

What the tests really do, from reading them:

- **Check 1** reads every file in the folder and judges each row by the stage it names, and by the SHA-256 of what opened. The pins are exact: 147 files, the folder hash, and a count per stage. A row with a post-quantum identity is recorded by name and returns before product code, so it can never count. My own script, written apart from the crate, got the same counts from the files.
- **Check 2** drives the tool as a child process, with no environment but its own `PATH`. Tool to Larsal: X25519 and passphrase, binary and armor, bytes compared. Larsal to tool: X25519 and passphrase, the tool's output file compared. Payloads: empty, 70,000 binary, image-like, exactly 65,536. Also two recipients both ways, a key file from the keygen, and that key file under a passphrase. A tool failure asserts. A set path always runs, so a mistyped one fails.
- **Check 3** flips every bit and makes every cut of a small X25519, passphrase and armored file, every header byte and chunk edge of a larger file, swaps, removes, repeats and splices whole chunks, moves the final marker, adds trailing bytes, and samples a larger file. Each must give `Error::Decrypt` and no byte to a writer. The only cut that opens is the armor's last line feed, which FIL-01.13 allows.
- **Check 4** records every scratch and output event of a whole decrypt and looks for the marker in each write to scratch. A failed decrypt touches no output and leaves no scratch. Encrypting makes no scratch at all and writes only ciphertext. A source scan proves only `fsio.rs` reaches the disk, and scans inside `fsio.rs` for prints, `fs::write`, `fs::copy` and new doors.
- **Check 5** counts every block the process frees, with a probe allocator, against 13 needles: plaintext, passphrase, identity bytes, identity text, identity text in lower case, the other key file, the X25519 shared secret, wrap key, file key and payload key, and the scrypt wrap key, file key and payload key. It walks every ending of a decrypt and of an encrypt on both roads. `file_wipe` does the same for the crypto primitives, on stack and heap. A control proves the probe sees a block that holds a needle.
- **Check 6** gives seven costs above the ceiling (21 to a 39-digit number) to the public road. Each is `Error::Decrypt` in under 1 s with a memory rise under 64 MiB. The control is cost 18, which must rise past that bound, so the bound measures something. `fil03_t02` counts zero key derivations for every refused cost and one for a legal one.
- **Check 7** is the two Checkers' seals, below.

## The published vectors (LD-366, LD-370)

From C2SP/CCTV, folder `age/`, commit 4448f2097b2daa812c91a26141f9f36c2096b9ca, license 0BSD, CC0 1.0 or Unlicense. 147 test files, folder hash `461c15f61ce87a16ef71f22080a5d7876a1fa21b00c62a6a077883fb4a73555b` by the rule in the folder's `SOURCE.md`. Each file equals the saved download, whose manifest has SHA-256 `300bce4a7afa15c4f96fa3cc8632077da8469b99ca1781163b59f171a81dbb30`.

| Stage a row names | All 147 | In profile age-classic-1, each passes by its stage and hash | OPEN, by name |
|---|---|---|---|
| Success | 26 | 21 | 5 |
| No match | 13 | 8 | 5 |
| HMAC failure | 1 | 1 | 0 |
| Header failure | 62 | 53 | 9 |
| Payload failure | 19 | 19 | 0 |
| Armor failure | 26 | 26 | 0 |
| **All** | **147** | **128** | **19** |

The 19 OPEN rows, each printed by name in a default run, none counted: armor_hybrid, hybrid, hybrid_and_x25519, hybrid_bad_tag, hybrid_currupted_enc_mlkem, hybrid_currupted_enc_x25519, hybrid_extra_argument, hybrid_grease, hybrid_identity, hybrid_long_file_key, hybrid_long_share, hybrid_low_order, hybrid_multiple_recipients, hybrid_no_match, hybrid_not_canonical_body, hybrid_not_canonical_enc, hybrid_short_share, hybrid_uppercase, hybrid_x25519_arg.

## Story check 2: what it rests on

I did not run it. The lead did, in the lead's own session, because the session's permission check refuses that run to a subagent. This is what I could prove and what I could not.

| Item | Result |
|---|---|
| The lead's log | `fil01_t01_fil03_t18_files_open_both_ways_with_the_reference_tool ... ok`, `fil03_t18_a_set_tool_path_runs_or_fails_loudly ... ok`, 2 passed, 0 failed, 19.69 s, exit 0, four key lines from the keygen. Log SHA-256 `e5e7e3940830336345a2f84319e0c331af2d4e9d02effbcd3e8e416202f7374a`, 02:54 on 2026-11-07 |
| Same source | `diff -r` of the proof's source against this commit: exit 0 for `crates/larsal-files` (308 files, git tree `cfa91f3b61b5527bda8af3c807af975171dca554`), `crates/larsal-crypto` (33 files, tree `de16aadc18c924062f763603f08ee2f832e3c0ae`) and `crates/larsal-platform` (tree `42059ae0373f67186ef7f3328b5919e9d638925c`). No source in those crates is newer than the test program the log names, `peer-ed341cd3111ba873`, built 02:24:51 |
| Rest of the tree | The proof's source differs from this commit only by an empty `fuzz/artifacts` folder and by what the commits after the engine and the tool fix moved: `scripts/check-names.sh`, `scripts/guarded/`, and `crates/larsal-browser/tests/int03.rs`. None of those builds into this test |
| The guard | The runner the Builder's rerun commands name, `run-tests-tool.sh`, runs the program under `run-key.sb`, which denies the network. The log's last line is in that runner's form |
| The tool's bytes | `age` `4012dfc2725883beafb710894af4f599b7a94f8c8e0f51f02cc96ab8df33915e`, `age-keygen` `c16e229245123d0ad27442317461d63915416cad0294395cd19ca93feb3211ea`, `age-plugin-batchpass` `9bf9f6691fb6f07e69c84f7d83c6fc1667b405dffac69a3b77b7ee21f9e4ca4c`, hashed as data. `age` and `age-keygen` equal LD-429's manifest. The plugin is 3979458 bytes and equals the archive member by SHA-256, hashed from the archive's stream, never written by me and never run |
| What I cannot prove | That the log came from those tool bytes. The test does not print or pin the tool's version or hash, and neither does the log |

**A second proof that does not rest on that run, and is smaller.** I wrote my own reader and writer of the format in stdlib Python, from FIL-01 and the published rows. No downloaded code ran. It proves the format, not the tool.

| Direction | What | Result |
|---|---|---|
| My reader on published rows | The 15 binary success rows inside the profile. The other 6 success rows are armored, and my reader takes binary only | 15 of 15 opened, each payload hash equal, 72 s |
| My writer to Larsal | X25519 at 0, 1, 65,536, 70,000, 131,072 and 200,000 bytes, and one passphrase file of 70,000 bytes | 7 of 7 opened, bytes equal. One changed byte near the end of a file gave `Error::Decrypt` |
| Larsal to my reader | The same six sizes, two recipients with my key as one, and one passphrase file at cost 18 | 8 of 8 opened, bytes equal, 160.77 s |

My first try of the Larsal side failed with `NotFound` on its first read, because my mutant driver had removed the run folder holding my demo files. The rerun wrote them again. Neither is a fault of the product.

## Mutants

Private copy `mut/tree`, built from `git archive` of this commit, under the guards, one mutant at a time on a green baseline of 341 tests. Each ran the programs of `larsal-files`, 120 tests, and also those of `larsal-crypto` when it touched that crate. Each row's ok and red add up to its baseline, so no test went missing. 30 mutants: 28 went red and 2 stayed green. The tree read 341 ok and 0 red before the first and after the last.

| Mutant | Check | What I undid | Red |
|---|---|---|---|
| v1-no-other-flag-count | 1 | The discard pass no longer tries the other flag on a full failing chunk | `fil03_t17_a_thin_or_foreign_corpus_does_not_pass`, `fil03_t17_derived_vectors_all_behave_and_each_family_is_present`, `fil03_t17_published_vectors_pass` and 1 more |
| v2-one-row-changed | 1 | One byte added to the published row `x25519` | `fil03_t17_a_thin_or_foreign_corpus_does_not_pass`, `fil03_t17_published_vectors_pass` |
| v3-hybrid-counts-as-pass | 1 | A refused hybrid row counts as a pass in the test runner | `fil03_t17_a_native_pq_row_is_recorded_open_and_never_a_pass`, `fil03_t17_a_thin_or_foreign_corpus_does_not_pass` |
| v3b-hybrid-row-identity-passes | 1 | A row with a hybrid identity reads as a pass, not OPEN | `fil03_t17_a_native_pq_row_is_recorded_open_and_never_a_pass`, `fil03_t17_a_thin_or_foreign_corpus_does_not_pass`, `fil03_t17_published_vectors_pass` |
| v4-stanza-long-line | 1 | The stanza body line width check removed | **Stayed green** |
| v5-nonce-at-payload-stage | 1 | A short nonce reports the payload stage, not the header stage | `check3_final_marker_and_trailing_bytes`, `fil03_t17_a_thin_or_foreign_corpus_does_not_pass`, `fil03_t17_derived_vectors_all_behave_and_each_family_is_present` and 1 more |
| t1-no-mac-check | 3 | The header MAC is not checked | `fil03_t13_every_cause_gives_the_same_typed_result_and_message`, `fil01_t02_mac_runs_over_the_original_bytes`, `fil01_t11_low_order_share_and_one_bit_bad_mac_are_generic` and 8 more |
| t2-other-flag-opens | 3 | A full chunk that opens under the other flag ends the file as a success | `fil03_t06_a_snapshot_changed_after_the_check_fails_the_second_pass`, `fil01_t12_bad_prefixes_and_chunk_games_are_one_generic_error`, `check3_every_header_byte_and_chunk_boundary_of_a_larger_file` and 8 more |
| t3-counter-not-in-nonce | 3 | The chunk counter is left out of the nonce | `fil01_t12_bad_prefixes_and_chunk_games_are_one_generic_error`, `fil03_t12_counters_and_offsets_never_wrap`, `check3_swapped_removed_repeated_and_spliced_chunks` and 4 more |
| t4-short-tail-ignored | 3 | A tail shorter than a tag marks the last chunk | `fil03_t06_a_snapshot_changed_after_the_check_fails_the_second_pass`, `fil01_t12_bad_prefixes_and_chunk_games_are_one_generic_error`, `check3_final_marker_and_trailing_bytes` and 4 more |
| t5-second-error-word | 3 | A payload failure gives another error than `Decrypt` | `fil03_t06_a_snapshot_changed_after_the_check_fails_the_second_pass`, `fil03_t13_every_cause_gives_the_same_typed_result_and_message`, `fil01_t12_bad_prefixes_and_chunk_games_are_one_generic_error` and 18 more |
| t6-no-whole-check | 3 | The whole-file check is skipped | `fil03_t06_a_snapshot_changed_after_the_check_fails_the_second_pass`, `fil03_t06_sealed_snapshot_has_no_name_its_handle_only_reads_and_it_reads_the_same_twice`, `fil03_t07_a_later_read_fault_is_reported_as_itself_not_as_corruption` and 56 more |
| t7-empty-last-chunk | 3 | An empty last chunk after a full one is allowed | `check3_final_marker_and_trailing_bytes`, `fil03_t17_a_thin_or_foreign_corpus_does_not_pass`, `fil03_t17_derived_vectors_all_behave_and_each_family_is_present` and 1 more |
| t8-header-reencoded-no-bind | 3 | The second pass no longer compares the header bytes | `fil03_t06_a_snapshot_changed_after_the_check_fails_the_second_pass` |
| s1-plain-to-a-temp-file | 4 | `validate` writes each plaintext chunk to a temporary file | `check4_only_the_file_system_module_can_reach_the_disk` |
| s2-plain-side-file-in-fsio | 4 | The output writer in `fsio.rs` also writes a side file | `check4_only_the_file_system_module_can_reach_the_disk` |
| s3-seal-keeps-the-name | 4 | The sealed snapshot keeps its name | `fil03_t05_each_capture_has_a_new_operation_folder`, `fil03_t05_the_descriptor_defines_the_captured_source`, `fil03_t06_sealed_snapshot_has_no_name_its_handle_only_reads_and_it_reads_the_same_twice` and 26 more |
| s4-scratch-gets-other-bytes | 4 | The scratch writer writes a plaintext marker | `fil03_t05_each_capture_has_a_new_operation_folder`, `fil03_t05_the_descriptor_defines_the_captured_source`, `fil03_t06_sealed_snapshot_has_no_name_its_handle_only_reads_and_it_reads_the_same_twice` and 26 more |
| w1-plaintext-copy | 5 | A plain copy of each plaintext chunk is freed | `fil01_t18_every_ending_of_a_decrypt_leaves_no_secret_in_a_freed_block` |
| w2-file-key-copy | 5 | A plain copy of the file key is freed, decrypt | `fil01_t18_every_ending_of_a_decrypt_leaves_no_secret_in_a_freed_block` |
| w3-passphrase-copy | 5 | A plain copy of the passphrase is freed | `fil01_t18_encrypt_leaves_no_key_in_a_freed_block`, `fil01_t18_every_ending_of_a_decrypt_leaves_no_secret_in_a_freed_block` |
| w4-secret-drop-does-not-wipe | 5 | `SecretBytes` does not wipe on drop | `int01_47_channel_secret_calls_wipe_stack_and_heap`, `fil01_t18_file_primitives_wipe_stack_and_heap`, `bytes_are_zero_when_dropped` and 5 more |
| w5-encrypt-file-key-copy | 5 | A plain copy of the file key is freed, encrypt | `fil01_t18_encrypt_leaves_no_key_in_a_freed_block` |
| w6-identity-copy | 5 | A plain copy of the identity bytes is freed | `fil01_t18_every_ending_of_a_decrypt_leaves_no_secret_in_a_freed_block` |
| w7-other-flag-copy-shipped-tests | 5 | A plain copy of the plaintext is freed in the other-flag branch | **Stayed green** |
| c1-reader-ceiling-gone | 6 | The file reader's ceiling removed | `fil01_t04_bad_scrypt_shapes_fail_before_any_key_derivation`, `fil03_t02_over_ceiling_or_malformed_means_zero_key_derivations` |
| c2-wrapper-ceiling-gone | 6 | The `larsal-crypto` wrapper's ceiling removed | `scrypt_refuses_a_cost_out_of_range_at_once` |
| c3-both-ceilings-gone | 6 | Both ceilings removed | `scrypt_refuses_a_cost_out_of_range_at_once`, `fil01_t04_bad_scrypt_shapes_fail_before_any_key_derivation`, `fil03_t02_over_ceiling_or_malformed_means_zero_key_derivations` and 3 more |
| c4-leading-zero-reads | 6 | A cost with a leading zero is read | `fil03_t02_over_ceiling_or_malformed_means_zero_key_derivations`, `fil03_t17_derived_vectors_all_behave_and_each_family_is_present` |
| u1-plaintext-on-a-disk-without-owners | 4 | Plaintext is allowed on a disk that keeps no owners | `fil03_t08_a_disk_that_cannot_keep_a_file_private_takes_only_ciphertext` |

The two that stayed green:

- **v4:** the width check is not the only layer. `decode_unpadded_into` writes into a 48-byte buffer and refuses a longer body (`crates/larsal-files/src/header.rs:90-94`). The behaviour holds.
- **w7:** this is C2R3-01, a real gap in the test. See "Routed" below. I added the missing ending in my private copy. On the product as it stands the walk is clean: ok, 33.18 s. With the same copy in that branch it goes red at `tests/wipe.rs:289`, exit 101. The shipped walk stays green with that copy, exit 0.

Two more things this table shows. s1 and s2 go red only by the source word scan, not by watching the disk, which is C1-R3-05. And c1 and c2 leave `check6_...` green, because the other ceiling still refuses; only c3, with both gone, turns it red. That is the two layers working.

Another probe, D: a plain file chosen for Decrypt. I gave 200,004 plain bytes. At the end of the copy the scratch file held all 200,004 of them. Then the unlock was refused, and the scratch held none. This is V-2, below.

The Builder's 216 rows, C1's 172 and C2's replay of 195 stand beside these. They were run on the same engine bytes (fix.patch). I did not rerun them.

## The name guard, planted in a private copy

`scripts/check-names.sh` in this commit is the narrower form: `listed = not inside and hashlib.sha256(data).hexdigest() in BIG_OK`. Only files whose whole bytes hash to one of the three published rows, and that are not inside another file, may unpack to 32 MB. What unpacks is matched in full by the same matcher. The Checkers read the wider form, in which nested copies also had the larger cap. I read the narrower one.

The word comes from the guard's own hex at run time and is never printed. A private copy of the guard lists my plants, the way the real one lists the rows.

| Plant | Guard | Result |
|---|---|---|
| A word past 16 MB in a new stream | Real | Exit 1, cannot unpack |
| A new 17 MB stream, no word | Real | Exit 1, cannot unpack |
| A real row: one byte changed in the stream, one in the head, one added, one put in front | Real | Each exit 1, cannot unpack |
| The row's stream without its head, or under another head | Real | Each exit 1, cannot unpack |
| A real row nested in gzip, zlib, zip or base64, or inside a plain tar | Real | Each exit 1, cannot unpack |
| The row under another name, or in a deeper folder, same bytes | Real | Exit 0: these are the listed bytes |
| The row's inner bytes, unpacked, plain | Real | Exit 0 |
| A word past 16 MB in a listed file, top level | Listed copy | Exit 1, holds the word, near line 1153434 |
| The same file with no word | Listed copy | Exit 0 |
| A word past 16 MB in a nested gzip, zlib, zip or base64 copy of a listed file | Listed copy | Each exit 1, cannot unpack |
| A word in the last bytes of exactly 32 MB | Listed copy | Exit 1, holds the word |
| 33 MB | Listed copy | Exit 1, cannot unpack |

The guard's own self test: exit 0. The whole-tree scan of this commit: `names: PASS (12178 files scanned, 19 vault files name-only)`, exit 0, 263 s. It hides nothing: only those three exact files, not inside another file, may unpack past 16 MB, and what unpacks is still matched in full.

I also changed the guard itself in my private copy, to see what its self test catches:

| Guard mutant | Self test | The real row or plant |
|---|---|---|
| G1: every file counts as listed | Exit 1, red | |
| G2: nested copies count as listed too | Exit 0, green | The row nested in gzip: exit 0, wrongly |
| G3: a listed file is not matched at all | Exit 0, green | Passes, wrongly |
| G4: the cap is not raised | Exit 0, green | The real row: exit 1, cannot unpack, so the whole-tree scan catches it |

So the self test has no row for G2 and G3. The rule holds today, by my plants. That is V-3, and the fix is one self-test row with a temporary `BIG_OK` entry.

## Tables

The last commit moves `scripts/guarded/tables/pins.json` and `routes.json` only. Every line is true for this commit, and nothing moves that the story does not need.

| Table line | Old | New | Why |
|---|---|---|---|
| `crates/larsal-platform`, in `net:larsal-platform/larsal_platform`, `workspace:larsal-platform/larsal_platform`, `workspace:larsal-sshagent/own_agent` | `b853ae73176c653f34f2defce8ba75adf38e04b5` | `42059ae0373f67186ef7f3328b5919e9d638925c` | Equal to this commit. The old value was stale |
| `crates/larsal-crypto`, in `workspace:larsal-sshagent/own_agent` | `5d5861a68cf567fb9e108174a0cedbd2ac27de4c` | `de16aadc18c924062f763603f08ee2f832e3c0ae` | Equal to this commit. The old value was stale |
| `Cargo.lock`, in `workspace:larsal-sshagent/own_agent` | `3f6a715903995f8cb1ee1b9a6abf4b66b61eab02` | `47270a1d7ec1e2f5aefe7617ca1344e407659191` | Equal to this commit. The old value was stale |
| `reviewed_commit` | | `ed1947d08dba8106db7a6a0b34a14c88b1317ea0` | The parent of the tables commit |
| `reviews.E22-S3` | absent | Added, in the form of `reviews.E16-S7a`, source commit ed1947d | The three rows above now name it. Its text says "its proof: LD row of the merge", so that row must exist at merge |
| `routes.json`, `scripts/check-names.sh` | `59df2b27bc2797cefa963ffb8ef508da86dff0c68e5135b37bf49d527ff643a9` | `364b0f7a6d33a4ace77ef2ae5fed8d41391fc886756cba88621ed677ed486fc3` | Equal to this commit |
| `routes.json`, `fuzz_routes.file_decrypt` | absent | `cc9a5a6ad53a92c7896f8d69c273989ac981c2bd17d7d3c4341d5e16e16fc288` | Equal to the target. 30 routes |
| `routes.json`, `fuzz_bins.file_decrypt` | absent | Added | 30 bins, equal to `fuzz/Cargo.toml` |
| `routes.json`, `fuzz_cargo_rest_sha256` | moved | `7d044c244665025f41f7ee9f6ab13268d4bce58ecc0d53aa1f2618c36ee69e35` | Equal to what I computed |

My own check: 55 rows, 43 pinned paths, 0 pins differ from this commit or the reviewed commit. No row was added or removed. `byte_checks` and `routes.json`'s `functions` did not move. `check_sh_sha256` still equals `scripts/check.sh`, which this story does not touch.

## Zero knowledge (LD-340, LD-371)

This crate has no network, no server, no upload and no verifier. It depends only on `larsal-crypto` and `larsal-platform`. `std::net`, `TcpStream`, `Command::` and `std::process` appear in `src/` only in tests: the scans that forbid them, and test helpers that call `/usr/bin/xattr`, `/usr/bin/touch`, `/bin/chmod` and `/bin/ls`. As LD-371 says, anyone who holds a passphrase-encrypted file can test guesses offline. That is the format, and MSG-FILE-LIMITS must say so when a screen exists. It is not a Larsal service, so LD-340 is not touched.

## Findings rows

The lead numbers these. Severity is mine or the Checker's. **None blocks this story.** "First caller" means whichever of E22-S4, E22-S5 or E23-S3 first calls this crate.

| Finding | Severity | What | File, input, result | Status |
|---|---|---|---|---|
| FIL-03.9 | Medium | Output cleanup looks at the name and then unlinks it: two calls, not one bound to the inode | `crates/larsal-files/src/fsio.rs:587-596`. Another writer of that folder swaps the name between the look and the unlink. The inode was emptied first, so no plaintext stays; the swapped-in file is what is lost | Open, blocks the first caller's close |
| C1-R3-01 | Medium | A false alarm on a full APFS disk: `Cleanup` when nothing is left, and the cause `Space` is lost | `fsio.rs:594,617`, test `flow.rs:1386`. A decrypt too big for an APFS image fills it. Emptying needs room APFS lacks, the unlink works, and all the room comes back. C1's 3-line change in a private tree gave `Space` 48 of 48 | Open, before the first screen or CLI shows this message |
| C2R3-01 (C1-R3-03 is the same road) | Medium | The wipe walk has no ending for a full chunk under the other flag | `tests/wipe.rs:106`, road `payload.rs:84-89`. My w7 stays green. With the ending added the product is clean and w7 goes red | Open, first caller |
| V-1 | Medium | The carried items were routed to E22-S4 only, and the plan lets another story land first | `plan/epics.md:689` lets E22-S5 land first, and line 718 has E23-S3 wait on E23-S2 and E22-S3, not on E22-S4. E22-S5's checks do not name these items | Open. This page says "first caller", and the rows below add the line to E22-S5 |
| V-2 | Low | A plain file chosen for Decrypt is copied whole to scratch before any look | `fsio.rs:220-239`, `373-393`. Input 200,004 plain bytes. Result 200,004 in the scratch file at the end of the copy, then `Error::Decrypt`, then none. FIL-03.5 says never stage plaintext. Story check 4 is about decrypted plaintext, so it is not broken. Fix: read the first line and refuse before capture unless it is the version line or the armor's first line, as `keys.rs` `looks_encrypted` does | Open, first caller |
| V-3 | Low | The name guard's self test has no row for "not inside another file", or for "a listed file is still matched" | `scripts/check-names.sh`. G2 and G3 stay green in the self test. My plants prove both rules hold today | Open |
| V-4 | Low | The peer test records no version or hash of the tool. The passphrase route ran only by the plugin; the terminal route `-p` did not run | `crates/larsal-files/tests/peer.rs`. Nothing ties the lead's log to the tool's bytes. Fix: print the tool's version, and its hash, in the test | Open |
| V-5 (C2R3-06 is the same) | Low | The record does not name the plugin that ran | LD-429 (`spec/decisions.md:536`) says only `age`, `age-keygen` and LICENSE were extracted. `MANIFEST.json`'s `extracted` list says the same. Research section 8 (`spec/research/file-encryption.md:95`) says no plugins | Open. Words under "What LD-429 must add" |
| C1-R3-02, C2R3-02 | Low | Opening the fuzz door has no test that goes red | `decrypt.rs:196`, `lib.rs:42`. C2 proved a 5-line `compile_fail` doc test | Open |
| C1-R3-04 | Low | FIL-03-T20's check does not see BSD flags | `flow.rs:959` | Open |
| C1-R3-05 | Low | The `fsio.rs` scan is a word list | `scratch.rs:233`. A disk write by a word not on the list passes | Open |
| C1-R3-09 | Low | Two tests share one folder per process, so the volumes program needs one thread | `tests/volumes.rs:74` | Open |
| C2R3-03 | Low | `Validated::write_to`, a stream the caller owns, was missing from E22-S4's list | `decrypt.rs:331` | Now on that list |
| C2R3-07 | Low | A doc comment is on the wrong test. `CleanupEmpty`'s words can mislead when the name was swapped | `crates/larsal-platform/src/macos/folder.rs:413-417`, `crates/larsal-files/src/error.rs:68` | Open, review the words before a screen shows them |
| C1-R3-06, C2R3-04 | Low | Guard cleanups, and a narrower form | ed1947d took the narrower form, so nested copies keep the 16 MB cap. The missing self-test row is V-3 | Closed but for V-3 |
| C1-R3-07, C2R3-05 | Low | Notes said story check 2 did not run | The lead's run came after. The rows on this page are corrected | Closed by this page |
| C1-R3-08 | Low | Two messages are not in FIL-03's table | Rows proposed below | Closes when the lead adds them |
| C1-R3-10 | Note | The output arm of the list error | C1 found no way in, probe q07c | Note |
| C1-R2-10 | | The pins needed a reviewed move | Moved in 109ef36, see "Tables" | Closed |


## Routed, and safe while nothing calls this crate

Who calls `larsal-files`, on this commit:

- `cargo tree --offline --locked -i larsal-files --workspace` prints only the crate itself. `larsal-ffi` and `larsal-cli` list it at no depth.
- `git grep` outside the crate finds it in `Cargo.lock`, `fuzz/Cargo.lock`, `fuzz/Cargo.toml`, the fuzz target, and two comments (`crates/larsal-crypto/tests/file_primitives.rs`, `crates/larsal-platform/src/macos/folder.rs`). Nothing under `macos/` names it.
- `fuzz-door`: the default workspace build shows only feature `default`. Only the fuzz crate turns it on, and that crate is its own workspace, so the feature cannot unify into a product build. `--all-features` appears in scripts only on `cargo metadata` and `cargo tree`, which build nothing.

| Open item | Is it safe to leave open now | Why | Must close before |
|---|---|---|---|
| FIL-03.9, output cleanup custody | Yes | `abort` empties the inode through its own descriptor first, so no plaintext stays under any name. The race can only lose a file that someone who can write to the output's folder planted in the moment between the look and the unlink. No caller exists to run it | The close of the first caller, E22-S4 or E22-S5 |
| C1-R3-01, `Cleanup` for `Space` on a full APFS disk | Yes | A false alarm in the safe direction: it says data may remain when nothing does. The unlink worked and the room came back. No screen can show it. C1's 3-line change in a private tree gave `Space` 48 of 48 | The first screen or CLI that shows this message |
| C2R3-01, no wipe ending for the other flag | Yes | A missing test, not a leak. In my private copy the walk with that ending added passes on the product as it stands, 33.18 s. The same walk with a plain copy in that branch goes red, and the shipped walk does not. The ending, about 7 lines, is below | The first caller |

Others go to the same list: the warned consent for `Error::Unprotected`, the weak key file flag (C2R2-06), `Validated::write_to` to a caller's stream (C2R3-03), the zeroing allocator in the front end's path, close errors (FIL-03.10), the sweep's record (FIL-03.11), no look at `MNT_LOCAL` for a network volume (C2's limit), and every item on the E22-S4 list below. The plan's order lets E22-S5 land first, and E22-S5's checks do not name any of them, so the list must say "first caller" (V-1).

Nothing has been done about these on this commit. For the first caller:

1. C2R3-01's ending, as I ran it, before `// Cancel in the check and in the write.` in `tests/wipe.rs`:

```rust
let at = x_file.windows(4).position(|w| w == b"--- ").unwrap();
let end = at + x_file[at..].iter().position(|b| *b == b'\n').unwrap() + 1;
let cut = &x_file[..end + 16 + 3 * 65_552];
let other_flag = black_box(open_all(cut, &by_key));
assert!(matches!(other_flag, Err(larsal_files::Error::Decrypt)));
drop(other_flag);
```

2. V-2's look before capture.

Card rows with no test on this commit: FIL-01-T06, T07, T10 and T17, FIL-03-T15, T19 and T23. The other 38 of 45 have one. FIL-03-T19 goes to E22-S6 and the other six to E22-S4, by the cards. FILE-P1 to P4 (`plan/security.md:214-217`) and AT-FILE-01 to 14 (`plan/attacks-and-checks.md:169-182`) stay todo: each names the app against the CLI, or later work, so none moves here.

## Secrets (rule 4), on the delta

- No `println!`, `eprintln!`, `dbg!`, `print!`, `tracing` or `log::` in `crates/larsal-files/src` outside tests, or in `aead.rs`, `bech32.rs` or the fuzz target.
- Types that print: `Identities` prints only a count. `Snapshot`, `Unwrapped`, `Validated`, `WeakFile` and `Validation` print only their names. `Stanza` is `pub(crate)` and holds only public bytes of the file. `Recipient` is a public key.
- `Error` holds no text from a file and no path. Internal `Failure` stages map to the one `Error::Decrypt`.
- Passphrases are `SecretString`. Identities, the file key, the payload key and the plaintext buffers are `SecretBytes`, or `scrubbed` on the stack in `larsal-crypto`. The scrypt crate's working blocks are plain heap, and rely on the front end's zeroing allocator (FIL-01.18). `larsal-files` installs none, so the first caller must keep it in the path.

## Rule 3 and rule 1, on the delta

- **Rule 3:** the diff adds no import of a crypto crate outside `larsal-crypto`. The one place that names them is a test's forbidden-word list, `crates/larsal-files/src/tests/format.rs:639-643`. `larsal-crypto` adds `aead.rs`, `bech32.rs`, `kdf::scrypt`, `base64::Form::Unpadded` and `bridge::Secret::from_bytes`, all over crates approved in LD-379.
- **Rule 1:** the guard's whole-tree scan of this commit passes: 12178 files scanned, 19 vault files by name only, exit 0, and its self test exit 0. Row names in `testdata/age-testkit/` hold no banned word. Its `README.md` and `SOURCE.md` name the format and its public project, as the research card and FIL cards do (S01, S02, S04, S09).

## Measured

FIL-03-T03 runs in every default run: `fil03_t03_memory_does_not_grow_with_the_file`, 512 MiB against 1 MiB, budget 8 MiB. FIL-03-T22's numbers are carried from round 1's code and were not rerun on this commit. Release, arm64, Apple M4 Pro, third run of three:

| Route, 4 GiB | Encrypt | Capture | Unlock | Validate | Save | Memory rise |
|---|---|---|---|---|---|---|
| X25519 | 4.991 s, 820.7 MiB/s | 2.746 s | | 4.399 s, 931.1 MiB/s | 5.113 s, 801.2 MiB/s | 0.02 MiB |
| Passphrase | 5.324 s | 2.723 s | 0.365 s | 4.372 s | 5.798 s | |

The key derivation at the read ceiling took 1.600 s, peak resident 1286.47 MiB, rise 1024.03 MiB. Round 3's production changes add an `fstatfs` at each new output and scratch check, and a second tag try only on a chunk that already failed. Neither is on a good file's data path. That is a reading, not a measurement.

The fuzz target `file_decrypt` ran 321,624 runs in 91 s in the Builder's round, no crash, cov 1897, peak 468 MiB. In the guarded run of this commit it ran 92,163 runs in 31 s, with no artifacts and no marks.

## Real volumes, carried from the Builder and C1

Private disk images attached `-nobrowse -noverify -noautoopen`, detached by device. I did not rerun them, as `hdiutil` must run with no profile. `tests/volumes.rs` shows as ignored in a default run, with its reason.

| Volume | Flag | Save | Encrypt | Scratch |
|---|---|---|---|---|
| FAT32, exFAT | true, mode reads 700 | `Unprotected`, listing empty | Ok, opens | `Destination` |
| APFS and HFS+, no owners | true, mode 600 | `Unprotected` | Ok | `Destination` |
| APFS and HFS+, `-owners on` | false, mode 600 | Ok, mode 600, bytes same | Ok, mode 600 | Ok |
| APFS read-only | true | `Destination` | `Destination` | not asked |
| Small FAT32, file too large | true | `Unprotected` | `Space`, names [] | not asked |

C1's raw scan after detach: no volume that refused plaintext holds its marker in any block, and the two controls do.

## The two Checkers (story check 7)

| Checker | Verdict | Read | Seal SHA-256 |
|---|---|---|---|
| C1 | APPROVE_EXACT_CANDIDATE, 0 blocking | fix.patch `077039c8806529308eb834da1c605269779ceaed6b7ad2fbfcf29c67e69cbc42`, and the wider guard diff `869bc7b4c48b8d17b5879fbbfea177b72d4e3f1483b66f9ce5d826a0a0fd3779` | `0010b3685f1ffc8ece8e9b068043d16dfb89fbc4b4fa8e8c1ce2a4a1f1ca1165` |
| Sensitive C2 | Approve the exact candidate, 0 blocking | The same two | `bd1502b30a373d74eed18e8762734a6680c6fe67bc44ec5ae62faee60e974cd2` |

I checked that those two patches and the two commits the lead wrote are the whole difference from 8403aad: 8403aad plus the tool patch has the tree of 88df65f, plus fix.patch has the tree of 6e04189, and only ed1947d (`scripts/check-names.sh`) and 109ef36 (the two tables) follow.

What the Checkers measured beyond the tests: 1011 corpus tries, 36000 seeded mutations near chunk edges, 18000 armor text mutations and 4832 small-file tries at every position, each equal between rounds (C1). 8,710 inputs across rounds, where 60 changed internal class and none opened or stopped opening (C2). 400 chunks under the other flag stop after 131,104 bytes (C2). C2 disclosed one rule break of its own: a shortened shell prefix let rustup download a toolchain, removed at once and not used. C1 disclosed three small slips of its own, none touching the candidate.

## Rows the lead carried

LD-430 is the mapping row, LD-431 the plugin record and which yes it rests on, LD-432 the build's decisions. F-340 to F-344 are the findings rows. The story status line and the carried line for E22-S4 and E22-S5 are in plan/epics.md, and FIL-03's two message rows are in its table.

## Limits of this signature

1. **Story check 2 rests on the lead's run.** I did not run the tool, its keygen or its plugin, and `LARSAL_AGE_TOOL` stayed unset. I proved the source was the same bytes. I cannot prove the log came from the hashed tool, as the log records no tool hash or version (V-4).
2. **The passphrase route** of that check ran only by the batch plugin. The tool's terminal route did not run.
3. **arm64 only.** No x86_64 test ran, and the card's second target stays open.
4. **FIL-03-T18's** 4 GB case, Unicode names, generated and manual passwords and app against CLI go to E22-S4 and E22-S5.
5. **19 hybrid rows are OPEN** (FIL-01.20). "Every published vector" means 128 of 128 in profile, by the mapping row, which the lead must still accept.
6. **Memory proof** sees freed heap blocks and, through `scrubbed`, stack in `larsal-crypto`. Registers and swap are not proven. The scrypt crate's working blocks rely on the front end's zeroing allocator, which this crate does not install.
7. **Real volumes and FIL-03-T22's numbers** are carried from the Builder and C1, not rerun on this commit. `hdiutil` must run with no profile. No network volume was tested, and `check_new` reads the mode and the ignore-ownership flag, not `MNT_LOCAL`, so a network volume that reads 0600 back would pass (C2's limit).
8. **Fuzz** is short: 31 s here and 91 s in the Builder's round. The 24-hour run waits for E13-S3.
9. **Open in the cards:** FIL-03.3's allocator abort review, FIL-03.10's checked close, FIL-03.11's sweep record, FIL-03-T07's crash and power cases (E22-S6).
10. **Randomness** cannot be proven by tests. It comes from `larsal-crypto`.
11. **The run's stated limit:** yanked status for 11 crates, and advisories only to 2026-10-30.
12. **The Checkers read the wider guard form** and not the last two commits. Only I read those two. I did not rerun the Builder's or the Checkers' mutants.
13. **What I did outside my root or the rule's plain words.** All read only: one crash report in the owner's DiagnosticReports, and the saved archive's stream in the checkpoints folder. My name-guard plants and whole-tree scan ran in Python without waiting on the native hold, as the rule names cargo steps. My mutants ran beside the lead's guarded run on a shared Mac, and read green before and after. My stdlib reader ran with no sandbox and wrote only under my root.

## Evidence

| What | SHA-256 |
|---|---|
| The lead's peer log | `e5e7e3940830336345a2f84319e0c331af2d4e9d02effbcd3e8e416202f7374a` |
| The Builder's rerun commands | `af40da92f561abf94fb74f86811331ca146405389266af731d1f7f7ab7273bd0` |
| The tool patch | `ed1d660c7f5ac40117fea0dee7df0519768463f428b7ec51e5d551c7a03ef453` |
| The vectors and engine patch | `077039c8806529308eb834da1c605269779ceaed6b7ad2fbfcf29c67e69cbc42` |
| The wider guard diff, not taken | `869bc7b4c48b8d17b5879fbbfea177b72d4e3f1483b66f9ce5d826a0a0fd3779` |
| The run's summary | `97d832a725f578cfdb3e4814f3dad072119885fa50a7186ed9901de8ec3f544e` |
| My mutants | `8d619336dd62d70a4e709dd76a31933047fe2973a3a11eefc8510413cfc5908d` |
| My name-guard plants | `02000771e6333102d4e262e23d07f83670431eab96a3b5c1393cecc5609afe9a` |
| My experiments | `b0e2285c19ab3c04e467a8ac2a05e68bcf2ca39788a16fccd32108e3a2b2707d` |
| My stdlib reader and writer | `d67a8285baab8b0e11c7e2d0decd53abbe0366a6e08322e665b94036d7f6fc40` |

The guarded run's root was /private/tmp/larsal-gc-109ef36-7qdo. These files do not last, so the numbers above are what stays.

## Report end

- Story: E22-S3.
- Files changed by Verify: none in the project. This page is proposed for `security/parity/`.
- Proof: this page, commit `109ef3660c656e47beaac581898066fcbffd9a8f`, guarded run PASS.
- Open issues: under "Findings rows" and "Limits of this signature".
- Next step: the lead merges this commit, adds this page, the status line, the FIL-03 rows and the decision rows, and numbers the findings. Whichever story first calls this crate closes FIL-03.9, C1-R3-01 and C2R3-01 first.

## Decision rows, as the Builder proposed them, corrected for commit 109ef36

The lead numbers these at merge. Corrections from the Builder's text are the peer check (row 6, row 7), the tables (row 14) and the name guard (row 15). Names of files under `proof/` and `CANDIDATE-NOTES.md` are the Builder's private files, which do not last; this page copies what must survive.

### Row 1: the crate and its data shape

E22-S3 adds `crates/larsal-files` (FIL-01, FIL-03; LD-366 to LD-371, LD-379). It depends only on `larsal-crypto` and `larsal-platform`, with `#![forbid(unsafe_code)]`. It has no process, no network, no FFI, no CLI and no Swift.

A decrypt is a chain of states, each made only from the one before it and consuming it. Only `Validated` hands out plaintext, so skipping a state does not compile (the crate's `compile_fail` doc tests).

| State | Holds |
|---|---|
| `SourceFile` | One read handle on the chosen input, opened with `O_NOFOLLOW`, and the identity it recorded |
| `Snapshot` | One read handle on sealed ciphertext: no name, no writer, link count 0. Inside the crate, a key file already read into wiping memory uses `in_memory`, which is `pub(crate)` |
| `Unwrapped` | That, the accepted header bytes, its nonce, the payload key and the work factor |
| `Validation::Ready(Validated)` | That, and the plaintext length a complete check proved |
| `Validation::Weak(WeakFile)` | The same, not yet agreed to; `accept()` stands for the user's consent |

Why: a normal stream reader hands out plaintext before the last chunk is proven. FIL-03.4 to FIL-03.7 ask for a whole check first, with no plaintext temporary file and bounded memory. The research card section 5 names this flow as its candidate.

Cost: disk traffic of one snapshot write and two reads, and two decrypt passes. The measured numbers are under "Measured" on this page.

`open_bounded` is `pub(crate)`. It goes past the consent state on purpose, for a key file only, and it reports the low work factor.

### Row 2: what larsal-crypto gained

Rule 3 holds: only `larsal-crypto` imports the crates of LD-379. New there, each free of any arrangement of the format, each with a named RFC test:

- `aead.rs`: ChaCha20-Poly1305 in place (RFC 8439). An open checks the tag first and leaves the data unchanged when it fails.
- `bech32.rs`: original Bech32 only, with a checked prefix, length and padding. Bech32m is refused.
- `kdf::scrypt` (RFC 7914), with `SCRYPT_MAX_COST = 2^23` (log N 20, r 8, p 1) checked before any work.
- `base64`: `Form::Unpadded` and `decode_unpadded_into`, both canonical.
- `bridge::Secret::from_bytes`: an X25519 secret from bytes that are already in wiping memory.

No new crate and no download.

### Row 3: what larsal-platform gained

Three calls in `macos/folder.rs`, where the unsafe and the libc already live. `open_regular` and `create_in` are not changed, so no other caller moves.

- `open_regular_nofollow`: F-101's open with `O_NOFOLLOW`, for a path chosen as one file (FIL-03.5). A link at the last step is refused by the open itself, so no look at the path before it can be raced. It never waits.
- `has_acl`: true when an open file or folder has an access control list (`acl_get_fd_np`, `ACL_TYPE_EXTENDED`). Any error but "it has none" (`ENOENT`) comes back as an error, and the caller counts that as a list.
- `ignores_ownership`: true when an open file's volume is mounted ignoring ownership (`fstatfs`, `MNT_IGNORE_OWNERSHIP`). An error comes back as an error, and the caller counts that as ignoring.

### Row 4: a folder that passes on an access list gets not one byte

FIL-03.8 says not to preserve an unexpected ACL. FIL-03.20 says no owner ACL inheritance. A new file in a folder with a `file_inherit` entry takes that entry from the system, while `fstat` shows 0600. So a mode check says nothing. Reproduced on a real folder with `/bin/chmod +a` in `fil03_t08_fil03_t20_a_folder_that_passes_on_an_access_list_gets_not_one_byte`, red on round 1's code.

**Decision: refuse and abort. Do not clear.** After the exclusive create and before the first byte, `NewOutput::create` asks the descriptor for a list. If there is one it runs the normal cleanup and returns `Error::Destination` (MSG-FILE-DESTINATION, "This location cannot be used"). The same check runs on the scratch root at its open, on each operation's folder when it is made, and in the sweep. A list that cannot be read counts as one, and that road is reachable: `everyone deny readsecurity` (`fil03_t08_a_list_that_cannot_be_read_counts_as_one`). It holds on every volume, and a list naming one user counts the same as one naming everyone.

Why not clear it: whoever the inherited entry lets in can open the empty file between the create and the clear, and keep that descriptor. A descriptor cannot be taken back. Only a refusal guarantees that no byte goes into an inode that had a list from its birth.

Why not create without one: `openx_np` takes a security descriptor at creation, but it has only a path form, and FIL-03.8 asks for descriptor-relative creation in a bound parent.

A folder's own list that it does not pass on changes nothing: `fil03_t08_a_list_the_folder_keeps_to_itself_changes_nothing`. The usual `everyone deny delete` on a Mac user's own folders is of that kind. Encrypted outputs take the same road, as FIL-03.8 speaks of all outputs.

The project's other way with lists is the safe save (F-089, `keep_file_info`): it copies the vault file's list on purpose, because that list is the user's own choice on the user's own file. This story has no such file: every output is new, and FIL-03.8 says so.

Sources, read on this Mac:

- SDK `man3/acl_get.3`: `acl_get_fd` returns null and sets `errno`, `ENOENT`, `EOPNOTSUPP`. `man3/acl_get_fd_np.3`.
- SDK `sys/acl.h` line 102: `ACL_TYPE_EXTENDED = 0x00000100`.
- SDK `man1/chmod.1` lines 417 to 426: `file_inherit`, `directory_inherit`.
- SDK `sys/stat.h` line 421 (`fchmodx_np`), `sys/fcntl.h` line 627 (`openx_np`, path only) and line 644 (`_FILESEC_REMOVE_ACL`).

Not verified: no network is allowed in this round. From memory only: common file tools and the system's copy library clear a list after creation. They do it for metadata correctness, and they have no reader to keep out of a plaintext file. The decision does not rest on it: it rests on the descriptor argument above.

### Row 5: a disk that cannot keep a file private (the lead's ruling, C1-R2-02, C1-R2-09, C2R2-08)

**A volume cannot keep 0600** when a new 0600 file reads back with another mode, or when it is mounted ignoring ownership. A flag that cannot be read counts as ignoring.

| Output | On such a volume |
|---|---|
| Encrypted | Allowed. The descriptor check still holds regular type and link count 1, and cleanup still goes by device and inode |
| Decrypted | Refused with `Error::Unprotected`, a distinct proposed reason. E22-S4 adds the warned consent |
| Any, with an access list on the new file | Refused with `Error::Destination`, on any volume |
| Scratch | Refused with `Error::Destination`: `private()` counts such a volume as not private |

**Cleanup goes by what is left, not by the link count.** FAT32 and exFAT go on showing one link after the unlink, so round 2's look at `nlink` gave a false alarm. `abort` now maps:

| Emptied through its handle | Name removed | Result |
|---|---|---|
| Yes | Yes | Ok, or the operation's own reason |
| Yes | No, or the name is not ours any more | `Error::CleanupEmpty`, proposed: "Larsal could not remove a file it made. The file is empty. Check the destination before you leave." |
| No | Either | `Error::Cleanup`, MSG-FILE-CLEANUP |

A name someone else already removed gets `CleanupEmpty` too: the file may live on under another name, and it is empty. That is the honest statement this layer can make.

Proved on real private disk images (`proof/volumes.txt`): FAT32, exFAT, APFS mounted with no owners, and APFS with `-owners on` as the control. `hdiutil` was refused under `compile.sb`, so the `hdiutil` steps ran with no profile. The test itself ran under `run-key.sb`. `tests/volumes.rs` shows as ignored in a default run, with its reason, and a set `LARSAL_TEST_VOLUMES` always runs.

### Row 6: published vectors, derived vectors

`crates/larsal-files/testdata/age-testkit/` holds the 147 published test files with their `README.md` and a `SOURCE.md` (github.com/C2SP/CCTV, commit 4448f2097b2daa812c91a26141f9f36c2096b9ca, license 0BSD, CC0 1.0 or Unlicense).

- **They run in every default run, with no ignore,** through `fil03_t17_published_vectors_pass`.
- **Exact pins:** 147 files, folder hash `461c15f61ce87a16ef71f22080a5d7876a1fa21b00c62a6a077883fb4a73555b`, and exact counts per stage: Success 21, NoMatch 8, HmacFailure 1, HeaderFailure 53, PayloadFailure 19, ArmorFailure 26, in all 128. A row cut, added or changed fails.
- **19 rows are OPEN by name, never a pass,** outside profile age-classic-1 (LD-366). They print in a default run as a direct write to stderr, which the harness does not capture. On a green `scripts/check.sh` step the output stays in that step's log, and `check.sh` was not touched. The mapping row is the lead's (LD-370).
- **A row with `armored: yes` goes through the armor route.** No aliasing table. The product's own route must refuse it too.
- **A row with no identity line** uses an unrelated demo identity, so its stage is the header's.

**The discard pass, by the lead's ruling:** when a full chunk fails, it tries the other flag. If that opens, the plaintext is counted as internal prefix (FIL-03.17), and the outcome is still `Failure::Payload`. Nothing new opens, the second pass is unchanged, and external output stays 0.

**A short or missing nonce is `Failure::Header` at unlock.** The second pass keeps its own check as a payload failure: at that point the header was already accepted, and a nonce that now differs means the snapshot changed.

**One change beyond the rulings:** the armor reader no longer calls an armor block with an empty body an armor failure. It reaches the header stage, as `armor_empty` says. Nothing new opens.

`crates/larsal-files/testdata/derived/` still holds 129 demo vectors from `testdata/make_derived.py`, stdlib Python written apart from the crate. Six changed expected stage or form with the rules above.

**Record for LD-429:** see "What LD-429 must add" on this page. The plugin ran once, in the lead's session, in the peer check.

### Row 7: the peer tool test

`crates/larsal-files/tests/peer.rs`: in a default run `fil01_t01_fil03_t18_files_open_both_ways_with_the_reference_tool` shows as `ignored`, with its reason. When `LARSAL_AGE_TOOL` is set it always runs, through `fil03_t18_a_set_tool_path_runs_or_fails_loudly`, so a mistyped path or a wrong tool fails the run.

It holds both modes both ways. The passphrase route needs no terminal: the batch plugin takes the phrase from `AGE_PASSPHRASE`, through `age -e -j batchpass` and `age -d -j batchpass`, with the plugin on `PATH`.

**Story check 2 ran in the lead's session, and rests on that run:** 2 passed, 0 failed, exit 0, on the same bytes of `larsal-files`, `larsal-crypto` and `larsal-platform`. The session's permission check refuses that run to a subagent, so no Builder, Checker or Verify agent ran it.

### Row 8: the work factor ceiling has two layers

A file's cost is refused by the header reader, and again by `kdf::scrypt`. Undoing the reader's alone leaves `check6` green, because the wrapper holds, while `fil03_t02` and `fil01_t04` go red (m09). Undoing the wrapper's alone turns `scrypt_refuses...` red (m72). Undoing both turns `check6` red (m75). The ceiling is kept in both places on purpose: `larsal-crypto` must not allocate 2 GiB for any caller.

### Row 9: output cleanup is not yet what FIL-03.9 asks

`abort` empties the output through its own descriptor, so no plaintext stays in that inode under any name. It then looks at the name and unlinks it: two calls, and I found no public macOS call that unlinks by inode. Its doc comment promises nothing about what the unlink removed.

Open: someone who can write to the output's folder can swap the name between those two calls and lose their file. FIL-03.9 sends the choice to a platform review: a custody mechanism, or declining to unlink. FIL-03.7 says a declined cleanup fails E22-S4's cancel check, so that review has to happen before E22-S4 can close. **This stays a blocker of the close of the first story that calls this crate, E22-S4 or E22-S5 (V-1).**

### Row 10: the sweep's proof of ownership is structural

`ScratchRoot::sweep` removes a leftover only when the root's name is still the root opened, the folder has the crate's name form, is 0700 and this user's, has no access list, holds no live operation's lock, and holds nothing but one regular 0600 snapshot with link count 1. FIL-03.11 says "authenticated". A record bound to a key is open and is routed to E22-S4, because the key would come from the app's settings.

The list of the root goes by name, after that check, as std has no listing by descriptor. A same-user process that can rename the folder in between can aim the sweep elsewhere, where it still takes only the exact form above (a `ponytail:` comment names this).

### Row 11: a failed scratch cleanup is `Error::Io`

FIL-03.11 says failure to remove owned artifacts is surfaced. A failed capture whose cleanup also failed says `Error::Io`, whatever stopped it, and so does an operation whose folder could not be removed after its checks failed. MSG-FILE-CLEANUP is not used there: it speaks of readable data at a destination, and scratch holds ciphertext. The next start's sweep retries.

### Row 12: choices left to E22-S4 that this layer exposes

- **The warned consent for a decrypted file on a disk that cannot keep it private** (Row 5).
- A scratch root is a parameter. Choosing it and refusing a cloud folder is E22-S4.
- `Identities::from_weak_file()` reports a key file with a low work factor. The consent question is E22-S4.
- User files go through capture only. The `fuzz-door` feature stays out of the FFI layer.
- `larsal-files` installs no allocator. The scrypt crate's working blocks are plain heap, and FIL-01.18 and research section 7 rely on the zeroing allocator of the front ends for them. E22-S4 and E22-S5 must keep that allocator in the path.
- MSG-FILE-DESTINATION on a folder that passes on a list is the screen's to word further, if the owner ever wants it to say why.

### Row 13: two new messages, proposed

`Error::Unprotected` and `Error::CleanupEmpty` are not in FIL-03's message table. Their wording is in `src/error.rs`. `spec/` was not edited, so the lead or a Spec agent adds them, or moves the wording.

### Row 14: fuzz and the check script

`fuzz/fuzz_targets/file_decrypt.rs` goes through `Snapshot::for_fuzzing`, a door that exists only behind the crate's `fuzz-door` feature. Only `fuzz/Cargo.toml` turns it on, with a seed corpus written by `crates/larsal-files/tests/fuzz_seeds.rs`. `scripts/check.sh` is **not** touched: its unsafe loop is generic and it lists no crates by name. The guarded tool's `routes.json` still moved in 109ef36, for this target and the name guard: `scripts/check-names.sh`, `fuzz_routes.file_decrypt`, `fuzz_bins.file_decrypt` and `fuzz_cargo_rest_sha256`.

`scripts/guarded/tables/pins.json` moved in 109ef36, because this story changes pinned paths: `crates/larsal-platform`, `crates/larsal-crypto` and `Cargo.lock`. Three rows moved and no others; their old and new hashes are under "Tables" on this page (C1-R2-10).

### Row 15: the name guard and three published rows

Three published rows unpack to about 16.8 MB, past `scripts/check-names.sh`'s 16 MB cap, so the guard exited 1 on them with "cannot unpack". The lead took a narrower form of the Builder's proposal in ed1947d: `BIG_OK` lists the three rows by SHA-256, and a listed file that is not inside another file may unpack to 32 MB, still matched in full. The same bytes nested in any other file keep the 16 MB cap. It follows the guard's own allow list by SHA-256 for WOFF2 fonts. `routes.json` pins the guard, so its line moved. The Checkers read the wider form; Verify read and planted the narrower one, under "The name guard" on this page.

## Findings, as the Builder proposed them, corrected for commit 109ef36

The lead numbers these at merge. No finding here is closed by this story unless it says so. Corrections from the Builder's text are story check 2 and the name guard, both of which were open when the Builder wrote.

### Corrected: what a disk that cannot keep 0600 does

Round 2 wrote that a file on such a volume "fails the 0600 check and gets MSG-FILE-DESTINATION". **That was false.** C1 ran it on real images: on FAT32 and exFAT every encrypt and decrypt ended in `Error::Cleanup`, with nothing left behind. A person with a USB stick was told a file might hold readable data when there was no file at all.

A volume cannot keep 0600 when a new 0600 file reads back with another mode, or when it is mounted ignoring ownership (the `statfs` flag). A flag that cannot be read counts as ignoring ownership. What happens now, on real private disk images (`proof/volumes.txt`):

| Case | FAT32, exFAT, APFS mounted with no owners | APFS with `-owners on`, the control |
|---|---|---|
| Encrypted output | Goes there and opens. A taken name is still taken | Goes there, at 0600 |
| Decrypted output | **Refused, `Error::Unprotected`, nothing left:** "This disk cannot keep a decrypted file private. Choose another folder and a new file name." | Goes there, at 0600 |
| Cancel of an encrypt | `Error::Cancelled`, name gone. No false cleanup alarm, though FAT32 and exFAT go on showing one link | Not run on this image; the normal road is `fil03_t09_*` |
| A file there as the source | Captured to local scratch, and opens | Not run on this image |
| Scratch root there | `Error::Destination`: scratch never goes on such a disk | Not run on this image |

On the no-owners APFS image, which keeps access lists:

- An access list on the new file is refused with `Error::Destination`, for encrypted and decrypted outputs alike.
- A folder that also blocks deletion gives `Error::CleanupEmpty`, and a 0-byte file stays, named as empty.

**A plain consequence the lead should know:** macOS can mount any external disk ignoring ownership, including APFS and HFS+ ones. Every disk image here that was attached without `-owners on` came up that way. So a decrypted output to such an outside disk is refused at this layer, whatever its file system, until E22-S4 adds the warned consent.

### New and open

- **A list or hard link put on the new file during the write stays** (Low, a known limit, C1-R2-08). `NewOutput::finish` does not look again, so the result is Ok. Only the same user can put a list on a 0600 file. A same-user process can hold a descriptor on it anyway, or read the folder it was told to write to, so another look would not move the boundary: this story's boundary is other users. A look at finish could give a false sense of proof, so none was added.
- **Output cleanup can lose a file planted at the exact moment** (Medium, open, FIL-03.9). `NewOutput::abort` empties its own inode, then looks at the name and unlinks it. Those are two calls. Someone who can write to the output's folder can swap the name between them, and the planted file is removed. A file planted before the look stays (`fil03_t09_a_renamed_output_is_emptied_and_a_planted_sentinel_stays`). FIL-03.9 sends the fix to a platform review, and it blocks the close of the first story that calls this crate (V-1).
- **Close errors are not checked** (Low, open, FIL-03.10). `std::fs::File` drops without reporting a close error, and `larsal-platform` has no checked close. A sync error is reported, on both routes. A close error after a good sync is not seen.
- **The sweep's ownership record is not authenticated** (Low, open, FIL-03.11). The proof is structural: name form, mode, owner, no access list, lock and contents. A same-user process could plant a folder of the exact form holding a ciphertext-shaped file. The sweep would remove that, inside the app's private scratch root only.
- **The sweep lists its root by name** (Low, open). It checks the root's name first, then lists by name, as std has no listing by descriptor. A same-user process that renames the folder between the two aims it elsewhere, where it still takes only the exact form above.
- **An armored file holding secret text still reaches a plain reader buffer** (Low, a known limit). `looks_encrypted` sends only the version line and the armor's own first line to the readers. A file that starts with one of those and then holds a private key by hand is read as ciphertext, and its first 64 KiB can stay in a freed `BufReader` block. No key tool writes such a file.
- **The 19 hybrid rows of the published vectors are OPEN, outside profile age-classic-1** (LD-366). Each is named in every default run, on stderr, and none counts as a pass. The mapping row is proposed on this page, under "Proposed rows the lead must carry".
- **Two messages are new and not in FIL-03's table**: `Error::Unprotected` and `Error::CleanupEmpty`. Their exact rows are proposed on this page.
- **A scratch cleanup that fails still leaves an empty operation folder** (Low, a known limit). `everyone deny delete,directory_inherit` on a scratch root after it was opened gives `Error::Io` and an empty folder, which the sweep leaves. `fil03_t11_a_capture_that_cannot_remove_its_new_folder_says_so` proves the report. Nothing readable is in that folder.

### Story check 2 ran in the lead's session

**Closed, and it rests on the lead's run.** The session's permission check refused the downloaded tool to every subagent, reason "Code from External", and none went around it. The lead ran `tests/peer.rs` in the lead's own session on `age`, `age-keygen` and `age-plugin-batchpass` under `run-key.sb`: 2 passed, 0 failed, exit 0. That program was built from the same bytes of the three crates as this commit. It covers the X25519 route and the passphrase route through the batch plugin, both ways, binary and armor reads, two recipients, and key files.

### The name guard and three published rows

**Closed by ed1947d.** See row 15 and "The name guard" on this page. The whole tree passes, with no banned word found.

### E22-S4's list

These go with the story, and E22-S4 should not close without them.

- **Warned consent for a decrypted file on a disk that cannot keep it private.** This layer refuses with `Error::Unprotected`. The consent, and the way to write past that refusal, are E22-S4's.
- **The weak key file flag** (C2R2-06). A weak encrypted key file gives usable identities, with only `Identities::from_weak_file()` to say so, and nothing makes a caller read it. The screen must read it and ask.
- **User files go through capture only** (C2R2-07). `Snapshot::in_memory` is `pub(crate)` now, and the fuzz door is behind the `fuzz-door` feature, which only the fuzz crate turns on. The FFI layer must not turn that feature on.
- **FIL-03.9's custody review blocks the close of the first story that calls this crate** (V-1). FIL-03.7 says a declined cleanup fails the cancel check.
- **`Validated::write_to`** (C2R3-03): a stream the caller owns takes plaintext with no check of where it goes. The caller must hold FIL-03's rules for it.
- **From "Findings rows" on this page:** C1-R3-01, C2R3-01 and V-2.
- The rest, unchanged from round 2: MSG-FILE-REPEAT, BUSY, SAVED-KEY, WEAK, QUANTUM and LIMITS. One operation at a time. Choosing the scratch root and refusing a cloud folder. The free-space preflight. Lock and revocation during an operation. The zeroing allocator in the front end's path. The 4 GB round trip through the app and its cancel. FFI. A screen's wording for a folder with an access list.

### Carried from the cards, not new

- FIL-01-T18: independent memory proof for both Mac targets. Only arm64 ran. x86_64 did not run.
- FIL-01.18 and research section 7: the stack and register review of the scrypt and ChaCha20-Poly1305 call paths. `scrubbed_deep` and `scrubbed` zero the stack below each call, and registers are not covered. The review sites were not walked by an independent reader.
- FIL-03.3: an allocation failure aborts the process (Rust's default). It is never reported as a cancel. No test injects that fault.
- FIL-03-T07: crash and power cases are left to E22-S6, as the card allows.
- FIL-01-T19: the hostile FFI half has no FFI to run against until E22-S4.

### Found by round 2's reviews and fixed in this round

| Id | What it was | Test that goes red without the fix |
|---|---|---|
| C1-R2-01 | FIL-03-T20 could not fail when metadata traveled | `fil03_t20_no_tag_attribute_list_or_date_of_a_source_reaches_an_output` |
| C1-R2-02, C1-R2-09, C2R2-08 | FAT32 and exFAT gave a false cleanup alarm, and a no-owners mount passed a check it should not | `fil03_t08_a_disk_that_cannot_keep_a_file_private_takes_only_ciphertext`, `fil03_t09_cleanup_goes_by_what_is_left_and_not_by_the_link_count`, `fil03_t08_t09_real_volumes` |
| C1-R2-03 | OPEN rows of a corpus were hidden on a pass | `fil03_t17_published_vectors_pass`. The print is a direct write to stderr, which the test harness does not capture |
| C1-R2-04, C2R2-04 | The access list check's error arm had no test, and my "no way in" was wrong | `fil03_t08_a_list_that_cannot_be_read_counts_as_one`, `fil03_t08_a_closed_descriptor_is_an_error_not_an_answer` |
| C1-R2-05 | Two reports of a failed cleanup had no test | `fil03_t08_a_folder_that_blocks_deletion_gets_the_empty_file_named`, `fil03_t11_a_capture_that_cannot_remove_its_new_folder_says_so` |
| C1-R2-06 | Every list test used an everyone entry | `fil03_t08_a_list_naming_one_user_counts_the_same` |
| C1-R2-07 | Source scans read only the top of `src/` | `production_sources` walks subfolders now; a row plants a module there |
| C1-R2-11 | The armored row's inner header failure had no test | `fil03_t17_a_row_names_its_stage_and_its_credentials` |
| C2R2-01 | The encrypt wipe walk covered one road and one ending | `fil01_t18_encrypt_leaves_no_key_in_a_freed_block` |
| C2R2-02 | The file key test did not sample every road | `fil01_t03_every_encryption_has_its_own_file_key`, `fil01_t03_both_public_roads_draw_from_the_one_generator`. **It proves no repeat and that both roads call the one generator. It does not prove randomness.** |
| C2R2-03 | Story check 4's scan skipped `fsio.rs` | `check4_only_the_file_system_module_can_reach_the_disk`, and the scan of `fsio.rs` in `src/tests/scratch.rs` |
| C2R2-05 | The identity needle was upper case only | `fil01_t18_every_ending_of_a_decrypt_leaves_no_secret_in_a_freed_block` |
| C2R2-07 | `Snapshot::in_memory` was a public door | `compile_fail` doc test in `src/lib.rs` |

C1-R2-08 is stated above. C2R2-06 stays on E22-S4's list above. C1-R2-10 closed in 109ef36: "Tables" on this page names every moved path.

### What the published vectors changed in the product

The lead ruled on 13 failing rows. All 128 rows in the profile now pass by the stage each row names.

- **A short or missing nonce is a header failure.** `Failure::Header` at unlock. The second pass's own nonce check is unchanged: a nonce that differs on the second read stays a payload failure, as it means the snapshot changed.
- **The discard pass tries the other flag on a full chunk that fails.** If it opens, its plaintext is counted as internal prefix, and the outcome is still `Failure::Payload`. Nothing new opens, the second pass is unchanged, and no caller's writer sees a byte.
- **An armor block with nothing inside reaches the header stage** (`armor_empty`). This one goes past the ruling, which named it a runner mistake: with the identity fixed the row still read as armor failure, because the reader counted an empty body as bad armor. The row says header failure. It is refused either way, under the same public error.

### A guard limit, not a defect

`macos::terminal::tests::app09_16_quit_signal_at_the_prompt_restores_the_terminal` fails under `run-key.sb`: `openpty` gets "Operation not permitted". It fails the same way on the base tree, and `terminal.rs` is not in this patch (`proof/platform-guard.txt`). That one test did not run to its end here.
