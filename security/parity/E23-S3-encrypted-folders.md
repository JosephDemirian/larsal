# E23-S3 Encrypted folders in Rust: Verify sign-off

Story: E23-S3 (plan/epics.md). Cards: FIL-04, FIL-06. Decisions: LD-372 to LD-378, LD-379, LD-428. Checkers: C1 and Sensitive C2, round 3.
Date: 2026-11-08.
Role: Verify, in two passes. The first pass (03:02 to 04:29) ran the story's test programs, Checker 1's plants and its own mutants in a private copy of commit ddaf340, and read the guarded run of ddaf340, which read FAIL. The lead then rebuilt the three commits with Main's identity. The second pass (04:31 to 05:30) checked that the rebuilt commits hold the same code, read the full guarded run of the new commit, `971870b8d1a6f7906afce1d01a1cfb0fe0c2793e`, and checked every proof file of the first pass against the SHA-256 the first pass sealed. The second pass ran no test, mutant or plant again: where this page says a test or mutant ran "on this code", it ran on ddaf340, whose tree differs from 971870b only in two lines of `pins.json` (The commits, below). Neither pass changed product code. Neither ran the peer's desktop app, its command line tool, the Java runtime or any other downloaded program, and `LARSAL_PEER_EXPORT` stayed unset. The peer vaults read are data, read by Larsal's own tests. The logs and scripts named here lived in private folders under /private/tmp that do not last, so this page copies what must survive.

**Result: signed with limits.** Commit `971870b8d1a6f7906afce1d01a1cfb0fe0c2793e`, three commits on 3d4ac36: 8abd77e (larsal-crypto and larsal-platform), 4a405fe (the folders crate, its fuzz route and the two lock files), 971870b (the guarded tool's two tables). 4a405fe has the tree `0a4580a076d39f30a0e300691e388ec8745b51f3`, which both Checkers approved, and 971870b changes the two tables alone. The full guarded run of 971870b (04:30 to 05:17, 2,803.0 s) reads **Overall FAIL, and its one reason is not in this story's code**: one Swift test of the QR feature (E21-S2), `QrFocusReturnTests/shortcutInTheEditor()`, did not see the focus arrive within its bound of 100 renders while the load average rose to 17. The story changes no Swift. Everything else in that run passed: Rust 4,476 passed, 0 failed, 99 ignored, 166 of 166 programs, every program of this story among them, and the five timing tests that failed in the run of ddaf340; APP09 18 of 18; Swift 461 of 462; the docs lane 18 doc tests, this crate's 3 among them; all 31 fuzz routes exit 0, `folder_readers` with 111,980 runs; 0 tests lost against the PASS run of e808d32. So the guarded Overall PASS this signature needs is still missing, for a reason outside this story: the lead reruns the full check of this commit, and adopts this page only when that run reads Overall PASS. Five of the 7 story checks hold in full. Check 4 holds but for one latency: a cancelled write took 187.52 ms in one run of five, against 100. Check 2 holds in one direction: vaults that the peer's desktop app and the peer's library made open in Larsal, every entry equal. Larsal's vaults in the peer app stay OPEN until the owner names that run. Of the first pass's 19 mutants all 19 went red, and Checker 1's plants reproduce C1R3-F1 and C1R3-F2 on this code.

Nothing but tests and the fuzz target calls this crate. No CLI, no Swift and no FFI reach it, so no person can meet what stays open. E23-S4 is its first caller by the plan's order, and these must close before E23-S4 closes:

- **C1R3-F1 (Medium):** a move reads the moved node once and never reads what came out. A node another writer swaps in during the move turn makes the move take a folder below itself: Ok, and the whole subtree leaves the tree. Fix: read the moved node's ID after the move and move it back on a mismatch, as the folder delete already does. C1 probed it: the plant then gives `Changed` with the tree whole, and the 89 lib tests still pass.
- **C1R3-F2 (Low):** a folder delete resumed after a crash removes the node it set aside without reading it, when another node took its name, so an item that arrived is orphaned.
- **The peer direction** (FIL-04-T14, C2-02) and a multi-chunk peer file in a default run (C2-04).
- **A cancelled write answered within 100 ms every time.** The median meets it; the slowest of five does not (Measured).

## The commits

The first candidate, ddaf340, carried the Mac's fallback identity `Joseph Ilhan <josephilhan@Josephs-MacBook-Pro.local>` at the host name (V-2). The lead rebuilt the three commits with Main's identity. Read from a private clone of the project's repository (`git clone --no-hardlinks`), with ddaf340 fetched from the first pass's clone:

| New commit | Its tree | Old commit | Old tree | Same code |
|---|---|---|---|---|
| `8abd77e8f07ab4c24c59e54f743b6c69cdfb5e13`, parent 3d4ac36 | `0ffcf0ddd7ccaf1c745bf821239199a18cf5850c` | d980ba7 | `0ffcf0ddd7ccaf1c745bf821239199a18cf5850c` | Yes, the same tree |
| `4a405feb32ff7b6b650b56c91d324debe2c89a1f`, parent 8abd77e | `0a4580a076d39f30a0e300691e388ec8745b51f3` | 9090fdc | `0a4580a076d39f30a0e300691e388ec8745b51f3` | Yes, the same tree, the one both Checkers approved |
| `971870b8d1a6f7906afce1d01a1cfb0fe0c2793e`, parent 4a405fe | `aca9d1841972d9e69b2bd6e1669e9f9e3ce4edf8` | ddaf340 | `b379e9dc15a306012e6cc07b5f05de2d33668824` | `git diff ddaf340 971870b` changes one file, `scripts/guarded/tables/pins.json`, two lines: `reviewed_commit` and `reviews.E23-S3.source` now name 4a405fe instead of 9090fdc |

- Author and committer of all three: `Joseph Demirian <hello@JosephDemirian.com>`, as on all 38 commits of Main (3d4ac36, which is also the repository's `origin/main`). The three messages are byte-equal to the old ones, and none names an agent or tool.
- Every pin of `pins.json` (147 pins in 59 rows) equals the path's hash at 971870b and at 4a405fe.
- So every test, mutant and plant of the first pass ran on the code this commit holds, and only the two table lines are new. The run below used them.

## The run

The guarded tool ran the full check of 971870b once, started by the lead at 04:30 with the baseline of e808d32's PASS run, while the lead held the BUSY-native file. I read its results and did not rerun it.

| Lane | Result | For this story |
|---|---|---|
| Source | exit 0. Commit `971870b8d1a6f7906afce1d01a1cfb0fe0c2793e`, tree `aca9d1841972d9e69b2bd6e1669e9f9e3ce4edf8`. The tool the run used is byte-equal to `scripts/guarded` at this commit (`diff -rq`), and its recorded `tables/pins.json` hash, `9b3e9824bd8b2b7c4ba94eea9ca090e3649b7198112e34c9f68ac8749e7f6b05`, is this commit's. Custody: 0 of 19 programs and 23 tool files changed. 59 grant rows read, 0 withheld, reviewed commit 4a405fe | The tables of this commit are the ones that ran |
| Static | exit 0, 18 of 18 steps, 569.9 s. Names PASS (12,283 files), advisories, bans, licenses and sources ok, unsafe count 506 in 20 crates | The usual offline limit: yanked status not proven for 11 crates, this story's aes-kw, aes-siv, cmac, dbl and scrypt among them |
| Rust | exit 0, 1,069.6 s: **4,476 passed, 0 failed, 99 ignored, 166 of 166 programs**. Workspace 3,520 passed, 83 ignored; sync 562, 9; net 74, 7; release 275; release-browser 45; 0 failed in each | Every program of this story passed: `larsal_folders` 89, `flip` 5, `raw_objects` 5, `peer` 3 with 4 ignored, `wipe` 1, `folder_primitives` 8 with 1 ignored, `fuzz_seeds` and `measure` ignored; the 4 SIV and 3 text tests in larsal-crypto; the 3 `macos::folder` tests of larsal-platform in both the workspace and net builds. The five tests that failed in the run of ddaf340 passed: `clipboard::tests::countdown_clears` and `new_copy_restarts_countdown` in the net build, `int03` F-244, F-245 and F-252 in the release-browser build |
| Native | exit 1, 583.0 s. **APP09 18 of 18. Swift 461 of 462**: the log, the result bundle and the database agree. The one failure: `QrFocusReturnTests/shortcutInTheEditor()` ("QR-T01 FEA-10.3: in the editor the shortcut takes the focused button's field and the draft: real keys"), at `QrFocusReturnTests.swift:229` twice (`QrFocus.shared.held == button` after the wait at line 88, a bound of 100 renders of at least 50 ms each) and at line 289 (the set that follows). It failed after 36.5 s; in e808d32's PASS run it passed after 15.8 s. Its suite took 328.7 s | Not this story's code. The story changes nothing under `macos/`, nothing in `larsal-ffi` or `larsal-core`. In larsal-crypto it adds modules and moves scrypt's settings check into `scrypt_settings` (import key derivation only); in larsal-platform it adds `macos/folder.rs` and widens one `pub use`. Nothing in the app calls them. The test waits for SwiftUI's focus; load average 17.2 at 05:12 (V-6) |
| Docs | exit 0, 222.6 s: **18 passed**, 0 failed, 22 result lines | This crate's 3 doc tests passed: `lib.rs` line 30 (the control, `validate` then `write_to`), and lines 19 and 24, `compile_fail`: a `Snapshot` has no `write_to`, and a `Validated` cannot be built outside the crate, its fields are private |
| Fuzz | exit 0, 347.6 s: **31 routes**, all exit 0, fewest runs 1,710, no new route missed | `folder_readers`: exit 0, 111,980 runs in 31 s, no artifact |
| Time | 2,803.0 s; the alarm is at 3,540 s and did not fire. Hold wait 0 | Build 330.9 s, static 569.9 s |
| Crash reports | Four new, all the guard's children, made on purpose; own and not on purpose: none | |
| Against the run of e808d32 | 4,939 compared: **0 lost**, 0 newly ignored, 0 waived, 134 new | The 134 new tests are all this story's: 127 ok, 7 ignored |

The run's `summary.txt`, `summary.json` and `test-names.json` have SHA-256 `8c1812c2048aff7c68bcf303ba52753b7893e79d3a1bf6e44df4c145e5b35cff`, `52f5930db3fb2092689dd3dd329c0fde1958d30482c0e5a66af4564d449fe27e` and `7854bdcc63ba670e1ab8e7de6538b8d6aebff63c6deec8442c4e97d14c9b484e`. In `test-names.json` one name is not ok or ignored: `swift:QrFocusReturnTests/shortcutInTheEditor()`.

### The run of ddaf340, before the rebuild

The first pass read the full guarded run of ddaf340 (03:02 to 04:01). It read **Overall FAIL**, and none of its reasons was in this story's code. Kept here because /private/tmp does not last:

| Lane | Result | For this story |
|---|---|---|
| Source | exit 0. Commit `ddaf3407d91a80bcb9aef851c294595d703f4030`. The tool was byte-equal to `scripts/guarded` at that commit; 59 grant rows read, 0 withheld | |
| Static | exit 0, 18 of 18 steps, 1,303.1 s. Names PASS (12,283 files), advisories, bans, licenses and sources ok, unsafe count 506 in 20 crates | The usual offline limit: yanked status not proven for 11 crates, this story's aes-kw, aes-siv, cmac, dbl and scrypt among them |
| Rust | exit 1: 4,471 passed, **5 failed**, 99 ignored, 166 of 166 programs. Workspace 3,520 passed, 0 failed; sync 562, 0; net 72, **2**; release 275, 0; release-browser 42, **3** | Every program of this story passed: `larsal_folders` 89, `flip` 5, `raw_objects` 5, `peer` 3 with 4 ignored, `wipe` 1, `folder_primitives` 8 with 1 ignored, `fuzz_seeds` and `measure` ignored. Every test this page names is in the run, ok, or ignored where the page says so |
| The 5 failures | `clipboard::tests::countdown_clears` and `new_copy_restarts_countdown`, in larsal-platform's net build: the clipboard still held text 1,600 and 2,000 ms after an 800 ms countdown. Both passed in the workspace build of the same run (03:48). `int03` F-244, F-245 and F-252, in larsal-browser's release build: "under 200 ms" took 200.001, 295.4 and 368.2 ms | Not this story's code. larsal-browser is unchanged. In larsal-platform the story adds `macos/folder.rs` and widens one `pub use` in `macos/mod.rs`; the clipboard is untouched. Load average at 04:04: 11.2, 14.5, 16.0 |
| Native | exit 1, stopped by the total alarm after 300.3 s: no Swift count, no APP09 count | The story changes no Swift, but Swift links larsal-ffi, which builds larsal-crypto and larsal-platform with this story's additions. The run of 971870b ran them: APP09 18 of 18, Swift 461 of 462 |
| Docs | Not run: total alarm | The crate's 3 doc tests ran and passed in the run of 971870b |
| Fuzz | Not run: total alarm. The route table and `fuzz/` agree on 31 routes | `folder_readers` ran in the run of 971870b: exit 0, 111,980 runs. The Builder's 60-second run on the same tree: 121,379 runs, exit 0 |
| Time | 3,555.4 s against the alarm at 3,540 s. The PASS run of e808d32 took 3,197.8 s | Build 843 s against 444, static 1,303 s against 671: load. This story's programs took 85.6 s of the workspace lane (V-4) |
| Crash reports | Six new; four were the guard's children, made on purpose; own and not on purpose: none | |
| Against the run of e808d32 | 495 tests lost: 462 Swift, 18 APP09 and 15 doc tests, all in the lanes that did not run. No Rust test lost, 0 newly ignored, 131 new | |

Its `summary.txt`, `summary.json` and `test-names.json` had SHA-256 `4066f3086a51693da0a6f28505f8ff1d5bd5c6f52363ad98f538ace06769f7d7`, `24e88cceef56cfb8810d134552f15b79bc7a2f25871403ce134e3e9e4c9f61f6` and `666f5963a765ebb452f1b6e2110970f6b45f4e71df60fcc91f6f4772958fddae`. A second run of ddaf340, started at 04:04, was stopped by the lead by its PID for the rebuild and is not evidence.

## The 7 story checks

Each test named below is in the test names of the run of 971870b, ok, or ignored where this page says so (checked by name in the second pass). The mutants named went red in the first pass's private copy of ddaf340, the same code (Mutants, below).

| # | Check | Test | Mutants that went red | Result |
|---|---|---|---|---|
| 1 | FIL-04's test cases | All 16, each with a test: the next table. The parts the cards leave to later stories or to the other Mac target are named there | All 19 | Holds, with the cards' own opens |
| 2a | Folder vaults the peer made open in Larsal | In every run: `peer_desktop_made_vault_opens_with_names_and_hashes_pinned`, `peer_desktop_made_copy_takes_a_new_file_and_keeps_the_rest`, `fil04_t16_a_retained_key_backup_still_opens_the_vault`. Ignored in the run and run by the first pass with `LARSAL_PEER_VAULTS`: `peer_library_made_gcm_vault_every_entry_equals_its_manifest`, `peer_library_made_dir_backups_hold_their_own_folder_id`, `peer_library_made_ctrmac_vault_is_refused_by_name`, 3 passed | V6 (peer), V12 and V7b (the ignored library test) | Holds |
| 2b | Larsal's vaults open in the peer app | `peer_export_a_larsal_vault_for_the_later_peer_run`, ignored. Not run by either pass | | **OPEN.** No downloaded program has run, by the owner's rule |
| 3 | One changed file changes only its own encrypted file | `one_write_changes_only_its_own_object`, `one_new_file_adds_only_its_own_object`, `one_rename_moves_only_its_own_object`, `one_delete_removes_only_its_own_object`, `a_folder_touches_only_its_own_objects` (each compares the hash and inode of every raw object before and after) | V17 | Holds |
| 4 | The speed targets of E23-S1 on this Mac | `tests/measure.rs`, release, ignored | Not a mutant check | By the Builder's release run on the same crate bytes (Measured), read by the first pass and not repeated: every rate target met at every size at the median, and every latency target but one met in all five runs. **The write cancel is not met:** median 50.99 ms, but the slowest of five took 187.52 ms against 100 ms (V-1) |
| 5 | One changed byte gives the generic error and no plaintext | `every_changed_byte_of_a_small_file_is_the_one_error_with_no_plaintext` (all 196 bytes of a 100-byte file, two bits each, 392 tries: `Error::Open`, the exact message, an empty sink, no write phase), `a_header_with_other_reserved_bytes_is_refused`, `no_early_plaintext_when_the_last_chunk_is_bad` (1 and 4 workers), `every_changed_byte_of_a_stored_name_gives_no_name`, and in the crate `fil04_t06_bad_chunks_release_nothing` | V6, V11, V12 | Holds |
| 6 | Keys wiped on lock | `fil04_t13_every_ending_leaves_no_secret_in_a_freed_block` (11 secrets, 24 endings and two more), `tests::session::fil04_t13_lock_during_a_pass_waits_and_then_nothing_comes_late`, `tests::session::fil06_t08_every_way_in_is_denied_after_revoke` (the keys are gone after lock) | V13, V14, V18 | Holds for freed heap blocks, on arm64 |
| 7 | Two Checkers (crypto) | C1 and Sensitive C2, round 3, below | Not a test | Both APPROVE_EXACT_CANDIDATE, 0 blocking |

**How check 6 sees memory.** The wipe program installs `larsal_platform::memory::Probe` over the system allocator. On every free, and on the old block of every realloc, it searches the block for one 8-byte needle and counts hits. A control first frees one unwiped marker block, which must be seen. `lock` revokes at once, waits for the write lock on the keys, and sets them to `None`. `MasterKeys` holds four `SecretBytes`, which zero themselves before their blocks go back, so "session: locked, then dropped", "names: a listing left open at lock", "read: revoke in each pass" and "read: lock from another thread" are endings like the others. The first pass's V18 frees one unwiped copy of the encryption master key inside `lock`, and the walk goes red on it. V13 keeps the keys after lock: the wipe walk stays green, as nothing is freed, and the two session tests go red. It cannot see stacks, registers, live blocks, kernel buffers, the page cache, swap, or x86_64. The scrypt crate's working blocks are plain heap, as in E22-S3: `larsal-folders` installs no allocator, so the zeroing allocator of `larsal-ffi` must stay in E23-S4's path.

## FIL-04's 16 test cases

| Case | Tests | What stays open |
|---|---|---|
| T01 create and reopen | `fil04_t01_create_and_reopen_has_the_exact_wire_profile`, `fil04_t01_create_refuses_a_used_place_and_an_empty_password` | The peer's inspection of a Larsal-made vault (check 2b) |
| T02 the signed configuration | `fil04_t02_read_takes_each_hmac_under_its_own_name`, `fil04_t02_hostile_headers_stop_before_any_key_work`, `fil04_t02_a_remote_key_is_refused_by_name_with_no_work`, `fil04_t02_changed_signed_bytes_give_no_session` | |
| T03 key derivation and key wrap | `fil04_t03_rfc_validity_apart_from_the_ceilings`, `fil04_t03_corrupt_key_material_gives_no_session`; in larsal-crypto `fil04_t03_any_change_to_a_wrapped_key_gives_no_key_data`, `fil04_t03_rfc7914_validity_is_not_the_ceiling`, `rfc3394_4_6_wraps_and_unwraps_256_bits_under_a_256_bit_kek` | |
| T04 the password's bytes | `fil04_t04_password_is_nfc_utf8_and_nothing_else`; in larsal-crypto `fil04_t04_composed_and_decomposed_give_the_same_bytes`, `fil04_t04_nothing_but_composition_changes` | Unicode newer than 17 (E23-S2's limit) |
| T05 freshness and the shared budget | `fil04_t05_every_boundary_size_has_the_public_layout`, `fil04_t05_every_write_is_fresh_even_of_the_same_content`, `fil04_t05_every_chunk_nonce_and_every_content_key_is_fresh`, `fil04_t12_a_failed_random_source_gives_no_output`, the eight `fil06_t16_*` | C2R3-01: a generator that repeats only across restarts passes |
| T06 chunks | `fil04_t06_bad_chunks_release_nothing`, `fil04_t06_the_empty_forms`, `fil04_t06_the_queue_stays_bounded_under_a_slow_first_worker`, `no_early_plaintext_when_the_last_chunk_is_bad` | |
| T07 truncation and changed bytes | `fil04_t07_authentic_trailing_chunk_removal_is_a_disclosed_limit`, `every_changed_byte_of_a_small_file_is_the_one_error_with_no_plaintext`, `fil04_t07_the_unauthenticated_representations_itemized`; in larsal-crypto `fil04_t07_a_failed_open_leaves_the_buffer_unchanged` | Whole trailing chunks cut is a disclosed limit (S6) |
| T08 authentic swap and replay | `fil04_t08_authentic_swap_and_replay_pass_and_are_disclosed` | The known-history block, FIL-06.9, goes to E23-S4 and E23-S6 |
| T09 names | `fil04_t09_names_and_paths_by_the_public_rule`; in larsal-crypto `rfc5297_a1_deterministic`, `rfc5297_a2_nonce_based_vector`, `fil04_t09_no_associated_data_and_an_empty_component_differ`, `fil04_t09_every_changed_byte_fails_and_gives_nothing`; the peer library's vault | A name sealed with the wrong parent passes the default peer test, whose names are all at the top (V7); the ignored library test catches it (V7b) |
| T10 long names and empty folders | `fil04_t10_long_names_and_empty_folders_work`, `fil04_t10_malformed_nodes_are_preserved_and_refused`; in larsal-crypto `fil04_t10_padded_url_base64_has_one_text` | |
| T11 links and special objects | `fil04_t11_links_and_special_objects_are_visible_and_never_followed` | |
| T12 primitives, imports, random failure | `fil04_t12_a_failed_random_source_gives_no_output`, `fil04_t12_and_t15_the_crate_imports_no_primitive_and_no_network`, `fil04_t12_no_mac_or_tag_is_compared_with_ordinary_equality`; in larsal-crypto `nist_cavp_gcm_256_chosen_rows`, `nist_cavp_gcm_256_decrypt_rows`, `rfc4231_case1_hmac_sha384_and_sha512_verify`, and, ignored, `nist_cavp_gcm_256_every_row_of_both_files`, which the first pass ran: sealed 375, opened 184, refused 191, ok | C2R3-02: two ways around the scan |
| T13 wipe and lock | Check 6 above | x86_64; stacks, registers and swap |
| T14 the peer matrix | Check 2 above | One direction OPEN; no 4 GB file has crossed |
| T15 offline guesses and no network | `fil04_t12_and_t15_the_crate_imports_no_primitive_and_no_network` | The words for what an observer learns belong to the screens, E23-S4 |
| T16 other profiles and old keys | `fil04_t16_other_profiles_are_refused_by_name_after_authentication`, `fil04_t16_a_retained_key_backup_still_opens_the_vault`, `peer_library_made_ctrmac_vault_is_refused_by_name` | |

The FIL-06 tests the Builder wrote (`fil06_t03` to `fil06_t18`) ran in the same program and pass.

## Story check 2: what ran, and where

| Vault | Made by | Where it lives | Run by | Result |
|---|---|---|---|---|
| The desktop vault | The peer's desktop app, published as another project's MIT test data (`crates/larsal-folders/testdata/SOURCE.md`) | In the tree, 8 files pinned by SHA-256 in `tests/peer.rs` | The guarded runs, and the first pass | 3 passed, every entry equal to its pinned name, size and hash |
| The library vaults, the GCM one and the CTR-MAC one | The format's public library, by the Builder's record; AGPL-3.0 test data of another project. The first pass checked their bytes, not who made them | Outside the tree, `LARSAL_PEER_VAULTS`. 44 files, each equal to `fixtures/FIXTURES.json` in the input folder | The first pass, on ddaf340's bytes (the same code): ignored tests, run on purpose | 3 passed: every entry of the GCM vault equals its manifest, folder ID backups hold their own IDs, and the CTR-MAC vault is refused by name |
| A Larsal-made vault in the peer app | | | Nobody | OPEN |

The library vaults matter for one more reason. The desktop vault holds only one-chunk files, all in the top folder. So in a default run, the chunk index in the additional data (V11, V12) and the parent ID in a name (V7) are checked against Larsal's own arrangement in tests, not against the peer's. The first pass's V12 and V7b went red only on the ignored library test. That is C2-04, and it stays open until a multi-chunk file and a nested folder that the peer made are in a default run.

**The peer run, when the owner names it** (the Builder's steps, copied here as they must survive):

1. The owner names the exact tool: name, version, download and its published hash or signature. Check the download against them before it runs. The desktop app opens a window, so it also needs the owner's go for that (rule 10). Demo data only, no clipboard, in a local folder no sync client watches.
2. Make a fresh export: build `cargo test -p larsal-folders --test peer --no-run`, then run that program with `LARSAL_PEER_EXPORT=<an empty folder>` and `peer_export_a_larsal_vault_for_the_later_peer_run --ignored`. It writes the vault and a JSON manifest: the password, every entry's type, size and SHA-256, and every raw object's SHA-256. The vault holds files of 0, 1, 32767, 32768, 32769 and 65536 bytes, a composed non-ASCII name, a long file name and a long folder name, an empty folder, a folder two levels deep, a file edited once, a file moved, and a file and a folder deleted.
3. Hash every file of the copy: each must equal its raw-object line, or stop.
4. Open it in the peer tool with the manifest's password exactly. Every entry is there with its type, size and SHA-256, and nothing extra shows.
5. Lock it without changing anything, and hash every raw object again: none may have changed.
6. On a new copy, in the peer tool: add a 4 GB file of known SHA-256, edit one small file, rename one, make one folder. Lock. Larsal opens that copy, every entry equal, the 4 GB file's hash equal. A multi-chunk file in a nested folder that the peer made also closes C2-04.
7. A 4 GB file Larsal made goes the same way as steps 3 to 5.
8. Record the tool and its hashes, every comparison, and the raw-object check before and after. Only then do FIL-04-T14 and check 2b's "both directions" hold. A refused unlock, a missing or extra entry, a differing hash or size, a raw object the tool changed by opening, or a 4 GB file that does not cross is a finding, never a pass (LD-370, LD-372).

The peer's command line tool, a Java runtime and the format pages were downloaded on 2026-11-07 for this story, on LD-428's standing yes, and recorded in a `MANIFEST.json` outside the project. Nothing downloaded has run: the session's permission check refused the first run of the runtime and the tool. The fixtures' record, `FIXTURES.json`, is not in that manifest; the first pass matched its 52 files by hash. Both go in the merge's LD row.

## Mutants

The first pass's mutants. All ran in its private copy of ddaf340, whose code is this commit's, each built from the copy and checked equal to that tree before and after. The control passed: lib 89, flip 5, raw_objects 5, peer 3 with 4 ignored, the library tests 3, wipe 1.

| Mutant | Rule | What was undone | Red |
|---|---|---|---|
| V1 | FIL-06.8 | `bound()` takes any node at the name | `fil06_t08_a_stale_folder_handle_changes_nothing` |
| V2 | FIL-06.3, FIL-06.12 | A tree delete of the top folder is not refused | `fil06_t12_a_tree_delete_of_the_top_folder_is_refused` |
| V3 | FIL-06.12 | The tree delete's walk outside sees no ID | `fil06_t12_a_tree_delete_never_follows_an_id_another_folder_uses`, `fil06_t12_the_outside_walk_sees_every_twin_and_skips_only_the_deleted_node`, `fil06_t03_a_walk_limit_anywhere_refuses_deletes_and_moves` |
| V4 | FIL-06.12 | The rmdir resume removes the content folder with no emptiness check | `fil06_t07_an_rmdir_resume_keeps_an_item_that_arrived` |
| V5 | FIL-06.16 | A whole-file write takes no header budget | five `fil06_t16_*` tests |
| V6 | FIL-04.6 | A chunk whose tag fails counts as proven | `fil04_t06_bad_chunks_release_nothing`, `fil06_t11_a_candidate_version_must_prove_itself`, `every_changed_byte_of_a_small_file_is_the_one_error_with_no_plaintext`, `no_early_plaintext_when_the_last_chunk_is_bad` |
| V7 | FIL-04.9 | Names sealed and opened with an empty parent ID | Five `fil06_*` tests in the crate. The default peer tests stay green |
| V7b | FIL-04.9 | The same, against the library vault | `peer_library_made_gcm_vault_every_entry_equals_its_manifest` |
| V8 | FIL-04.5 | One fixed nonce for every chunk | `fil04_t05_every_chunk_nonce_and_every_content_key_is_fresh`, `fil04_t05_every_write_is_fresh_even_of_the_same_content` |
| V9 | FIL-04.5 | One fixed header nonce | the same two |
| V10 | FIL-04.5 | One fixed content key | `fil04_t05_every_chunk_nonce_and_every_content_key_is_fresh` |
| V11 | FIL-04.6 | Chunk index 0 in every chunk's additional data, both ways | Four `fil04_t05` to `fil04_t07` tests. Flip and the default peer tests stay green |
| V12 | FIL-04.6 | The chunk index little-endian, both ways | The same four, and `peer_library_made_gcm_vault_every_entry_equals_its_manifest` |
| V13 | FIL-04.13 | Lock keeps the keys | `fil04_t13_lock_during_a_pass_waits_and_then_nothing_comes_late`, `fil06_t08_every_way_in_is_denied_after_revoke`. The wipe walk stays green |
| V14 | FIL-04.13 | An unwiped copy of each opened content key is freed | `fil04_t13_every_ending_leaves_no_secret_in_a_freed_block`: "content key after read: success: 6 freed blocks, the largest 32 bytes" |
| V15 | FIL-06.12 | `delete_dir` never sees a shared ID | `fil06_t12_delete_dir_of_a_shared_empty_folder_removes_only_its_node`, `fil06_t03_a_walk_limit_anywhere_refuses_deletes_and_moves` |
| V16 | FIL-06.8 | The folder delete does not check the ID of the node it set aside | `fil06_t08_a_stale_folder_handle_changes_nothing` |
| V17 | Check 3 | An update also removes its folder's ID backup | `one_write_changes_only_its_own_object`: the folder backup `dirid.c9r` removed beside the changed file. The 89 lib tests stay green |
| V18 | Check 6 | `lock` frees an unwiped copy of the encryption master key | `fil04_t13_every_ending_leaves_no_secret_in_a_freed_block`: "encryption master key after session: locked, then dropped: 1 freed blocks, the largest 32 bytes" |

**Checker 1's round 3 plants, run unchanged by the first pass on ddaf340, the same code** (`c1r3.rs`, SHA-256 `9f3c5163096c00a61360f6761728752bf64a25d743400524f7d9e23b95ecd998`): 10 passed, 3 failed, as C1 reported.

- `c1r3_a_swap_inside_the_move_turn_takes_a_folder_below_itself` fails: the move answers `Ok(())`, the tree goes from `/p/`, `/p/a/`, `/p/b/`, `/p/b/c/`, `/p/b/c/f.txt` to `/p/` alone, and two content folders with 2 and 3 entries are orphaned. This is C1R3-F1.
- `c1r3_rmdir_resume_with_another_node_at_its_name` fails: the record ends `Rmdir/Aborted` and one content folder with 2 entries is orphaned. This is C1R3-F2.
- `c1r3_walk_limit_of_a_folder_without_its_backup` fails: a folder of 10,001 items with no ID backup lists as `Open`, and a tree delete elsewhere gives Ok. This is C1R3-F4, words only.

The Builder's 24 mutants of round 3, C1's 55 and C2's 40 stand beside these. They ran on the same tree, 0a4580a. Neither pass reran them.

## Tables

The last commit moves `scripts/guarded/tables/pins.json` and `routes.json` only. Every line is true for this commit, and nothing moves that the story does not need.

| Table line | Old | New | Why |
|---|---|---|---|
| `crates/larsal-platform`, in `net:larsal-platform/larsal_platform`, `workspace:larsal-platform/larsal_platform`, `workspace:larsal-sshagent/own_agent` | `d5f4716f44bed3f1affb0093576bda5d24c8aff0` | `b8094dac260dda78b292c539244457c548f50537` | Equal to this commit. The story adds descriptor steps there |
| `crates/larsal-crypto`, in `own_agent` | `de16aadc18c924062f763603f08ee2f832e3c0ae` | `251c7717d991872b965834a82ff003314fbe5531` | Equal to this commit |
| `Cargo.lock`, in `own_agent` | `47270a1d7ec1e2f5aefe7617ca1344e407659191` | `1ce8a38450c24c3a06250bd913aa1ae3ca480f50` | Equal to this commit. It adds the one package `larsal-folders` |
| `crates/larsal-folders`, in `own_agent` | absent | `106b96c13b2e2b35fdcf738cd4e21b2529122841` | Equal to this commit. A new workspace folder that no other row pins, so the row's own rule takes it |
| `crates/larsal-files`, in `own_agent` | absent | `cfa91f3b61b5527bda8af3c807af975171dca554` | Equal to this commit and to the base. E22-S3 added the folder and no row pinned it; the same rule takes it now |
| The `review` of those three rows, `reviewed_commit` and `reviews.E23-S3` | E21-S2, 64d017d | E23-S3, 4a405fe | 4a405fe is the parent of the tables commit (9090fdc in ddaf340, before the rebuild). The entry says "its proof: LD row of the merge", so that row must exist at merge |
| `own_agent`'s `why` | five folders | seven, larsal-files and larsal-folders added | True |
| `routes.json`, `fuzz_routes.folder_readers` | absent | `a6370f1c9b7a38f3b179fb89d69252ce6bf02bd6fb7ffb9d679011c67826e9af` | Equal to `fuzz/fuzz_targets/folder_readers.rs`. 31 routes, each equal to its file |
| `routes.json`, `fuzz_bins.folder_readers` | absent | Its five lines | 31 bins, equal to `fuzz/Cargo.toml` |
| `routes.json`, `fuzz_cargo_rest_sha256` | `7d044c244665025f41f7ee9f6ab13268d4bce58ecc0d53aa1f2618c36ee69e35` | `a013bdbf22b6ce920672b3b9fcc6f54be848b1b585acc02cfa3c074767798e8d` | Equal to what the first pass computed by the tool's own rule |

Both passes checked all 59 rows: every pin, 147 in all, equals this commit, and 4a405fe. After this commit every folder under `crates/` is pinned by some row. `byte_checks`, `check_sh_sha256` and `routes.json`'s `functions` did not move, and `scripts/check.sh` and `scripts/check-names.sh` are not touched.

**`scripts/guarded/README.md` still says "the five workspace folders no other row pins"** (line 47) and names five. The table and its `why` now say seven. The words are stale; the rule is kept. Verify would not change the README in this commit: it is one of the tool's 23 hashed files, the run checked those bytes, and a README edit is a tool change for the next round of the guarded tool. The LD row of the merge should say so.

## Zero knowledge (LD-340)

The crate has no network, no server, no upload and no verifier. It depends only on `larsal-crypto`, `larsal-model` and `larsal-platform`. The import scan `fil04_t12_and_t15_the_crate_imports_no_primitive_and_no_network` reads every source file at the top of `src/`. `std::process` appears only in a unit test that makes a FIFO with `/usr/bin/mkfifo`. Local stores hold ciphertext copies, the header ledger and journals that keep only encrypted names, parent IDs, digests and state under a MAC. As FIL-04.15 says, anyone who holds a copy of the folder can test password guesses offline. That is the format, not a Larsal service, so LD-340 is not touched.

## Findings rows

The lead numbers these. Severity is Verify's or the Checker's. **None blocks this story.**

| Finding | Severity | What | File, input, result | Status |
|---|---|---|---|---|
| C1R3-F1 | Medium | A move does not read what it moved, so a swap in that moment takes a folder below itself | `crates/larsal-folders/src/write.rs` `rename`, 1221-1282: the node is read at 1224 and 1229, the move is at 1130 after the seam `rename.before_switch` (1125), and nothing reads back. The folder delete does read back (1486-1495). Plant: p/a empty and p/b/c/f.txt; at the seam a's node goes and b's node takes a's name; `rename(old a, c, "moved")`. Result `Ok(())`, only `/p/` left, two content folders orphaned, no recovery copy | Open, closes before E23-S4 closes. The Builder's residual row says "not reproducible by a test without a seam"; the seam exists, and that row must also say the whole subtree drops out |
| C1R3-F2 | Low | A resumed folder delete removes the node it set aside when another node holds its name | `write.rs` `resume_rmdir` 1892-1894 answers Aborted, then `clear_aside` (1801) removes that node unread. Crash at `rmdir.after_aside`, a file arrives, another folder's node appears at the name: record `Rmdir/Aborted`, one content folder with 2 entries orphaned | Open, before E23-S4 closes. The FIL-06.12 card row must name this case until it is fixed |
| C2-02 | Medium | No Larsal-made vault has been opened by the peer app, and no 4 GB file has crossed | Check 2b | Open until the owner names the peer run |
| C2-04 | Low | A default run checks the chunk index and a name's parent ID only against Larsal's own arrangement | V11, V12 and V7 stay green on the default peer tests; V12 and V7b go red on the ignored library test | Open until a multi-chunk, nested peer-made vault is in a default run |
| V-1 | Low | A cancelled write is answered after the half-written files are removed: median 50.99 ms, slowest of five 187.52 ms against 100 ms (Builder). Neither pass reran it: the lead's holds. The research line asks for the cancel within 100 ms and says median for the rates only, so Verify reads it as every time | `tests/measure.rs` responsiveness, 1 GiB, 4 workers. The Builder timed the cause: the unlink of the 512 MiB staged file and of the kept copy | Open, before E23-S4's cancel is shown to a person. Fix: answer the cancel first, remove after |
| C1R3-F3 | Low | Test gaps: Y07, Z12 and Z13 survive the crate's tests. Z13 (delete_dir's emptiness check before the walk off) survives every test, and would delete a shared folder that is not empty with Ok | C1's tables | Open. One test each |
| C2R3-01 | Low | The freshness test says "a counter or another guessable source fails", but a generator that repeats only after a restart passes | `src/tests/content_rules.rs:158-163`; C2's X41b, X44b | Open. Record each draw in test builds, or narrow the comment |
| C2R3-02 | Low | The no-ordinary-equality scan misses `.cmp(...).is_eq()`, and counts a comment as a verify call | `content_rules.rs:303-327`; C2's S6, S7 | Open |
| Workers | Low | More workers give no steady gain: at 1 GiB, 1, 2 and 4 workers read to output at 155.5, 221.2 and 307.6 MiB/s, create 26.2, 218.0 and 213.5, one run each | `tests/measure.rs` | Open: measure again on an idle Mac before the default is fixed |
| Staging cleanup | Low | `close_staging` looks at a name and then removes it, two calls, in the operation's own random 0700 staging folder | `write.rs` `close_staging`. Only ciphertext goes there; on a volume that ignores ownership another account could swap a file in between | Open |
| Wipe limits | Low | The wipe walk sees freed heap only | `tests/wipe.rs` header | Open: FIL-04.13's independent proof on both targets |
| Format limits | Medium | The format does not authenticate whole-object swaps, old authentic versions, whole trailing chunks cut, a folder's ID link, or the key file's layout | `fil04_t07_*`, `fil04_t08_*` assert each one happens | Open: E23-S6 disclosure, FIL-06.9 in E23-S4 and E23-S6 |
| C1R3-F4 | Info | The walk-limit words are off by one for a folder with no ID backup | `write.rs:1581-1582` refuses above 10,001 raw entries, the backup counted. Plant R3-09 | Words in the FIL-06.7 and FIL-06.12 rows |
| C1R3-F5, C2R3-04 | Info | The Builder's LD list holds the FIL-06.8 row twice, and the FIL-06.16 card row claims too much in two places | Builder's `proposed-LD.md` lines 16 and 17 | Fixed by the rows below |
| C1R3-F6 | Info | A stale file handle moves a file that later took its name | A file handle carries no ID, as the card says. Nothing is lost | Note |
| C2R3-03 | Info | X45, X47 and X30e survive with no key and nonce pair repeated | C2's table | Note |
| V-2 | Info | The first candidate's three commits carried `Joseph Ilhan <josephilhan@Josephs-MacBook-Pro.local>`, the Mac's fallback identity at the host name; Main's 38 carry `Joseph Demirian <hello@JosephDemirian.com>` | `git log 3d4ac36..ddaf340` | Fixed: the lead rebuilt them as 8abd77e, 4a405fe and 971870b, author and committer `Joseph Demirian <hello@JosephDemirian.com>`, the same trees, the same messages; `reviewed_commit` and `reviews.E23-S3.source` follow to 4a405fe (The commits) |
| V-3 | Info | The guarded README's own_agent paragraph says five folders | `scripts/guarded/README.md:47` | Open: next guarded-tool round |
| V-4 | Low | The full guarded run sits close to its alarm when the Mac is loaded | The PASS run of e808d32 took 3,197.8 s of 3,540. This story adds 85.6 s of tests and one crate to build and lint. At load averages of 11 to 16 the run of ddaf340 reached 3,555.4 s and lost its native, docs and fuzz lanes; at 5 to 17 the run of 971870b took 2,803.0 s. One full run costs 47 to 60 minutes of the Mac | Open: the lead runs the full check when other agents' builds are paused. If runs keep reaching the alarm, the lead parks it for the owner's report: the alarm is the owner's cap |
| V-5 | Low | Wall-clock tests in the full run fail when the Mac is loaded, in code this story does not touch | `crates/larsal-platform/src/clipboard.rs:303` `countdown_clears` and `:317` `new_copy_restarts_countdown` (an 800 ms countdown checked at 1,600 and 2,000 ms); `crates/larsal-browser/tests/int03.rs:1458` F-244, `:1562` F-245, `:1596` F-252 ("under 200 ms", best of 5, the F-334 fix). Run of ddaf340, load 11 to 16: all five FAILED (the clipboard pair in the net build only; the int03 three at 200.001, 295.4 and 368.2 ms). Run of 971870b, the same code: all five ok | Open. Each failure costs a full rerun. Fix: bound the clipboard tests by the countdown's own event, not the wall clock, and let int03 measure CPU time, or run these lanes alone; until then a lead reading one of these five as a lone failure reruns |
| V-6 | Low | A Swift focus test of the QR feature fails when the Mac is loaded: the one failure of the run of 971870b | `macos/LarsalTests/QrFocusReturnTests.swift:229` in `shortcutInTheEditor()` (QR-T01, FEA-10.3, E21-S2): `QrFocus.shared.held == button` after the wait at line 88, at most 100 renders of at least 50 ms each, then line 289. Run of 971870b, load up to 17.2: failed after 36.5 s, its suite 328.7 s. Run of e808d32: passed after 15.8 s. The story changes no Swift | Open. Fix: wait on the focus change itself, or a time bound sized for a loaded Mac, in E21-S2's test code |

### Found by the reviews and fixed before this commit

Each was found in round 1 or 2 and is fixed on this commit. The test named goes red without the fix, by the Builder's or the Checkers' mutants.

| Id | Severity | What it was | Test |
|---|---|---|---|
| C1-F1 | High | A folder moved into itself or below its own child said Ok, and the subtree left the tree | `fil06_t07_a_folder_never_moves_into_itself_or_below_itself` |
| C1-F2 | High | A tree delete followed a directory ID a live folder outside also used, and removed the other's files | `fil06_t12_a_tree_delete_never_follows_an_id_another_folder_uses` |
| C2-01 | High | No test guarded freshness: one nonce for every chunk, or a zero content key, passed | `fil04_t05_every_chunk_nonce_and_every_content_key_is_fresh` |
| C1R2-F1 | High | A stale folder handle acted on whichever folder later took its name | `fil06_t08_a_stale_folder_handle_changes_nothing` |
| C1R2-F2 | Medium | A tree delete of the top folder orphaned every top-level folder | `fil06_t12_a_tree_delete_of_the_top_folder_is_refused` |
| C1R2-F5 | Low | The rmdir resume removed the content folder without the emptiness check | `fil06_t07_an_rmdir_resume_keeps_an_item_that_arrived` |
| C1R2-F6 | Low | `delete_dir` removed the content of a folder a twin still used | `fil06_t12_delete_dir_of_a_shared_empty_folder_removes_only_its_node` |
| C1R2-F4 | Low | Test gaps around the outside walk | `fil06_t12_the_outside_walk_sees_every_twin_and_skips_only_the_deleted_node` |
| C2-03, C2R2-02 | Low | The ledger MAC was compared as text; constant time proven by reading only | `fil06_t16_a_ledger_copy_with_a_changed_mac_is_refused`, `fil04_t12_no_mac_or_tag_is_compared_with_ordinary_equality` |
| C2R2-01 | Low | A counter for the content key or header nonce passed | `fil04_t05_every_chunk_nonce_and_every_content_key_is_fresh`, by bit distance |
| C1-F3 | Low | The stores-apart check never refused on its own in a test | `fil06_t13_stores_apart_refuses_on_its_own` |
| (Builder) | Low | A create refused as not apart left the empty folder it made | `fil06_t13_a_create_refused_as_not_apart_removes_only_what_it_made` |
| C1-F4 | Low | The ledger's limits did not say that deleting both copies, or a second stores folder, starts at 0 | Words, in the FIL-06.16 row |
| C1R2-F3, C2R2-03 | Medium | The whole-folder walk fails closed with reach: one big folder anywhere refuses every tree delete, empty-folder delete and such a move, as MSG-FOLDER-OPEN | Kept by the lead's ruling, now said in the rows and pinned by `fil06_t03_a_walk_limit_anywhere_refuses_deletes_and_moves` |

## Card rows: which of the Builder's to adopt

Adopt as written: the FIL-04.10 backup row, MSG-FOLDER-BUDGET, MSG-FOLDER-CANCELLED, MSG-FOLDER-INSIDE, and the plan/architecture.md rows (the plug-ins line, the folder tree, the new section, the file table, the "Must:" line, the crates table, the larsal-crypto and larsal-platform lists, the fuzz line). Add one sentence to the new architecture section: "It installs no allocator: the scrypt crate's working blocks rely on the zeroing allocator of the front end, so `larsal-ffi`'s must stay in the path."

Adopt with these changes:

- **FIL-06.16:** "the key file's (signed_by, version_proven)" becomes "the configuration's (signed_by) and the key file's (version_proven)". "and finds no MAC check anywhere else in the crate" becomes "and finds no other call to `mac::verify_` in the crate; a computed MAC compared some other way is not seen (C2R3-02)" (C2R3-04).
- **FIL-06.7 and FIL-06.12**, in the card rows and in the Builder's two LD rows for them: each "with more than 10,000 items" becomes "with more than 10,001 stored entries, its ID backup counted (more than 10,000 items when it has its backup)" (C1R3-F4).
- **FIL-06.12:** after "when the node aside holds another ID, it goes back to its place and the record is Aborted." add "When another folder's node now holds its name, the resume ends Aborted and removes the node it set aside without reading it, so an item that arrived in that folder is left unreachable (C1R3-F2, open until fixed)."
- **FIL-06.8:** after "Reads (listing, lookup, capture) check the session only." add "A write reads the node and then acts in a second call. A node swapped in between is caught where the write reads what came out: a folder delete reads its ID, a file delete a file's digest. A move and a file update do not read it back, so a node swapped in during a move is not caught, and the move can take a folder below itself (C1R3-F1, open until a move reads back)."

The Builder's residual-windows finding loses "Not reproducible by a test without a seam in that moment": Checker 1's plant uses the seam `rename.before_switch`. Its Status becomes the C1R3-F1 row above.

## Routed, and safe while nothing calls this crate

Who calls `larsal-folders` on this commit: only `fuzz/Cargo.toml` names it, with feature `fuzz-door`, and the fuzz crate is its own workspace, so the feature cannot reach a product build. No Swift, no `larsal-ffi`, no `larsal-cli`. `larsal-folders` does not call `larsal-files`, so F-340, F-341 and F-342 are not reached by this story.

| Open item | Safe to leave open now | Why | Must close before |
|---|---|---|---|
| C1R3-F1 | Yes | It needs an outside writer inside one move turn, in this exact shape. A sync that merges two Macs' moves can already give the same result through the format. No caller exists to run a move | E23-S4 closes |
| C1R3-F2 | Yes | It needs a crash in the folder delete, an item arriving, and another node at the name before the restart | E23-S4 closes |
| C2-02, C2-04 | Yes | Larsal reads what the peer made. Only Larsal's own writing is unproven against the peer, and no person can write a folder with Larsal yet | The owner's peer run; E23-S4 closes |
| V-1 | Yes | No screen shows a cancel. The median meets the target | E23-S4's cancel |

## Secrets (rule 4), on the delta

- No `println!`, `eprintln!`, `dbg!`, `print!`, `tracing` or `log::` in `crates/larsal-folders/src` outside tests, and none in the fuzz target.
- `Error` is `Copy` and has no payload: no text from a file, no path, no name. Every content failure is the one `Error::Open` with its fixed words.
- `MasterKeys` prints `MasterKeys([hidden])` and is not `Clone`. Passwords are `SecretString`. Master keys, the key from the password, content keys and plaintext buffers are `SecretBytes`, and the master keys sit on pages kept in RAM where the system allows it. A recovery item's `Debug` leaves out its name.
- Nothing plain goes to a file the crate makes. Scratch and recovery copies hold ciphertext, and the journal holds encrypted names. The wipe walk checks that no scratch stays.

## Rule 3, rule 1 and unsafe, on the delta

- **Rule 3:** `larsal-folders` imports no crypto crate. Every primitive and every random byte comes through `larsal-crypto`: `random::fill` in `content.rs`, `read.rs`, `vault.rs` and `write.rs`. The only place that names the crates is the scan's own word list. `larsal-crypto` adds `gcm.rs`, `siv.rs`, `keywrap.rs` and `text.rs` and grows `kdf.rs`, `mac.rs` and `base64.rs`, over crates approved in LD-379.
- **Rule 1:** the run's name guard passes on the whole tree (Static, above). `testdata/SOURCE.md` names the public project of the desktop vault, as the research card does. The second pass ran `scripts/check-names.sh` from its private clone of this commit on this page.
- **Unsafe:** `#![forbid(unsafe_code)]` in `crates/larsal-folders/src/lib.rs:46`. The new `unsafe` blocks are in `crates/larsal-platform/src/macos/folder.rs` only, each with a `// SAFETY:` note, as Rust rule 2 allows; both Checkers read them.

## Measured

The Builder's round 3 release run of `tests/measure.rs` on tree 0a4580a, whose crate bytes this commit holds unchanged (log SHA-256 `81eadcf546254e2bd01876d6a7af881f0d0639de3b2480d1f108753c2542cf3f`). Verify read the log and did not repeat the run: the lead held the Mac for the guarded runs, and 4 GiB files five times over would load the Mac under them. Load average before the Builder's run: 7.03, 6.88, 7.22, with other work running. Same-Mac baseline: read 16,279.7 MiB/s from the cache, write with fsync 1,150.7 MiB/s, so the rate target is min(100, 0.25/(3/R+2/W)) = 100 MiB/s.

| What, 4 workers, five runs | 256 MiB | 1 GiB | 4 GiB | Target | Met |
|---|---|---|---|---|---|
| Read to new output, median | 234.2 MiB/s | 589.5 MiB/s | 171.6 MiB/s | ≥ 100 MiB/s | Yes |
| Create, median | 238.1 MiB/s | 578.2 MiB/s | 163.3 MiB/s | ≥ 100 MiB/s | Yes |
| Slowest of five, read / create | 190.5 / 175.5 | 115.5 / 133.4 | 124.8 / 84.7 | (the target is the median) | |
| Peak memory above the start | 0.6 MiB | 0.6 MiB | 0.2 MiB | | Bytes and hash equal on every run |

| Latency | Median | Slowest | Target | Met |
|---|---|---|---|---|
| List 128 names | 0.60 ms | p95 0.81 ms | ≤ 250 ms | Yes |
| 10,000 names, first 256 | 4.88 ms | p95 4.91 ms | ≤ 500 ms | Yes |
| Unlock after the key work, first page | 9.74 ms | p95 12.94 ms | ≤ 500 ms | Yes |
| First progress of a write, 1 GiB | 34.04 ms | 70.96 ms | ≤ 100 ms | Yes |
| Chunk boundary, 81,915 samples | 0.03 ms | 47.21 ms | ≤ 250 ms | Yes |
| Cancel acknowledged, read | 16.06 ms | 24.98 ms | ≤ 100 ms | Yes |
| **Cancel acknowledged, write** | 50.99 ms | **187.52 ms** | ≤ 100 ms | **No, one run of five (V-1)** |

The key work itself (N = 2^18, r = 8) took 378.3 ms at the median and is not counted or lowered. Workers, 1 GiB, one run each: read to output 155.5, 221.2 and 307.6 MiB/s with 1, 2 and 4 workers; create 26.2, 218.0 and 213.5 (the Workers row).

## The two Checkers (story check 7)

| Checker | Verdict | Read | Seal SHA-256 | Report SHA-256 |
|---|---|---|---|---|
| C1 | APPROVE_EXACT_CANDIDATE, 0 blocking | fix.patch `f0190ee8c3f62dcfb3e4ab381919cd941e7f89706102daac6535e4e8408371a5`, tree 0a4580a, and the round 3 delta `cf0a6bae97d96074ea2748a30cbf6e48a9ce067baeb4114e9e82cd19d67ad2ba` | `51442f0ac3e342a0539e5397bef834059ddc0408328ce40ed60a9ba71c732b54` | `70e335cd428256c4c45af72ca105d3e3667813a05aa7e462cd224689f5c71222` |
| Sensitive C2 | APPROVE_EXACT_CANDIDATE, 0 blocking | The same | `571c6a96b7e73fa5ec0660b441731a26b0e56c0b37b4bdd7bfe820e9bb2df926` | `defa1688d835fb49fb822df723d5271b1ed80b7a161d9cda7c6a0db402294e6a` |

Rounds 1 and 2: C1 asked for changes twice; C2 asked once and approved round 2. Their findings of rounds 1 and 2 are fixed, kept by the lead's ruling, or open in the rows above. The first pass checked that base plus fix.patch has the tree of 9090fdc, and that only ddaf340, the two tables, follows. The second pass checked that 4a405fe has that same tree, and that only 971870b, the two tables, follows.

## The run of record (added by the lead at landing)

Limit 9 below names the run of 04:30. This signature's precondition asked for a full guarded run of 971870b8d1a6f7906afce1d01a1cfb0fe0c2793e that reads Overall PASS. The lead ran it again with other agents' builds paused (root `/private/tmp/larsal-gc-971870b-yQ24`): **Overall PASS**, 2623.3 s of the owner cap. Rust 4,476 passed, 0 failed, 99 ignored, 166 of 166 programs; Swift 462 of 462 (the result bundle: 462 passed, 0 failed); APP09 18 of 18; docs 18 passed; fuzz 31 routes, all exit 0, fewest runs 1557; against e808d32's baseline 0 lost, 0 newly ignored. `summary.txt`, `summary.json`, `test-names.json`: `e8f252357d9f1df86a180e7672c33fe61ce0891e13c0a17707b034f552e58541`, `ef2c45dc0c1b0dee0d6d37695e95fcd39c0ad8082a2d186bcb2e623160ca6127`, `9fcd274cb1b290a2ef3ac767e5d929a66095620a1c87b9a4ce3cafd7e8f63b3d`. The lead checked these lines against the precondition word for word before the fast-forward.

## Rows the lead carried

LD-480 is the build's decision row; LD-481 to LD-490 are the Builder's ten rows, the second FIL-06.8 row dropped as a copy (C1R3-F5), with the C1R3-F4 words in the FIL-06.7 and FIL-06.12 rows, the C1R3-F2 sentence in the FIL-06.12 row and the residual-window sentence in the FIL-06.8 row. LD-491 is the tables row, LD-492 the downloads, LD-493 the peer run. F-406 to F-431 are the Builder's findings rows: those fixed in a round are closed, four point to the Verify row that stays open, and the residual-windows row now points to F-432. F-432 to F-441 are the rows above, C1R3-F1 first. The card rows are in FIL-04.10, FIL-06 (FIL-06.7, .8, .12, .16 and the three messages) and plan/architecture.md, with the changes the section above names; the architecture's larsal-crypto list became table rows. The FIL-06.16 row's proof words, as Verify corrected them (C2R3-04), read: the source scan holds the ledger's check (read_copy), the journal's (read_journal), the configuration's (signed_by) and the key file's (version_proven) to larsal-crypto's verify, and finds no other call to `mac::verify_` in the crate; a computed MAC compared some other way is not seen (C2R3-02). `FIXTURES.json` is kept next to `MANIFEST.json`, outside the project. The story status line and E23-S4's carried line are in plan/epics.md.

## Limits of this signature

1. **Check 2b is OPEN.** No Larsal-made vault has been opened by the peer app, and no downloaded program ran.
2. **The library vaults ran only on purpose.** In the run they show as ignored, with their reason.
3. **arm64 only.** No x86_64 test ran.
4. **Memory proof** sees freed heap blocks only. Stacks, registers and swap are not proven. The scrypt crate's working blocks rely on the zeroing allocator of the front end.
5. **Speed** is the Builder's run, read by Verify and not repeated, on a shared, loaded Mac. The write cancel's slowest run is over its target.
6. **Fuzz** is short: 31 s for `folder_readers` in the guarded run (111,980 runs) and the Builder's 60 s. The 24-hour run waits for E13-S3.
7. **Randomness** cannot be proven by tests. It comes from `larsal-crypto`.
8. **Not rerun:** neither pass reran the Builder's or the Checkers' mutants, and both read the guarded runs rather than running them. The second pass ran no test, mutant or plant: it relies on the first pass's runs on ddaf340, whose code is this commit's, and checked their proof files by SHA-256 only.
9. **The guarded run of 971870b reads Overall FAIL**, for one reason outside this story's code: the Swift test `QrFocusReturnTests/shortcutInTheEditor()` (V-6), so Swift is 461 of 462 on this commit. Rust, APP09, docs, fuzz and the baseline all pass in it. This signature holds once a guarded run of this commit reads Overall PASS.

## Evidence

| What | SHA-256 |
|---|---|
| The Builder's fix.patch | `f0190ee8c3f62dcfb3e4ab381919cd941e7f89706102daac6535e4e8408371a5` |
| The round 3 delta | `cf0a6bae97d96074ea2748a30cbf6e48a9ce067baeb4114e9e82cd19d67ad2ba` |
| The Builder's source seal | `a2f56bcba1aa657b257ac5944554e79b308c2f05fb286405efc62a6e49809f02` |
| The downloads manifest, `MANIFEST.json` | `af8707bbd160c56803c4e1cd786183f622612ca00397c7f46555953522de1185` |
| The fixtures' record, `FIXTURES.json` | `fdc20ba1a6802f661f0ceb8fc07b2fe46de9d13b262dfca6d23a674462b4df3a` |
| `pins.json` and `routes.json` of this commit, 971870b | `9b3e9824bd8b2b7c4ba94eea9ca090e3649b7198112e34c9f68ac8749e7f6b05`, `a85702cf7688e34f0422632ea51317da28b27732764e9f4e98c83cf741e1567e` |
| `pins.json` of ddaf340, before the rebuild | `204f1a54de669dc6a6c5afee227087ba973d3355a1a5b122a50d5af017970611` |
| The guarded run of 971870b: `summary.txt`, `summary.json`, `test-names.json` (FAIL, 04:30, Swift 461 of 462) | `8c1812c2048aff7c68bcf303ba52753b7893e79d3a1bf6e44df4c145e5b35cff`, `52f5930db3fb2092689dd3dd329c0fde1958d30482c0e5a66af4564d449fe27e`, `7854bdcc63ba670e1ab8e7de6538b8d6aebff63c6deec8442c4e97d14c9b484e` |
| The guarded run of ddaf340: the same three (FAIL, 03:02, total alarm) | `4066f3086a51693da0a6f28505f8ff1d5bd5c6f52363ad98f538ace06769f7d7`, `24e88cceef56cfb8810d134552f15b79bc7a2f25871403ce134e3e9e4c9f61f6`, `666f5963a765ebb452f1b6e2110970f6b45f4e71df60fcc91f6f4772958fddae` |
| The first pass's mutant table, 20 rows: the control passed, 19 went red | `797d69cee4324df6cddf1e21fb22fd06ec00dffca34a453065a9aa0f8f1ac69b` |
| The first pass's mutant script | `fe6c53f9c3dcf287106afc4ee951c821d8ca379019733c50932f3ba3cd038e49` |
| The control run and the library vault tests | `6a2a5b7600bad9827b3304bc4809b425b804e70bfdb7f17a70ebaf889065fbbe` |
| Checker 1's plants on ddaf340 | `7139c873bec125ad36b7089a047843e901e8f1af38f346e7cbe5cd04af40e9c5` |
| The whole NIST GCM files, run on purpose | `a8beb4ab07cbce8676e45a0d1b98cf441dffc941ae6b19f719af3fc2f8be5f5a` |
| The hashes of every input the first pass read | `013ccb3e0b02ad48c89292b4c4491015d1af2d1baa9724fcb59e6fcd3da069bc` |
| The first pass's seal (SIGNED_WITH_LIMITS on ddaf340) and report | `da8ba61087715d9d684f9b7387bce1e8c419d8387b7faa32fe2c0c9920f05bc5`, `49a7a62234dfa36d5d832a89d31bc809f877ce11a4295623c2d9634eb7d75f8d` |

The second pass recomputed every SHA-256 the first pass sealed, from the files in the Builder's, the Checkers' and the first pass's folders and the downloads folder: each one matched.
| Checker 1's plant file, `c1r3.rs` | `9f3c5163096c00a61360f6761728752bf64a25d743400524f7d9e23b95ecd998` |
| The Builder's speed run and fuzz run | `81eadcf546254e2bd01876d6a7af881f0d0639de3b2480d1f108753c2542cf3f`, `8126cb98f92c7eb62e63f51a6771879f1a7e66980d8c39839b407a795e17acf7` |

## Report end

- Story: E23-S3.
- Files changed by Verify: none in the project. This page is proposed for `security/parity/`.
- Proof: this page, commit `971870b8d1a6f7906afce1d01a1cfb0fe0c2793e`, the same code as ddaf340 (The commits). Guarded run of 971870b at 04:30: Overall FAIL by one Swift test outside this story (V-6); Rust 4,476 passed, 0 failed, every program of this story among them; APP09 18 of 18; 18 doc tests; 31 fuzz routes; 0 tests lost (The run).
- Open issues: under "Findings rows" and "Limits of this signature".
- Next step: the lead runs the full guarded check of 971870b again, with other agents' builds paused. If it reads Overall PASS, the lead merges this commit, adds this page with that run's numbers in The run, the status line, the card rows and the decision rows, and numbers the findings. If it fails in a program, doc test or fuzz route of this story, this signature does not hold. E23-S4 closes C1R3-F1, C1R3-F2 and V-1 before its own close.
