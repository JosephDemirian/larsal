# E16-S7b Key changes and the key-file part: Verify, second pass

Story: E16-S7b (plan/epics.md). Cards: SYN-03 (SYN-03.1, .3, .8, .9, .12, .14), MOD-11.31, MOD-12.4, MOD-13, APP-05, FMT-03.22, FMT-03.23, INT-08.34. Decisions: LD-264, LD-266 (2), LD-267 (2), LD-269 (3), LD-426, LD-427. Checkers: C1 and Sensitive C2 (key handling), five rounds, and a narrow sixth round for V-1.
Date: 2026-11-17 (phase one, before the run of record); 2026-11-23 (phase two, the run of record).
Role: Verify, second pass (a narrow re-pass). It proves round 6's fix commit `1130d94` and its tables commit `ecd621f`, the stack that lands the story (candidate-m21, head `91a7377e797b2198bdb482f3c9550785925c8317`), the end of V-1, and that each row of the first pass still holds at that head. Everything was run from a private clone. Phase two read the run of record of candidate-m22 (top commit `a90fc8bf4acbeb44e7d0de3737ac8bc766c85e77`), read line by line the two story files its lead commits change, and proved the rows those files touch again on a90fc8b.

**Result: signed with limits.** The first pass refused `3c3bb9c` on V-1 alone. Round 6 fixed V-1 with one test file, and the fix holds on 91a7377:
- V-1's two tests pass together 20 of 20 times.
- With the old tag built back in, 0 of 10 runs pass.
- The 11 `restart()` tests pass together 12 of 12 times.
- No other folder is shared.

Every story check that has tests passes by its named tests on 91a7377. For each of them, a mutant turns those tests red: a product mutant, or for check 11 a planted script line. The private copy was restored after each. Every other row of the first pass still holds.

The run of record is candidate-m22's guarded full check of `a90fc8bf4acbeb44e7d0de3737ac8bc766c85e77`, in two parts on that one commit with one tool. Both parts read Overall PASS. Its diff over 91a7377 changes two story files, `saving.rs` and `session.rs`, and in each only what the test build compiles. Verify read both line by line, and proved again on a90fc8b every row they touch (the next section). Two guarded runs of 91a7377 failed under the Mac's load and are not the run of record. In both, the story's tests all pass, and static, native and docs exit 0.

## The run of record

Phase one's PENDING line set four items: (1) part A reads Overall PASS, with the story's 96 test functions ok and 0 names lost; (2) part B reads Overall PASS, with every Swift and APP-09 test passed and every fuzz route run in full; (3) in each part, 0 grants withheld, 0 custody changes, and the owner's 3600 s cap kept; (4) the diff over 91a7377 names none of the story's 21 code paths. Phase two read each of them from the run's own files, in the live roots and in their durable copies builds/m22-run/partA and partB (`run-of-record.txt`, `lead-commits.txt`, `f439-identity.txt`). Candidate-m22 is 91a7377 plus two lead commits: `9800dfd228d67fc4c4aaa0290d87272afe088893` (F-439's patch) and a90fc8b (its tables). F-439 is the findings row about wall-clock tests that fail when the Mac is loaded (security/findings.md).

| Item | Part A: `--only static,rust`, root /private/tmp/larsal-gc-a90fc8b-2zpr | Part B: `--only native,docs,fuzz`, root /private/tmp/larsal-gc-a90fc8b-2Smn |
|---|---|---|
| First line | `Overall PASS (only static,rust)`. The tool exits 4, as a passing part does | `Overall PASS (only native,docs,fuzz)`. The tool exits 4 |
| Commit and tool | a90fc8b, tree `a0b8cac8`. The 23 tool files the part hashed equal a90fc8b's own `scripts/guarded` files, and its log says "tool against the commit: equal" | The same commit, tree and 23 tool hashes as part A |
| Steps | source exit 0; static exit 0 in 627.0 s, 18 of 18 steps, names PASS (12599 files scanned); rust exit 0 in 1280.4 s. Native, docs and fuzz did not run | source exit 0; native exit 0 in 669.5 s; docs exit 0 in 185.7 s; fuzz exit 0 in 405.9 s. Static and rust did not run |
| Counts | Rust: 5274 passed, 0 failed, 134 ignored, 179 of 179 programs. By lane (passed, failed, ignored): workspace 4105, 0, 112; sync 755, 0, 15; net 81, 0, 7; release 288, 0, 0; release-browser 45, 0, 0 | Swift: 492 tests in 74 suites passed (result bundle: 492 passed, 0 failed, 0 skipped). APP-09: 18 passed, 0 failed. Native attempts G1, A1 and B1 each exit 0 with 0 gate failures. Docs: 23 passed, 0 failed. Fuzz: 37 routes, each run for 31 s against its 30 s budget (`FUZZ_SECONDS='30'`, gc_static.py:66) with exit 0, fewest runs 1111, no alarm, and each route's log has one "Done N runs" line with the summary's N |
| The story's tests | All 96 of the story's test functions are ok: 93 in `sync:larsal-ffi`, and one each in `workspace:larsal-core`, `workspace:larsal-format` and `workspace:larsal-sync`. No release lane runs any of them. V-1's two tests are ok | None of them is a Swift, docs or fuzz test. The story has no fuzz route: routes.json has no row for it, and it is the same blob at 91a7377 and at a90fc8b |
| Tests this page and the rows name | 62 of them are in the run. All are ok but 4, which are ignored by design, as in the baseline: `t26_kill_child`, `fil03_t08_t09_real_volumes`, and the workspace copies of `fea01_32_field_heavy_vaults_stay_bounded` and `t83_f252_int03_17_urls_of_2048_characters_under_200_ms`. Those two are ok in the release and release-browser lanes | None of them runs in part B |
| Baseline test-names-f52befe.json | 5204 names of part A's steps compared: 0 lost, 0 newly ignored, 204 new. Verify's own count is the same | 524 compared: 0 lost, 0 newly ignored, 9 new. Verify's own count is the same |
| Grants and custody | 60 grant rows read, 0 withheld (reviewed_commit 9800dfd); custody 0 changed (19 programs, 23 tool files) | The same |
| Crash reports | None new during the run, none on purpose, none own and not on purpose | None new during the run. The line reads "own and not on purpose: None", because part B has no rust step to count them; with none new, none can be own |
| Time, against the owner's 3600 s cap | 1914.7 s from 2026-11-22 19:11:51 +0300, with no hold wait | 1178.3 s by the tool; 1268.4 s wall from 2026-11-22 20:15:23 +0300, with 90.0 s of hold wait |
| summary.txt SHA-256 | `17e3784b…`, equal in the live root, in builds/m22-run/partA and in run-evidence | `23d6bc0b…`, equal in all three places |

**Part B's first try** (root /private/tmp/larsal-gc-a90fc8b-xeLh) read `Overall FAIL (only native,docs,fuzz)`, tool exit 1. One Swift test failed, `ParityGeneratorTests/passphraseControls()` (macos/LarsalTests/GeneratorTests.swift:267), so Swift reads 491 of 492 and attempt B1 exits 65. The rest of it reads as part B: APP-09 18 of 18, docs 23 passed, 37 fuzz routes with exit 0, 0 names lost, custody 0 changed, no crash reports. Its `swiftc` pin differs from part B's because the tool builds `bin/swiftc` for each run with the root's path inside it (gc_native.py:724). The lead judged the failure a timing flake (builds/records-m22/lead-rows.md, row 9). It touches no row here: the story has no Swift screen, and every row rests on Rust tests, which run in part A.

### What the lead commits change

`git diff --name-only 91a7377e797b2198bdb482f3c9550785925c8317 a90fc8bf4acbeb44e7d0de3737ac8bc766c85e77` names 18 paths. Two of them are story code paths, so PENDING item 4 does not hold as written: `crates/larsal-ffi/src/saving.rs` and `crates/larsal-ffi/src/session.rs`, both from 9800dfd. Its own fallback applies: Verify read both diffs line by line against this page. The other 19 story code paths are the same blob at 91a7377 and at a90fc8b, and 15 of the 21 are the same as at 5ab6374. routes.json is the same blob. a90fc8b changes only pins.json.

| File | What changes | What it does to the rows |
|---|---|---|
| saving.rs, `b33477c5` to `6cf78bf6` | Lines 1 to 1742 are byte-equal. The three hunks (at lines 2934, 2951 and 2960 of a90fc8b) lie inside `#[cfg(test)] mod tests`, which runs from line 1743 to the file's end. In `f_101_a_save_the_lock_overtook_keeps_the_change_in_a_recovery_copy`, a 200 ms sleep becomes a wait until the slot's version reaches the one before plus 2 | Nothing. That test is not the story's, and no row cites it. No product line changes |
| session.rs, `e0f97e46` to `3aadf772` | 11 lines inserted, 0 removed. The old `fn state()` stays word for word, now under `#[cfg(not(test))]`. Under `#[cfg(test)]`, a second `state()` takes the same lock and wraps its guard in `crate::share::Timed`, which reads through to the guard. It times the hold only when a test records that session (`Hold::begin` gives `None` otherwise), and the hold ends before the guard drops | The product build is the same. In the test build, every larsal-ffi row's tests now take the lock through the wrapper. No story test records a session; still, the rows' tests and mutants ran again on a90fc8b (below) |
| pins.json, `6370d9aa` to `1238554b` | 54 pins move, in 7 groups, each to its object at 9800dfd and at a90fc8b. `reviewed_commit` becomes 9800dfd, 40 row labels become F-439, and `reviews."F-439"` is added; `reviews."E16-S7b"` is unchanged. At a90fc8b, all 151 pins of the 60 rows equal their objects at a90fc8b and at 9800dfd | No check is weaker. One row keeps the label E16-S7b (the review entry's note, below) |

9800dfd is F-439's approved patch exactly. `git diff --binary 91a7377 9800dfd` has the SHA-256 of builds/f439/r4/fix.patch, `3a9676da…`. Applied to 91a7377 in a private index, the patch writes tree `a53d8382`, which is the tree of 9800dfd and of `d4b32783`, the head its two Checkers read. Both reports read APPROVE_EXACT_CANDIDATE (c1-report.md `5d349790…`, c2-report.md `8888772e…`). Both lead commits carry the owner's name as author and committer, and their messages name no agent or tool.

The story's 21 code paths are:
- crates/larsal-core: `src/retired.rs`, `src/settings.rs`, `tests/mod13.rs`
- crates/larsal-ffi: `API.md`, `src/copies.rs`, `src/edit.rs`, `src/local_state.rs`, `src/qr.rs`, `src/saving.rs`, `src/session.rs`, `src/sync.rs`, `src/sync/tests.rs`, `src/vault_settings.rs`, `src/wizard.rs`
- crates/larsal-format: `src/integrity.rs`
- crates/larsal-platform: `src/device_key.rs`
- crates/larsal-sync: `src/lib.rs`, `src/state.rs`, `src/sync.rs`, `src/sync/tests.rs`
- scripts: `check-sync-link.sh`

The story's commits also changed two tables, `scripts/guarded/tables/pins.json` and `routes.json`.

### The rows again on a90fc8b

session.rs's new `state()` is in the test build of every larsal-ffi row, so Verify ran those rows again on a90fc8b, from a private clone. The test program (larsal-ffi lib, features net and sync) was built from a fresh target with an empty CARGO_HOME under compile.sb: exit 0 in 132 s, 0 warnings, 613 tests listed, SHA-256 `ae597f6a…` (`build.txt`). Every run was under run-key.sb. Each mutant was applied in the private copy ctl/ only, with phase one's mutants.py (`00641cc6…`), built into ctl/'s own target, run on the row's named tests, and the copy restored; ctl/ is clean at a90fc8b after each one and at the end.

| Row | On a90fc8b | Result |
|---|---|---|
| The story's larsal-ffi tests: `sync::tests::` and `local_state::tests::`, 3 threads (`story.txt`) | 170 passed, 0 failed, 1 ignored (`t26_kill_child`, run by its parent test), in 88 s. All 93 tests the story added to sync/tests.rs are ok, and so are the 20 its checks cite, the 127 syn03 tests and the 6 C1R4-01 tests | as on 91a7377 |
| V-1's pair together, 2 threads, 5 runs, with the sampler (`race.txt`) | 5 of 5 runs pass and 0 of 10 results are not ok. Both tests' own folders stood at once in 168 of 219 samples | holds |
| Control: the old tag built back in ctl/ (`control.txt`) | 0 of 3 runs pass and 6 of 6 results are not ok. In each run, `syn04_t13_t08_…` has the first run of record's words, "The local vault file is unavailable. Try again." The control program holds no `t13-ld264` | holds |
| The 11 `restart()` tests together, 3 threads, 2 runs (`restart.txt`) | 2 of 2 runs are all ok, with 11 distinct spare folders in each and never the old shared name | holds |
| Checks 1 to 7, 9 and 10: phase one's mutants (`mutants.txt`) | Each one is red on its named tests, as on 91a7377. M1: t01 and f321. M2: "the file stays". M3: t04. M4: all 3, and T16 on M4's program. M5: "A's Merge anyway takes no deletions". M6c: the 2099 test, "the real change goes past the planted time". M7: tests.rs:4401. M9: 2 of the 5 ("not in the exact form Larsal writes"). M10b: T24's own needle search, "PUT /v1/vaults/… holds" the part's hex | 9 of 9 red |
| C1R4-01 and the session.rs union: mutant MU, `open_last_synced` opens any file | 5 of the 6 C1R4-01 tests are red | as on 91a7377 |
| Round 5's plants: the three files `16ca8187…`, `97e46095…` and `3179bb2d…` appended in ctl/ (`plants.txt`) | 5 pass. 3 are red by design, each with its Checker's words: c1r5_p2 ("the saved edit reached neither the server nor an unlock at the linked path"), c1r5_p3 ("approve_unlock opened a linked file with a key file that is not the part") and c2r5_probe19 (`MSG-SYNC-LOCAL-FILE` for a store that gives no part) | as the first pass |
| U6 (C2R5-2): the plants plus `last_synced` ignoring the file name | c2r5_probe21 is red: "vault 2's part kept as vault 1's" | as the first pass |

The page's other rows were read at 91a7377 and not run again. They rest on files a90fc8b does not change, or on the story's tests in other crates, which are ok in part A:
- Check 11's script and the two build scripts it reads are the same blob at a90fc8b (`check11-files-a90fc8b.txt`).
- The 14 files the rows quote anchors from are the same blob (`anchor-files-a90fc8b.txt`).
- sync/tests.rs, which round 6's tag scanners read for V-1, is the same blob.
- larsal-sync, larsal-format and larsal-core change no story file.

## The whole difference

| Item | Result |
|---|---|
| Clone | `file:///Users/josephilhan/Documents/Code/larsal`, no hardlinks; candidate-m16 and candidate-m21 fetched; checked out at 91a7377. `git fsck` is clean, and 12618 tracked files hash equal to HEAD's blobs (`identity.txt`) |
| First pass's commits | `5ab6374` (the story) and `3c3bb9c` (its tables, the first pass's commit; parent 5ab6374, tree `dec8ae84`). Round 5's fix.patch `bfea2fc7…` on `d6179b1` still writes tree `399e3018`. 17 of its 21 paths are blob-equal; the 4 moved files carry the story's 18, 14, 337 and 142 changed lines, equal and in order (`r5-identity.txt`) |
| Round 6 | `1130d94`, parent 3c3bb9c: `git diff --binary` is byte-equal to round 6's fix.patch (SHA-256 `b26a8434…`, 1000 bytes), and applying it to 3c3bb9c writes tree `19f07f9f`. It changes only `crates/larsal-ffi/src/sync/tests.rs`: line 4059 becomes `KeyChange::new("t13-ld264")`, and `restart()`'s spare folder takes the restarted Mac's folder name (lines 4856 to 4859). Both round 6 Checkers: APPROVE_EXACT_CANDIDATE (C1-REPORT.md `23a5eb65…`, C2-REPORT.md `f51b9549…`) |
| Its tables | `ecd621f` changes only pins.json: `reviewed_commit` becomes 1130d94, the words of `reviews."E16-S7b"` change, and the `crates/larsal-ffi` pin of 31 rows moves from `90832dea` to `c44d4b6d`, which is its object at 1130d94. No other pin moves (`tables-r6.txt`) |
| The stack | 15 commits, linear, each with author and committer Joseph Demirian <hello@JosephDemirian.com> and no agent or tool name. E22-S6 (`02d03ab`, `7d9af23`) and E25-S2 (`c9f9ad0`, `5d03a2c`) change no story path except the guarded tables. E7-S2 (`99674d1`, `1d14347`, `08e615d`, `9c8b6e4`, `edac292`, `4789dc6`, `91a7377`) shares `crates/larsal-ffi/API.md`, `src/edit.rs` and `src/vault_settings.rs` |
| The three shared files | Every line the story added stands at 91a7377, same text, same order: API.md 11 of 11, edit.rs 14 of 14, vault_settings.rs 56 of 56. Every line it removed stays removed (7, 0, 3). A three-way merge of the story side and E7-S2 alone over Main gives each head file with 0 conflicts, and each side's diff comes off the head file with exact context (`kept-lines.txt`, `merge3.txt`). merge3.txt counts only lines that are not blank (+13 and +54), because edit.rs adds 1 blank line and vault_settings.rs adds 2 (`unchanged.txt`) |
| Clash | Verify read the merged code whole: `change_key`, `new_key_file`, `choose_key_file`, `view` and `site_access_count` in vault_settings.rs; `Keep`, `EditState`, `add_site` and `remove_site` in edit.rs. E7-S2's Browser Keys and site-list changes and this story's key-change guards share no function and no state. In kept-lines.txt, the functions the story adds lines in and the functions E7-S2 changes have 0 in common, in each of the three files. No line a later story adds names a function the story changed, and the reverse matches only homonyms (`cross-calls.txt`, `cross-calls-back.txt`) |
| Pins at the head | All 151 pins at 91a7377 equal their objects, at 91a7377 and at its `reviewed_commit` 4789dc6. Three rows still carry the label E16-S7b; each pin equals its object at 5ab6374, 1130d94 and 91a7377 (`pins-check.txt`) |
| Unchanged since 5ab6374 | Of the story's 21 code paths, only four change after 5ab6374: API.md, edit.rs and vault_settings.rs (E7-S2), and sync/tests.rs (round 6, the same blob `6216c64d` at 1130d94 and at the head). The other 17 have the same blob at 5ab6374 and at 91a7377. No file in crates/larsal-sync, larsal-format or larsal-platform changes. In larsal-core, only `src/refs.rs` changes (E7-S2, 99674d1), and it is not a story path (`unchanged.txt`) |

## V-1: found in the first pass, closed by round 6

| Proof (91a7377, run-key.sb) | Result |
|---|---|
| The pair together, 2 threads, 20 runs, with a sampler of the temp folder (`race.txt`) | 20 of 20 runs pass and 0 of 40 results are not ok. Both tests' own folders (`sync-t13-a` and `sync-t13-ld264-a`) stood at once in 262 of 311 samples, so the runs did overlap |
| Control: the old tag built in a private copy (`control.txt`) | 0 of 10 runs pass and 20 of 20 results are not ok. Two of them have the first run of record's words, "The local vault file is unavailable. Try again." The copy was restored |
| The 11 tests that call `restart()`, together (`restart.txt`) | 12 of 12 runs are all ok: 10 at 3 threads and 2 at 11. Every run shows 11 distinct spare folders, and the old shared name `larsal-ffi-restart-spare-<pid>` never appears |
| Round 6's two tag scanners on the head (`scan-compare.txt`) | Scanner 1 finds no shared name (no DUP line). Scanner 2 finds dup 2 (both safe), dup-reach 20 and nest 24, the same counts as round 6. It now sees 60 more name sites (3473 against 3413), all from the later stories. One of them is E7-S2's new test in crates/larsal-ffi/tests/edit.rs. That test reaches the shared parent folder `edit-tests` through `personal("full-allow")`. All 22 `personal` calls there give different file names (`edit-tests-names.txt`) |

## The story's checks on 91a7377

The named tests below ran in Verify's own runs on the head program (`story-tests.txt`: 170 passed, 0 failed, 1 ignored). That ignored test is `t26_kill_child`, a child run by its parent test. All 93 tests the story added to sync/tests.rs are ok.

Each mutant was applied in the private copy only, built, run on the row's named tests, and the copy restored (`mutants.txt`, `mutants2.txt`).

| # | Check | Named tests | Mutant seen red, then restored | Result |
|---|---|---|---|---|
| 1 | A vault added to the server opens only with its master password plus the key-file part | `syn03_1_t01_f321_a_guess_of_the_right_password_cannot_open_the_server_copy`, `syn03_2_nothing_typed_opens_nothing_when_the_part_is_the_whole_key`, `syn03_1_f321_a_password_only_file_at_a_linked_path_never_goes_up` | M1: no part's key change (`if fresh` read as false). t01 and f321 are red | ok |
| 2 | A vault that already has a key file keeps it, and its F goes with the vault | `syn03_1_t02_a_vault_with_a_key_file_keeps_it_and_its_f_goes_with_it` | M2: every vault is treated as one without a key file. Red: "the file stays" | ok |
| 3 | E16-S7a's two-client test passes again, with the part copied by the helper | `syn03_5_t04_two_macs_change_two_entries_at_once_and_both_keep_both` | M3: the part pointer lookup misses its own file. Red | ok |
| 4 | LD-264 with LD-267 (2): A changes the password while B uploads under the old one, and both edits survive | `syn03_8_t13_ld264_a_key_change_and_an_upload_under_the_old_key_keep_both_edits`, `syn03_3_ld267_2_a_key_retired_before_the_put_comes_to_the_state`, `syn03_8_t18_cancel_uploads_nothing_and_the_ticks_ask_no_more` | M4: a copy under a retired key is never held as one. All 3 red | ok |
| 5 | B's deletion under the old key is deleted everywhere after B's next sync | `syn03_8_t14_bs_deletion_under_the_old_key_is_deleted_everywhere` | M5: Merge anyway runs a same-vault merge. Red: "A's Merge anyway takes no deletions" | ok |
| 6 | A planted copy under A's old password with a future key time neither brings the old key back nor deletes anything | `syn03_9_t16_a_planted_copy_under_the_old_password_brings_nothing_back`, `ld264_c1_a26b_a_planted_future_key_time_before_the_change_does_not_undo_it` | M4 turns T16 red. M6c turns the 2099 test red with "the real change goes past the planted time" (see the note below) | ok |
| 7 | After A's next upload the old password no longer opens the server copy | `syn03_9_after_as_next_upload_the_old_password_no_longer_opens_the_server_copy` | M7: the answer does not record the copy's version. Red: the server stays at version 2 (tests.rs:4401, left 2, right 3, in logs/mutants/M7-run.log) | ok |
| 8 | Two Checkers (key handling) | Five rounds of C1 and Sensitive C2 (round 5 approves `bfea2fc7…`), then a narrow round 6 (both APPROVE_EXACT_CANDIDATE of `b26a8434…`, tree `19f07f9f` on 3c3bb9c) | none | ok |
| 9 | LD-427: a linked vault carries no field 12, and a file with any field 12 entry does not go up and gives `MSG-SYNC-SAVE-FIRST` | `ld427_f322_a_public_name_is_on_no_request_and_in_no_server_bytes`, `ld427_a_file_with_field_12_gives_save_first_and_a_save_heals_it`, `ld427_a_merge_of_a_server_copy_with_field_12_writes_none`, `ld427_field_12_after_the_part_never_goes_up`, `ld427_a_vault_not_linked_keeps_field_12` | M9: the part's save keeps field 12. 2 of the 5 are red (the put refuses a file not in Larsal's exact form) | ok |
| 9b | LD-427: "the settings page says so" | No screen in this story; sync stays off in the app build. E16-S9 draws MOD-12.4's words | none | carried open |
| 10 | SYN-03 T24 runs on T13's run, with `demo2` and the part bytes as needles (LD-426) | `syn03_14_t24_nothing_in_plain_on_the_key_change_run` | M10 (the first upload carries the part after the file's bytes) turns it red, but by an earlier step. M10b (every request carries the part as hex in a header; the flow goes on) turns it red by its own needle search: "PUT /v1/vaults/… holds" the part's hex | ok |
| 11 | `scripts/check-sync-link.sh` also reads `scripts/repro-build.sh` (F-323) | `check11.txt`: PASS, exit 0, on the clone. In the private copy, `cargo build --features net,sync` appended to repro-build.sh gives FAIL, exit 1; appended to build-core.sh, also FAIL, exit 1. Restored | the planted line is the mutant | ok |

Note on check 6: M6 alone stays green on check 6's two tests. M6 drops the key floor from Vault Settings' key change. The 2099 time came in through a merge, so the vault's own `MasterKeyChanged` holds it, and larsal-core's `key_changed` already goes one second past it. Only both guards gone (M6c) turn the 2099 test red. M6 alone turns red the floor's own test, `ld264_a_key_time_seen_on_a_skipped_copy_counts`, where the future time was seen on a copy that was not merged. So no guard goes untested.

## The first pass's other rows on 91a7377

| Row | How it was rechecked | Result |
|---|---|---|
| session.rs union (C2R5-3) | session.rs, saving.rs and sync.rs are byte for byte as at 3c3bb9c, so the first pass's reading stands. Its C1R4-01 tests (6) are ok, and mutant MU (`open_last_synced` opens any file) turns 5 of the 6 red. VR-1 and VR-2 were not rerun: the first pass kept no copy of `vr_probes.rs` | holds |
| Round 5's plants (`plants.txt`) | The three plant files (`16ca8187…`, `97e46095…`, `3179bb2d…`, the hashes the first pass names) were appended in the private copy. 5 pass. 3 are red by design, each with its Checker's words: c1r5_p2, c1r5_p3 and c2r5_probe19. Restored | as the first pass |
| U6 (C2R5-2) | Plants plus U6 (`last_synced` ignores the file name): c2r5_probe21 is red (vault 1 unlocks with vault 2's bytes and part, and keeps vault 2's part under its label). Of every `sync::tests` and `local_state::tests` test under U6, 174 pass and 4 fail; all 4 are plants. Restored | as the first pass |
| larsal-sync, larsal-format syn03, larsal-core mod13 (`others.txt`) | Built and run at the head under compile.sb and run-key.sb | 40, 6 and 12 passed |
| Card anchors in the proposed rows (`anchors-rows.txt`, `anchor-files.txt`) | The rows quote anchors from 14 files. 13 of them are the same blob at 3c3bb9c and at 91a7377. The 14th, API.md, changed with E7-S2, and the rows propose no edit there. Every quoted anchor was looked up again at 91a7377 | 59 found, 0 missing |
| Guard profiles (`profiles.txt`) | compile.sb and run-key.sb equal the pause folder's, once each root path reads ROOT | equal |

## The two guarded runs of 91a7377 (information, not the run of record)

The two runs ran at the same commit and failed under the Mac's load. Their summary files equal the durable copies in run-evidence/91a7377-swRo and 91a7377-70WW (`guarded-runs.txt`).

| Item | Run 1, root /private/tmp/larsal-gc-91a7377-swRo | Run 2, root /private/tmp/larsal-gc-91a7377-70WW |
|---|---|---|
| Overall | FAIL | FAIL |
| source, static, native, docs | exit 0 each. Static: 18 of 18 steps, names PASS. Swift: 492 of 492. APP-09: 18 of 18. Docs: 23 passed | the same |
| rust | 5250 passed, 2 failed, 134 ignored. Sync lane: 754 passed, 0 failed, 15 ignored. Failed: `fea01_32_field_heavy_vaults_stay_bounded` (release lane) and `t83_f252_int03_17_urls_of_2048_characters_under_200_ms` (release-browser lane), both timing tests | 5251 passed, 1 failed, 134 ignored. Sync lane: 754 passed, 0 failed, 15 ignored. Failed: `t83_f252_int03_17_urls_of_2048_characters_under_200_ms` (release-browser lane) |
| fuzz | stopped by the total alarm after 160.0 s | stopped by the total alarm after 39.9 s |
| The story's tests | all 96 ok, in the lanes that run them | all 96 ok |
| Named tests | ok: the 18 tests the first pass cites, V-1's other test, the 11 `restart()` tests and the 6 C1R4-01 tests (36 names) | ok, the same 36 |
| Baseline | f52befe: 5728 compared, 0 lost, 191 new | the same |
| summary.txt SHA-256 | `4012bb5e…` | `fa47eaaa…` |

## The open and carried rows

The first pass's judgements stand on 91a7377, where the code they name has not changed. They stand on a90fc8b too: there the only change to that code is session.rs's test-build `state()`, and the plants and U6 give the first pass's results.

| Row | Severity | Judgement |
|---|---|---|
| V-1 (F-589) | Medium | **Closed** by 1130d94 (round 6), proven above. The findings row records it |
| C1R5-01 (F-590) | Low | Real. c1r5_p3 is still red by design on 91a7377. Not blocking while sync is off. Goes to E16-S9 before sync is turned on |
| C2R5-2, C1R5-03 (F-591) | Low | Real test gaps. U6 is killed only by c2r5_probe21, which is not in the story. Goes to E16-S9 |
| C1R5-02 = C2R5-1 (F-585) | Low | Real: false words while only the device store is unread (c2r5_probe19 and c1r5_p2 are red by design). Goes to E16-S9 |
| C2R5-4 (F-592) | Low | Real (words). c2r5_probe20 gives the same results on 91a7377. Goes to E16-S9 |
| MOD-12.4's settings words | — | Carried open. E16-S9 draws them |
| SYN-03 T23's reference-tool half (F-584) | — | Carried open. Verify did not run the reference tool (rule 2). Goes to E16-S9's Verify |
| API.md's `sync_start` words | Info | No edit in the records commit, because it would move 31 pins. E16-S9 corrects it with C1R5-01's fix |

## The Checkers' round 6 notes, judged

| Note | Judgement |
|---|---|
| C1-1 = C2-1: crates/larsal-files/tests/volumes.rs | **Real, Low, not blocking.** `Local::new` makes `larsal-volumes-<pid>` (line 73) and `work_folder` makes `run-<pid>` (line 137), each with `fs::create_dir(..).unwrap()`. Both tests that reach them run only with LARSAL_TEST_VOLUMES set, and one of them also needs `--include-ignored`. With 2 or more threads the second create fails loudly: a false red that deletes nothing. No file under scripts/ names the variable or either flag (`volumes.txt`). The file is the same blob on Main, at 3c3bb9c and at the head, and the story does not touch it. Owner: E22 (file encryption), the next story that edits that file. A findings row is proposed (F-593) |
| C1-2: the patch moves the `crates/larsal-ffi` pin | Done by ecd621f, proven above. No row |
| C2-2: `sshagent-keys` rebuilt once per process | By design. The OnceLock in crates/larsal-sshagent/tests/common/mod.rs fills the folder once per test process, and every test program of that crate names the same folder. That is safe because no two of those programs run at once: the guarded tool runs lanes one after another, and a lane's programs one at a time (`run_lane` in scripts/guarded/gc_rust.py, no threads), and `cargo test` runs test programs in turn too. No row |
| C2-3: `personal("int0318")` leaves its folder | **Real, Info.** Run alone on the head program, `t84_t85_int03_18_website_rows_in_matcher_order_with_their_notes` leaves `larsal-ffi-int0318-<pid>` in the run's temp folder (`int0318.txt`). Its four siblings remove theirs (edit.rs lines 3065, 3134, 3202, 3245). The folder holds demo data only. Owner: the next story that edits those tests. A findings row is proposed (F-594) |
| Verify's own: `reviews."E16-S7b"` names round 6 only | **Real, Info.** Three rows still labelled E16-S7b keep pins that 5ab6374 set. At a90fc8b, F-439's tables relabel two of them F-439, because their `crates/larsal-platform` pin moves with F-439's change to that crate; one keeps the label, `workspace:larsal-sync/larsal_sync`, whose two pins (`crates/larsal-sync` `0505c3d0`, `crates/larsal-platform/src/device_key.rs` `2018b2c6`) are the same since 5ab6374 (`lead-commits.txt`). The run compares pins by value and reads no review entry (`gc_pins.py` `evaluate`), so no check is weaker. Owner: the lead, at the next change to the tables. A findings row is proposed (F-595) |

## Limits of this pass

1. **The run of record ran in two parts, and part B passed on its second try.** Its first try failed one Swift test that no row of this story rests on (above). Phase one's seal is FINAL-SEAL-pre.json; phase two's is FINAL-SEAL.json.
2. **No Swift screen.** Sync stays off in the app build until E16-S9, and Verify ran no xcodebuild, swift or SwiftLint. The Swift and APP-09 counts above come from the guarded runs and from part B of the run of record.
3. **VR-1 and VR-2 were not rerun.** The first pass kept no copy of its probe file. They stand on the first pass: up to 91a7377 session.rs did not change, and at a90fc8b only its test build does, where the same lock guard is read through a wrapper.
4. **The tag scanners read the source.** A folder name built at run time from outside data is not seen; the race, the control and the restart runs cover the two shared names that were found.
5. **The mutants are a sample**, one or two per check. They are not a full mutant table; round 5's table stands for that.
6. **Load.** Other agents' runs and another project kept the Mac busy. Timing tests are not this story's, and every build and run here started with no hold mark standing. Phase two's builds and runs saw one-minute load averages from 5.8 to 28.7, on AC power, powermode 0, while other agents' builds and guarded runs used the Mac.
7. **arm64 only, offline.** The run's own stated limits also apply.
8. **Phase one's program and profiles are gone.** /private/tmp lost phase one's root on 2026-11-22. Its program `87afff51…` stands by that hash in story-tests.txt and build.txt. Its two profiles were made again from the pause folder's, and their hashes equal the seal's. Every other file the seal names equals its hash, in builds/e16s7b-verify-r2 or at its own path (`seal-pre-check.txt`).
9. **The reruns on a90fc8b are one batch, with fewer runs than on 91a7377:** the story's tests once, V-1's pair 5 times, the old tag 3 times, the `restart()` group twice, each mutant once.

## Evidence

Phase one's files were under /private/tmp/larsal-e16s7bv3-9G4CpIVJ/proof, which /private/tmp lost on 2026-11-22; their copies in builds/e16s7b-verify-r2/proof are the record. Some files in that folder are dated 2026-11-12, and others are in its root-copy-1753 folder. They come from two earlier tries at this pass, and nothing here rests on them.

| What | SHA-256 |
|---|---|
| The head's larsal-ffi lib test program (net, sync) | `87afff51e15370ac278f504a9e563a25178b0f6cfff24731f34f43061beb67d7` |
| identity.txt | `74a8b778d20b2fe040b7714adfb377cfce187c8387954a1acab5ac39756331c0` |
| tables-r6.txt | `556aabf7900daad96d35b0820576b8eeae234f0bd3dcdcbe549dcb5840acd0fd` |
| pins-check.txt | `befc05398fe2d57ce06eb11030ac551a70855d7cfb584e51443a0903e52713ce` |
| kept-lines.txt | `47c307589d115bfca2da22b025fcff3d6e94decb0b4131c97198edda2e15053a` |
| merge3.txt | `3d435514f4f9f13e292486d96fc8a7efbcff8f66b546e090c76c58a3b6e92cc9` |
| r5-identity.txt | `2d44a82901bde94214ae8defc723dfb440521c8c839333b6753d9a17578aed7c` |
| race.txt | `a9f5d30d522c8960cda1aec0a630154993d7bebbb07fdfb4191b0b4fb71f5ec5` |
| control.txt | `c756d2a038a1674e3e051ba5d6b9ec4a62129643423a1ea544e9153b3b23d308` |
| restart.txt | `8de7240ba11a2fcce2384ce285e52635c07770ba95348dd5567b830d9fb8c2bc` |
| story-tests.txt | `07cc78c85980c112710e6ca3576dc378d2a16927959c937131c023af97f901b2` |
| mutants.txt | `f32d0d4fb657bbb492ecc95cdd1aaa18fd0b1b3a4c65d887ca5c15e0a94810f6` |
| mutants2.txt | `e0385688a07cf92b7d4ca0195429d81187392ba53faed5cbf0105f341169fb56` |
| plants.txt | `d9c1c322ae5b3894e9b12d9eaf0aa3aa0c3572778ffd9475110fce963ec5957b` |
| check11.txt | `d252e14e3add1972e541f147ce00eba635150e7547a4d8a2a90cd07f7832f1fc` |
| others.txt | `499cd15a37274f99c6cddf8e0231a2e6948626c8e659d0826dd465313a0ec777` |
| int0318.txt | `fdafaa809419a1acc117351b6d850655bcfdbcd30904b751c09b6c659554bf24` |
| volumes.txt | `f379987b6dca68a7784d05360e263ede091ff365cce53d15c7aedc3710e7f025` |
| scan-compare.txt | `95b77851aab99b675401783bee2520e4e4e9be1cefd7a084a172cb9fc53a1b48` |
| guarded-runs.txt | `3b250c9621fcf366e70d3aed031ee9a118220777c3065e59e2aa7d656319c99c` |
| anchors-rows.txt | `d48dfe580b870e4b9a97265bc1d18eab1643209015518e222a2467b25576c606` |
| anchor-files.txt | `8fd27d46317ff1c83599766cf42337c43b2d75c9d4ca59076c487f216e43522a` |
| unchanged.txt | `7f67db8785ae47ccdadaabe8eda1f09968687de338bcc5251f187c3439915780` |
| edit-tests-names.txt | `ddbd0254fe05ea37ef55f3c580b082d90c12fd06b360c02cff831ee2f9e89f4b` |
| Run 1 summary.txt / summary.json / test-names.json | `4012bb5edbfe420f644d7e430cd1549a04b5f74a068706ec6cffa9014f0f86fe` / `d1003b4856309004202297cdc0340840664af84ea8f46d329848011b733ac2c6` / `b7c6f0a00d9061efea5b9eae6235b9ec6d3d125fd63ca08645f075a69b77f991` |
| Run 2 summary.txt / summary.json / test-names.json | `fa47eaaa772170fdd18e75d777d88e21025e8d0255b70ccfa58a3f44d123b511` / `941c6662754002a557ee315e25834f39bc58ecc8a77a3ef503c99b2079c67598` / `fdd16d80145b75eb18e842b862a89b3ef74833a516433d596ea61a56c757cc41` |
| Round 6 fix.patch / C1-REPORT.md / C2-REPORT.md | `b26a843487a8d4507bce3703c13fa9d3718cbd60ee445546d6162dcadb3cca21` / `23a5eb6514c350a569b1a853408a75b90a79bf7421a86f06b008ae07cfc04325` / `f51b95497636a8253c74651c38214e233406bedb545671419ecd23cb036bedc8` |
| Verify's seal | Phase one's FINAL-SEAL-pre.json (`3173bbfe6c8fddcf8c86e8d451d71d548f569b60f067dcaa36f24db867bb60ee`): the copy in builds/e16s7b-verify-r2/, as its /private/tmp original is gone |

Phase two's files are under /private/tmp/larsal-m22post-e16-i6WghAxN/proof. The run of record's files are in its two roots and in builds/m22-run/partA and partB, where each one equals its live root's.

| What | SHA-256 |
|---|---|
| Part A summary.txt / summary.json / test-names.json / run.json | `17e3784b627602f0cef558fd60f9f3eab9d2036be9ec57debc6a8016f6826db3` / `8539862ec4a3a44a46f13dd3b64d81b78e7f4abaa1a799fb135cbc8b192fb1d8` / `49ed18f67b2a1fba2171ce76e25a964129955b1b1909029cb7f384309a20ff2f` / `92020919dffb66371185fde00c086af46f4072a4a3f5bc3c5bfcfb9bb361a3e9` |
| Part B summary.txt / summary.json / test-names.json / run.json | `23d6bc0b9668ec34dc4c8f963a2fae7aaae398f02e701640b5e3bba926e62330` / `e3b21764088a65cec8c743423a5337f88efbd9a6446fea3a9fa757d6332dc7d3` / `2b5460eb5833db7499e5bca1c4e7ed4254d94f7bfd413485415a1bd8a2ac96be` / `f0452a526b813195fe50836467c3410bef2650f32f897177be4fb54836937d25` |
| Part B's first try summary.txt | `588e6e281622627fe563b0fd4daa7268b030649a54d172ac49d8c0eaffb68a5b` |
| Baseline test-names-f52befe.json | `8113610bd887ebe5604bdc79739b4f10997d9bf3839b11d482296834d24de041` |
| F-439 fix.patch / c1-report.md / c2-report.md | `3a9676da376780566ed85ebe63eb382e3d56da221fa4cb62d73c77387831b297` / `5d3497903a3f909ab88f581461a643fae1e73a9696e5f610d39efefdaac18a27` / `8888772ee510e18ca564af28f7c195a0fa1990ef4f68b0444311ef1aa1f48ab5` |
| a90fc8b's larsal-ffi lib test program (net, sync) | `ae597f6a97015663b01ca0884e9e608b4a09246a2394aa81ef536f44c3fb1297` |
| Phase two's proof files and seal | Listed with their hashes in /private/tmp/larsal-m22post-e16-i6WghAxN/FINAL-SEAL.json, which has a copy in builds/e16s7b-verify-r2/ |

## Report end

- **Story:** E16-S7b.
- **Verdict:** signed with limits (second pass). Phase one signed at 91a7377 pending the run of record; phase two read the run of record of candidate-m22 at a90fc8bf4acbeb44e7d0de3737ac8bc766c85e77 (both parts Overall PASS) and proved the touched rows again there.
- **Files changed by Verify:** none in the project. This page is proposed for `security/parity/E16-S7b-key-changes-and-part.md`, and its rows are in E16-S7b-proposed-rows.md.
- **Proof:** the tables above and the files under proof/.
- **Open:**
  - C1R5-01, C1R5-02 = C2R5-1, C2R5-2, C2R5-4 and C1R5-03 go to E16-S9 (F-585, F-590, F-591, F-592).
  - MOD-12.4's words and T23's reference-tool half (F-584) stay carried.
  - The volumes.rs pair (Low, E22; F-593), the int0318 folder (Info; F-594) and the review entry's words (Info; F-595) are new findings rows.
- **Next steps:**
  1. Put this page and the rows into the records commit.
  2. Copy phase two's proof folder to the durable checkpoints before /private/tmp is cleared.
