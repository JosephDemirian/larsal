# E7-S2 Association and site access prompts: Verify

Story: E7-S2 (plan/epics.md line 292, with its amending rows LD-556, LD-330 (4), LD-326 (1), LD-322 (7), LD-318 (2)) and LD-211 (1), which routes MOD-12 T41 to this story. Cards: INT-02 (INT-02.1 to INT-02.32, D-INT02-2, R02-2, T01 to T75), INT-01.30, INT-03.17, INT-03.18, MOD-12.18 (T41). Frames: `dialogs-connect-a-browser` and `dialogs-browser-asks-for-an-entry` of design/option-a. Checkers: C1 in three rounds, C2 in rounds 2 and 3.
Date: 2026-11-17 (phase one, on 91a7377); 2026-11-22 (phase two: the run of record of a90fc8b).
Role: Verify, the narrow re-pass after round 3, phase one (2026-11-17, after the lead's runs of 91a7377; this page called it phase two of the re-pass that day). The first Verify refused the story at 40c1689 on 2026-11-12 (V-1 to V-6). Round 3 fixed V-1 to V-5 and both its Checkers approved its exact patch; the lead stacked it as candidate-m21 (91a7377). The second pass's agents of 2026-11-12 measured on 91a7377 but never gave a result; their drafts and evidence copies were read, and only what this pass checked or ran again is used here. This pass proved again from a private clone that the stack carries the reviewed patches and nothing else of the story, read the lead's two guarded runs of 91a7377 of 2026-11-17, ran every fix's tests itself, broke each fix on purpose in private copies (26 Rust mutants, 8 Swift mutants in two guarded native runs) and saw the tests turn red, measured the two dialogs against Option A from its own offscreen shots, and read the merged code of the three files the story shares with E16-S7b. It ran no browser, changed no project file and made no commit in the project. Its logs live under /private/tmp, which does not last, so this page copies what must survive. Phase two (2026-11-22, a second Verify agent, root /private/tmp/larsal-m22post-e7-TjBZj6HD) checked phase one's seal, read the lead's two-part run of record of candidate-m22's top a90fc8b and its first try, read line by line what a90fc8b changes in the story's files, ran those rows again on a90fc8b with four mutants, and filled in the run; the section "Phase two's changes to this page" lists every word it changed.

**Result: signed with limits.** Every check of this pass passes: the stack is the reviewed work; V-1 to V-5 are fixed, each fix has a named test that passes and that fails when Verify undoes the fix (23 of 26 Rust mutants and 7 of 8 Swift mutants; the survivors are test gaps that cannot show a value); the two bridge dialogs match Option A within the limits: changed pixels 1.61 % and 1.63 % for the Connect dialog and 0.37 % and 0.40 % for the site access prompt, light and dark, against the 3 % limit; boxes within 1.5 pt, text runs within 2 pt; every string and colour present. V-6 is carried to the lead's test-browser round. The run of record, candidate-m22's top a90fc8b in two parts, reads Overall PASS in each, with every test of this story ok; F-439's lines in two of the story's files change no row's proof (phase two ran those rows again on a90fc8b, with four mutants seen red). Phase two adds one Low finding outside the story's code (FUZZ-MAXLEN).

## The run of record

The guarded run of candidate-m22's top, a90fc8bf4acbeb44e7d0de3737ac8bc766c85e77 (91a7377, then 9800dfd, F-439's round 4 patch approved exactly by its Checker 1 and Sensitive Checker 2, then a tables commit that changes only scripts/guarded/tables/pins.json), in two parts by the lead's ruling of 2026-11-17: the same commit and tool copy, each part under the 3600 s cap, each Overall PASS (a passing part exits 4), each compared with the baseline for its own steps. Part A `--only static,rust`: root /private/tmp/larsal-gc-a90fc8b-2zpr, 2026-11-22 19:11:51 to 19:43:46 +0300. Part B `--only native,docs,fuzz`: root /private/tmp/larsal-gc-a90fc8b-2Smn, 20:15:23 to 20:36:31. Copies: larsal-checkpoints/resume-2026-11-06/builds/m22-run/partA and partB, and run-evidence/a90fc8b-2zpr and -2Smn; each summary.txt, summary.json and test-names.json there equals the root's byte for byte, and run.json and run-start.json in builds/m22-run too. Read by Verify's phase two with its scripts/run_read.py and fuzz_read.py (proof/run/). The run files hold no power state.

| Item | What the run had to read (phase one) | What it read |
|---|---|---|
| Overall | `Overall PASS`, commit = candidate-m22's top, the tool against the commit equal, grants 60 rows read, 0 withheld (or the count of that commit's pins.json) | Part A: `Overall PASS (only static,rust), commit a90fc8bf4acbeb44e7d0de3737ac8bc766c85e77, root /private/tmp/larsal-gc-a90fc8b-2zpr`; part B: `Overall PASS (only native,docs,fuzz), commit a90fc8bf4acbeb44e7d0de3737ac8bc766c85e77, root /private/tmp/larsal-gc-a90fc8b-2Smn`; the tool exits 4 in each (the lead's rerun.out). Each part's summary, test names, run.json and run-start.json name a90fc8b, tree `a0b8cac88bf2bd0dc55892c9465b27afd0fe9791` (a90fc8b's), and each part ran exactly its steps. "tool against the commit: equal" in each run-quiet.log (19:11:55, 20:15:27); the same 23 tool files in both parts (map SHA-256 `1823522a…`), each equal to `git show a90fc8b:scripts/guarded/<file>`, the 23 files that path tracks. Grants: 60 rows read, 0 withheld, `reviewed_commit` 9800dfd (a90fc8b's pins.json). Custody: 23 tool files and 19 programs, 0 changed; no source, sentinel or custody change; nothing left under the roots |
| Only F-439 on top | `git diff --stat 91a7377 <top>` names none of E7-S2's 23 files (proof/stack/stack-check.txt item 2 lists them) | **Not as written; re-proven.** `git diff --name-only 91a7377 a90fc8b` names 18 paths: 17 are 9800dfd's, whose diff from 91a7377 is F-439's fix.patch byte for byte, and a90fc8b's tables commit changes pins.json. Two of the 17 are among the story's 23 files, crates/larsal-core/src/refs.rs and crates/larsal-ffi/tests/edit.rs, and pins.json is a file of the story's tables commit. Verify read the three diffs line by line: none changes what a row of this story proves; it ran the rows on refs.rs and tests/edit.rs again on a90fc8b and saw four mutants turn them red (section "Phase two") |
| Rust | 0 failed, every program run; int02 72 of 72; round 3's six new Rust tests ok in each lane that runs them: int02 `v1_int02_18_a_protected_user_name_is_hidden_in_the_summary_and_in_the_prompt_rows`, `v1_int02_18_r02_1_a_protected_title_and_the_vault_flags_hide_the_value`, `v1_c2_06_int02_18_a_reference_to_a_protected_value_is_hidden_in_the_prompt_rows`; larsal-ffi `bridge_vaults::tests::v1_int02_18_the_prompt_row_swift_reads_hides_a_protected_user_name`, `larsal_settings::tests::t41_mod12_18_s_brw_01_is_off_until_saved_on`, `vault_settings::tests::t02_int02_1_a_created_value_not_in_iso_8601_comes_as_stored` (workspace and sync) | Part A rust exit 0, 1280.4 s: **5274 passed, 0 failed, 134 ignored, 179 of 179 programs** (workspace 4105 passed and 112 ignored, 153 of 153 programs; sync 755 and 15, 17 of 17; net 81 and 7, 2 of 2; release 288 and 0, 6 of 6; release-browser 45 and 0, 1 of 1). int02 72 of 72 (workspace); the three int02 tests of round 3 ok; the three larsal-ffi ones ok in workspace and in sync. The two wall-clock tests that failed the lead's runs of 91a7377 pass: release `larsal-core/fea01::fea01_32_field_heavy_vaults_stay_bounded` and release-browser `larsal-browser/int03::t83_f252_int03_17_urls_of_2048_characters_under_200_ms` ok (ignored in workspace, as release-only tests are). Static exit 0, 627.0 s: 18 of 18 steps, names PASS (12599 files scanned) |
| Swift | every test of native-expected.txt's count passes (492, unless F-439 adds Swift tests), with `BrowserAskTests/hiddenRowValues()`, `accessAnswers()`, `connectFrame()`, `accessFrame()`, `answers()`, `VaultSettingsBehaviourTests/t02CreatedAsStored()` and `t41FollowsIntegration()` ok | Part B native exit 0, 669.5 s: **Swift 492 of 492 in 74 suites** (the log "passed"; the bundle 492 passed, 0 failed, 0 skipped, 0 expected failures; the database 492 of 492 cases ok; TEST EXECUTE SUCCEEDED). native-expected.txt is `492 18` at a90fc8b: F-439 adds no Swift test. Attempts G1 exit 0 (5.2 s), A1 exit 0 (187.3 s), B1 exit 0 (346.2 s), 0 gate failures, B1's 55 guard requests read, no report of another process. The seven named tests ok, and `VaultSettingsBehaviourTests/browser()`, `LarsalSettingsTests/dependentControls()`, `ParityEditorPagesTests/browser()` and `ReportsTests/browser()` ok |
| APP-09, docs, fuzz | APP-09 18 of 18; docs all passed; every fuzz route run for its time (no route stopped by the total alarm) | APP-09 18 of 18 (18 running, 0 failed, 0 ignored). Docs exit 0, 185.7 s: 23 passed, 0 failed. Fuzz exit 0, 405.9 s: 37 routes, each exit 0 and each its 30 s ("37 targets, 30s each"; every log ends after 31 s), fewest runs 1111, no new route, no artifact, no alarm; the story's five routes below |
| Baseline, time | 0 names lost, 0 newly ignored against the baseline; the run within the 3600 s cap | test-names-f52befe.json (SHA-256 `8113610bd887ebe5604bdc79739b4f10997d9bf3839b11d482296834d24de041`, 5728 tests): part A compared the 5204 names of its steps, 0 lost, 0 newly ignored, 0 waived, 204 new; part B 524, 0, 0, 0, 9 new. Verify recomputed both from the files: the same counts, and 5204 + 524 = 5728, so every baseline name falls in one part's steps. Part A 1914.7 s of the cap (no hold wait), part B 1178.3 s (wall 1268.4 s, 90 s of it waiting for a hold); no alarm in either |
| Crash reports (phase two's item) | — | Part A: new during the run none, on purpose none, own and not on purpose none; part B: new none, on purpose none, own and not on purpose "None" (part B runs no rust step, the step that counts its own); no new diagnostic report in either run.json |

The story's tests by name (each part's test-names.json):

| Tests | Lanes and result |
|---|---|
| larsal-browser int02, all 72 | workspace: 72 ok |
| int01, all 102, T06's `port::t84_short_proof_other_nonce_or_wrong_content_gets_error_8` and `safari::t84_short_proof_other_nonce_or_wrong_content_gets_error_8` among them; int01_setup, all 28 | workspace: 102 ok; 28 ok |
| int03, all 45 | workspace: 42 ok and 3 ignored (`t83_f244_…`, `t83_f245_…`, `t83_f252_…`, release-only); release-browser: 45 ok, `t45_to_t49_int03_11_labels_and_paths`, `int03_10_registrable_domain_equals_a_label_by_label_run_of_every_rule`, `t84_int03_18_notes_under_website_rows` and `t89_int03_19_the_build_carries_the_list_and_its_version` among them |
| larsal-ffi `bridge_vaults::tests` 4, `vault_settings::tests` 3, `browser_seam::tests` 2, `browser::tests` 6, `larsal_settings::tests` 28, `reports::tests::int_02_32_browser_report`, `edit::tests::t84_t85_…`; tests/edit `f281_int02_16_the_editor_keeps_a_host_added_to_a_full_list` and `int_02_29_browser_page_stores_its_options` | workspace and sync: all ok |
| larsal-core mod12, all 30 | workspace: 30 ok |
| larsal-browser fuzz_seeds, 2 | workspace: 2 ignored, as written (they write the corpus when run by hand) |
| Swift `BrowserAskTests` 5, `VaultSettingsBehaviourTests` 10 | all ok |
| APP-09 | 18 ok |
| Every test name this page and the proposed rows cite | 118 names cited; 104 are tests of the run, each ok in a lane that runs it (release-only tests ignored in workspace, ok in release or release-browser); the other 14 are hashes, Verify's probes or a mockup function |

The story's fuzz routes (part B, g/logs/artifacts/fuzz-<route>.log; proof/run/fuzz-and-timing.txt):

| Route | Seeds | Done | Crash or artifact |
|---|---|---|---|
| references | 23 files | `Done 2397 runs in 31 second(s)` | none |
| browser_message | 30 files ("seed corpus: files: 30 min: 2b max: 1048579b"), LD-318 (2)'s two seeds among them | `Done 34434 runs in 31 second(s)` | none |
| search_query | 36 files | `Done 43417 runs in 31 second(s)` | none |
| url_match | 21 files | `Done 155349 runs in 31 second(s)` | none |
| autotype_sequence | 12 files | `Done 67920 runs in 31 second(s)` | none |

Part B's first try, /private/tmp/larsal-gc-a90fc8b-xeLh (2026-11-22 19:47:23, 1181.7 s; copies builds/m22-run/partB-try1 and run-evidence/a90fc8b-xeLh), read Overall FAIL with tool exit 1 for one Swift test only: `ParityGeneratorTests/passphraseControls()`, one issue at macos/LarsalTests/GeneratorTests.swift:267:9 (the phrase's words not all capitalised after the case press), Swift 491 of 492; its eight failure lines are that test, the counts it lowers and B1's exit 65. Docs 23 of 23, fuzz 37 routes (fewest runs 1116), APP-09 18, the baseline 0 lost and 0 newly ignored, no crash report; the same commit and tool. It touches no row of this story: GeneratorTests.swift and the generator are not among the story's files, `BrowserAskTests` and `VaultSettingsBehaviourTests` passed in that try (all 11 of the story's Swift tests ok), and the same test passed in the run of record on the same commit (the lead's row 9 judges it a timing flake of the test).

## The lead's two runs of 91a7377 (information)

Read with Verify's script scripts/run_read.py from each run's summary.txt and test-names.json (proof/runs/run1-run2-read.txt, and the head and failure lines in proof/runs/*-summary-head-and-failures.txt).

| Item | Run 1, /private/tmp/larsal-gc-91a7377-swRo | Run 2, /private/tmp/larsal-gc-91a7377-70WW |
|---|---|---|
| summary.txt SHA-256 | `4012bb5edbfe420f644d7e430cd1549a04b5f74a068706ec6cffa9014f0f86fe` | `fa47eaaa772170fdd18e75d777d88e21025e8d0255b70ccfa58a3f44d123b511` |
| test-names.json SHA-256 | `b7c6f0a00d9061efea5b9eae6235b9ec6d3d125fd63ca08645f075a69b77f991` (commit 91a7377) | `fdd16d80145b75eb18e842b862a89b3ef74833a516433d596ea61a56c757cc41` (commit 91a7377) |
| Overall | FAIL | FAIL |
| Steps at exit 0 | source; static (18 of 18 steps, names PASS, 849.6 s); native (711.0 s); docs (23 of 23, 244.1 s) | source; static (18 of 18, 838.4 s); native (823.9 s); docs (23 of 23, 293.7 s) |
| Rust | exit 1: 5250 passed, 2 failed, 134 ignored, 179 of 179 programs. Failed: release `larsal-core/fea01::fea01_32_field_heavy_vaults_stay_bounded` and release-browser `larsal-browser/int03::t83_f252_int03_17_urls_of_2048_characters_under_200_ms`, both wall-clock tests (F-439) | exit 1: 5251 passed, 1 failed, 134 ignored. Failed: release-browser `t83_f252_…` only |
| Fuzz | exit 1: stopped by the total alarm; 37 routes, fewest runs 0 | the same |
| Swift, APP-09 | 492 of 492 (74 suites); APP-09 18 of 18 | the same |
| Baseline, time | 5728 compared against f52befe, 0 lost, 0 newly ignored, 191 new; 3544.6 s of the cap | the same counts; 3544.5 s |
| This story | int02 72 of 72 (workspace); round 3's six new Rust tests ok (the three larsal-ffi ones in workspace and sync); the seven Swift tests ok; int01 102, int01_setup 28, larsal-ffi `bridge_vaults` 4, `vault_settings` 3, `browser_seam` 2, `browser` 6, `larsal_settings` 28, `reports::tests::int_02_32`, `edit::tests::t84_t85_…`, tests/edit `f281_…` and `int_02_29_…` all ok in both lanes; larsal-core mod12 30; int03 42 ok and 3 ignored (workspace), 44 ok and `t83_f252_…` failed (release-browser) | the same |

Neither failure touches this story's code: fea01 is larsal-core's field-heavy vault bound, and t83_f252 times URL matching over 2,048-character URLs (int03.rs, matching.rs and psl.rs are not in E7-S2's files; E7-S2 changes site.rs's `record_use` only). The fuzz step ran out of the run's 3600 s; no route reported a crash. In the run of record of a90fc8b both tests pass in their release lanes.

## The whole difference

| Item | Result |
|---|---|
| Base | Main 10544e6c2dd03a6e7be9213fda971b765772df21 (E22-S5's docs commit). Rounds 1 and 2 were reviewed on b6eaf17 and merged for the first Verify as 8d3bf55 (the code) and 40c1689 (pins.json only), branch candidate-m17 |
| Round 2's patch | fix.patch SHA-256 `b82ec0a04ced759a16c73ba95638b0b6faae042e8dd7fde02b77531d5fa49cbd`; both round 2 Checkers APPROVE_EXACT_CANDIDATE; `git diff 10544e6 8d3bf55` equals it byte for byte (the first Verify's proof) |
| Round 3's patch | fix.patch SHA-256 `6cc45b7dc37e623411baf4bb1ee888453bc6c2463ae090ca347f2c5f84cbd587` (checked again against round 3's copy), base 40c1689c89d3eab6c23b87a817b8eb455c68b698, 16 paths, +748 −149; Checker 1 and Sensitive Checker 2 APPROVE_EXACT_CANDIDATE for head 9341b8b3e34c12ee1f2aa9e39bc6eb6be9508df2, tree `c2f380672c3d92355e0c15fb2b63b3ca12d9efab` |
| Patch on its base | `git read-tree 40c1689` into a private index, `git apply --cached fix.patch`, `git write-tree`: `c2f380672c3d92355e0c15fb2b63b3ca12d9efab`, the approved tree; `git diff --binary 40c1689 c2f38067` equals fix.patch byte for byte. 9341b8b's commit object is in the Builder's private clone only; its tree stands for it |
| The stack | Branch candidate-m21, seven commits on candidate-m20 `5d03a2c7715c20caf5e0f4a267fb3435cde24492` (E16-S7b, E22-S6, E25-S2, which have their own Verifies): `99674d13919f1ce48537ec5f80f502cdc734cbe2` (8d3bf55 picked, its patch-id), `1d14347bc71e46c30a00918b4b4abe6b5a31a512`, `08e615d49ced72ea4eea7d317141f807b1273567`, `9c8b6e428d7567d67bd6b2c688fadb51d80798dd`, `edac2926b04bc2c08feec51763b63e34265339a0`, `4789dc644c3050048cf1148cfec47e87b6110fc3` (round 3's five commits picked), and `91a7377e797b2198bdb482f3c9550785925c8317` (tables), tree `f34040a95f290d0490f44f268694a77df0f9aafb`. The old tables commit 40c1689 is not picked |
| The story's files | `git diff 10544e6 c2f38067` names 24 paths, 23 without scripts/guarded/tables. The six picks change exactly these 23 and no other file. 20 of them have at 91a7377 the blob they have in c2f38067 |
| The three shared files | crates/larsal-ffi/API.md, src/edit.rs and src/vault_settings.rs are also changed by candidate-m20. For each, the change lines of 5d03a2c..91a7377 are E7-S2's of 10544e6..c2f38067 exactly (+4 −4, +9 −48, +126 −6), and those of c2f38067..91a7377 are candidate-m20's of 10544e6..5d03a2c exactly (+11 −7, +14 −0, +56 −3) |
| The merged functions, read whole | edit.rs: E7-S2 changes `add_site` and `remove_site` (now `larsal_browser::Lists::of`, `add`, `write`) and removes `write_site_access` and `MAX_SITES`, both private to the file; candidate-m20 adds `Keep::proven` and the `EditState` fields `sync_held` and `sync_given`, all three under the `sync` feature. vault_settings.rs: E7-S2 changes `BrowserKey` (new `created_text`), `view` and adds `site_access_count` and two tests; candidate-m20 adds `part_kept`, `typed_kept` and changes `change_key` and the key file step. API.md: different rows. No changed signature either side relies on, no duplicated item, no rule one side changed under the other. `BrowserKey` is built only in vault_settings.rs and in VaultSettingsTests.swift, both E7-S2's. candidate-m20 changes no Swift file (proof/stack/shared-files-read.txt). Both feature sets of the merged crate pass in the lead's runs: workspace 4091 passed, sync 754 passed, 0 failed |
| Tables | 91a7377 changes only scripts/guarded/tables/native-expected.txt (`488 18` to `492 18`) and pins.json: `reviewed_commit` to 4789dc6; 60 rows, the same keys; 43 rows changed, each taking the review name E7-S2 and at least one moved pin: 49 pin entries of six paths (crates/larsal-ffi 31, macos/LarsalTests 6, macos/Larsal 5, crates/larsal-browser 3, crates/larsal-ffi/src/lib.rs 3, crates/larsal-core 1), each equal to its object at 4789dc6; 0 pins differ from their objects at 91a7377 |
| Authors | Author and committer of all seven commits: `Joseph Demirian <hello@JosephDemirian.com>`; one parent each; no trailer and no tool name in any message |
| The seam in a release build | Absent: `#[cfg(debug_assertions)] mod browser_seam;` (lib.rs lines 12-13) and every call site in browser.rs (lines 167, 256, 258, 268) under the same cfg. lib.rs, browser.rs and browser_seam.rs are the files the first Verify built in release at 40c1689 (no seam string in `liblarsal_ffi.a`) with round 3's lines; they equal their blobs in c2f38067 |
| candidate-m22 (phase two) | a90fc8bf4acbeb44e7d0de3737ac8bc766c85e77 = 91a7377, 9800dfd228d67fc4c4aaa0290d87272afe088893 (F-439 round 4, its fix.patch byte for byte, tree `a53d8382…`) and a90fc8b (scripts/guarded/tables/pins.json only). It changes two of the story's 23 files with F-439's test-only lines (next section) |

All in proof/stack/stack-check.txt (44 checks, all ok) and proof/stack/shared-files-read.txt. Phase two's checks of candidate-m22 are in the next section.

## Phase two: the seal, candidate-m22 and the story's files F-439 touches (2026-11-22)

A second Verify agent, root /private/tmp/larsal-m22post-e7-TjBZj6HD (mode 0700), cloned the project with `--no-hardlinks` (no object of the clone is a hard link; candidate-m22 among its branches) and checked out a90fc8b (tree `a0b8cac88bf2bd0dc55892c9465b27afd0fe9791`; `source/` stayed clean, `work/` is a private copy of it for the reruns and the mutants). Every shell began with `/usr/bin/env -i` and HOME, TMPDIR, XDG_CACHE_HOME, CARGO_HOME (empty at the start) and CARGO_TARGET_DIR under that root, RUSTUP_HOME the owner's and RUSTUP_AUTO_INSTALL=0; cargo ran offline, `--locked`, `-j 3`, under compile.sb, and the test programs under run-key.sb (the brief's profiles with only the root paths changed: proof/host/profiles.txt); Python was the pinned 3.9 with `-B -I`. Before every build and run it waited while BUSY-native or HOLD-native-quiet existed. It ran no guarded run, no Swift and no xcodebuild, changed no project file and made no commit.

| Check | Result |
|---|---|
| Phase one's seal | FINAL-SEAL-pre.json (SHA-256 `4403e2fdcdfa4c5312fecba1d2f26cf892025d709f697d57f016069229822e6d`) lists 1138 evidence files. Phase one's root lost its files on 2026-11-22; all 1138 stand in the v3/ copy with their sealed SHA-256: 0 gone, 0 differing (each read with lstat as a regular file; proof/seal/seal-check.txt) |
| The stack under the run | `git diff --binary 91a7377 9800dfd` equals F-439 round 4's fix.patch byte for byte (SHA-256 `3a9676da376780566ed85ebe63eb382e3d56da221fa4cb62d73c77387831b297`; F-439 round 4's Checker 1 and Sensitive Checker 2 each read APPROVE_EXACT_CANDIDATE and name that hash in their result and seal); `git apply --cached` of it on 91a7377 in a private index gives `a53d838276b243c78464a0d93a859d7f3518c2ad`, 9800dfd's tree; a90fc8b changes only scripts/guarded/tables/pins.json; one parent each; author and committer `Joseph Demirian <hello@JosephDemirian.com>`, no trailer (proof/diff/f439-patch-check.txt) |
| What a90fc8b changes | `git diff --name-only 91a7377 a90fc8b`: 18 paths, 2262 lines added and 524 removed. Of the story's 23 files: crates/larsal-core/src/refs.rs and crates/larsal-ffi/tests/edit.rs. Of the story's tables commit 91a7377: scripts/guarded/tables/pins.json. No path under spec/, plan/, design/, security/, macos/ or extension/ (proof/diff/diff-names.txt) |
| refs.rs, line by line (145 diff lines) | Four hunks, none in the story's lines. `EntryIndex.order` becomes `order::Order<'v>`, a private wrapper of the same `Vec<&'v Entry>` whose `push`, `len`, `get` and `iter` hand out the same entries in the same order; only a test build counts each entry handed out (an `AtomicUsize` under `#[cfg(test)]`; `seen()` is empty in every other build); `order` starts as `Order::default()`. A new `#[cfg(test)] mod f_244_tests` (F-244, INT-03.17). The story's change, the clause of `masked` that hides a field named "Password" (F-272, and V-1's rule for references), stands as on 91a7377: `masked`, `search_reads_withheld`, `find_indexed`, `find_scoped` and `resolve` are byte-equal, 51 lines lower (`masked` from line 485 to 536; proof/diff/functions-equal.txt) |
| tests/edit.rs, line by line (39 diff lines) | One hunk: `mod_09_10_ticking_expires_sets_now` (MOD-09.10, F-439) reads "now" before and after the call instead of allowing 2 s. The story's two tests, `int_02_29_browser_page_stores_its_options` and `f281_int02_16_the_editor_keeps_a_host_added_to_a_full_list`, and their helpers `personal` and `entry_id` are byte-equal |
| pins.json, row by row | `reviewed_commit` 4789dc6 to 9800dfd; a new review F-439; 60 rows, the same keys; 40 rows changed, 37 of them this story's, which take the review name F-439 (and 2 of E16-S7b's, 1 of E25-S2's); 54 pin entries of seven paths moved (crates/larsal-ffi 31, crates/larsal-platform/src/clipboard.rs 13, crates/larsal-browser 3, crates/larsal-platform 3, crates/larsal-ffi/src/session.rs 2, crates/larsal-core 1, crates/larsal-server 1); every pin at a90fc8b equals its object there; the six rows that keep E7-S2's name and the pins of macos/Larsal, macos/LarsalTests and crates/larsal-ffi/src/lib.rs are unchanged; native-expected.txt stays `492 18` (proof/diff/pins-read.txt) |
| The other files this page names | crates/larsal-browser/src/matching.rs: 186 lines added, none removed, each under `#[cfg(test)]` (a per-thread step count) or in the new `mod f439_tests`. tests/int03.rs: only F-439's timing tests (T81, T83, F-244, F-245, F-252) and their helpers; the four int03 tests this page cites are byte-equal and call no changed item (proof/diff/int03-helpers.txt). psl.rs: unchanged. saving.rs: a test only; session.rs: the test build's `state()` is timed by share.rs's test-only `Timed`, the other builds' `state()` unchanged under `#[cfg(not(test))]`; `save.non_data_on_lock` is still read nowhere in saving.rs or session.rs. The seeds fuzz/corpus/browser_message/seed-28 (FF FF FF FF) and seed-29 (1,048,579 bytes) are the blobs of 91a7377 |
| Does any row's proof change? | No. In every build but larsal-core's own unit tests, refs.rs hands out the same entries in the same order, and no line of the story changed; the app and every other crate's tests link larsal-core without its test lines. The rows on refs.rs (F-272 and its LD row, V-1's reference rule, INT-02.18, T23 to T56) and on tests/edit.rs (F-281, T68 to T70) were run again all the same (below) |

Verify's runs on a90fc8b (proof/logs/progress.txt, each line with the load and the power state; proof/mutants/):

| Run | Result |
|---|---|
| int02, control (23:22) | **72 passed, 0 failed** (load 4.15 on 14 cores, AC Power, powermode 0) |
| larsal-ffi lib, the story's modules (23:24) | `bridge_vaults::tests::` 4 of 4, `vault_settings::tests::` 3 of 3, `larsal_settings::tests::t41_mod12_18_s_brw_01_is_off_until_saved_on`, `browser_seam::tests::` 2 of 2, `reports::tests::int_02_32_browser_report`, `edit::tests::t84_t85_…` ok (load 6.28) |
| larsal-ffi tests/edit (23:25) | `f281_int02_16_the_editor_keeps_a_host_added_to_a_full_list` and `int_02_29_browser_page_stores_its_options` ok (the target's temp folder pointed into run-key.sb's writable area by a link, as phase one did; the profile unchanged) |
| Mutant M272: refs.rs `masked` without its clause for a field named "Password" (phase one's M272) | int02 **71 passed, 1 failed**: `f272_r02_2_a_password_stored_plain_with_protect_password_off_never_reaches_a_summary` (int02.rs:1750); larsal-core rebuilt; restored, byte-equal to source/ and to a90fc8b's blob |
| Mutant VM-V1-refs-own: refs.rs `masked` ignores a field's own protected flag | int02 **71 passed, 1 failed**: `v1_c2_06_int02_18_a_reference_to_a_protected_value_is_hidden_in_the_prompt_rows` (int02.rs:2024); restored, byte-equal |
| int02 after the two restores (23:25) | **72 passed, 0 failed** |
| Mutant ME-281-list (23:52): edit.rs `add_site` puts the host on the other list (`lists.add(&[host], deny)` for `!deny`) | `f281_…` **failed** (tests/edit.rs:444: the Allow list holds 2 hosts, not 1000) and `int_02_29_…` **failed** (tests/edit.rs:401, "adding to Deny removes it from Allow"); larsal-ffi rebuilt; restored, byte-equal to source/ and to a90fc8b's blob |
| Mutant ME-T70-off (23:52): edit.rs `set_browser_option` writes "false" for an option turned off even when the entry had no key (`Some("false".to_owned())` for `had.then(…)`) | `int_02_29_…` **failed** (tests/edit.rs:425, "off without a key: nothing written"); `f281_…` passed, as it sets no option; restored, byte-equal |
| tests/edit's two tests after the restores (23:52) | `f281_…` ok; `int_02_29_…` ok (load 10.10, AC Power, powermode 0) |

The host before the runs (23:11:45): load 6.49 4.81 4.07 on 14 cores, AC Power, 100 % charged, powermode 0, no mark, no guarded run; after each chain, the same power state, no mark and no process of the guarded tool (proof/host/host-1.txt, host-2.txt at 23:30:14, host-3.txt at 23:54:34). Verify started no guarded run and signalled no process.

## Verify's own runs

From the private clone at 91a7377 (clean at the start; `work/` and `nat/` are private copies of it). Every shell began with `/usr/bin/env -i` and HOME, TMPDIR, XDG_CACHE_HOME, CARGO_HOME and CARGO_TARGET_DIR under Verify's root, RUSTUP_HOME the owner's and RUSTUP_AUTO_INSTALL=0. Cargo was offline, `--locked`, `-j 3`, under compile.sb; programs ran under run-key.sb (the profiles of the brief with only the root paths changed). Python was the pinned `Python3.framework/Versions/3.9` with `-B -I`. Swift ran only through private copies of the guarded tool (`guarded_check.py <commit> --repo nat --only native --busy … --hold …`), each exported from the commit it ran. Before every heavy step Verify waited while `BUSY-native` or `HOLD-native-quiet` existed (E23-S4's native run held the mark from 14:38 to 14:48; Verify's builds waited for it).

The earlier agent's probes were reused after their hashes matched its notes: `probe_int02_v2.rs` `5f350697…`, `probe_int02_v3_extra.rs` `4692388a…`, `probe_bridge.rs` `38bf4a4f…`, `probe_vault_settings.rs` `bc482dab…` (proof/probes/work-files.txt; the probed int02.rs, bridge_vaults.rs and vault_settings.rs of `work/` equal the hashes its notes record). Its Swift evidence (runs m1 and m2 of 2026-11-12) has no hash record, so it is not used as proof; its mutants were run again here.

| Step | Result |
|---|---|
| Stack proofs | Above; proof/stack/ |
| int02 with Verify's probes | **80 passed, 0 failed**: the 72 tests of the project and 8 probes (the first pass's seven and the second pass's "more ways to a protected value") |
| larsal-ffi lib, the story's modules | `bridge_vaults::tests::` 5 of 5 (4 of the project, the probe `verify_c2r3_01_the_prompt_row_swift_reads_hides_a_protected_title`); `vault_settings::tests::` 4 of 4 (3 of the project, the probe `verify2_v2_a_long_created_text_with_line_breaks_comes_as_stored`); `larsal_settings::tests::t41_mod12_18_s_brw_01_is_off_until_saved_on`, `browser_seam::tests::` 2 of 2, `reports::tests::int_02_32_browser_report`, `edit::tests::t84_t85_…` ok |
| larsal-ffi tests/edit | `f281_int02_16_the_editor_keeps_a_host_added_to_a_full_list` and `int_02_29_browser_page_stores_its_options` ok (the target's temp folder pointed into run-key.sb's writable area with a link; the profile unchanged) |
| int03 | 42 passed, 3 ignored |
| Guard refusals, not failures of the code | larsal-ffi `browser::tests::`: 1 of 6 passed; the five `e7s6_*` tests stop at their `create_dir` of a /tmp folder (browser.rs lines 351, 382, 424, 470, 512: "Operation not permitted"), which run-key.sb denies; all 6 pass in both of the lead's runs. In the mutant control, `larsal_settings::tests::app03_s_time_01_02_reach_the_copy` fails at the pasteboard the guard denies, so the larsal_settings mutant is judged by the 27 others |
| Builds | 0 compiler warnings in the four builds |
| Rust mutants | 26 in `work/`, one at a time, each file restored byte for byte: **23 killed by named project tests, 3 survive**; the same verdict as the earlier agent's 26, mutant for mutant (proof/mutants-read.txt) |
| Assets | scripts/make-option-a-assets.py run again in a private `git archive` export of 91a7377: exit 0, and `diff -r` of its macos/Larsal against a second export exits 0: Glyphs.swift, the colour sets and the fonts are what the script makes; Glyphs.swift has `plugs-connected` 0xEB5A and `globe-simple` 0xE28E, as the vendored fill.css says (`\eb5a`, `\e28e`) |
| Native run n1 | f3363d8 = 91a7377 with SM-V3a (proof/native/swift-mutant-diffs.txt; pins.json's macos/Larsal pin moved in 5 rows), root /private/tmp/larsal-gc-f3363d8-nf8S, 14:58 to 15:08: tool against the commit equal; grants 60 rows, 0 withheld; G1 exit 0 (4.4 s), A1 exit 0 (198.1 s), 0 gate failures; B1: Swift 492 tests in 74 suites, **491 passed, 1 failed**: `VaultSettingsBehaviourTests/t41FollowsIntegration()` at VaultSettingsTests.swift:223, :224 and :225 (SM-V3a killed). The other six named tests, `VaultSettingsBehaviourTests/browser()`, `LarsalSettingsTests/dependentControls()`, `ParityEditorPagesTests/browser()` and `ReportsTests/browser()` ok; APP-09 18 of 18. The tool's 8 failure lines are all that one test (step exit 65, the three counts, no TEST EXECUTE SUCCEEDED); the kernel's sandbox rows were read (55 requests, 0 bad); no crash report; 585.6 s. Overall FAIL (only native), as a mutant run must read. Its shots are the parity shots |
| Native run n2 | c0b43ca = 91a7377 with SM-V1a, SM-V1b, SM-V1c, SM-V1d, SM-V2, SM-V3b and SM-V3c (pins.json's macos/Larsal pin moved in 5 rows), root /private/tmp/larsal-gc-c0b43ca-5Ajx, 15:45 to 15:55: tool against the commit equal; grants 60 rows, 0 withheld; G1 exit 0 (4.2 s), A1 exit 0 (218.1 s), 0 gate failures; B1: Swift 492 tests in 74 suites, **489 passed, 3 failed**: `BrowserAskTests/hiddenRowValues()` at BrowserAskTests.swift:95, :96, :99 and :105, `VaultSettingsBehaviourTests/t02CreatedAsStored()` at VaultSettingsTests.swift:190 and `t41FollowsIntegration()` at :223, :224 and :225; line 106 passed (SM-V1c survives). `accessAnswers()`, `connectFrame()`, `accessFrame()`, `answers()`, `browser()`, `dependentControls()`, `ParityEditorPagesTests/browser()` and `ReportsTests/browser()` ok; APP-09 18 of 18. Every failure line of the tool is one of those three tests; the kernel's sandbox rows were read; no crash report; 598.3 s. Overall FAIL (only native), as a mutant run must read |
| The owner's folders (lead's ruling 1) | Before and after each run Verify recorded four roots: ~/.swiftpm, ~/Library/Developer, ~/Library/Caches/org.swift.swiftpm and ~/Library/org.swift.swiftpm (lstat of every entry; under CoreSimulator/Devices also each file's SHA-256; scripts/owner_snap.py). n1: 9546 entries before and after, 1984 under Devices, **0 changed**, not even device_set.plist's inode; n2: 9546 entries before and after, **0 changed**. CoreSimulatorService was the same process (pid 18889, started 12:14:18) before and after both runs. Native work went on (ruling 1) |
| The log store | Before each native run Verify read /var/db/diagnostics/logd.0.log since kern.boottime (2026-11-16 19:25:32 UTC): one Quarantined line (audiomxd), no "Quarantined: /kernel"; the same after each run (proof/native/n1 and n2, logd-before.txt and logd-after.txt), and the guarded tool read the kernel's sandbox rows in every attempt |
| Leftovers | None of Verify's processes is left: chain2.sh, load.sh and the parity run ended on their own (their PIDs are in proof/logs/). The guarded tool's two roots, /private/tmp/larsal-gc-f3363d8-nf8S and /private/tmp/larsal-gc-c0b43ca-5Ajx, stay in place for the lead, as the lead's run roots do; their evidence is copied under proof/native/. `source/`, `work/` and `nat/` are clean at 91a7377; the mutant commits are branches of `nat/` only, never pushed |

### V-1 to V-5: the fix, its tests, the mutants

"ok" means passed in Verify's own runs on 91a7377, in both of the lead's runs and in the run of record of a90fc8b.

| Finding | Fix on the stack | Tests, by name | Mutants Verify saw red, then restored |
|---|---|---|---|
| V-1 (Medium): a protected Title or UserName reached Swift unmasked in the prompt rows | 1d14347: vaults.rs `protected` (line 338: the field's own flag or the vault's flag for that standard field), `shown` (lines 345-358: nothing for a protected field or a masked resolution), `rows` (line 840: title, user name and logo host through `shown`, with `title_hidden`, `username_hidden`), `matches`; prompts.rs `Row`; bridge_vaults.rs `BrowserQuestionRow`; BrowserAsk.swift `BrowserAccessRow` (the mask, read "hidden") | int02 `v1_int02_18_a_protected_user_name_is_hidden_in_the_summary_and_in_the_prompt_rows`, `v1_int02_18_r02_1_a_protected_title_and_the_vault_flags_hide_the_value`, `v1_c2_06_int02_18_a_reference_to_a_protected_value_is_hidden_in_the_prompt_rows`; larsal-ffi `bridge_vaults::tests::v1_int02_18_the_prompt_row_swift_reads_hides_a_protected_user_name`; Swift `BrowserAskTests/hiddenRowValues()` ok in both of the lead's runs and in Verify's n1 | Rust, 17: VM-V1-own, VM-V1-vault, VM-V1-shown-check, VM-V1-masked, VM-V1-rows-raw, VM-V1-rows-tmark, VM-V1-rows-umark, VM-V1-rows-host, VM-V1-search, VM-V1-webhost, VM-V1-rows-icon, VM-V1-ffi-umark, VM-V1-ffi-swap, VM-V1-ffi-host killed; VM-V1-rows-custom-icon, VM-V1-ffi-icon, VM-V1-ffi-tmark survive. Swift: SM-V1a (a hidden title drawn as its text) killed at BrowserAskTests.swift:105; SM-V1b (VoiceOver reads a hidden user name) killed at :96 and :99; SM-V1d (the same for the title) killed at :95 and :99; SM-V1c (a hidden user name drawn through `MaskedUser`, not the mask) survives (V2-2). Round 2's M272 and C272rows killed |
| V-2 (Low): T02, a `_CREATED_` value that is not ISO 8601 was not shown as stored | 1d14347: vault_settings.rs `BrowserKey.created_text` (line 419); VaultSettingsPages.swift `SettingsBrowser.connected` | larsal-ffi `vault_settings::tests::t02_int02_1_a_created_value_not_in_iso_8601_comes_as_stored` ok; Swift `VaultSettingsBehaviourTests/t02CreatedAsStored()` ok in both of the lead's runs and in Verify's n1 | Rust VM-V2-none, VM-V2-always killed; Swift SM-V2 (`connected` ignores `createdText`) killed at VaultSettingsTests.swift:190. Round 2's M280 killed |
| V-3 (Low): LD-211 (1), Browser Keys ignored S-BRW-01 | 1d14347 and 08e615d: VaultSettingsPages.swift `SettingsBrowser.body` (line 93) and `off` (line 80) | Swift `VaultSettingsBehaviourTests/t41FollowsIntegration()` ok in both of the lead's runs (Verify's two runs each carry its mutants). Rust `larsal_settings::tests::t41_mod12_18_s_brw_01_is_off_until_saved_on` ok (it pins the setting's default; it is not the fix's test, C2R3-02) | Swift SM-V3a (integration read as always on; n1) killed at VaultSettingsTests.swift:223, :224 and :225; SM-V3b (the page never disabled) killed at :224 and :225, and SM-V3c (no notice) at :223 (n2); Rust VM-V3-default killed |
| V-4 (Low): the two dialogs differed from Option A, parity not proven | 1d14347, 9c8b6e4, edac292: BrowserAsk.swift (teal, `plugs-connected`, `globe-simple`, the panel with logo tiles, 460 × 270 and 460 × 325), Glyphs.swift, the parity tools | Swift `BrowserAskTests/connectFrame()`, `accessFrame()` (the sizes), `answers()`, `accessAnswers()` (behaviour) ok in both of the lead's runs and in Verify's n1 and n2 | Measured, not mutated: the parity section below. The assets script run again gives the committed tree |
| V-5 (Info): the Swift demo Connect text was stale; no Rust test pinned the warning sentence | 1d14347: BrowserAskTests.swift's demo text; int02 `t01_t07_…` asserts the whole text | int02 `t01_t07_int02_1_4_connect_dialog_names_the_vault_and_writes_the_association_on_connect` ok | Rust VM-V5-warning killed |
| V-6 (Low): no browser on this Mac for the extension's suites | Carried by the lead's ruling to its test-browser round | — | — |

### The mutants

Rust (proof/mutants.txt, logs in proof/logs/mut/): each built and run alone in `work/`; "killed" names project tests that pass in the control run (same program, same filter) and fail with the mutant; every changed file was restored and checked byte-equal after each. Verify's probes are counted apart: a mutant only a probe catches is a survivor.

| Mutant | What it undoes | Result |
|---|---|---|
| VM-V1-own | `protected`: the field's own flag dropped | killed: `v1_int02_18_a_protected_user_name_…`, `v1_int02_18_r02_1_…` |
| VM-V1-vault | `protected`: the vault's flags dropped (40c1689's rule) | killed: `v1_int02_18_r02_1_…` |
| VM-V1-shown-check | `shown`: no protected check | killed: `v1_int02_18_a_protected_user_name_…`, `v1_int02_18_r02_1_…` |
| VM-V1-masked | `shown`: a masked resolution shown | killed: `f272_r02_2_…`, `r02_2_a_user_name_that_reads_a_password_is_sent_empty_with_hidden_value`, `v1_c2_06_…` |
| VM-V1-rows-raw | `rows`: title and user name resolved raw, as 40c1689 | killed: all three `v1_` tests |
| VM-V1-rows-tmark, VM-V1-rows-umark | `rows`: the title's, the user name's hidden mark dropped | killed: `v1_c2_06_…`, `v1_int02_18_r02_1_…`; for the user name also `v1_int02_18_a_protected_user_name_…` |
| VM-V1-rows-host | `rows`: the logo host read from a hidden URL | killed: `v1_int02_18_r02_1_…` |
| VM-V1-search | `matches`: search reads fields the vault protects | killed: `v1_int02_18_r02_1_…` |
| VM-V1-webhost | `web_host`: never a host | killed: `t53_r02_1_int02_22_search_is_one_plain_term_over_title_user_and_host`, `v1_c2_06_…`, `v1_int02_18_a_protected_user_name_…` |
| VM-V1-rows-icon | `rows`: the standard icon number wrong | killed: `v1_int02_18_a_protected_user_name_…` |
| VM-V1-rows-custom-icon | `rows`: another custom icon's name (vaults.rs lines 851-859) | **survives**: no test asks for an entry with a custom icon |
| VM-V1-ffi-umark, VM-V1-ffi-swap, VM-V1-ffi-host | bridge: the user name's mark dropped; the two marks swapped; the logo host dropped | killed: `bridge_vaults::tests::v1_int02_18_the_prompt_row_swift_reads_hides_a_protected_user_name` |
| VM-V1-ffi-tmark | bridge: the title's mark dropped (bridge_vaults.rs line 222; C2R3-01's F2) | **survives** the project's tests; Verify's probe `verify_c2r3_01_…` (a protected Title through `browser_question`) fails with it |
| VM-V1-ffi-icon | bridge: the icon number dropped (line 225) | **survives** |
| VM-V2-none, VM-V2-always | `created_text` never set; set for an ISO 8601 value too | killed: `vault_settings::tests::t02_int02_1_…` |
| VM-V3-default | S-BRW-01 defaults on | killed: `larsal_settings::tests::t41_mod12_18_…` |
| VM-V5-warning | the Connect text loses its warning sentence | killed: `t01_t07_int02_1_4_…` |
| M272, M277b, M279-1, M280, C272rows | round 2's mutants on the functions round 3 changed, and round 2's survivor C272rows (the rows resolve in full mode) | all killed: `f272_r02_2_…`; `f277_ld326_1_…`; `bridge_vaults::tests::f279_1_…`; `vault_settings::tests::t71_int02_30_…`; `v1_c2_06_…` |

Swift (proof/native/n1 and n2): mutants in private commits of `nat/`, each with pins.json's macos/Larsal pin moved to the mutated tree so every grant holds, run through the guarded tool; each fails its own expectation lines, so one run tells them apart. SM-V3a fails the same lines as SM-V3b and SM-V3c together, so it ran alone, in n1 (proof/native/swift-mutant-commits2.txt).

| Mutant | Run | What it undoes (91a7377's line) | Result |
|---|---|---|---|
| SM-V3a | n1 | VaultSettingsPages.swift line 93: `enabled` read from a key that does not exist, negated: integration always on | **killed**: `t41FollowsIntegration()` fails at VaultSettingsTests.swift:223, :224, :225 (integration off: no notice; Disconnect and "Remove all…" enabled) |
| SM-V1a | n2 | BrowserAsk.swift line 157: a hidden title drawn as its text, not `Masked.line()` | **killed**: `hiddenRowValues()` fails at BrowserAskTests.swift:105 (the hidden title draws like an empty one) |
| SM-V1b | n2 | BrowserAsk.swift line 184, `spoken`: a hidden user name read as its text | **killed**: :96 and :99 |
| SM-V1c | n2 | BrowserAsk.swift line 162: a hidden user name drawn through `MaskedUser(user: row.username)`, an empty line, not `Masked.line()` | **survives**: line 106 passes, as the row it compares against has no second line (V2-2) |
| SM-V1d | n2 | BrowserAsk.swift line 183, `spoken`: a hidden title read as its text | **killed**: :95 and :99 |
| SM-V2 | n2 | VaultSettingsPages.swift line 86, `connected`: the `createdText` line removed | **killed**: `t02CreatedAsStored()` fails at VaultSettingsTests.swift:190 |
| SM-V3b | n2 | VaultSettingsPages.swift line 99: `.disabled(!enabled)` removed | **killed**: `t41FollowsIntegration()` at :224 and :225 |
| SM-V3c | n2 | VaultSettingsPages.swift lines 95 to 97: the notice removed | **killed**: `t41FollowsIntegration()` at :223 |

The survivors are test gaps, not leaks: the vault side sends a hidden value as empty text before the bridge or Swift see it, so a lost mark or a missing mask shows nothing where the mask belongs, never a value. Rows for them are in the findings.

### Verify's probes (int02's and larsal-ffi's own helpers, demo vaults)

| Probe | Input | Result on 91a7377 (Verify's run of 2026-11-17) |
|---|---|---|
| The first pass's seven | F-272 (11 reference forms through find, search, recent and the rows), F-273, F-274 (1) to (3), F-276, and the V-1 note | All pass. The V-1 note now reads: summary `username` "" with `hidden_value` true; the row `username` "" with its mark, `title` "Example (work)" shown; no byte of `demo-protected-user` in the question |
| More ways to a protected value | On E7, page `https://example.net/`: (A) Title `{S:Secret}` with a protected custom field; (B) Title `{REF:T@I:‹E1›}` with E1's Title protected; (C) Title `{REF:A@I:‹E1›}` with the vault's URL flag on; (D) Title `{T-CONV:/{USERNAME}/upper/}` with a protected user name; (E) Title `{URL:HOST}` with the URL protected by its own flag; (F) Title `x{NOTES}y` with protected notes; (G) Title `{REF:T@U:alex}` with the vault's UserName flag on; (H) E1's Title `code {TOTP}` | Passes: each title comes "" with its mark in the summary (`hidden_value`) and in the row; no spelling of the secret is in the question or the summary; a search by the secret never gives E7; the logo host is "" when the URL is hidden (C, E); (H) no digit reaches the row or the summary. The control, a reference to a title nothing protects, shows "Example Mail" |
| The title's mark through the bridge (C2R3-01) | larsal-ffi: the vault's Title flag on, the demo GitHub entry asked for on another site, the question read with `browser_question` | Passes: the row's title "" with its mark, the user name shown, host `github.com`, no byte of the title in the question. It fails with VM-V1-ffi-tmark, VM-V1-ffi-swap and VM-V1-ffi-host |
| A long `_CREATED_` text (V-2) | larsal-ffi: `add_association(v, "long", key, "line one\nline two\n" + 1 MiB of "x", now)`, then `VaultSettings::view()` | Passes: `created` None; `created_text` the whole text, 1,048,594 bytes in three lines: the stored text crosses without a bound (the findings row) |

## The dialogs' parity (BUILD-AND-VERIFY.md items 1 to 7)

Verify's own offscreen shots from run n1, the private commit f3363d8 (91a7377 with SM-V3a, which changes only VaultSettingsPages.swift, so BrowserAsk.swift, Glyphs.swift and the fonts are 91a7377's), drawn by `BrowserAskTests/connectFrame()` and `accessFrame()` in the guarded tool's hidden test launch; the references are design/option-a/reference/{light,dark}/ of 91a7377. Scripts: parity/measure2.py (items 1 to 5), measure_text.py (text runs), tokens2.py (colours both ways), ink.py (how dark the text draws); the pixel diff is a Python port of pixelmatch (threshold 0.1, anti-aliasing ignored) whose two files equal the earlier copy's by hash. Verify opened the twelve images: the four shots, the four reference images and the four diffs.

| Item | dialogs-connect-a-browser, light / dark | dialogs-browser-asks-for-an-entry, light / dark |
|---|---|---|
| Shots, SHA-256 | `d0412d10…` / `db11eb95…` | `ab49745f…` / `a82c9d98…` |
| 1 Present, size | Present; 920 × 540 px, the reference's size (460 × 270 pt) | Present; 920 × 650 px (460 × 325 pt) |
| 2 Text: manifest strings in the accessibility tree | 6 of 6, the whole Connect text among them | 11 of 11 (6 whole; 5 inside a row's label: the titles and user names) |
| 3 Tokens: colours of 0.5 % or more, both ways | 0 missing, 0 extra (6 and 7 colours); the teal tile #22a6bd with plugs-connected | 0 missing, 0 extra; the teal tile with globe-simple, the logo tiles, the check boxes' #1b6c80 and #52b6c9 |
| 4 Geometry: solid boxes; text runs | Boxes within 0.5 pt (the tile, the field's border, Deny's border; Connect's fill 0). Text runs within 2 pt: the field's text starts 2 pt left, the Name label ends 1 pt lower; the body's lines 2 to 4 are left out, as they wrap at other words (below) | Boxes within 1.5 pt (the checked boxes' fill 1 to 1.5 pt, where the app's check is thinner; the tile's part below the glyph 1 pt; Deny 1 pt wider to the left). Text runs within 1 pt |
| 5 Pixels | 1.61 % / 1.63 %; three quarters of it in the body text's band (120 to 240 px), most of the rest in the field (320 to 400 px) | 0.37 % / 0.40 % |
| 6 Behaviour | `BrowserAskTests/answers()` ok (n1 and both lead runs) | `accessAnswers()` ok (n1 and both lead runs) |
| 7 Accessibility | VoiceOver's names are item 2's strings; a hidden row value reads "hidden" (`hiddenRowValues()`); keyboard reach, focus ring and contrast not measured (limit 4) | The same |
| Verdict | **PASS**: under 3 %, every changed area explained by items 2 to 4 | **PASS** |

What the images show. Connect: the tile, the glyph, the title, the Name label, the field and both buttons stand where the reference has them. The reference's first sentence still names the product by its working name, where mockup.js, manifest.json, INT-02.4 and the app read "A Larsal extension asks…", so lines 2 to 4 wrap at other words: that is the diff's red band (C1-3, the stale images). The field's text sits 2 pt left. Access: the panel, the logo tiles, both rows and their rule, the Remember line and the buttons stand where the reference has them; the diff marks the check marks (the app's check is thinner), the unchecked box (its border darker), the user names' line (0.5 pt lower) and Deny's left edge (C1-4). In both frames and both themes the app's text draws darker than the reference's: 14 to 48 % more ink with the same run widths (parity/ink.txt), the same font and weight rendered by Core Text against the browser that exported the reference images; the field's text the most (1.35 light, 1.48 dark).

The numbers equal those of both round 3 Checkers and of the measurement of 2026-11-12 (1.61, 1.63, 0.37, 0.40). The settings frame `vault-vault-settings-browser-keys`, whose page round 3 changed (the notice, `created_text`), reads 1.18 % / 1.17 % with the same port: its diff marks the reference's window buttons (the shot draws no window frame), the reference's "last used …" words, which the page has never drawn (Main 10544e6 draws the same line), and the text's rendering; the vault report measured 1.08 % / 1.07 % with the pixelmatch package on 2026-10-28.

The two rows for design/parity/dialogs/report.md are card edit 10 of the proposed rows.

## The story's checks

INT-02's test rows (spec/integrations/INT-02-association-site-access.md lines 250 to 324). "ok" means the test passed in Verify's own run of int02 (72 of 72 project tests) or of the named larsal-ffi module or Swift test on 91a7377, in both of the lead's runs, and in the run of record of a90fc8b (above). A row whose code did not change since 40c1689 (crates/larsal-browser but prompts.rs, vaults.rs and tests/int02.rs; crates/larsal-core/src/refs.rs; crates/larsal-ffi's browser.rs, browser_seam.rs, lib.rs, reports.rs and tests/edit.rs; extension/) also stands on the first Verify's proof (that list is of 91a7377). From 91a7377 to a90fc8b, F-439 changes four of those files, refs.rs, tests/edit.rs, crates/larsal-browser/src/matching.rs and tests/int03.rs, with test-only lines and tests of other cards; the story's functions and cited tests in them are byte-equal, and the rows on refs.rs and tests/edit.rs were run again on a90fc8b ("Phase two" above).

| Rows | Proof | Result |
|---|---|---|
| T01, T07 | `t01_t07_int02_1_4_connect_dialog_names_the_vault_and_writes_the_association_on_connect` ok; it now asserts the whole Connect text (V-5) | Verified |
| T02 | larsal-ffi `vault_settings::tests::t02_int02_1_a_created_value_not_in_iso_8601_comes_as_stored` ok and Swift `VaultSettingsBehaviourTests/t02CreatedAsStored()` ok in both of the lead's runs and in Verify's n1 ("Connected 10/24/26 8:11 PM"); mutants VM-V2-none, VM-V2-always, SM-V2 killed | **Verified** (was Failed, V-2) |
| T03 | `t03_int02_2_the_default_name_skips_taken_and_invalid_names`, `f279_3_int02_2_a_name_of_64_characters_is_valid`, `int02_2_connect_never_overwrites_a_taken_name` ok; the button: BrowserAsk.swift line 75 `.disabled(problem != nil)` | Verified |
| T04, T05, T08, T09, T12 | `t04_…_gets_1_and_no_dialog`, `t05_…_answered_at_once_without_a_dialog`, `t08_…_ends_as_deny_after_120_seconds`, `t09_sr16_a_lock_closes_the_connect_dialog_and_writes_nothing`, `t12_int02_6_deny_gives_6_and_writes_nothing` ok | Verified |
| T06 | int01 `port::t84_short_proof_other_nonce_or_wrong_content_gets_error_8` and `safari::t84_short_proof_other_nonce_or_wrong_content_gets_error_8`: ok in both of the lead's runs and in the run of record (int01 102 of 102). Verify's run guard refuses int01's /tmp sockets, so Verify did not run it itself; int01 is unchanged since the first Verify, and in crates/larsal-browser a90fc8b changes only matching.rs's test-only lines and tests/int03.rs | Verified (the lead's runs; the run of record) |
| T10 | `t10_int02_5_pairing_words_of_the_int01_demo_keys` ok: SHA-256 `476bfcad…7411f7e`, words "nutshell speech regretful pretense". The card row is stale (card edit 1) | Verified; card words with this report |
| T11 | The dialog's words against the test client's own: ext test_04 and popup test_04. Not run by Verify (no browser) | Carried open (V-6, the lead's test-browser round; with LD-556 at E7-S6) |
| T13 to T19 | `t13_t14_…_check_lists_every_unlocked_vault_holding_the_key`, `t15_int02_8_disconnect_in_vault_settings_removes_last_used_too` with Swift `VaultSettingsBehaviourTests/browser()`, `t16_t51_…_records_last_use`, `t17_…_newest_uses_first`, `t18_t19_…_one_vault_unless_search_all` ok | Verified |
| T20, T22 | The unlock panel is not built | Carried to E7-S4 (lead ruling) |
| T21 | Holds in code: `unlock` answers at once, error 1 when locked, and there is no panel. No test names it (C1-05) | Carried to E7-S4 (the test) |
| T23 to T56, T75 | The int02 tests named after each row (t23_t24 to t55_t56, t75), with `int02_12_the_template_group_is_never_offered`, `t31_int01_45_…`, `f272_…`, `f274_*`, `f276_…`, `f277_…`, `f279_2_…` ok | Verified |
| T45, INT-02.18's rows | `t45_int02_18_rows_show_resolved_titles_and_user_names` ok, and the three `v1_` tests, the larsal-ffi `v1_` test and Swift `hiddenRowValues()` ok: a protected value never reaches a row | **Verified** (was Failed, V-1) |
| T40, T72 | `t40_t72_int02_17_31_never_ask_gives_at_once_and_notifies_once_in_10_minutes` ok (the vault side calls its notifier, here a fake). Larsal.app's `notify` (bridge_vaults.rs lines 139-143) is empty | Verified for the vault side; the MI02-13 posting stays with W-08 (lead ruling) |
| T57 to T66, T74 | `logins.save`, `logins.update`, `groups.list`, `groups.create`: `later_requests_check_the_association_then_answer_12` ok | Carried to E7-S4 and E7-S7h (lead ruling) |
| T67 | Swift `LarsalSettingsTests/dependentControls()` ok in both of the lead's runs and in Verify's n1 and n2 | Verified |
| T68 to T70 | ffi tests/edit `int_02_29_browser_page_stores_its_options` ok, Swift `ParityEditorPagesTests/browser()` ok in both of the lead's runs and in Verify's n1 and n2 | Verified |
| T71 | ffi `vault_settings::tests::t71_int02_30_entries_with_an_item_listing_no_host_are_not_counted` ok; mutant M280 killed | Verified |
| T73 | ffi `reports::tests::int_02_32_browser_report` ok, Swift `ReportsTests/browser()` ok in both of the lead's runs and in Verify's n1 and n2 | Verified |
| MOD-12 T41 (LD-211 (1)) | Swift `VaultSettingsBehaviourTests/t41FollowsIntegration()` ok in both of the lead's runs; Verify's mutants SM-V3a, SM-V3b, SM-V3c killed | **Verified** (was Failed, V-3) |

## The amending rows

| Row | Proof | Result |
|---|---|---|
| LD-556 | Built: browser.rs gives every bridge `bridge_vaults::handler(Arc::downgrade(&Session::shared()))` (lines 72-73; `NoVaults` removed); the Connect-dialog seam (browser_seam.rs; debug only); the two `ld556_*` tests ok. Not done: PopupWithLarsal and ChromeWithLarsal against Larsal.app launched hidden; blocked by E7-S6's unbuilt debug developer id (setup.rs line 45 `STORE_IDS` empty), Larsal.app's missing INT-01.46 notices, and the seam's missing lock, unlock and demo-vault open | Carried open to E7-S6 (lead ruling) |
| LD-330 (4) | int03.rs's glob overlap assert in `t45_to_t49_int03_11_labels_and_paths` and `int03_10_registrable_domain_equals_a_label_by_label_run_of_every_rule` ok (int03 42 passed, 3 ignored in Verify's run on 91a7377; in the run of record 42 ok and 3 release-only ignored in workspace, 45 ok in release-browser). int03.rs, matching.rs and psl.rs are unchanged from the first Verify to 91a7377. a90fc8b (F-439) changes int03.rs's timing tests and their helpers and adds test-only lines to matching.rs (each added line under `#[cfg(test)]` or in its new test module, none removed); the two tests are byte-equal and call no changed item, and psl.rs is unchanged | Verified |
| LD-326 (1) | One `Cell::new(COPY_BUDGET)` per request in `find` (vaults.rs line 746), `get` (1075), `code` (1133), `search` (1173) and `recent` (1210), handed to every step, round 3's `rows` among them (`self.rows(uses, &asked, meter)`, line 945); `f277_ld326_1_one_work_meter_bounds_the_whole_logins_get` ok; mutant M277b killed again. The entry index is made once per vault visit (C1-08; INT-03.17's words) | Verified, with INT-03.17's words. `code.get`'s one meter is right by reading, untested (C1-03, to E7-S4) |
| LD-322 (7) | `logins.find` and errors 14 and 15: int02 `t71_int03_1_a_page_app_cannot_match_gets_14`, `t72_t73_…`, `t74_t75_…`, `t76_…`, `t86_at_f05_lookalike_pages_get_15` ok. The INT-03.18 notes: ffi `edit::tests::t84_t85_int03_18_…`, int03 `t84_int03_18_notes_under_website_rows` ok. A form host in Deny: `ld322_7_int02_17_a_denied_form_host_hides_the_entry` ok. The MPL-2.0 notice of the Public Suffix List in the SBOM: the first Verify's make-sbom run; THIRD-PARTY-NOTICES.md is unchanged since | Verified |
| LD-318 (2) | tests/fuzz_seeds.rs writes the two `browser_message` seeds (FF FF FF FF; the 1,048,579-byte flat-list frame); the first Verify's fuzz run read both; the file and the seeds are unchanged, at a90fc8b too (seed-28, blob `7bde8641…`, and seed-29, blob `2e480b55…`, are 91a7377's). In the lead's two runs the fuzz step stopped at the total alarm. In the run of record the route ran its 30 s over its 30 seed files ("max: 1048579b"), `Done 34434 runs in 31 second(s)`, no crash or artifact. Without T65's `-max_len=1048580` libFuzzer runs inputs of at most 1,048,576 bytes, so the smoke runs seed-29 3 bytes short and never reads the whole frame (FUZZ-MAXLEN) | Verified: the two seeds as asked, and the route's run in the run of record; the whole 1 MiB frame in a fuzz run is open (FUZZ-MAXLEN) |
| LD-330 (5) | T89 with the network denied: the first Verify's run (int03 equal under run-key.sb and with the network lines removed); the code is unchanged (at a90fc8b, `t89_int03_19_the_build_carries_the_list_and_its_version` is byte-equal and calls no item F-439 changed, and psl.rs is unchanged); T89 ok in the run of record (workspace and release-browser) | Verified (the first pass; the run of record) |
| LD-211 (1) | MOD-12 T41: built and tested (above) | **Verified** (was Failed, V-3) |

## The lead's rulings, applied

| Ruling | Where it lands |
|---|---|
| Before round 3: LD-556's run against Larsal.app goes to E7-S6; INT-02.11's unlock panel (T20, T22, and T21's test) to E7-S4; APP-05.4's silent save at lock to a follow-up of E5-S10; MI02-13 stays with W-08; the Low test gaps go to E7-S6's round (larsal-ffi's browser files) or E7-S4 (larsal-browser); C1-06's card contradiction is fixed in the card words | Carried as the first page said; LD rows (LD-611 to LD-614, LD-620); card edits 2 and 3 |
| Round 3, ruling 1 (V-1): no protected value reaches Swift through a prompt; a masked row value is the empty text plus a hidden mark | Built and proven (above); card edits 4 to 6 |
| Ruling 2 (V-2): T02, as stored; ISO 8601 keeps its rendering; a Rust test and a Swift test | Built and proven |
| Ruling 3 (V-3): LD-211 (1), MOD-12.18, T41; tests on the side that decides it | Built in Swift and proven by the Swift test and three Swift mutants; card edit 7 |
| Ruling 4 (V-4): the two dialogs copy Option A; parity by BUILD-AND-VERIFY.md; the words stay (W-07) | Built; parity measured by Verify; the official `compare.mjs` run carried with V-6; card edit 10 (LD-633) |
| Ruling 5 (V-5): the demo Connect text equals Rust's; a Rust test pins the warning sentence | Built and proven |
| Ruling 6 (V-6): no browser is installed or downloaded; the browser classes and T11 are carried | Carried; Verify ran no browser |
| Ruling 7: what round 2 proved must still hold | int02 72 of 72; round 2's mutants M272, M277b, M279-1, M280 killed again; its survivor C272rows now killed |
| Ruling 8: crates/larsal-browser/src/server.rs is not edited | Not in the patch or the picks |
| Since round 3, ruling 1: the simulator service's own rewrite of device_set.plist is not a write by Larsal's code or tools; record the folder before and after each native run and go on unless bytes there or any other owner path change | Applied in Verify's two runs: the four roots recorded before and after; 0 changes in each (not even device_set.plist's inode), so native work went on |
| Since round 3, ruling 2: V-6 stays carried to the lead's test-browser round (a private pinned Chromium outside /Applications): the four browser classes, INT-02 T11 and the new export of the stale connect reference images | Carried; LD row LD-626 and findings rows F-631 and F-638 |

## Security, on the stack

- **What crosses to Swift.** `BrowserQuestion` and `BrowserQuestionRow` (bridge_vaults.rs; uniffi records with `Debug` and `Clone`) carry the dialog's words and, for each row, `title`, `username`, `title_hidden`, `username_hidden`, `host`, `icon`, `custom_icon`. Title, user name and the URL behind `host` come through one function, vaults.rs `shown` (lines 345-358): nothing for a field its own flag or the vault's flag protects, and nothing for a resolution that display mode marks as having read a protected value (the Password always; a reference, a conversion, a URL part, a search over a protected field). A hidden value is the empty text; its mark is one bit. Swift draws the fixed mask ●●●●●● (six dots, whatever the value's length), read "hidden". The access question's title, text, Remember and line hold only the browser's name and page hosts; the Connect question holds the vault's name.
- **What Verify tried.** A protected custom field through `{S:…}`, references to a protected Title and to a URL the vault protects, a conversion of a protected user name, a part of a protected URL, protected notes, a title found by a search over protected user names, a one-time code, and the first pass's 11 password forms: each comes hidden in the summary and in the row, with no byte of the value in the question's `Debug` text or in the summary; search never finds an entry by a hidden value. No print or log statement is in vaults.rs, prompts.rs, site.rs, bridge_vaults.rs, browser.rs, BrowserAsk.swift or VaultSettingsPages.swift; the debug-only seam speaks no line for a site access prompt.
- **The summaries.** Unchanged in rule, now through the same `protected`: the vault's flags hide a Title or UserName in `logins.find`, `logins.search` and `logins.recent` too (on 40c1689 only the field's own flag and a masked resolution did).
- **Browser Keys.** `BrowserKey` carries the association's name, its ISO 8601 time, or its stored `_CREATED_` text. None is a secret. The text has no bound (the findings row F-636).
- **The bridge in Larsal.app, the seam, hostile vault items, pages and frames.** As the first page said; those files carry only round 2's and round 3's reviewed lines.
- **Zero knowledge (LD-340).** Round 3 adds no network path, no file and no log. The vault side still answers only INT-01's local channel.

## The Checkers

| Round | Builder | C1 | C2 |
|---|---|---|---|
| 1 (2026-11-01) | Built: INT-02's vault side, the one dialog line with Connect and the site access prompt, the LD-318/322/323/326/330 rows and the Swift dialogs | Sent back: F-272, F-273, F-274 Medium; F-275 to F-281 Low | No result (the 2026-11-01 pause) |
| 2 (2026-11-09, base b6eaf17) | Fixed F-272 to F-277 and F-279 to F-281, T10's words, the wiring and the seam (LD-556); both suites 30 of 30 and 10 of 10 against the test Larsal | APPROVE_EXACT_CANDIDATE, 0 blocking; 15 own mutants, 8 killed | APPROVE_EXACT_CANDIDATE, 0 blocking; 12 own mutants, 6 killed |
| 3 (2026-11-12, base 40c1689) | Fixed V-1 to V-5 under the lead's eight rulings, carried V-6; 16 of 16 mutants killed; its one native run stopped at a compile error in new test code (fixed in its second commit) | APPROVE_EXACT_CANDIDATE, 0 blocking; 21 mutants (13 on V-1 to V-5 all killed; round 2's C272rows now killed); one native run: Swift 492 of 492, APP-09 18; parity 1.61 %, 1.63 %, 0.37 %, 0.40 % | APPROVE_EXACT_CANDIDATE, 0 blocking; 19 mutants, 18 killed, F2 survives; probes c2_p01 to c2_p08 pass; one native run: 492 and 18; parity measured, items 2 to 5 pass |

Neither round 3 Checker ran a Swift mutant; Verify ran eight.

## Checker notes of round 3, judged

| Note | Real? | Where it goes |
|---|---|---|
| C1-1 = C2R3-05: every guarded native run makes the simulator service rewrite device_set.plist | Real; a write by Apple's service, not by Larsal's code or tools | Closed by the lead's ruling 1; LD row LD-628; in Verify's two runs of 2026-11-17 the service (running since 12:14:18) left the folder untouched |
| C1-2 = C2R3-03: the parity report's two rows say "not measured" | Real | Card edit 10 (LD-633) fills them with Verify's numbers; the `compare.mjs` run with V-6 |
| C1-3: the connect reference images are stale | Real, Info | Findings row F-638; the lead's test-browser round |
| C1-4: shared-part differences (`CheckMark`, `PlainField`) inside the budget | Real, Info; Verify saw both in its own shots: the diff marks the check boxes, and the field's text starts 2 pt left; it also measured that all text draws darker in the app (14 to 48 % more ink with the same run widths) | Findings row F-640 for the parity owner |
| C1-5: Browser Keys reads S-BRW-01 only when drawn | Real, Info; T41 asks for no live update | Findings row F-639 |
| C1-6: five of the Builder's shell calls ran without the `env -i` prefix | Real, process; read-only looks and one edit of API.md that is in the patch; no rustup ran | Closed; the Builder's NOTES.txt holds it |
| C2R3-01 (Low): mutant F2 survives, no larsal-ffi test checks that the bridge passes the title's hidden mark | Real. Verify's VM-V1-ffi-tmark (bridge_vaults.rs line 222, `title_hidden: false`) passes all four of the project's `bridge_vaults::tests` and fails Verify's probe; VM-V1-ffi-icon (line 225) passes all five. No value can show through it: the vault side sends a hidden title as empty text, so a lost mark draws an empty title without the mask | A findings row (the larsal-ffi test gaps, F-635), to E7-S6's round with Verify's probe as the test. Not blocking: the stack is the reviewed patch, and the gap cannot leak |
| C2R3-02 (Low): the Rust V-3 test passes on the base; only the Swift test covers the fix | Real as stated; the Swift test does cover it: SM-V3a, SM-V3b and SM-V3c each fail `t41FollowsIntegration()` at their own lines (VaultSettingsTests.swift:223 to :225) | Closed; the LD row on V-3 (LD-623) names the Swift test as the fix's test |
| C2R3-04 (Info): `fil02_t13` lost 1 of 3 runs alone; `f164` is timing | Real, outside the story; the second pass saw two more of the kind under load (`searchSpeed()`, `quitSignals()`), and the lead's runs of 2026-11-17 two more (`fea01_32`, `t83_f252`) | Findings row F-641 beside F-439; F-439's round |

## Verify's findings

| ID | Severity | Blocking | State |
|---|---|---|---|
| V-1 (F-626) | Medium | was blocking | Fixed in 1d14347, verified |
| V-2 (F-627) | Low | was blocking | Fixed in 1d14347, verified |
| V-3 (F-628) | Low | was blocking | Fixed in 1d14347 and 08e615d, verified |
| V-4 (F-629) | Low | no | Fixed in 1d14347, 9c8b6e4, edac292; parity measured; the `compare.mjs` run carried with V-6 |
| V-5 (F-630) | Info | no | Fixed in 1d14347, verified |
| V-6 (F-631) | Low | no | Open: the lead's test-browser round |
| V2-1 (F-636) | Low | no | Browser Keys draws a `_CREATED_` text of any length and line count. crates/larsal-ffi/src/vault_settings.rs line 419 hands the stored text over whole; macos/Larsal/VaultSettingsPages.swift line 113 draws it with no line limit; the format allows 64 MiB a text value. Input: `_CREATED_long` = two short lines and 1 MiB of "x". Result: `created_text` holds all 1,048,594 bytes (Verify's probe, passing on 91a7377). No secret; a hostile vault can make its own Browser Keys page slow. Fix: the first line, cut at 64 characters, in Rust; INT-02.1's words follow |
| V2-2 (F-637) | Info | no | `BrowserAskTests.hiddenRowValues` does not prove that a hidden user name draws the mask: macos/LarsalTests/BrowserAskTests.swift line 106 compares a row with a hidden user name against a row with no second line. Input: SM-V1c (BrowserAsk.swift line 162 draws `MaskedUser(user: row.username)` for a hidden one). Result: line 106 passes in Verify's run n2 (91a7377 with SM-V1c beside six other mutants, each caught at its own line), so the test does not catch it. The code is right today, and VoiceOver's "hidden" is tested (line 96). Fix: compare against a row whose user name is a blank of the same line height, or read the line's label |
| V2-3 (F-634, F-635) | Info | no | Three display details of a prompt row have no test: the custom icon's name (vaults.rs lines 851-859, VM-V1-rows-custom-icon), and the icon number and the title's mark through the bridge (bridge_vaults.rs lines 225 and 222, VM-V1-ffi-icon, VM-V1-ffi-tmark = C2R3-01). No value can show through them |
| V2-4 (F-642) | Low | no | Outside the story: the guarded tool's gate "no kernel rows read" fails in every native attempt when the log store has quarantined the kernel's rows (2026-11-12 11:40:36 until the restart of 2026-11-16). Not the case today: no /kernel line since the last boot; the lead's runs read native exit 0, and Verify's two native runs passed that gate in every attempt |
| FUZZ-MAXLEN (F-643) | Low | no | Found in phase two, outside the story's code. The fuzz smoke (scripts/check.sh line 250; the guarded tool's `fuzz()`, scripts/guarded/tables/routes.json line 115) runs `browser_message` without `-max_len`, so libFuzzer caps inputs at 1,048,576 bytes and reads each seed cut to that length (vendor/crates-io/libfuzzer-sys-0.4.13/libfuzzer/FuzzerLoop.cpp lines 807 and 832). LD-318 (2)'s seed-29, a frame of length 1,048,575 (1,048,579 bytes), runs 3 bytes short: `read_frame` sees the stream end inside the frame, and no fuzz run reached the 1 MiB flat-list frame (F-211). The run's log: `-max_total_time=30` only; "INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 1048576 bytes"; "seed corpus: files: 30 min: 2b max: 1048579b". The first Verify ran the route "as scripts/check.sh's smoke, seeds then 30 s" (its page, line 74), so under the same limit. Fix: run the route in the smoke with the flags its target names for T65, `-max_len=1048580 -len_control=0 -malloc_limit_mb=2` (fuzz/fuzz_targets/browser_message.rs lines 12 and 13) |

## Outside the story: what this Mac did to the runs

| What | Evidence | Effect |
|---|---|---|
| Wall-clock tests | The lead's runs: release `fea01_32_field_heavy_vaults_stay_bounded` (run 1) and release-browser `t83_f252_int03_17_urls_of_2048_characters_under_200_ms` (both) | Overall FAIL in both runs; F-439's round, the reason for candidate-m22; both pass in the run of record |
| The fuzz step | Both runs: "fuzz: stopped by total alarm", 37 routes, fewest runs 0, at 3544.6 s and 3544.5 s of the 3600 s cap | In the run of record (two parts) every route ran its 30 s, no alarm |
| The load | The 1-minute load average on 14 cores while Verify's native runs went (proof/logs/load.txt): 18.1 in n1's last minute (the sampler started then) and 15.5 to 47.9 through n2 (one sample a minute; the peak during its build) | In Verify's two native runs no test failed but its mutants' targets (n1 491 of 492, n2 489 of 492, APP-09 18 of 18 in each) |
| The log store | No "Quarantined: /kernel" line since the boot of 2026-11-16 19:25:32 UTC (one line, audiomxd, at 22:24:59 +0300) | The kernel-row gate can read its rows; the lead's runs read native exit 0 |
| Busy marks | E23-S4's native run held BUSY-native (empty) from 14:38 to 14:48. A hold with words, "f439 load proof", stood on BUSY-native from 15:08 to 15:44, and Verify's n2 waited for it. Verify's guarded runs made and removed their own empty marks; Verify removed no mark | — |
| Part B's first try | /private/tmp/larsal-gc-a90fc8b-xeLh: `ParityGeneratorTests/passphraseControls()` failed once (GeneratorTests.swift:267:9), Swift 491 of 492; it passed in the run of record on the same commit | Overall FAIL of that try only; the lead's row 9 (LD-654) judges it a timing flake of the test; no file or row of this story |
| The load in phase two | 1-minute load 3.74 to 10.10 on 14 cores during Verify's reruns on a90fc8b, AC Power, 100 % charged, powermode 0 (each line of proof/logs/progress.txt) | No test failed but the mutants' targets |
| Busy marks in phase two | Verify's second chain found an empty BUSY-native at its first gate (23:42:54 on 2026-11-22) and waited 18 polls of 30 s, to 23:51:54; it touched no mark | — |

## Card words proposed with this report

The exact words, each with its anchor quoted as it stands on 91a7377, are in the proposed rows ("Card edits"):
- INT-02 T10: round 2's row (INT-01.50's keys, `476bfcad…`, "nutshell speech regretful pretense").
- INT-02.16: "past that, the hosts already stored are dropped first, in sorted order, so the hosts just added stay" (C1-06).
- INT-03.17: "one work meter per request and one entry index per vault visit" (C1-08).
- INT-02.18: round 3's words: a protected title or username, or one whose resolution reads a protected value, never leaves Rust and shows as the mask; and a new test row T45a.
- INT-02 R02-2 and the security note on titles and usernames in dialogs: both still said the prompt rows stay resolved; they now follow INT-02.18.
- MOD-12.18 and T41: the notice's words and the disabled controls.
- plan/architecture.md: larsal-ffi rows for `browser.rs`, `bridge_vaults.rs` and the debug-only `browser_seam.rs`, and the larsal-ffi line in E7's additions.
- design/parity/dialogs/report.md: the two bridge dialogs' rows with Verify's numbers (LD-633).

## The open and carried rows

| Row | Severity | Safe to leave open? |
|---|---|---|
| The run of record (candidate-m22's top, a90fc8b, two parts) | — | Closed: Overall PASS in both parts, every test of this story ok in it (the table at the top) |
| V-6 (F-631): the four browser classes, INT-02 T11, the new export of the connect reference images and the `compare.mjs dialogs` run | Low | Yes, by the lead's ruling: its test-browser round. extension/ did not change in round 3, and the vault side the suites reach is the code int02 tests |
| The run against Larsal.app (LD-556, F-460; the two round 2 Builder rows, F-632 and F-633) | Low | Yes, ruled to E7-S6 |
| T20, T21, T22 (INT-02.11's panel), T57 to T66 and T74 (later request types) | Low | Yes, ruled to E7-S4 and E7-S7h |
| APP-05.4's silent save at lock | Low | Yes, ruled: the last-use item is written with the vault's next save |
| MI02-13's posting (T72) | Info | Yes, ruled to W-08 |
| The Checkers' and Verify's test gaps (C1-03, C1-04, C1-05, C1-07, C2-01, C2-02, C2-05, C2R3-01, V2-2, V2-3; F-634, F-635, F-637) | Low or Info | Yes: the code is right on each today, and none can show a protected value |
| V2-1 (F-636): an unbounded `_CREATED_` text | Low | Yes: no secret; it needs a hostile vault and harms only that vault's own settings page |
| C1-3, C1-4, C1-5 (F-638, F-640, F-639) | Info | Yes |
| FUZZ-MAXLEN (F-643): the fuzz smoke runs LD-318 (2)'s 1 MiB seed 3 bytes short | Low | Yes: the two seeds are what LD-318 (2) asks for, the 1 MiB flat-list frame has its own tests (int01 `port::t88a_flat_list_frame_of_1_mib_gets_plain_error_12` and `safari::t88a_…`, ok in the run of record), and the fix is the smoke's flags for this route (the lead's tools) |

## Limits of this signature

1. **The run of record is two runs.** By the lead's ruling of 2026-11-17 it is two guarded runs of a90fc8b with the same tool, static and rust in part A, native, docs and fuzz in part B, not one run of every step; each read Overall PASS and each compared the baseline for its own steps (phase two recomputed both: 5204 and 524 names, together the baseline's 5728). No check ties one part's builds to the other's beyond the commit, the tree and the tool map (C1R2-02 of the tool round). Part B took two tries; the first failed one Swift test outside this story. The run files hold no power state.
2. **No browser.** The four browser classes (ChromeWithLarsal, ChromeWithoutX25519, PopupWithLarsal, PopupParity), INT-02 T11 and the `compare.mjs dialogs` run did not run; they are carried to the lead's test-browser round (V-6). T11 rests on the round 2 Builder's run of 2026-11-09 against the test Larsal.
3. **Two native runs, neither a clean control.** Both of Verify's runs carry mutants, so neither is a clean run of 91a7377's Swift; the clean proof is the lead's two runs (492 of 492 each). Verify's runs show the rest of the suite passing beside the mutants (491 and 489 of 492). The brief allowed two native runs; a clean control was not one of them.
4. **Parity tools.** The pixel numbers come from a Python port of pixelmatch, not from `compare.mjs` with the pixelmatch package; geometry comes from ink boxes in the images, not from the mockup's DOM; contrast, the focus ring and keyboard reach were not measured. The connect frame was measured against reference images that hold an older first sentence.
5. **Rows that stand on the first pass.** The seam's absence from a release library, the SBOM notice and T89 with the network denied were not run again: their code did not change since 40c1689 (nor in a90fc8b: lib.rs, browser.rs, browser_seam.rs and THIRD-PARTY-NOTICES.md are not in its diff, and T89's test is byte-equal). The five fuzz routes ran in the run of record, not in Verify's own runs. int01 (T06) and five `e7s6_*` tests of browser.rs were not run by Verify: its run guard refuses their /tmp sockets and folders; they pass in both of the lead's runs and in the run of record.
6. **Guard refusals in Verify's own Rust runs.** `larsal_settings::tests::app03_s_time_01_02_reach_the_copy` needs a pasteboard the run guard denies. larsal-ffi's tests/edit writes under the target's temp folder, which the run guard denies; Verify pointed that folder into the guard's writable area with a link (the profile unchanged).
7. **Mutants are samples.** 26 Rust and 8 Swift mutants on the changed functions; a survivor shows a gap, a kill does not prove every line.
8. **Earlier evidence.** The second pass's agents of 2026-11-12 left drafts, probes and native evidence. Only the probes were reused (hash-checked); their numbers in this page are this pass's own.
9. **F-439 on two of the story's files.** a90fc8b changes refs.rs and tests/edit.rs with F-439's test-only lines. Phase two read them, found the story's functions and tests byte-equal, and ran the rows on them again on a90fc8b with four mutants; the other rows rest on phase one's runs of 91a7377 and on the run of record.
10. **The fuzz smoke's reach** (FUZZ-MAXLEN). The run of record ran every route for its 30 s, but without `-max_len` libFuzzer runs LD-318 (2)'s 1,048,579-byte seed cut to 1,048,576 bytes, so no fuzz run here reached a whole 1 MiB frame. Read from libFuzzer's source and the run's log; Verify ran no fuzz target.
11. **Phase two's evidence lives under /private/tmp**, which does not last; this page and FINAL-SEAL.json carry its numbers and hashes.

## Evidence

Verify's root: /private/tmp/larsal-e7s2v3-cqhvQUNx (mode 0700; it does not last). Copies: /Users/josephilhan/Documents/Code/larsal-checkpoints/resume-2026-11-06/builds/e7s2-verify-r2/v3/ (the same relative paths). FINAL-SEAL-pre.json in the root lists the SHA-256 of every evidence file. The root lost its files on 2026-11-22; phase two found all 1138 sealed files, each with its sealed SHA-256, in the v3/ copy.

| File | What | SHA-256 |
|---|---|---|
| proof/stack/stack-check.txt | the stack: 44 checks | `cc6581e6be9dd9aba4f65be0ebb6de65a4f0b84cece4faf7a39a8006819474db` |
| proof/stack/shared-files-read.txt | the three shared files read whole | `16053d027c86f137e688036644852efbb75b7bf59b861c88d8bdd71a32ea2895` |
| proof/runs/run1-run2-read.txt | the lead's two runs of 91a7377, read for this story | `b48d3d3bb553f3b1cac4842084de60a87eccc19257e2ddfa0e2a2d2a4411167b` |
| proof/probes/work-files.txt | the probed files of work/ and their recorded hashes | `a1be1d6712ca9a009afa9bf061f1b0e0dfc9338e13a300e21a26cebf8be62d44` |
| proof/logs/rust/READ.txt | Verify's own Rust runs | `fd61a068425b4295f6284850f775acd0d6a15109a230c1a8cd876e0c6dc403b0` |
| proof/logs/rust/run-int02-all.log | int02, 80 of 80 | `953429642f5b209893da0238e07d6c907f3adbb389c8c01cc3753cbebe91dc94` |
| proof/mutants.txt | the 26 Rust mutants | `948d575de51ffadfeab25c4b9447f4afabb0b6c308e1de8b01022ad387c500e7` |
| proof/mutants-read.txt | the mutants against the earlier agent's | `702538ab0cf885974fa4cc8f373b94aa2622e497a71346ded8bdf57f56f08a84` |
| proof/assets/assets-diff.txt | the assets script run again: diff -r exit 0 | `939311b48ad1345a0080efbcd7c92c17ab03d2e1e819bb7269f9307e5aa56704` |
| proof/native/swift-mutant-commits2.txt | the two private Swift mutant commits | `ba22ef69f00975022162ec0abd51e814464e9c7696c8d6e986871473531881a5` |
| proof/native/swift-mutant-diffs.txt | the two commits' diffs against 91a7377 | `e725631c67baff263abeae801f7d77630173394be727031124d10dbf224af361` |
| proof/native/n1/summary.txt | native run n1 | `20a48936c8833ea13763b5fde561d76f388afc0d804a6fc3035642c2e11bba39` |
| proof/native/n1/lane-out/B1/xcode-test.stdout | native run n1, the Swift lane | `cd5885879af76914710353ac3a2fb64776fdc4fc802fda2f2cb8a4e5cb1c2c95` |
| proof/native/n1/read.txt | native run n1, read | `016cb585caa0def8bda20590004c436edccc75fe8e204818958c356bc38b1920` |
| proof/native/n1/owner-diff.txt | native run n1, the owner folders | `193d9084b8f350b3a4f62e044ede578145d08ae889b04b775fdb3d1b3959ef64` |
| proof/native/n2/summary.txt | native run n2 | `97509b7e3ba7ab35e4e757788c0d404debd272efec889e296cdf96ec54675247` |
| proof/native/n2/lane-out/B1/xcode-test.stdout | native run n2, the Swift lane | `6ada4e21268dbe77d50ca37539de56481ba811d753fb5fa50b7f6440593c26fa` |
| proof/native/n2/read.txt | native run n2, read | `214f667316e861af328925d58b7395d08968c823595099be69e6d66d82a42160` |
| proof/native/n2/owner-diff.txt | native run n2, the owner folders | `193d9084b8f350b3a4f62e044ede578145d08ae889b04b775fdb3d1b3959ef64` |
| parity/summary2.txt | parity: sizes, strings, colours, boxes, pixels | `f45c6e622ca703d93e200592f8457850dfee68b44990e0ac34f697b9e0aba59d` |
| parity/text-runs.txt | parity: text runs | `6bbab7198c26145ea3e5ff9158802ee0f3d7c8fa9a4e9401a1e48693faa77201` |
| parity/browser-keys.txt | parity: the Browser Keys frame | `d2663010dea7891f472bb7f481d7a7fec0c40cba64babf76eeae4c92d2c8470c` |
| parity/tokens2.txt | parity: colours both ways | `e54ed7be3a78928f75a4246843c0a32eeac3973e23495546d60a9d362eb0a063` |
| parity/ink.txt | parity: how dark the text draws | `e5246cbff6f4453f867abd0a45a5e2e9b26449506cc1bdec6f8259234b49b2ed` |
| proof/rows-recheck.txt | the first Verify's 58 test names, rechecked | `661a4221300af5219c4a1774f8b928968dd1b3fd419e46ec8e8072202523ad6c` |
| proof/logs/load.txt | the load average during the native runs | `e3f4823bd1d7b453f755e94abd1cb83a160e25e73900a4d82ee57c8305f57786` |

Phase two's root: /private/tmp/larsal-m22post-e7-TjBZj6HD (mode 0700; it does not last). FINAL-SEAL.json there lists the SHA-256 of these files, of every log under proof/ and of the proposed files.

| File | What | SHA-256 |
|---|---|---|
| proof/seal/seal-check.txt | phase one's 1138 sealed files, each found with its hash | `7b5d5183a13f1e618b21bf6b40a421a4eb735547d908ab85619f44633e924c03` |
| proof/run/run-read.txt | the run of record read: copies, each part, the tool, the baseline, the story's tests, the first try | `013d6d37fc6cc394afd61add7f0dae29fdefea1e0562fb651f37fbec18257a25` |
| proof/run/fuzz-and-timing.txt | the story's five fuzz routes; the release-only timing tests by lane | `14fa524375b05a80d3894212c6c1c91b1af56ca1d08acb17a1048900110b95ea` |
| proof/run/fuzz-seed-length.txt | libFuzzer's input limit and how it reads a longer seed (FUZZ-MAXLEN) | `7aae7ea40e92c7ef591b44deae19d83cc9b5b5142ab6f7ce439165f374304991` |
| proof/run/first-try-swift-failures.txt | part B's first try: its one failing test and the story's two suites | `1faf4772873dfd82fc19c82b30f8f13cb89fc16b596e0fbfc14e6faed1007736` |
| proof/diff/f439-patch-check.txt | 9800dfd against F-439's fix.patch; the two commits | `d9e99f6043e5c5d2b534ba1382b9fedf74ed4d2354165bd728cd66b5f9db37c9` |
| proof/diff/diff-names.txt | the 18 paths of 91a7377..a90fc8b, and the story's 23 files | `369f0fd87dc5767298706ef5151cd6edd5a86cff8fae9e3e05f4d24d55e66fbd` |
| proof/diff/refs.rs.diff | refs.rs, 91a7377..a90fc8b | `4546fca49d6e3f4727fe0f87eead419d05849513ca16974e57e5cca58b114977` |
| proof/diff/tests-edit.rs.diff | tests/edit.rs, 91a7377..a90fc8b | `692f4540bcd9670f11e549402a4fa41aaabd3aaf90c9021018a295b41e38056d` |
| proof/diff/functions-equal.txt | the story's functions and tests in refs.rs, tests/edit.rs and int03.rs, byte for byte | `45e403d0f3286a0090f6b49eb86b64dd12e72cd4cecd26cf8334a958ec805319` |
| proof/diff/int03-helpers.txt | the four cited int03 tests call no item F-439 changed | `58efd6040a60407157f651a4e471a66b1f23187eb02798ee970ea550d3f409a2` |
| proof/diff/pins-read.txt | pins.json, row by row | `479d575382487ddfe70cb00f109aaa25c4a8f3d6ab20b3c9542f1116f7de04b0` |
| proof/logs/progress.txt | every build and run of phase two, with load and power | `cb142c4df420ad824e5ce4a5608f1e3d3900357a49dcbf14c97d0d04092ae44b` |
| proof/logs/run-int02-control.log | int02 on a90fc8b, 72 of 72 | `9e23afe23db5f00a34e0fdc3bf4825b868f7bdf7314713cbd458adad32b82135` |
| proof/logs/run-int02-control2.log | int02 after the refs.rs restores, 72 of 72 | `5276b7fc6ca4f0df785dc8706a6e4b10fdbde931994d1cd11c47f041441f0ea3` |
| proof/mutants/mutants-log.txt | each mutant applied and restored, with hashes | `8a9e2f1b2663009c437fc5fce596babb29b72745b47a618423b289dad90da568` |
| proof/mutants/run-int02-M272.log | M272: int02 71 of 72 | `1032613f46b5e05ae76516e91351ebbdae0a410cb99af46a54857f83f7c7fa16` |
| proof/mutants/run-int02-VM-V1-refs-own.log | VM-V1-refs-own: int02 71 of 72 | `3d2f2d386507afc93c041d3a9c364dda458b64b0105285531e8f645256c4ae7a` |
| proof/mutants/run-edit-ME-281-list-f281_int02_16_the_editor_keeps_a_host_added_to_a_full_list.log | ME-281-list, f281 | `6a35d13c8d972bff0c1385e87684d3bc9435435d27743c61eed5582633a4c43b` |
| proof/mutants/run-edit-ME-281-list-int_02_29_browser_page_stores_its_options.log | ME-281-list, int_02_29 | `3fa91aaa3bd56d785f2a6e78a1776506d7a9ca3b963fceed859f0dcf0e20f97e` |
| proof/mutants/run-edit-ME-T70-off-f281_int02_16_the_editor_keeps_a_host_added_to_a_full_list.log | ME-T70-off, f281 | `8bb10538de5d06bfa3ce06122f84547418292cb88088520960b233226cb0217d` |
| proof/mutants/run-edit-ME-T70-off-int_02_29_browser_page_stores_its_options.log | ME-T70-off, int_02_29 | `c7c26659e2510e3181e41868a74d0c6459dad2d7eddfb9a50c2a35d1e305681f` |
| proof/host/host-1.txt | the host before phase two's runs | `ce1ddddd0418b81112472d227f6aa41966745c7509e5f549cb0347b88821317e` |
| proof/host/host-2.txt | the host after the first chain | `62245d0ad8bffae7a3c7465f9900aa88428f866c5c4b26f7f76ed4c18ff4e528` |
| proof/host/host-3.txt | the host after the second chain | `14245af4e0e23ee9cd83e2020c36e358890e602f6a9e294a36320a29f6bce07c` |
| proof/host/profiles.txt | the two guard profiles against the brief's | `080abc4b643ac362891ba9c6fd8efff27e543b4b685da9efeb8fdfecd7e67f12` |
| proof/anchors/anchors-a90fc8b.txt | the 15 card anchors of the proposed rows, each once at its line at a90fc8b | `657662807682c7c0e2d4a4d97403514a32e3ee0f502b88903bf2572167dee550` |

## Phase two's changes to this page

Phase one's words stand except these (2026-11-22):
- Header: the date line; the role paragraph's first sentence, which names the pass phase one as the brief of 2026-11-22 does, and its last sentence (phase two); the result paragraph: "pending the run of record" removed and its last sentence replaced, because the run of record reads PASS.
- "The run of record": phase one's placeholder line, its table and the FAIL paragraph replaced by the run as read, with phase one's demands kept in the table's middle column. Its item "Only F-439 on top" did not hold as written (two of the 23 files are in the diff), so the item says what phase two did instead, as the brief asks.
- "The lead's two runs of 91a7377": one sentence added (both failing tests pass in the run of record).
- "The whole difference": a row for candidate-m22; the line below it points to the new section "Phase two".
- "V-1 to V-5": "ok" now includes the run of record.
- "The story's checks": the first paragraph says that its list of files unchanged since 40c1689 is of 91a7377 and which four of them F-439 changes; T06 names both int01 tests in full and the run of record.
- "The amending rows": LD-330 (4) and LD-330 (5) no longer say "unchanged" without the a90fc8b qualifier (F-439 changes int03.rs and matching.rs); LD-318 (2) has the route's run in the run of record and FUZZ-MAXLEN.
- "Verify's findings": FUZZ-MAXLEN added.
- "Outside the story": the effects of the wall-clock tests and the fuzz step in the run of record; rows for part B's first try, phase two's load and the busy mark.
- "The open and carried rows": the run of record closed; FUZZ-MAXLEN added.
- "Limits": item 1 rewritten (the run is two runs), item 5 (the fuzz routes ran in the run of record; a90fc8b leaves the first pass's rows' files alone), items 9 to 11 added.
- "Evidence": phase one's root lost; phase two's evidence table added.
- "Report end": proof, open and next step.

## Report end

- Story: E7-S2.
- Files changed by Verify: none in the project (phase one and phase two). This page is proposed for `security/parity/E7-S2-site-access-prompts.md`.
- Proof: this page; the run of record of a90fc8b, Overall PASS in both parts (/private/tmp/larsal-gc-a90fc8b-2zpr and /private/tmp/larsal-gc-a90fc8b-2Smn); phase two's checks and runs on a90fc8b (proof/ under /private/tmp/larsal-m22post-e7-TjBZj6HD; FINAL-SEAL.json there).
- Open: V-6 (F-631); the carried rows above; V2-1 to V2-4 (F-636, F-637, F-634 and F-635, F-642); FUZZ-MAXLEN (F-643).
- Next step: the lead writes the proposed rows in one docs commit (the board line, 10 card edits, the LD rows, the findings rows) and runs `sh scripts/check-names.sh` over the tree.
