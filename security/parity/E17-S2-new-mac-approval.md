# E17-S2 A new Mac: approval by code, or the Recovery Kit: Verify sign-off

Story: E17-S2 (plan/epics.md). Cards: SYN-05 (SYN-05.1 to SYN-05.7; T01 to T06 and T08 to T10), SYN-06.11 with SYN-06.14's keys (T09 to T12, the approval half of T19), SYN-06.12's kit path again (T13, T14), SYN-01.4, SYN-01.8, SYN-01.12, SYN-02.2, SYN-02.3, SYN-04.11 (T14), CRY-05.4, CRY-05.5 (CRY-05 T15). Decisions: the builder's E17-S2 rulings (1) to (13) (builds/e17s2/r1/proposed-LD.md; LD-775 to LD-787); the lead's rulings (a) to (g) on the Checkers' notes, 2026-11-23 (builds/e17s2/r1/LEAD-RULINGS.md); m24's lead rows 1 to 6 (builds/records-m24/lead-rows.md; LD-788 to LD-793); LD-262, LD-266 (2), LD-327 (5) and (7), LD-340, LD-426; E17-S1's carried rows F-715 to F-726 and F-733. Checkers: Checker 1 and Sensitive Checker 2, each APPROVE_EXACT_CANDIDATE with nothing blocking (results/c1-result.json, results/c2-result.json).
Date: 2026-11-23.
Role: Verify, after the story landed in m24. This pass proves the commit that landed, `d212c1fff379766ced830fbb256e50382cb55e57` (the candidate-m24 top), from a private clone: the approved patch and its pick, the tables commit, the lead's two-part guarded run of record, the story's tests run again at the top, an independent check of the code's known value, the product build's dependency tree, the server's log lines, and 17 mutants in a private copy. It changed no project file, made no commit or push, and ran no xcodebuild, swift, swift-format or SwiftLint. The logs named here live in a private folder under /private/tmp that does not last, so this page copies what must survive; durable copies are in the lead's checkpoint, builds/e17s2-verify/.

**Result: signed with limits.** The approved patch landed unchanged: E17-S2's pick b0cb109 gives each of the story's 28 paths the approved tree's blob and mode and changes nothing else, and the tables commit d212c1f changes only the guarded tables. The lead's run of record of d212c1f passes in both parts (Overall PASS, tool exit 4, under the cap, 0 lost, 0 newly ignored, the two waived names E17-S2's replaced tests; Swift 497 of 497, APP-09 18 of 18), and each of the story's 294 runnable tests is ok. Each of the story's eight checks has its tests ok in the run and again in Verify's run at the top, and a mutant of its defence was seen red in a private copy and put back (17 mutants). Nothing Critical or High is open. The Checkers' notes go to E17-S3 as the lead ruled (m24's lead row 6, LD-793), the Medium one among them a test gap, not a defect; checks 5 and 6 each carry one of them (the 401 of `…/keys` after 15 minutes, and the device a refused seal leaves). E17-S1's F-715, F-716, F-717, F-719, F-720, F-721, F-722 and F-723 close with this story and F-733 with its tables commit. The limits are listed below.

## The whole difference

| Item | Result |
|---|---|
| The approved patch | builds/e17s2/r1/fix.patch, sha256 c831728d7b22c2e4daf38021d99496161039b5cca0d23fb49febe716c9734ab7, equals `git diff --binary ee81269 aee5c02` byte for byte; applied with `git apply --index` on ee81269 it gives tree 250c4c8f860ac19745c85ab5065f64c48848e77f, aee5c02's tree |
| The pick | b0cb1099a9894a6724421e4ab3b2c80cd5c6fb58 on ed02665 (m23's records top): the 28 paths it changes are the patch's 28; on each, the pick's blob and mode equal the approved tree's, and ed02665 holds each path exactly as ee81269 does (same-context pick, no line union) |
| The tables commit | d212c1fff379766ced830fbb256e50382cb55e57 changes only scripts/guarded/tables/pins.json (166 lines) and programs.json (+4): reviewed_commit 7bba8ad to b0cb109, a review entry "m24", 38 pin values moved (37 rows), 0 values differ from the trees; the new rows workspace:larsal-sync/approval_wipe (programs: harness-runtime-key.sb, as account_wipe; pins: crates/larsal-sync 962314e6… and crates/larsal-platform/src/device_key.rs 2018b2c6…, the key-route check). It changes what the tool runs and pins, not what any row proves: no code or test moves, and every story test runs in the lane it ran in before |
| Identity | Author and committer of b0cb109 and d212c1f: Joseph Demirian &lt;hello@JosephDemirian.com&gt;; no agent or tool words in either message |
| What the story touches | larsal-proto (approval.rs and base32.rs new; limits, routes, lib), larsal-server (approvals.rs new; auth, http, keys, store, lib; tests common, syn04, syn06), larsal-sync (approval.rs and tests/approval_wipe.rs new; account, sync, test_server, lib; client and account tests), larsal-ffi's src/sync/tests.rs only (no API change), larsal-platform's net.rs (+10 lines, Method::Delete). ed02665..d212c1f: 30 files, +7,264 −588 |

## The run of record: d212c1f

Both parts name commit d212c1fff379766ced830fbb256e50382cb55e57, use one tool copy ("tool against the commit: equal" at 12:17:30 in part A and 13:23:54 in part B), compare against m23's names of 7418b3d (test-names-7418b3d.json, sha256 f407e8a3…) and take the lead's waiver file (waivers-m24.json, sha256 2ab05d4f…).

| Item | Part A: static and rust | Part B: native, docs and fuzz |
|---|---|---|
| Root | /private/tmp/larsal-gc-d212c1f-1LWZ | /private/tmp/larsal-gc-d212c1f-DvmB |
| Overall | PASS (only static,rust), tool exit 4 | PASS (only native,docs,fuzz), tool exit 4 |
| Time | 2,160.6 s of the 3,600 s cap, hold wait 0 s | 1,241.0 s of the cap, hold wait 390 s |
| Phases | static 734.3 s, 18 of 18 (names guard over 12,794 files); rust 1,418.2 s: 5,438 passed, 0 failed, 148 ignored, 185 of 185 programs | native 987.0 s: Swift 497 of 497 in 75 suites, APP-09 18 of 18, kernel rows lost 0 in A1, B1 and G1, the owner's simulator folder unchanged (1,983 names); docs 23 of 23; fuzz 37 routes, fewest runs 1,104 |
| Rust lanes | workspace 4,245/0/122 (159 programs), sync 779/0/19 (17), net 81/0/7, release 288/0/0, release-browser 45/0/0 | none |
| Baseline | 5,541 compared, 0 lost, 0 newly ignored, 2 waived, 47 new | 538 compared, 0 lost, 0 newly ignored |
| Waived | keys::tests::syn06_12_decoy_is_an_ed25519_point (now syn06_12_c2_f2_the_decoy_is_drawn_at_start_and_nobody_holds_its_key) and store::tests::syn02_2_a_schema_1_store_opens_as_schema_2_with_its_rows (now syn02_2_an_older_schema_is_refused_and_folder_unchanged); no other | none |
| Crash reports | 4 new, all on purpose (larsal_platform's prompt_child); own and not on purpose: none | none new |
| Grants | 62 rows, 0 withheld | the same 23 tool values as part A |

The story's tests in the run (proof/story-tests-in-run.tsv, from part A's test-names.json): the 295 test functions in the story's files are 294 ok and 1 ignored (`sync::tests::t26_kill_child`, ignored at the base too): 129 in the workspace lane and larsal-ffi's 165 ok and 1 ignored in the sync lane. No release lane holds a story test. Against 7418b3d's 6,079 names, d212c1f's 6,124 lose exactly the two waived names and add 47.

## The story's checks

Every test named below is ok in part A and again in Verify's run at d212c1f (logs/full/, 233 passed, 0 failed). Every mutant ran in Verify's private copy (target/ms, the git archive of d212c1f), turned the named test red at the line given, and was put back; each file's sha256 then equalled the commit's blob, and the clean and final runs were green.

| Check | Tests (ok in part A and in Verify's run) | Verify's mutant, red | Judgement |
|---|---|---|---|
| 1. The E16-S7a and E16-S7b tests add their second device through the code compare, and the helper is gone | larsal-ffi `sync::tests::syn03_2_t03_another_mac_takes_the_vault_and_links_it`, `syn03_5_t05_a_deletion_stays_deleted_on_the_other_mac` and the other sync tests (165 ok, 1 ignored), their second Mac by `approved()` with `parts_through_server`; larsal-server `tests::syn04_t14_no_seam_writes_a_device_row`; `TestSeams::add_device` and `copy_parts` appear in no code (add_device only as that test's needle, lib.rs:235) | V1b: N's code with the two nonces swapped in `Committer::reveal`: both larsal-ffi tests red at crates/larsal-sync/src/test_server.rs:490 ("858 005" against "297 372"; "422 486" against "813 788"). V1a: an `add_device` seam added back: syn04_t14 red at crates/larsal-server/src/lib.rs:232 | Met. Against E17-S1's ruling (g): its first branch holds (F through `put_keypart` and `get_keypart`, the only larsal-ffi file changed is src/sync/tests.rs, so no API change), so F-719 closes here, not in E17-S4 |
| 2. Both test clients show the same 6-digit code | `approval::tests::syn05_t01_syn06_11_t09_one_code_on_both_screens_and_n_joins_and_syncs`; `syn05_4_t02_known_value_against_an_independent_sha256` (larsal-proto); `approval::tests::syn06_11_the_approve_helper_gives_a_device_that_signs_in` (larsal-sync) | V2: E's `Responder::check` with K_C and K_R swapped: T01 red at crates/larsal-sync/src/approval/tests.rs:292 ("866 416" against "457 350") and the approve helper red at test_server.rs:490 ("both screens show one code") | Met. Verify recomputed T02 from the cards alone (Python hashlib, no Larsal code): field list 208 bytes, SHA-256 b94b6676…43ee, code 530 993, commitment 041b9d12…64d6, equal to the test's constants (proof/t02-independent.txt) |
| 3. A test relay that swaps a key gives different codes, and nothing is sealed | `syn05_t03_a_relay_that_swaps_k_c_in_message_3_fails_e_s_check`; `syn06_11_t10_a_relay_that_swaps_n_s_one_request_key_gives_other_codes` (`Attack::OwnC`, a valid X-Wing key; CRY-05 T15); `syn05_3_the_commitment_is_compared_whole`; T04's 10,000 runs in memory and 20 through the test server | V3b: the commitment compare removed: T03 red at approval/tests.rs:552 (no `CodeFailed` on E) and syn05_3 red at :1444. V3a: `K_C` left out of the code (larsal-proto `code()`): T02 red at crates/larsal-proto/src/approval/tests.rs:65 (72575 against 530993) | Met. T03 ends with no code shown and nothing sealed; T10 gives two codes and, with Codes differ, no seal request and no device (N cannot sign in). T04 printed 0 matches in 10,000 runs and 0 in 20 |
| 4. A second commitment for the same request is refused | larsal-server `syn05_t05_syn06_11_t11_one_claim_and_one_commitment` (a second claim and a second commitment each get 409 and end the request) | V4: a second commitment taken when the stage is Committed: red at crates/larsal-server/tests/common/mod.rs:197 (204 where 409 was expected) | Met |
| 5. A request older than 15 minutes is refused | larsal-server `syn06_11_t11_a_request_older_than_15_minutes_is_refused` (each of 9 steps of a request, taken at T0+899 s and refused at T0+901 s by the server's clock); larsal-sync `syn06_11_t11_an_expired_or_claimed_code_is_refused_on_both_clocks` (each client's own clock) | V5a: two more minutes in `by_code`: red at crates/larsal-server/tests/syn06.rs:1061 ("stage 0": 201 where 401 was expected). V5b: the client's life doubled: red at approval/tests.rs:923 | Met as built: N's code routes and `…/keys` answer 401, E's seal, `GET` and `DELETE` 404, with nothing registered; 899 s is the last valid second (C1-F4). Against the lead's ruling (c): `…/keys` should answer 404, so that E's client does not sign in again and send message (2) twice; that is E17-S3's, a findings row (Info, F-870), not a defect of the refusal |
| 6. No device is registered before "Codes match" | larsal-server `syn06_11_t09_t19_n_is_registered_only_after_e_seals` (the database read after every step); T01's probe ("nothing sealed, signed or pinned before Codes match"); `syn06_11_t12_t19_the_server_registers_only_a_device_the_identity_key_signed` | V6a: a devices row written at the claim: red at syn06.rs:853 ("after claim" 2 devices where 1 was expected). V6b: E seals in `Approver::poll` before Codes match: T01 red at approval/tests.rs:300 ([1, 1, 0] where [0, 0, 0] was expected) | Met. Against the lead's ruling (b): a seal N refuses after reading it leaves N's device registered (no secret reaches it); that is after Codes match, so outside this check, and E17-S3's (findings row, Low, F-865) |
| 7. The kit path registers a device | larsal-server `syn06_12_recovery_challenge_and_sign_in`; larsal-sync `account::tests::syn06_12_t13_e17s1_the_kit_and_the_password_restore_into_an_empty_demo_app_state` and `syn06_12_t14_a_wrong_kit_or_password_gives_one_message` | V7: `recover_device` never inserts the device: red at syn06.rs:558 (409 where 200 was expected) | Met |
| 8. Two Checkers | Checker 1 (c1-result.json, sha256 e407b335…) and Sensitive Checker 2 (c2-result.json, sha256 6c8226ab…) each APPROVE_EXACT_CANDIDATE on aee5c02, tree 250c4c8f, seal bf2a7355…; nothing blocking | none needed | Met; their notes are ruled (the open rows below) |

## Also read

| Item | Result |
|---|---|
| SYN-05 | Commit first, as RFC 6189 section 4.4.1.1: the server holds N's commitment before it takes message (2) (crates/larsal-server/src/approvals.rs:310); `ctx`, `commit` and `code` as SYN-05.1 and SYN-05.4 write them (T02 above); the commitment and every pin compared with `ct_eq`; the code shown as two groups of three. Each side's acts are typed: only `ECompared::codes_match` gives `EMatched`, the only type with `seal()`, and only `NCompared::codes_match` gives `NMatched`, the only type that reads the seal |
| SYN-06.11 | Built as two requests where step 2 named one (claim, then `…/commit`), because `ctx` needs the `approval_id`; stages 0 to 5; the seal is a CRY-05.4 record plus the composite device signature; N's `GET` after the seal hands the request over and the row goes. Card edits 1 to 4, 8, 10 to 12 write it down |
| SYN-02 | Schema 3 with no migration: 1, 2 and 4 refused with the folder unchanged; the approvals table holds the code's SHA-256, never the code. SYN-02.2's words, its edge case and T03 and T04 were out of date since E17-S1 (card edits 13 to 17). Verify's run of SYN-02 T14 printed "19 needles (3 codes in 8 forms), 184 forms, 82 places (38 proxied exchanges as request and reply, 6 server files), 697662 bytes searched, 0 found" |
| CRY-05 with E25-S3's suite | The seal route takes only `[25722, 1, 3]` (V11: the suite filter always true turns `syn06_11_t12_t19_…` red at common/mod.rs:197, 204 where 400 was expected); CRY-05 T15 is SYN-06 T10's test (a relay's own valid X-Wing key); the device signature is CRY-05.5's composite signature, checked with the stored identity key before any devices row (403 else) |
| LD-327 (7) | Done by E17-S1 (`challenges.kind`); its test `store::tests::syn06_12_challenge_kinds_are_kept_apart` re-proven: V9 (the kind filter always true) turns it red at crates/larsal-server/src/store.rs:1756 |
| Rule 3 | No crate but larsal-crypto imports a crypto crate: larsal-proto names none; larsal-sync's rustls and rcgen are optional, for its test server; larsal-server's tokio-rustls and rcgen are LD-263 (18)'s TLS exception; Cargo.lock unchanged from ed02665; larsal-sync gains a dev-dependency on larsal-crypto's test-kem-secret feature, as larsal-ffi's has (proof/rule3.txt). A product build: `cargo tree -p larsal-server` prints `larsal-server v0.1.0 []`, and larsal-ffi with `--features sync` has no larsal-server in its normal or build tree (proof/product-tree.txt) |
| Rule 4 | `e17s2_approvals_leave_no_request_secret_in_memory` printed RESIDUE 0 at every stage (needles: the code, the seed and the X-Wing shared secret; the code and the seed; the code, the unrevealed n_C and the seed), S_acct copies 4, 4, 4 then 0, control 1; V12 (one leaked copy of the code at the claim) turns it red at crates/larsal-sync/tests/approval_wipe.rs:223 (RESIDUE [1, 0, 0] after Codes match). The server's 278 log lines in Verify's run are all request lines (method, route, status, size, time), 0 of any other form (proof/server-log-lines.txt). Open: the code's text in N's pooled connection buffers (the lead's ruling (e)) |

## Verify's own runs

All on this Mac's battery, powermode 2, one-minute load 14 to 23, three jobs, under compile.sb (builds) and run-key.sb (tests), each after the wait for BUSY-native and HOLD-native-quiet (only BUSY-native.lock stood; neither mark).

| Run | Time (2026-11-23) and battery | Result |
|---|---|---|
| Build of larsal-proto, larsal-server and larsal-sync tests at d212c1f | 15:19:45 (62%) to 15:21:37 (59%) | built (logs/build-1.log) |
| Clean runs before the mutants | 15:28:24 (51%), 15:29:58 (49%), 15:31:19 to 15:33:49 | all named tests green: three crates, server, larsal-ffi (T03 and T05: 2 passed) |
| 17 mutants | 15:28:40 (51%) to 15:33:52 (44%) | each red under its named test (logs/mut/V*-test.log); each incremental build 1.5 to 6.5 s |
| Final runs after the mutants | 15:34:00 (43%) to 15:35:06 (42%) | all green; every mutated file equals the commit's blob |
| Every test of the story's 9 programs | 15:35:22 to 15:35:58 (42%) | 233 passed, 0 failed: larsal_proto 45, larsal_server 46 and its binary 1, syn01 27, syn04 16, syn06 17, larsal_sync 79, account_wipe 1, approval_wipe 1 |
| The printed figures (T02, T04, SYN-02 T14, the wipe) | 15:36:49 (41%) | logs/print.log |

## The open and carried rows

| Row | Severity | Judgement |
|---|---|---|
| The lead's ruling (a): eleven client mutants no builder test kills (C1-F1, C2-F1 Medium; C2-F2, C2-F3 Low; F-864) | Medium | Real test gaps, not defects: the checks are in the code. Open findings row naming E17-S3, which adopts the Checkers' tests |
| (b): a refused seal leaves N's device (builder; C1-F2; C2-F7; F-865) | Low | Real; no secret reaches the device. Open row, E17-S3 |
| (c): `…/keys` answers 401 after 15 minutes (builder; C1-F3; C2-F6; F-870) | Info | Real; nothing is registered. Open row, E17-S3; card edit 8 words both answers |
| (d): no fuzz targets for the account and approval readers (builder; C1-F5; F-866) | Low | Real. Open row, E17-S3, with its fuzz_routes table move |
| (e): the code's text in pooled buffers (C2-F4; F-867) | Low | Real; the code admits one claim. Open row, E17-S3 |
| (f): lazy expiry (C2-F5; F-868) | Low | Real; no route takes a lapsed request. Open row, E17-S3; card edit 14 words it |
| (g): E17-S1's flaky syn06_13_t15 (builder; C2-F8; F-869) | Low | Real (about 1 run in 40); it passed in part A. Open row, E17-S3 |
| C1-F4: 899 s is the last valid second (F-871) | Info | As written; card edit 8 words it. C1-F6 and C1-F7 need no row (the lead's ruling) |
| The builder's rows on T03 and T04, SYN-06.14's words, and the tables at the base (F-872 to F-874) | Info | Closed by card edits 13 to 17, card edits 1, 3, 4 and 10, and d212c1f's tables |
| A doc comment naming the removed helper (crates/larsal-ffi/src/sync/tests.rs:364; F-875) | Info | Verify's row, for E17-S4 |
| E17-S1's F-715, F-716, F-717, F-719, F-720, F-721, F-722, F-723 | Medium and Low | Closed by E17-S2 (Status edits); Verify's V13, V14 and V15 kill the adopted tests of F-715, F-722 and F-721; the builder's M21, M22, M23 and M25 those of F-716, F-717 and F-720 |
| F-733 | Info | Closed by d212c1f: each of the 62 rows names a review entry |
| F-718 (larsal-ffi loads no account keys) | Medium | Carried: E17-S4. Sync stays off in the app build (LD-426) |
| F-725, F-726 | Low | Carried; F-726 gains the new place of the base32 code (larsal-proto) |
| Rows this story does not run | carried | SYN-05 T07 (E17-S4's screens); the device list and sign-out everywhere (E17-S3); invites (E18-S4) |

Nothing Critical or High is open.

## Limits of this signature

- The run of record is the lead's: Verify read its records and did not run the whole check again, the native phase or any release build; part B's Swift and APP-09 counts are the run's.
- Verify's mutants cover the eight checks and the rows named; they are not a full mutation run. The builder's M21, M22, M23 and M25, which kill the adopted tests of F-716, F-717 and F-720, were not run again.
- The product-build claim rests on the dependency tree (no test feature in larsal-server's product build, no larsal-server under larsal-ffi), not on a search of a release binary's strings.
- Every Verify run was on battery (62% to 41%, powermode 2), under load from other work on this Mac; no timing figure is claimed.
- The Checkers' surviving mutants and probes are cited from their reports; Verify did not rerun them.

## Evidence

| What | SHA-256 |
|---|---|
| fix.patch | c831728d7b22c2e4daf38021d99496161039b5cca0d23fb49febe716c9734ab7 |
| builds/e17s2/r1/LEAD-RULINGS.md | 7b486f690763e65892d4db161a89cc2d30ce509519664a1c6068d8eb37803aa8 |
| builds/e17s2/r1/source-seal.json | bf2a73557608ada0c1f325ab92ca9c9623e4431860c97912e38cec2b0805ccff |
| results/c1-result.json | e407b335573dc3f59ee38aa5b9756a513d318c53a648aea38190d150e8655d37 |
| results/c2-result.json | 6c8226ab3689470109862dd6544cf3af1d872d5a6f4b614c57f109bfdf0898c8 |
| builds/records-m24/lead-rows.md | a3c26051fc259d592a6de187469ad7c58d3eeef7940cdd0c4a537b6cf28ba74f |
| builds/records-m24/waivers-m24.json | 2ab05d4fabc83ee6301f0f31c851ca0b49ed1e6d477ad845392cf5a1ab8d76a3 |
| builds/m24-run/candidate-m24-d212c1f.bundle | 3eeeea93c159f234c0566bf2aaaf943b616a84f2ac20a34c25b83303d0f7e303 |
| part A rerun.out | 6a3608182dd1a744196601883904c2c6be848b12fadd5144056a0d286e418a06 |
| part B rerun.out | 99da69e829a40b1ecbc8e9beecdbd8b6d16609334391aeb244556a4dd689abc8 |
| part A run.json (its root) | 423922a0c610a97d674665974429a4d07131c1bd41d1f738a17a917546fbad9b |
| test-names-d212c1f.json | 076a154bab5b6a207dbbd2e3ce04fc7208de15fece18f5315374bb7323469b31 |
| test-names-7418b3d.json | f407e8a39ed73b17c87ca95be02351bc5ac151b91e83f5018b21b403300d1211 |
| proof/patch-proof.txt | f2a816202b175aed3d205b97cfdaa924ab48bb533036cf829e19f6a1e31018f6 |
| proof/tables-commit.diff | 690ddafef639ad6d49621c58200c1e64aa8acb452002cca24c67aeddf3b63501 |
| proof/pins-check.txt | 82469f8388615bca53bb338332e52cddb2769ff2b381285444afc6dd5e018ded |
| proof/pins-labels.txt | b3705560f03d25b1e5337c1630ee16cf3f3d0fb9abc63add87613aeb885c4c57 |
| proof/story-tests-in-run.tsv | 464aa80fab5dfdcf04729edc1dc411369f6b5f1b0202b4ffe768ab79cc396ee9 |
| proof/t02-independent.txt | f396fa09f3762ac289b37f4e85b3fd6bf9989082500118bb81ac00486a1d6c79 |
| proof/rule3.txt | dfe0960c43effaea282fb37d5b664a70a4e2e85b31f3f4a50f639d9fdc508e0b |
| proof/product-tree.txt | e9f852f3bb074cac23dacac9f08aa43967c35080849eca32ff3f4f276f761dad |
| proof/server-log-lines.txt | 462317630dabcd15142bcc82724cfd0a67da37304bff95146173a5288c6c5545 |
| proof/m24-stat.txt | a86889e3ea3ebc1edaab0bab9a2dcd6c28cbd32583e2002901180083d23f25b6 |
| proof/anchors.txt | 979943fed3fb2670d5fd3cfdb8381aa45d87c85f161b2740fce7a6ba118b26c2 |
| proof/inputs-sha256.txt (every input's hash) | 27bf7979350b3dff18b3c739a752cd93a9ae1786c8c1e18955fe40dbf21db47c |
| proof/run-files-sha256.txt (both parts' files) | e2f707c953ccb32a3f99e361043af9890b1904817db214192e9f981c33ea6878 |
| logs/print.log | 36335108f7432ca321c657614168c78f665b7bb27e92386d52a344eb7fea440a |

proof/evidence-manifest.txt holds the hash of every file of Verify's proof/, logs/, scripts/ and profiles/; FINAL-SEAL.json holds the manifest's hash and this page's.

## Report end

- Story: E17-S2. Verdict: signed with limits at d212c1fff379766ced830fbb256e50382cb55e57.
- Files proposed: this page (security/parity/E17-S2-new-mac-approval.md) and E17-S2-proposed-rows.md (the board line, 23 card edits, 13 LD rows, 13 findings rows, 9 Status edits and one Area addition). No project file was changed.
- Proof: the commands and outputs named above, in Verify's root and in builds/e17s2-verify/.
- Open: the seven rows of the lead's rulings (a) to (g) (F-864 to F-870) for E17-S3; F-718 for E17-S4; F-725 and F-726; Verify's doc comment row (F-875). Nothing Critical or High.
- Next: the lead puts this page and the rows in m24's records commit and runs the name guard.
