# E24-S2 New SSH keys made in Larsal: Verify sign-off

Story: E24-S2 (plan/epics.md). Cards: INT-06.E24.01 to INT-06.E24.06 with cases E24-S01 to E24-S06 (spec/integrations/INT-06-ssh-agent.md), E9's agent path (INT-06.4, INT-06.27), APP-03, APP-05, FMT-13.3. Decisions: the lead's E24-S2 rulings of round 1 ((1) to (5) of the brief), round 2 ((1) to (8)) and round 3 ((9) to (13)); LD-133, LD-193, LD-209, LD-428. Checkers: C1 and C2, three rounds; both approved round 3's fix.patch exactly.
Date: 2026-11-23.
Role: Verify. This pass proves what landed in candidate-m23, top `7418b3dbee98ff12b1d4c115d5fa914f77b37c5c` on Main `d5b466d1ee28783f40817151dd00405f3cddf877`, from a private clone: the pick of the approved patch, every later m23 commit's diff on the story's paths, the lead's two-part guarded run of record (read, not rerun), its own reruns on 7418b3d of the story's Rust tests for checks 1 to 3, the random seam, rule 4 and rsa_wipe, under the repo's guard profiles in debug and release, and seven mutants in nine runs in a private copy (MB and MW in debug and in release), each seen red (MF as a test build that fails) and then restored, with two experiments on the memory probe. It changed no project file and ran no Swift.

**Result: signed with limits.** The pick c4adf2c carries round 3's approved tree exactly: 193 of its 196 paths have the approved blob, and the 3 line unions carry exactly the patch's change lines; it changes nothing else. Two later commits touch the story: 32866f2, which merges two larsal-crypto dev-dependency lines into one, and 7418b3d, the guarded tables. Verify read both line by line, reran the tests of each row they change on 7418b3d, and saw a mutant go red for each row but one: the audit route's ignore, which Verify could not rerun (limit 6). The run of record reads **Overall PASS** in both parts (tool exit 4). Part A, static and rust, took 1,978.0 s; part B, native, docs and fuzz, took 1,209.2 s plus a 360.1 s hold wait outside the cap. Against f52befe's names, 0 were lost and 0 newly ignored, and the 5 waived names are E25-S3's five. The run holds 81 of the story's tests: 62 ok and 14 ignored by design in part A, and the 5 Swift tests ok in part B. None failed.
- Checks 1 and 3 are verified.
- Check 2 is verified from the run of record. Verify's own profile cannot start sshd (limit 2).
- Check 4 is verified for presence and words. Pixels cannot be measured, because the E24 proposal frames have no reference image (limit 3).
- Check 5 rests on the guarded native lane's gate (limit 4).

Nothing Critical or High is open for a shipped binary. The rsa High row (F-742) stays in LD-133's residual class, closed in every binary that makes or opens a key. Verify adds three rows. V-1 (Low): since m22's 9800dfd, the memory probe counts fewer dead copies on the stack of the thread that runs the count in a debug build; every E24-S2 mutant still turns red. V-2 (Info): no guarded release lane runs the rule 4 tests. V-3 (Info): the larsal-ffi tests leave their demo vault folders in TMPDIR.

## The whole difference

| Item | Result |
|---|---|
| Base | Main `d5b466d1ee28783f40817151dd00405f3cddf877`. candidate-m23 adds eight commits; top `7418b3dbee98ff12b1d4c115d5fa914f77b37c5c`, tree `27c277fa377cdbed373df24bb1765d339aafae79` |
| Commits | 4579551 (E25-S3), 0524eb2 (E17-S1), c4adf2c (E24-S2), 4c02175 (the test browser), 1da705a (tool round 2), 32866f2 (the lead's fix: one larsal-crypto dev-dependency line), 7bba8ad (the lead's fix: driver words), 7418b3d (guarded tables). Each has author and committer Joseph Demirian <hello@JosephDemirian.com> and no trailer |
| The reviewed patch | Round 3 fix.patch, SHA-256 `e8ff386c5ab9d722d00a380a95aeb175ed55e76a07b271dd6e882d80988b9679`. `git apply --cached` on a private index of `91a7377e797b2198bdb482f3c9550785925c8317` writes tree `d13faa972dd3c276a547c8388fe1e9786027bad9`, the tree of the approved head 195eef3. The bundle e24s2-r3.bundle verifies; its 16 commits carry the owner's name only |
| The pick | c4adf2c (parent 0524eb2) changes exactly the approved diff's 196 paths; 193 have the approved blob. Three are line unions, because E25-S3 or E17-S1 changed them first: crates/larsal-crypto/Cargo.toml (12 change lines), crates/larsal-ffi/Cargo.toml (4) and crates/larsal-ffi/tests/edit.rs (470). For each of the three, the change lines from 91a7377 to the approved tree equal those from 0524eb2 to c4adf2c. 0 bad paths |
| Later commits on the story's paths | 4c02175, 1da705a and 7bba8ad touch none. 32866f2 changes crates/larsal-ffi/Cargo.toml only. E25-S3's and E24-S2's larsal-crypto dev-dependency lines become one line, `larsal-crypto = { workspace = true, features = ["test-kem-secret", "test-random"] }`, which keeps both comments; the first candidate, 3dc7c54, stopped at 'duplicate key' at line 75. 7418b3d changes the guarded tables only |
| The tables commit | programs.json gains `workspace:larsal-crypto/rsa_wipe` (:410) and `workspace:larsal-crypto/ssh_stack_wipe` (:418), each harness-runtime-base.sb with no classes, as the builder's tables-moved.txt asks. The second closes C1R3-F4. In routes.json, check_sh_sha256 and `functions.audit` change: the audit's two runs now carry `--ignore RUSTSEC-2023-0071`, as scripts/check.sh:219-220 does. pins.json changes 133 values (reviewed_commit 7bba8ad). native-expected moves from 492 18 to 497 18 (E24-S2's five Swift tests) |
| What the story touches | 196 paths in all. Code and tables (31 paths): crates/larsal-crypto (5), larsal-ffi (8), larsal-sshagent (3), larsal-cli (1, the crypto list), macos/Larsal (5), Larsal.xcodeproj (1), LarsalTests (1), design/option-a/proposals.html (the ssh-save-error frame), Cargo.toml, Cargo.lock, fuzz/Cargo.lock, deny.toml, scripts/check.sh and scripts/check-vendor.sh. Vendored files (165): p384 0.14.0, p521 0.14.0, rsa 0.10.0-rc.18, crypto-primes 0.7.2, and the crypto-bigint 0.7.10 manifest cut |

## The run of record: 7418b3d in two parts

The lead ran both parts with one tool copy, the baseline test-names-f52befe.json and the waivers waivers-m23.json. Verify read both parts and the lead's copies in builds/m23-run/ (equal by hash) and did not rerun them.

| Item | Part A (`--only static,rust`) | Part B (`--only native,docs,fuzz`) |
|---|---|---|
| Root | /private/tmp/larsal-gc-7418b3d-whFL | /private/tmp/larsal-gc-7418b3d-yNtq |
| Overall | **PASS**, tool exit 4; `summary.txt` `646402b215d792e0…` | **PASS**, tool exit 4; `summary.txt` `039111c2923f6d24…` |
| Time | 1,978.0 s of the owner's 3,600 s cap, hold wait 0 | 1,209.2 s of the cap; 360.1 s hold wait outside it |
| Commit, tree, tool | 7418b3d, tree 27c277fa. The 23 tool files equal scripts/guarded at 7418b3d; custody 0 changed; grants 61 rows, 0 withheld (reviewed commit 7bba8ad) | The same, with the same 23 tool hashes as part A |
| Static | 18 of 18. Names PASS (12,784 files, 19 vault files name only). Unsafe 582 in 21 crates. Advisories, bans, licenses and sources ok, with the audit route as 7418b3d moved it | Not requested |
| Rust | 5,393 passed, 0 failed, 148 ignored, 184 of 184 programs: workspace 4,200/0/122 (158), sync 779/0/19 (17), net 81/0/7 (2), release 288/0/0 (6), release-browser 45/0/0 (1) | Not requested |
| Swift, APP-09 | Not requested | Swift: 497 tests in 75 suites passed; bundle 497/0/0; database 497 cases, 654 runs, 497 ok. APP-09: 18 passed |
| Hidden launch | Not requested | Attempts G1, A1 and B1 exit 0 with no gate failure (window samples 3, 0 and 113); the owner's simulator folder unchanged (1,983 names) |
| Docs, fuzz | Not requested | Docs 23 passed. Fuzz: 37 routes, all exit zero, fewest runs 700 |
| Baseline | 5,204 compared, **0 lost**, 0 newly ignored, 5 waived, 342 new. The 5 waived names are E25-S3's renamed or removed tests (hpke cry04_6, seal_open_and_wrap_round_trip, t09, t10, larsal_proto ld305_5), each named in waivers-m23.json; no waiver goes unused | 524 compared, **0 lost**, 0 newly ignored, 0 waived, 14 new |
| Crash reports | 4 new, all on purpose (larsal_platform's guard_child and prompt_child); own and not on purpose: none | None |
| Limits the run states | Yanked status not proven for 22 crates (offline index); advisories 1,395, newest 2026-10-30 | None |

**The story's tests in the run** (proof/story-tests-in-run.txt). These are the test functions the approved patch adds or whose bodies it changes, its two new programs rsa_wipe and ssh_stack_wipe, and the Swift suite NewSshKeyTests: 81 names in all.
- Part A sync lane: 23 ok, 4 ignored.
- Part A workspace lane: 39 ok, 10 ignored.
- Part B: the 5 Swift tests ok (e24Frames, e24S01Choices, e24S04FailedSave, e24S04S05GenerateSaveCopy, e24S06CancelWhileMaking).

None failed. The 14 ignored are the children their parent tests run (ssh_stack_wipe's four child tests, the four larsal-ffi stack children in each lane, and the worker child), plus rsa_wipe's rsa-crate control, which is red on purpose (below). No story test runs in a release lane: the release lanes run int03, fea01, fea05, fea06, fea07, mod08 and mod11 (limit 5).

## The story's checks

| # | Check (plan/epics.md, E24-S2) | Proof | Result |
|---|---|---|---|
| 1 | Each made key is read by `ssh-keygen -y` and `ssh-keygen -lf` (throwaway HOME, never ~/.ssh) with the same public key and fingerprint Larsal shows | Run of record: own_agent `e24_s06_ssh_keygen_reads_each_new_key_and_shows_what_larsal_shows` ok (part A, workspace lane). Verify's rerun on 7418b3d (proof/run-c-keygen.log) covers all six kinds. `ssh-keygen -y -f /dev/stdin` with the key piped is refused with "bad permissions". The test's named pipe (mkfifo 0600 in a 0700 folder) serves the key 8 to 20 times, then is removed. Each `-y` line equals Larsal's, and `-l` reads 256 ED25519, 256, 384 and 521 ECDSA, and 3072 and 4096 RSA, each with comment e24@demo. Mutant MV, in which Larsal shows the public parts of a second key, turns the test red at own_agent.rs:2173 (the `-y` line differs from Larsal's line) | Verified |
| 2 | The key signs in to a loopback `sshd` through E9's agent path | Run of record: `e24_s06_each_new_key_signs_in_to_a_loopback_sshd_through_the_agent` ok, under the reviewed sshd grant (harness-runtime-target-tmp-sshd.sb: sshd starts its own sandbox). In Verify's rerun, everything before the sign-in passes: nothing signs in while the agent is empty, `has_ssh_key` (INT-06.4) holds, the key loads to `Place::System`, and `ssh-add -l` lists it. The sign-in then fails at own_agent.rs:2258, because sshd cannot start its own sandbox inside Verify's run-key.sb (limit 2). Mutant MV turns the test red at :2254 (the listing). The builder's R20, killed by the has_ssh_key assert, stands | Verified (limit 2) |
| 3 | No private key file is written | The product's one SSH write is Save Public Key: `e24_s05_save_public_key_writes_the_public_line_and_asks_before_replacing` ok in the run and in Verify's rerun. Mutant MS, in which Save Public Key writes the private attachment's text, turns it red at edit.rs:1125: the file held "-----BEGIN OPENSSH PRIVATE KEY-----" instead of the "ssh-rsa" line. The ssh-keygen route uses only a named pipe, and its folder holds nothing else afterwards (check 1). Rule 4: the stack tests below. The generic Save… and Open of an attachment can still write id_<type> as plain text; that row (F-746) is carried to E24-S6 | Verified |
| 4 | Mac QA matches the frames | Part B's `NewSshKeyTests/e24Frames()` drew the six frames offscreen in light and dark: 12 PNGs, 1,200 px wide, each with its accessibility dump, copied into proof/frames. Ten are byte-equal to the builder's round 2 frames; ssh-save-error carries round 2's new words. Present: 6 of 6 in each theme. Words (proof/frames-words.txt): 130 of the proposal rows' 136 strings are found, and nothing is drawn that the rows do not hold. The 6 missing strings are 3 known differences, each in both themes: the panel's value "Working · finish time unknown" is absent from the dump (the open Low row, F-748); the tile's label "SSH key saved · result illustration" draws as "SSH key saved"; and the frame note on e24-s1-ssh-created is not drawn (ruling (5)). Verify opened four images: light new-ssh and ssh-created, and dark new-ssh-rsa and ssh-save-error. The tile, segmented choices, fields, words and buttons stand as in the proposal frames. Tokens, geometry and pixels were not measured (limit 3). Verify ran no Swift mutant; the builder's S1 to S3 were killed in its guarded native run 1 | Verified for presence and words; pixels open (limit 3) |
| 5 | Tests launch hidden (rule 10) | Part B's native lane: G1, A1 and B1 exit 0 with no gate failure (B1 took 113 window samples), and the owner's simulator folder is unchanged. Verify's own tests ran as sandboxed command line programs; none opened a window, took focus or used the general pasteboard (the clipboard test uses the private named pasteboard) | Verified from the run (limit 4) |

**Rule 4 and INT-06.E24.02** (the private half never leaves Rust, and no copy stays after use). Verify's controls are on 7418b3d under run-key.sb, in debug unless marked.
- ssh_stack_wipe's four tests are ok. Ed25519 seed: live 1, after drop 0. ECDSA d big-endian: live 1, after drop 0; little-endian: 0 and 0. The release build gives the same.
- The worker test is ok: Ed25519 `[1]`, ECDSA `[1, 0]`, debug and release.
- larsal-ffi's four `..._leaves_no_copy_after_new_ssh_key` tests are ok: `[0]` or `[0, 0]` after the call, and the E9 parse control reads 1.
- Mutant MB (the Box removed, the key held by value again) turns all eight calling-thread tests red in debug. In release it turns ssh_stack_wipe's four red (live 4, after drop 3), and the worker test stays green, as C2R3-F1 says.
- Mutant MW (the worker runs the key maker without the stack wipe) turns the worker test red: in debug through P-256 (`[2, 0]` where the key holds `[1, 0]`), in release through Ed25519 (`[2]` where it holds `[1]`).

**Random source** (INT-06.E24.02, lead ruling (4); 32866f2 changed its feature line). `e24_s02_c1_a_failed_random_source_makes_no_key_and_saves_nothing` is ok in the run and in Verify's rerun.
- Mutant MA, in which the test seam is ignored, turns it red at ssh_new.rs:590: Ok(NewSshKeyView…) where Err(Refused("Key not saved. The system random source failed.")) was expected.
- Mutant MF drops test-random from 32866f2's merged line. The test build then fails: `error[E0425]: cannot find function test_os_source_down` at ssh_new.rs:567 and :587.
- `cargo tree --offline --locked` (proof/features.txt): the product builds of larsal-ffi, larsal-cli and larsal-sshagent turn on larsal-crypto's "default" only. larsal-ffi's test build adds "test-kem-secret" and "test-random".

**RSA** (the rsa High row, F-742; 7418b3d added its program row). rsa_wipe's main test is ok in the run (part A) and in Verify's rerun (4.9 s). Blocks freed while one RSA 3072 key is made, outside the zeroing allocator: p 16, q 8, d 3, dp 1, dq 1, qinv 19, qinv Montgomery 20, all in limb order; 0 inside it. OpenSshKey and NewSshKey drop with (0, 0) for every marker and for the key text.
- The ignored control, run with `--ignored`, is red as designed: "blocks freed with a copy: ["p LE: 1", "q LE: 1", "qinv Montgomery LE: 1"]". The residual class is real.
- Mutant MZ (Zeroing::dealloc hands blocks back unwiped) turns the main test red at rsa_wipe.rs:185: "p LE: a copy reached the system", (16, 1).

The other rows the story's tests carry (comment rules, collisions, the draft revision, the failed save, Copy Public Key) are ok in the run. Their mutants are the builder's (round 2 Q1 to Q13, round 1 R1 to R20) and the Checkers' (M1, M5, B, W, Z). Verify did not repeat them, because no later commit changes those rows.

## Verify's own runs

Private clone of the project at 7418b3d; the private copy `mut` is a `--no-hardlinks` clone at 7418b3d. Every build ran under compile.sb and every test under run-key.sb, from the e16s7b-build profiles with only the root paths changed (`compile.sb` `520d3669…`, `run-key.sb` `115f1545…`; swapping the old root back gives the source files byte for byte). Cargo ran offline and `--locked`, with 3 jobs and an empty CARGO_HOME. Each heavy step started only when neither BUSY-native nor HOLD-native-quiet existed (proof/marks-wait.log): the first wait took 30 s at 08:36, and every later one was clear at once. Power: AC with powermode 0 throughout, except the rsa control build and run at 09:01:55 to 09:02:35, which ran on battery with powermode 2. One harness change, H0, made the own_agent rerun possible: its socket folder moved from /tmp to the run root, `crates/larsal-sshagent/tests/common/mod.rs:62` (proof/h0-harness-relocation.diff). Every mutant applied only on top of H0, and H0 was undone at the end, so `mut` equals 7418b3d.

| Run | Result |
|---|---|
| Controls, debug (08:37 to 08:40) | Build 7418b3d (larsal-crypto, larsal-ffi, larsal-sshagent test programs). c-seam ok; c-stack-crypto 4 ok; c-worker ok; c-stack-ffi 4 ok; c-save ok; c-keygen ok for 6 kinds; c-signin red at :2258 only (limit 2) |
| Mutants, debug (08:41 to 08:46) | MA red (7 s build); MB red, crypto 4 of 4 and ffi 4 of 4 (42 s); MW red (35 s); MV red, keygen and sign-in tests (12 s); MS red (30 s); MF does not build (51 s). After each, restore: the files equal 7418b3d's blobs, and the tree differs only in H0 |
| Restored rebuild (25 s) | All six controls green again |
| Release (lto, codegen-units 1), 08:49 to 08:50 and 09:02 to 09:05 | Control: ssh_stack_wipe 4 ok, worker ok. MB: the four calling-thread tests red, the worker test green. MW: the worker test red (Ed25519 `[2]`) |
| RSA (09:01 to 09:02) | rsa_wipe main test ok; the ignored control red as designed; MZ red at :185 |
| Probe experiments, V-1 (09:03, 09:12) | Source at 7418b3d with the memory probe of 91a7377 (crates/larsal-platform/src/macos/memory.rs blob `96f09a9c`, the probe both round 3 Checkers used). With MW, the worker test reads Ed25519 `[3]`, where 7418b3d's own probe reads `[1]`. With MB in debug, the calling-thread tests read live 4 and after drop 3, where 7418b3d's probe reads live 2 and after drop 1. Restored after each |
| Leftovers | The larsal-ffi tests left 15 demo vault folders in Verify's run TMPDIR, and the MS mutant left its demo .pub output. Verify removed all of it. The MS logs held the text of the demo RSA private key the test made; Verify removed that text and kept its length. No process of Verify's is left |

## The open and carried rows

| Row | Severity | Judgement |
|---|---|---|
| C2R2-F1, the made key's stack copies (round 3 Medium row, F-734) | Medium | Closed by round 3 (ab32ede): proven above, with MB red in each build |
| C2R2-F2, no test guarded the worker's wipe (round 3 Low row, F-735) | Low | Closed (c8a2dc8): MW is red in the worker test in each build. The row's words take C2R3-F1's fix: MB turns all nine red in debug, and the eight calling-thread tests red in release |
| The rsa High row (rounds 2 and 3; F-742) and its Info row (key generation's temporaries; F-743) | High | The lead's ruling holds: LD-133's residual class. In every shipped binary that makes or opens a key, the zeroing allocator wipes the blocks: larsal-ffi src/lib.rs:54-56 and larsal-cli src/main.rs:29-31; larsal-bridge has larsal-crypto only as a dev-dependency. RUSTSEC-2023-0071 stays ignored in deny.toml:27 and in check.sh's audit (:219-220; routes.json moved by 7418b3d). C2R3-F4 joins the row: larsal-server links rsa (larsal-server → larsal-crypto → ssh-key → rsa) with no allocator and makes no RSA value, because it has no SSH code. Any story that brings SSH key code into another binary installs Zeroing there or reopens the row. Not blocking |
| C1R3-F1: ECDSA d written as a non-minimal mpint (vendor/ssh-key/src/private/ecdsa.rs:40-41, :82-96; F-763) | Low | Real: about 1 in 4 P-521 keys and 1 in 512 P-256 or P-384 keys are affected. RFC 4251 section 5 forbids the extra byte, yet ssh-keygen reads such keys (C1's FIFO test), so checks 1 and 2 hold. It reaches the agent add message too, for every ECDSA key. The fix is in the LD-209 copy under vendor/, so it is carried to E24-S7 (lead's ruling). Not blocking |
| C1R3-F2: the P-384 Box carries stale partial copies of d in release (crates/larsal-crypto/src/ssh.rs:71; F-745) | Low | Real: the 416 B block holds bytes [0..16] and [0..8] of d. LD-133 wipes it at drop (0 after the wipe in 5 of 5 rounds). The same class as the Hasher row (F-744). A findings row next to it |
| C1R3-F3: ruling (9)'s type list | Low | Wording: SshKey (key.rs:39), EntryKey (entry.rs:96-104) and Step (entry.rs:337-344) hold an OpenSshKey by value. Added to the ruling (9) LD row (LD-706); no API change |
| C1R3-F4: no ssh_stack_wipe program row (F-764) | Info | Closed by 7418b3d (programs.json:418); the run of record ran the program under harness-runtime-base.sb |
| C1R3-F5: the new stack tests leave out RSA (F-765) | Info | Sound: RSA's private values are heap Mpints, which the Box does not change, and rsa_wipe covers them. No change |
| C2R3-F2: copies_in_memory could fault when a region went away during its scan (F-766) | Info | Real for the probe at 91a7377. m22's 9800dfd (F-439), an ancestor of 7418b3d, reads through `mach_vm_read_overwrite` as C2 suggested (3 uses at 7418b3d); F-701 stays the probe's open row. Checker 2's three crash reports (demo keys only) stay in the owner's DiagnosticReports; the lead decides whether to remove them |
| C2R3-F3: one RSA base64 copy after drop with the system allocator alone (F-767) | Info | The probe's own needle builder, not Larsal: no action |
| V-1: the memory probe counts fewer dead copies on the counting thread's own stack in debug (F-768) | Low | Real, and m22's (9800dfd), not E24-S2's: with the same source and the same mutant, 91a7377's probe sees 4/3 (MB) and `[3]` (MW), and 7418b3d's sees 2/1 and `[1]`. In release, 7418b3d's probe reads MB 4/3, as the builder's round 3 counts with the old probe did in both builds. Every E24-S2 mutant is still red in each build, so the story's guards hold, but with less margin in the debug lane the guarded tool runs. One possible cause, not proven: the new probe's own frames reach deeper and overwrite dead frames below the caller before the read. To the next change of the memory probe, with F-701. Not blocking |
| V-2: no guarded release lane runs a rule 4 test (F-769) | Info | Real: the release lanes run seven programs, none of them E24-S2's, and these tests' results depend on the build (MB leaves the worker test green in release; V-1 changes the debug counts). To the next tool round: add ssh_stack_wipe and the larsal-ffi stack tests to a release lane. Not blocking |
| V-3: the larsal-ffi tests leave their demo vault folders (F-770) | Info | Real: `personal()` in crates/larsal-ffi/src/edit/ssh_new.rs (:295-305) copies the Personal demo vault to `larsal-ffi-<tag>-<pid>` in TMPDIR, and no test removes the folder. Verify's runs left 15 such folders; Verify removed them. Demo data only, and the guarded tool's TMPDIR is under its own root. To the next story that edits those tests. Not blocking |
| The builder's open rows | Low and Info | AT-J01 (check.sh's audit and the route table; F-757): closed by 7418b3d. The four AT-J03 rows (F-753 to F-756): both round 3 Checkers matched the figures; the lead's written approval goes with the records commit. The crypto-bigint 0.7.10 cut (F-758): read by Checker 2 (C2R2-F7, F-739). The anonymous-pipe row (F-759): closed by card item 1. Round 1's Swift mutant row (F-760): closed by round 2's guarded native run 1. Carried as written: the Making your SSH key panel's accessibility value (Low, F-748), the Hasher row (Low, F-744), the generic Save… and Open (Low, E24-S6; F-746), the comment-change rule (E24-S3; F-749), rsa rc.19 to rc.22 (the story that next moves rsa; F-738), the audit profile and stale-mark wording (the lead; F-741, F-761) |

Nothing Critical or High is open for a shipped binary. None of these rows blocks the story.

## Limits of this signature

1. **The run of record is read, not rerun.** Verify's own runs cover the story's Rust tests on 7418b3d and the rows the later commits change.
2. **The sign-in step of check 2** is proven by the run of record only. Under Verify's run-key.sb the real sshd cannot start its own sandbox (gc_profiles.py:33-34), so Verify saw the test pass up to the agent listing, and MV red there. No mutant was seen red at the sign-in step itself; the builder's R20 stands.
3. **Frame parity is proven for presence and words only.** No reference image of the E24 proposal frames exists in the tree (design/option-a/proposals/ holds other sections only). Tokens, geometry and pixels need one drawn from proposals.html, which Verify does not render. The owner's one-pass review of proposals stays nonblocking (LD-268, LD-363).
4. **No Swift run by Verify** (never xcodebuild or swift). The Swift checks and rule 10's hidden launch rest on part B's native lane and its gate. The Swift mutants are the builder's S1 to S3, from its guarded native run 1.
5. **No story test runs in a release lane** of the guarded tool. Release evidence is Verify's release reruns (crypto stack and worker, with MB and MW) and the round 3 builder's and Checkers' runs. The larsal-ffi stack tests were not rerun in release by Verify.
6. **cargo audit was not rerun** (no advisory copy in Verify's empty CARGO_HOME). The audit route's ignore is read from 7418b3d and from part A's static lane (advisories ok); the builder's audit-no-ignore.txt shows exit 1 without it.
7. **arm64 only**, offline. The run's own stated limits apply (yanked status, advisory date).

## Evidence

| What | SHA-256 |
|---|---|
| Round 3 fix.patch, round3.patch, e24s2-r3.bundle, source-seal.json | `e8ff386c5ab9d722d00a380a95aeb175ed55e76a07b271dd6e882d80988b9679`, `5f600ef70796fcd836029d2912caff3cb0df8c91f7ebdf79b73c3dca1943e742`, `2d5f3d5ca708eb4d4ce25f5cd6e917e968889ae2a085a37681ae72cf8666baee`, `bc01bd3b6ead34923cd8ee8f12aefbcf003c2d430a7e47d828c3c1dad3b2a18b` |
| Round 3 CANDIDATE-NOTES.md, NOTES.txt, proposed-cards.md, proposed-LD.md, proposed-findings.md | `c10eca835f6edc246eb9b13bb3a97ec8eac4b890d23a611b541d35ed544b514e`, `d07699c5b56faca1a1d0fba15552c644b276dbe4140a77839051968c9ec2908d`, `37e2b63f213f0f4a5ca1dcaefc99bf3bba3ef8780bf31336a670db9cd9f1dffe`, `78be000cddb2c73a781ddfeb7cdd5a24c574a4185507e80e56573eaf54e90441`, `3afb89092aab93b5c0e93d985780f4f4f5b82abd5d2a92439459b1d86a2bd52d` |
| Round 3 C1-REPORT.md, C2-REPORT.md, c1-result.json, c2-result.json | `8f6a6e83d2de5663ebbfb4488d3390f129182bbeebf9a1c263858da2e7ab7e49`, `05eeb06060744be7984c0aa318057e14243641ce5bcbc9b961b9bf8e1aab144c`, `998503e90fd55a717d2e1bfeab585b38c55c0b056431e0fd16238f286de0c345`, `d3a1774e6485c3a66ae7ef5b47f0bce273731625fa2aff57a86aa6b047d665ca` |
| Part A summary.txt, summary.json, test-names.json, run.json | `646402b215d792e0bc7c99b606ea314295a16f4c5d45515bc8119d11f83b604e`, `4417a038b0b5a1bfac54558b093bb82960b1bcface0f72f9a3aeb7d93edca56f`, `b1f4c60c1afcad43a006eff0093126b5964169f9763a4dde124fb21f6752cae1`, `f4861d017dd1c6fe3a1c9debca993773b1710fce6fff8600e993f568aec4662b` |
| Part B summary.txt, summary.json, test-names.json, run.json, results/native.json | `039111c2923f6d243ff442a8bc9448af170c5ae2f9b85ee4451c22491dcfa45e`, `c2748f67264f04c3cd2151b07245c784687828fe2b6d5dd87a071494f503c2d4`, `984c3c3f2f1fe97733ae3b2f2eeb7ad96413c65d640c6d01b178a52a57b00faa`, `d0eee714a0c443b2b1b4f808f5b401b5f8057b6432456909250d17f6e0393f29`, `1c270ed431bdb88c0e8c8f4ec1b94bcf118fea7e56acc3dfd09c417c6ae1dbf0` |
| Baseline f52befe test-names, waivers-m23.json, lead-notes.md | `8113610bd887ebe5604bdc79739b4f10997d9bf3839b11d482296834d24de041`, `a99f9caabde2186d8a4893a6df746a282b629d7bfe895cb8421613b2e6fe383c`, `056245c6237ebdd8abe09e3f68aab33dd805983c37096ee916c1ad06a4c88768` |
| Verify's profiles compile.sb, run-key.sb | `520d3669824be14ca5583b7bd554744718df0dd454cbe28524727cd577932805`, `115f1545c13dca6a77ad5c58a5441f4bc558f321bfef5463ff32618aa2cbbfd8` |
| Verify's proof: every log, the 24 frame files and the scripts | proof/EVIDENCE-SHA256.txt (its own hash is in FINAL-SEAL.json) |
| Verify's seal | `/private/tmp/larsal-m23v-e24-Fc2ojThj/FINAL-SEAL.json`; copy in builds/e24s2-verify/ |

## Report end

- Story: E24-S2. Verdict: signed with limits at 7418b3d (candidate-m23).
- Files changed by Verify: none in the project. This page is proposed for `security/parity/E24-S2-new-ssh-keys.md`; the board line, card edits, LD rows and findings rows are in E24-S2-proposed-rows.md.
- Open: V-1 (Low, the memory probe's next change), C1R3-F1 (Low, E24-S7), C1R3-F2 and the Hasher row (Low, LD-133's class), V-2 and V-3 (Info), and the carried rows above. Nothing Critical or High is open for a shipped binary.
- Next step: the lead's records commit (this page, the rows, Status Done), then E24-S3.
