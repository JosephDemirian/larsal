# E22-S5 `larsal encrypt` and `larsal decrypt`: Verify sign-off

Story: E22-S5 (plan/epics.md). Cards: FIL-02 (FIL-02.18 to FIL-02.22, T17 to T22, T24), FIL-03 (FIL-03.2, .7 to .11, .13, .14), FIL-01.7, with INT-10. Decisions: the lead's E22-S5 rulings of rounds 1 to 3, LD-340. Checkers: C1 and Sensitive C2, three rounds.
Date: 2026-11-09.
Role: Verify, in two passes. The first pass refused c2ed5dc (V-1: `cargo deny` bans failed on larsal-cli's path entry for larsal-files; V-2: `--identity-entry` did not read the app's "File key"). Round 3 fixed both, C1R2-01 and V-4. This second pass proves the commit that landed, `f52befe27a18dd119343cf493f09c15b76a78ada`, from a private clone: the carried patch, the tables, the lead's full guarded run of record, its own runs of fil02 and int10 under the repo's cli-runtime.sb, `cargo deny` on a fresh clone, the Mac app's own code path (larsal-ffi's files bridge) against the built `larsal` in both directions, and probes of the arguments, the environment and a planted FIFO. It changed no project file, made no commit and ran no xcodebuild, swift, swift-format or SwiftLint. The logs named here live in private folders under /private/tmp that do not last, so this page copies what must survive; durable copies are in the lead's checkpoint folder builds/e22s5-verify-r3/.

**Result: signed with limits.** Commit `f52befe27a18dd119343cf493f09c15b76a78ada` on Main `b6eaf1731ea8bdccc285b8851a868c2dd5e0612c`, two commits: fb49182 (the story) and f52befe (its guarded tables). The guarded run of f52befe reads **Overall PASS**: Rust 5072 passed and 0 failed, fil02 27 of 27 (1 ignored, run by hand), int10 141, Swift 488 of 488, APP-09 18, docs 18, fuzz 32 routes, 0 names lost, 2897.9 s of the 60-minute cap. Both story checks hold. Check 1 is proven through larsal-ffi's files bridge, the Rust code the Mac app's screens call, not through the Swift screens (limit 1).

## The whole difference

| Item | Result |
|---|---|
| Base | Main `b6eaf1731ea8bdccc285b8851a868c2dd5e0612c` (E11-S6, E22-S4 and E7-S7d records on e2c32e1). `git diff e2c32e1..b6eaf17 -- crates Cargo.toml Cargo.lock` is empty, and e2c32e1 is an ancestor of b6eaf17 |
| Commits | `fb491828e392d5f7db53f5d63b6fa472c9271eb3` (the story), `f52befe27a18dd119343cf493f09c15b76a78ada` (guarded tables). Each has author and committer Joseph Demirian <hello@JosephDemirian.com> |
| The reviewed patch | Round 3 fix.patch, SHA-256 `bc43f0c0c94905ef284b404f3268625bf52db6e13ba04c4f0eee7102ced72023`, approved by both round 3 Checkers (APPROVE_EXACT_CANDIDATE). `git apply --cached` on a temporary index of e2c32e1074b74758920ff14196306ccfb3340ca6 writes tree `57e936af4d1654f89b467163ca92abacca9347d3`, the approved tree |
| Carried onto Main | `git diff --binary b6eaf17 fb49182` and `git diff --binary e2c32e1 57e936af` both hash to `bc43f0c0…` (the fix.patch itself). Path by path, the same 10 paths: Cargo.lock, crates/larsal-cli/Cargo.toml, src/args.rs, src/files.rs, src/main.rs, src/shell.rs, src/term.rs, tests/data/weak-key-file.age, tests/fil02.rs, tests/int10.rs; each has the same blob before (e2c32e1 = b6eaf17) and after (57e936af = fb49182). No union |
| The tables commit | f52befe changes only `scripts/guarded/tables/pins.json` and `programs.json`. `reviewed_commit` becomes fb49182, a new `reviews."E22-S5"`; two pins move: `workspace:larsal-cli/int10` `crates/larsal-cli` to `8b272f58b0291a165408985aea9617287ba7baeb`, `workspace:larsal-sshagent/own_agent` `Cargo.lock` to `eee89e280dfacc948a9f8ae4d946fef744fbd0b2` (both rows relabelled E22-S5); the new row `workspace:larsal-cli/fil02` pins `crates/larsal-cli` `8b272f58…`, `crates/larsal-files` `91bec9d37378894c3e52560956af0adfc22c1f75` and `crates/larsal-ffi` `40622cbfaafb86b2f459a112da67262564566353`. Each equals the git object at fb49182; all 151 pins of the table equal their object at f52befe (0 stale) |
| The fil02 grant | programs.json `"workspace:larsal-cli/fil02": {"classes": [], "profile": "cli-runtime.sb"}`, the same classes and profile as int10's row; checks no-nsapplication, no-owner-tty, no-pbcopy, equal to int10's. No wider |
| What the story touches | crates/larsal-cli and one Cargo.lock line pair (larsal-files and the test-only larsal-ffi in larsal-cli's list). No other crate, no path under macos/, spec/, plan/ or scripts/ besides the two tables |

## The run of record: f52befe

Started by the lead at 16:26:19 from its tool copy /private/tmp/larsal-m15-GtHZ/c with the baseline of b5bfaca and no waiver file; root /private/tmp/larsal-gc-f52befe-srvS; `summary.txt` written at 17:16:07. Verify read it and did not rerun it.

| Item | Result |
|---|---|
| Overall | **PASS**, not partial, 0 failure lines. `summary.txt` SHA-256 `5ed26dd3e88c43731b2a5bb05045bf7ea3335771c1f4c94e12b225f48bc129ad` |
| Time | 2897.9 s of the owner's 3600 s cap; the 90.0 s hold wait is outside it (the tool's `--hold` rule); start to summary 2988 s |
| Commit, tree, tool, tables | Commit f52befe in run-start.json, summary.json and test-names.json; tree `eef50b288e2a0ac95eea9b4d39e4a69310c398d9`, this commit's. All 23 `tool_sha256` equal `scripts/guarded` at f52befe (0 differ). The tool copy's tables equal the commit's: pins.json `5a7ccac8…`, programs.json `c31d92b5…`, routes.json `8f341935…`, needs.json `a02932df…`, native-expected.txt `f1d8b15d…`. Custody 0 changed, 19 executables, 23 tool files; tool drift none. Grants 60 rows read, 0 withheld |
| Static | 18 of 18 steps. Names PASS (12372 files, 19 vault files name only). Unsafe 512 in 21 crates. Advisories, **bans**, licenses and sources ok (V-1 fixed) |
| Rust | 5072 passed, 0 failed, 132 ignored, 178 of 178 programs: workspace 4015/0/110 (152), sync 650/0/15 (17), net 74/0/7 (2), release 288/0/0 (6), release-browser 45/0/0 (1); every lane reconciles PASS; guard library requests 0 |
| fil02 (`workspace:larsal-cli/fil02`, cli-runtime.sb) | 27 ok, 1 ignored. ok: e22s5_check1_app_path_round_trip_after_e22s4, e22s5_check1_fil02_t24_fil03_t18_library_files_open_with_larsal_decrypt, e22s5_check1_fil03_t18_larsal_encrypt_files_open_in_the_library, fil02_t17_two_processes_one_output_name_one_owner, fil02_t18_fil02_t19_a_passphrase_in_the_arguments_is_refused_and_never_printed, fil02_t18_generate_saves_first_then_encrypts, fil02_t18_no_parse_error_repeats_a_word_the_user_typed, fil02_t18_usage_errors_come_before_any_work, fil02_t19_an_encrypted_key_file_asks_for_its_own_passphrase_pty, fil02_t19_every_prompt_ignores_quiet_pty, fil02_t19_fil01_t07_a_weak_chosen_passphrase_needs_a_yes_pty, fil02_t19_no_secret_from_the_environment_only_tmpdir_is_read, fil02_t19_passphrase_and_key_from_vault_entries, fil02_t19_passphrase_file_bytes_exactly, fil02_t19_terminal_prompt_twice_without_echo_pty, fil02_t20_standard_input_carries_data_or_a_secret_never_both, fil02_t21_each_quit_signal_at_the_prompt_restores_echo_pty, fil02_t21_fil03_t02_a_declined_low_work_factor_is_a_handled_cancel, fil02_t21_fil03_t02_a_weak_key_file_asks_before_saving_pty, fil02_t21_fil03_t07_each_quit_signal_during_the_work_leaves_nothing_pty, fil02_t21_fil03_t08_fil03_t13_fil03_t14_own_words_and_exit_codes, fil02_t21_fil03_t10_broken_stderr_and_a_failing_destination_fail, fil02_t21_fil03_t11_a_crash_leftover_is_swept_at_the_next_start, fil02_t21_fil03_t11_a_fifo_or_link_of_the_scratch_form_is_never_opened, fil02_t22_fil03_t21_each_success_says_its_limits, fil02_t24_published_files_from_another_tool_open_with_larsal_decrypt, int10_45_encrypt_and_decrypt_are_not_shell_commands. Ignored: e22s5_ruling5_four_gib_round_trip_through_the_command_line (by hand, below) |
| int10 (`workspace:larsal-cli/int10`, cli-runtime.sb) | 141 ok, 1 ignored (`qr::qr_t29_b_child`, run only as its parent's child); the clipboard cases are among the ok |
| larsal-files | `workspace:larsal-files/larsal_files` 126 ok, with its 11 single-test programs in the workspace lane |
| Swift | Log: 488 tests in 74 suites passed. Bundle: 488 passed, 0 failed, 0 skipped. Database: 488 cases, 645 runs, 488 ok |
| APP-09 | 18 passed, 0 failed |
| Docs | 18 passed, 0 failed, 23 result lines |
| Fuzz | 32 routes, all exit zero, fewest runs 1172, no new route |
| Baseline | b5bfaca's test-names (SHA-256 `aaf13a2228695564c0c13176f86dc65db3b8f4db135c5ef316fd552bc387a6b0`): 5700 compared, **0 lost**, 0 newly ignored, 0 waived, no waiver file, 28 new names, all fil02's. test-names.json holds 5728 names: 5596 ok, 132 ignored, 0 failed |
| Crash reports | none new; on purpose none; own and not on purpose none |
| Limit the run states | Yanked status not proven for 11 crates (offline index); advisories 1395, newest 2026-10-30 |

Against the refused run of c2ed5dc: Rust 5070 to 5072 passed and 133 to 132 ignored (the app path test now runs; the FIFO test is new); static bans FAILED to ok.

## The story's checks

| # | Check (plan/epics.md, E22-S5) | Proof | Result |
|---|---|---|---|
| 1a | A file made by the Mac app opens with `larsal decrypt`, by passphrase | Run of record: e22s5_check1_app_path_round_trip_after_e22s4 ok (it calls the bridge's `Session::encrypt_file_passphrase` on a copy of the demo vault option-a-personal, then the built `larsal decrypt --passphrase-file`, byte for byte); format level e22s5_check1_fil02_t24_fil03_t18_library_files_open_with_larsal_decrypt ok. Verify's own run (`app-path.log`, the first pass's private test `verify_e22s5_1_app_path_makes_files_for_the_command_line` applied to a private copy and removed after): `larsal decrypt app-pass.age --passphrase-file pass.txt` exit 0, byte for byte equal | Verified |
| 1b | A file made by the Mac app opens with `larsal decrypt`, by the app's own file key | The bridge's `create_file_key` saves a file key entry ("File key" field), `encrypt_file_recipients` encrypts to it. In the run: e22s5_check1_app_path_round_trip_after_e22s4 ok (`--identity-entry` with `--vault`). Verify's own run, the same steps as the first pass's refusal: `larsal decrypt app-key.age --identity-entry <that entry> --vault Demo.larsalvault` exit 0, byte for byte equal (it was exit 1, MSG-FILE-DECRYPT at c2ed5dc). Mutant R01 (Password only) turns the test red (round 3 TABLE.md) | Verified (V-2 closed) |
| 1c | The other way round | `larsal encrypt` makes cli-pass.age (`--passphrase-file`) and cli-key.age (`--recipient`, the app key's public recipient); the first pass's private test `verify_e22s5_2_command_line_files_open_through_the_app_path` opens both with `Session::decrypt_file` (a typed passphrase; `FileCredential::Entry` of the app's key), byte for byte ("step 2: both files open through the bridge"). In the run: the committed app path test does the same, and e22s5_check1_fil03_t18_larsal_encrypt_files_open_in_the_library ok | Verified |
| 2 | A passphrase is never taken from the command line itself (only a prompt, a file or the vault) | Parser (`crates/larsal-cli/src/args.rs`, FILE_SECRET): `--passphrase` is a flag; every value option names FILE, ENTRY, VAULT, GROUP, TITLE or KEY. In the run: fil02_t18_fil02_t19_a_passphrase_in_the_arguments_is_refused_and_never_printed, fil02_t18_no_parse_error_repeats_a_word_the_user_typed, fil02_t19_no_secret_from_the_environment_only_tmpdir_is_read ok. Verify's own probe (`probe.log`, demo secret S): `encrypt --passphrase=S`, `-p S`, `--passphrase S`, `decrypt --passphrase=S`, `-p S`, `--pass=S`, `--key=S`, an extra argument, `--identity-entry S` without --vault: exit 2 each; `larsal --passphrase=S encrypt`: exit 1. None prompts, none makes output, S never printed. LARSAL_PASSPHRASE, LARSAL_PASSWORD, PASSPHRASE, AGE_PASSPHRASE, LARSAL_MASTER_PASSWORD, PASSWORD set to S: `--passphrase` without a terminal exit 1 with its own words, no credential option exit 2, no output. larsal-cli/src reads the environment only through `temp_dir` (TMPDIR), LARSAL_TEST_SELF_TEST_FAIL (debug builds) and LARSAL_TEST_PASTEBOARD (the clip command's test board) | Verified |
| Carried | Whichever story calls larsal-files first closes F-340, F-341 and F-342 | E22-S4 did (Done, its Verify signed; the three rows read "closed 2026-11-09 by E22-S4" on Main). The command line calls the same larsal-files functions; larsal-files' 126 tests pass in the run. fil02_t21_fil03_t07_each_quit_signal_during_the_work_leaves_nothing_pty now also asserts no `.larsal-staging-` folder (V-4; mutant R06 red). The first pass's staging probe (18 SIGTERM or SIGHUP runs in encrypt's write, decrypt's check and save) left nothing; round 3 C1's signal probes (64 and 24 runs, TERM, HUP, INT, QUIT) left nothing | Holds on the command line paths. F-341's full disk is proven only by larsal-files' own tests |

The lead's rulings, checked: round 1, larsal-cli only (holds: the 10 paths above); the app round trip at format level (exceeded: proven through the app's bridge too); no passphrase from argv or environment (check 2); no partial output and the echo restored on signals (fil02_t21_each_quit_signal_at_the_prompt_restores_echo_pty and fil02_t21_fil03_t07 ok in the run; round 3 C2's echo probe: INT, TERM, HUP, QUIT at a prompt end by 128+N with echo on); a 4 GiB round trip (below). Round 3: V-1 (`larsal-files = { workspace = true }`, `crates/larsal-cli/Cargo.toml:23`), V-2, C1R2-01, V-4, Y24 and Y41 as above and in the rows.

## Verify's own runs

Private clone `file:///Users/josephilhan/Documents/Code/larsal`, candidate-m15 fetched, f52befe checked out (HEAD unchanged at the end, no file left changed). Built under compile.sb, cargo offline, `--locked`, 3 jobs, CARGO_HOME empty (the repo vendors every crate). Tests under the repo's own cli-runtime.sb, generated by `scripts/guarded/gc_profiles.py` for this root. Heavy steps started only once the run's `results/native.json` existed and neither BUSY-native nor HOLD-native-quiet was present (LD-568).

| Run | Result |
|---|---|
| `cargo deny --offline --locked check bans licenses sources` on the fresh clone | exit 0: bans ok, licenses ok, sources ok (V-1). Advisories are the run's (ok) |
| fil02 | 27 passed, 0 failed, 1 ignored, 58.2 s |
| int10 | 141 passed, 0 failed, 1 ignored, 75.5 s (the clipboard cases pass: cli-runtime.sb has the private pasteboard line) |
| The Mac app's path, both ways (check 1) | `app-path.log`: all four steps pass, as in the table above. The `larsal` binary run: SHA-256 `3867b3cfcf3f7eefd1c9004801bda491cc11b6e6433b6bd69c4815464ab694c6` (the test build fil02 uses) |
| Arguments and environment (check 2) | `probe.log` A and B, as above |
| C1R2-01 | `probe.log` C: a FIFO named `larsal-scratch-` + 32 `e` in TMPDIR: encrypt and decrypt each end in 1 s, exit 0, output made; a link to a FIFO at that name: exit 0. At c2ed5dc both still ran after 10 s. In the run: fil02_t21_fil03_t11_a_fifo_or_link_of_the_scratch_form_is_never_opened ok |
| SC2R2-01, seen again | `probe.log` D: stdout to a pipe whose reader is gone: exit 1, the readable 0600 file left equal to the source, one line "standard output or standard error could not be written."; stderr broken: exit 1, file left. Carried to E22-S6 |
| Leftovers | `larsal` left nothing in TMPDIR. The larsal-ffi test process left one empty `larsal-file-scratch-<pid>` folder (V-5, carried); removed, it was Verify's |
| 4 GiB (ruling 5) | Not rerun (shared disk). Round 3's Builder ran it on the approved head tree (57e936af, larsal-files with E22-S4's staging): encrypt 20.3 s, max RSS 287,424,512 bytes; decrypt 37.6 s, max RSS 280,281,088; "4 GiB: byte for byte equal"; 1 passed, 153 s; run/tmp empty after. Round 1's run agrees (17.8 s, 39.1 s, about 279 MB, equal) |

## The open and carried rows

| Row | Severity | Judgement |
|---|---|---|
| V-1, V-2 (with V-3), C1R2-01, V-4 | Medium, Medium, Medium, Low | Closed by round 3 (fb49182), each proven above and by a mutant that goes red (R07, R01, R02 and R03, R06) |
| C1R2-03 = SC2R2-02 (Y24, Y41) | Low | Closed: Y24 = R04 red; Y41 = R05 equivalent, accepted by both round 3 Checkers and by Verify (term::broken() is read only on the success path, which always writes the notes to the same stderr after any prompt) |
| SC2R2-01 | Low | Real, seen again. Not blocking: the file is the complete output the user asked for, 0600, and exit 1 is not success; the words should say it was saved. E22-S6 (lead's ruling) |
| C1R2-02 = SC2R2-03 | Low | Real, seen again ("no entry at <typed>."). E22-S6 (lead's ruling) |
| C1R2-04 | Info | Closed by the card edits in the records commit, which also amend INT-10.1 (3) and the exit code table's last sentence (Verify r3: both still said usage exits 1 and that Larsal never uses 2) |
| V-5 | Info | Real, seen again in Verify's own app-path run. The next story that edits larsal-ffi's files code (lead's ruling) |
| C1R3-01 | Info | Real test gap: no entry holds both a "File key" and a different Password, so K03 survives. Code right today. Not blocking. E22-S6 (one fil02_t19 case) |
| C1R3-02 | Info | Real: the live-run lock check in sweep_one is reached by no test (K04); it guards only the moment between a run's mkdir and its flock, as N05 and N06. Timing only; no row |
| C1R3-03 | Info | Agreed: K05 and K06 are equivalent for the command line (still_named refuses a link later; O_DIRECTORY alone refuses a FIFO without waiting on macOS; Verify's FIFO probe ends at once). No row |
| C1R3-04 | Info | Real: the app reads the same field but takes one key and reads a Password fallback as a passphrase (`crates/larsal-ffi/src/files.rs:1204-1211`); the command line reads a key list from either. Card and LD words corrected in the rows; the `keys_of` comment (`crates/larsal-cli/src/files.rs:325-327`) goes with the next larsal-cli edit, E22-S6 |
| C1R3-05 = C2R3-01 | Low | Real. sweep_one opens the name twice (open_dir, then larsal-files' `ScratchRoot::open`, a plain `File::open` at `crates/larsal-files/src/fsio.rs:174`); a swap between them can still make a start wait. With TMPDIR set to a shared sticky folder another local user can do it with their own entry, so round 3's LD words "only someone who can already rename this user's entries" were wrong; the rows state the right reach and add it as FIL-02.22's limit (8). Denial of service only, nothing read or written, narrow (C2's 360 same-user race runs: 0 hangs). Not blocking. The fix belongs in larsal-files: the next story that edits larsal-files |
| C1R3-06 | Info | Real and handled: the larsal-ffi dev-dependency unifies larsal-platform's `code-sign` into the test build of `larsal` (larsal-cli calls none of it; the product build's normal-edge tree is unchanged, round 3 tree-before = tree-after), and the fil02 pins row pins crates/larsal-ffi. Stated in the architecture words; no row |
| C2R3-02 | Info | Real test gap: no test keeps an entry's key text out of a parse error (mutant C2-02 survives); code right today (C2's badkey probe). E22-S6 |
| SC2R2-01, C1R2-02 carried; FIL-02.20 `encrypt -` | Info | The stream encrypt larsal-files lacks is a row for the next story that edits larsal-files; the command line refuses `encrypt -` with a usage error until then (FIL-02.20 allows it) |
| Builder's equivalents and timing mutants (N02, N05, N06, N14, N24, X04b, M24) | Info | Accepted as stated in round 3's TABLE.md (84 run, 76 killed, 8 survive with reasons). No rows |

None blocks this story.

## Limits of this signature

1. **Check 1 goes through larsal-ffi's Rust bridge**, the code the Swift screens call, not through the Swift screens themselves; the screens add argument passing, which E22-S4's own tests and Verify cover.
2. **The 4 GiB round trip** is the round 3 Builder's run on the approved tree, read from its log, not rerun by Verify (shared disk).
3. **F-341 (a full disk)** is not run on the command line; larsal-files' own tests cover it.
4. **Wiping** rests on code reading and larsal-files' wipe tests; no memory probe of the `larsal` process (N14).
5. **The sweep's double open** (C2R3-01) is a stated limit until larsal-files opens from the descriptor.
6. **Timing.** Verify's `cargo deny` and build (17:07:46 to 17:09:09) started when native.json existed and no flag was present, but overlapped the run's docs and fuzz lanes, which read PASS; fil02 and int10 ran after the run's summary.
7. **arm64 only**, offline. The run's own stated limits apply (yanked status, advisory date).
8. Verify's logs use the private test's entry title, which the name guard flags; it appears only in those private logs, never in this page.

## Evidence

| What | SHA-256 |
|---|---|
| Round 3 fix.patch, delta.patch, CANDIDATE-NOTES.md, proposed-cards.md, proposed-LD.md, proposed-findings.md, source-seal.json, NOTES.txt | `bc43f0c0c94905ef284b404f3268625bf52db6e13ba04c4f0eee7102ced72023`, `7fd258191ce59cca2c8cdad2d7facaa129ef7b613e95749e5106e05f5415c5cb`, `af733d64ae8ef8c8bdcc4755c8abcc9c5eb33be4d5c3d9d2af66134657ba2154`, `04fa178a54039e3c38e3559039cd6d5751078e77e058ebb8220da0c9ab28fc73`, `69d50ddb48e8b05bad18b4e939767cd41216a891f0b598ca1460b71ff98f86da`, `485f007fc9ffb0c5674306e8c4631241e727275e2c391234e61bd40b702b7abe`, `0ef268dd29da71500064a5c4563f1618aca804a192808b308e7095d644b0e9b6`, `d288e3bcb3a2b219b4499244fca4dd18d16e1e29679de4aea47a39d07654cfc0` |
| Round 3 C1-REPORT.md, C2-REPORT.md, workflow-result.json, proof/TABLE.md, proof/four-gib.log | `e829ffcead77a7fe995357f1924a0abbef08e9b2202d3910aa674822c53cbdae`, `ab4296dd95470f4d9d22285517c8164a7c2476c9ea5eb02966ca519dc452a6b1`, `9ce8d7a07e2c1c3442cd59a3cdc1a0324565530484b74f68825e9d6ba2e5d35a`, `7aeff78d05a20d9af7f8bad752e53bda8d747d9c7899cb2c8dee70531e852354`, `a8e0e2e4f44c4a5e935601e056b677395eccb7aa9b547112861be2112ed9a8a6` |
| First pass: REPORT.md, FINAL-SEAL.json, round 1 4 GiB run.log | `04762cbd001274bcd07e239009eb366683d675d6d32dcd1ebe129277f8ab64ab`, `e4cf2511512184d90fc650fa4f4398f38cdf16893bb2903faa1c87df64ddd759`, `be68b1bcde48076bc4ad11df3afc83b7818fc15b52e045f031b576e9c6b10b6f` |
| Run of record `summary.txt`, `summary.json`, `test-names.json`, `run-start.json`, `run.json` | `5ed26dd3e88c43731b2a5bb05045bf7ea3335771c1f4c94e12b225f48bc129ad`, `5fa0d7e015bfdbfaca550d8a37617c0c04c5180dbe35b20bfba9acef3c86bb19`, `8113610bd887ebe5604bdc79739b4f10997d9bf3839b11d482296834d24de041`, `73d6988e25673aa754ee91d76d255d569c2e574bbdab3af4dfd49612227d1870`, `db10c92682e3d9309e84487457d8124db8c259b23c2468855193398b444562d9` |
| Run `results/` static, rust, native, docs, fuzz, source | `5ac559b978a4b36b1490c8cce4f538aff673d3359b620a4c079d4ccf7879357c`, `7d2f19d5f6255973cbb987cb0ef95335f4c559fc09ec8d130775719b46cb01ef`, `c05a40e127eaa375907789ee48d5e475e8bdb99a9d089c640fb1230a92c08388`, `15b21dc6cbc86d7da58f9f9864f84d2feaf97476215208884ff5d546b866e360`, `160c23390c28f4dbcde944e3b07890afecf42137bf7bc0dc9ac604d8e5e2e051`, `b6338475863f8a8c631108f0248efb67b78461ce3263592845b188d033a93f69` |
| Baseline b5bfaca test-names | `aaf13a2228695564c0c13176f86dc65db3b8f4db135c5ef316fd552bc387a6b0` |
| Verify's deny.log, build.log, fil02.log, int10.log, app-path.log, probe.log, build-ffi.log, holds.log | `4646f4bfa3c7988e6a592abbc1803ff5ab6d821803b6cbb7795aa6d889cc025e`, `be748b8dd388f89df2fc67687ec9492cd5c492e44bf9e3da8d0360e33f1ebe15`, `c6c07f00102d55b04abd0b9a79a9034d2d293ed4515ff6b7cee67225825ba2cf`, `b2c486dc72eaaca4cfff909eb202ac60ef7c8a69757b0b60e18bd2fe345fc3c0`, `0effa90d1e13e93de5a65e99c6f7486e91b576f0c9bde62949235401f3645ccb`, `5cc355726bc1b01bc33851d938e9e6cf7402faab23095b932a23b79a4db6b342`, `36357a09260221176cdbf21d725b65b1d37f2b579ba8a1f6bff665426a3e6a9c`, `554d54cfa91b0efad70edc3ac2c6bf55203a2ad1e7334a920f8c7d6a2a83396a` |
| The `larsal` binary Verify ran | `3867b3cfcf3f7eefd1c9004801bda491cc11b6e6433b6bd69c4815464ab694c6` |
| Verify's seal | `/private/tmp/larsal-e22s5-vr3-NHLQpRXq/FINAL-SEAL.json`; copy in builds/e22s5-verify-r3/ |

## Report end

- Story: E22-S5. Verdict: signed with limits at f52befe.
- Files changed by Verify: none in the project. This page is proposed for `security/parity/E22-S5-file-encryption-cli.md`.
- Proof: this page; the run of record at /private/tmp/larsal-gc-f52befe-srvS (Overall PASS, Rust 5072/0, fil02 27, int10 141, Swift 488, APP-09 18, docs 18, fuzz 32, 0 lost, 2897.9 s); Verify's runs above.
- Open: SC2R2-01, C1R2-02, C1R3-01, C2R3-02, the keys_of comment (E22-S6); C2R3-01 = C1R3-05 and the stream encrypt (next larsal-files story); V-5 (next larsal-ffi files story).
- Next step: the lead puts this page at `security/parity/E22-S5-file-encryption-cli.md` and, in the same records commit, sets E22-S5's status and carried lines, applies the card edits, adds the LD and findings rows, and runs the name guard.
