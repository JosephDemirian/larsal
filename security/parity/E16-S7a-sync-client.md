# E16-S7a Sync client: Verify sign-off

Story: E16-S7a (plan/epics.md). Cards: SYN-01, SYN-03, SYN-04. Earlier refusal: Verify V2, finding V2-1 (F-299).
Date: 2026-11-06.
Role: Verify. I ran probes and mutants in a private copy of the tree. I changed no product code. The logs and scripts named here lived in private folders under /private/tmp that do not last, so this page copies what must survive.

**Result: signed with limits.** Commit `2a0392c684aaa6cebe4c33311e7c1a2a42bbe738`, three commits on f831ef2: 358bce8 (the fix), 9ce5562 (the words), 2a0392c (the tables). All 7 story checks and all 4 amendments pass under the guarded tool, and V2-1 is closed. Sync stays off in the app build.

Two things stay open by design and block turning sync on:

- A server can test password guesses against the server copy of a password-only vault, until E16-S7b adds the key-file part.
- Field 12 (public custom data) goes to the server in clear, and it can hold text a user typed. E16-S7b does not change this. The lead rules, or FMT-03.22 changes.

## The run

The guarded tool ran the full check of this commit once. I read its results and did not rerun it.

| Item | Result |
|---|---|
| Overall | PASS, 2281.8 s |
| Commit and tree | Run commit is this commit. Run tree equals the commit's tree, c36e93848e1aef3d323dc0811f22d96bc38ca873 |
| Tool | 23 files, none differs from the commit's `scripts/guarded`, and the run's own copy holds the same bytes |
| Tables | `pins.json` 1b31a3b45b9188909897f77b4d56f9c3b26f41d34eb4ab4c29a3ca4cc15e82a0 and `routes.json` 12875b4e2a9a0c020cee75da4ecd036b9e984e3448423289e114811d8446e918, both equal to this commit |
| `scripts/check.sh` | 04ebc025ea433f09b5b6e8d817947c647adee106d732f3a9b07e0eddd6479ade, equal to `routes.json` |
| Grants | 55 read, 0 withheld. Reviewed commit 9ce5562; the only commit after it changes the two tables alone |
| Custody | 0 changed, 19 executables, no sentinel changed, no source changed, nothing left under the root, no alarm |
| Lanes | source exit 0; static exit 0, 438.1 s; rust exit 0, 825.9 s; native exit 0, 515.5 s; docs exit 0, 168.8 s; fuzz exit 0, 326.2 s |
| Static | 18 of 18 steps. Names PASS, 11833 files, 19 vault files by name only. Unsafe count 425 in 18 crates. Advisories, bans, licenses and sources ok |
| Rust | 4124 passed, 0 failed, 88 ignored, 143 of 143 programs. Workspace 3219/0/72 (119 programs), sync 518/0/9 (15), net 67/0/7 (2), release 275/0/0 (6), release-browser 45/0/0 (1). Guard library requests 0 in all lanes |
| Swift | 399 tests in 57 suites passed, 0 failed, 0 skipped. The APP-09 lane: 18 passed |
| Docs | 9 passed, 0 failed |
| Fuzz | 29 routes, all exit zero, fewest runs 772 |
| Test names against the earlier run | 4583 compared, 0 lost, 0 newly ignored, 1 waived, 56 new |
| Crash reports | 4, all on purpose, from the guard's own test children |
| Limit the run states | Yanked status not proven for 11 crates: the index is offline. Advisories 1395, newest 2026-10-30 |

The waiver covers one test: `syn04_t13_t08_no_password_in_any_request_and_no_token_in_any_file`. It was renamed `syn04_t13_t08_syn03_t24_no_password_in_any_request_and_no_token_in_any_file`, which ran ok in the sync lane.

## The 7 story checks

Each test ran ok in the run's own log. Each mutant went red in my private copy.

| # | Check | Test | Mutants that went red |
|---|---|---|---|
| 1 | A client signs in through `device_key.rs`, and a changed signature gets 401 | `larsal_sync::client::tests::syn04_4_signs_in_through_device_key_and_a_changed_signature_gets_401`, also `syn03_10_t19_401_signs_in_once_then_signed_out`, `syn04_6_a_401_after_the_new_sign_in_is_signed_out` | A1, A2, A3, A4 |
| 2 | Two clients change two entries at once: both changes on both | `larsal_ffi::sync::tests::syn03_5_t04_two_macs_change_two_entries_at_once_and_both_keep_both` | C2 |
| 3 | A deletion stays deleted | `larsal_ffi::sync::tests::syn03_5_t05_a_deletion_stays_deleted_on_the_other_mac` | C3 |
| 4 | A rolled-back server is refused with a warning | `larsal_sync::sync::tests::syn03_7_t10_a_rolled_back_server_is_refused_with_a_warning`, `larsal_ffi::sync::tests::syn03_7_t44_a_listed_rollback_reaches_the_open_vault_and_downloads_nothing`, also T11, T12, T28 | R1, R2, R3, R4, R5 |
| 5 | Endless 412: 3 tries, then a plain error | `larsal_sync::sync::tests::syn03_6_t08_endless_412_gives_3_tries_then_busy`, `syn03_6_the_wait_is_random_from_1_to_3_s`, `syn03_10_t29_a_long_retry_after_waits_300_s_and_counts_as_a_try` | T1, T2, T3, T4 |
| 6 | Runs on unlock, after a save (debounced), every 60 s and on Sync now; never while locked | `larsal_sync::sync::tests::syn03_4_t09_runs_on_unlock_after_a_save_every_60_s_and_never_locked`, `syn03_4_a_trigger_during_a_run_or_while_busy_waits`, `larsal_ffi::sync::tests::syn03_4_t09_the_session_runs_on_unlock_after_saves_every_60_s_never_locked`, `syn03_4_unsaved_changes_or_an_open_editor_hold_the_run` | L1, L2, L6, L7 |
| 7 | larsal-ffi without `sync` links nothing of larsal-sync | Gate `scripts/check-sync-link.sh`, step `sync-link` in G1 (`scripts/check.sh:108`), log "check-sync-link: PASS" | Plants below |

What the tests really do, from reading them:

- Check 1 signs in against Larsal's own server with the test-seam key. A second device of the same account changes every signature by one bit and gets `SignedOut`.
- Check 2 runs two sessions in two threads on one server. It asserts both titles on both Macs and version 3 on the server.
- Check 3 deletes for good on A, syncs B, edits on B, and asserts A does not get the entry back.
- Check 4 refuses a lower version and the same version with other bytes: nothing merged, no PUT, the state does not move. T44 proves the list check reaches the open vault.
- Check 5 counts exactly 3 PUTs, 2 waits of 1 to 3 s, and 3 merges.
- Check 6 walks a test clock and asserts runs at exactly 0, 13,000 and 60,000 ms, in the schedule and through the session.

## The 4 amendments

| Amendment | Test | Mutants that went red | Limit |
|---|---|---|---|
| LD-327 (6): SYN-04 T08, client half of T13 and T20 | `syn04_t13_t08_syn03_t24_no_password_in_any_request_and_no_token_in_any_file`, `syn01_13_t20_the_client_logs_nothing`, `syn04_6_t08_debug_output_never_shows_the_token`; server side `syn04_10_t13_no_request_holds_the_password_or_a_value_made_from_it`, `ld321_4_t20_log_line_never_holds_a_secret_and_every_reply_no_store` | Z2, Am6a, Am6b | T20 reads source text. The token-in-a-file half is by the test's walk of both Macs' folders, with no mutant of mine |
| LD-325 (5) (a): stored public key compared on open | `larsal_platform::device_key::tests::ld325_5a_open_takes_only_the_stored_public_key` | Am5a | Real keychain path not run: no keychain on this Mac under the rules. The app build does not link it (0 SecKey symbols) |
| LD-325 (5) (b): token out of the reply at once | `client::tests::ld325_5b_the_signin_reply_moves_into_the_wiping_buffer`, `net::tests::syn04_post_sends_body_and_answer_debug_hides_it` | Am5b | It reads source text: it holds the move, not the wipe |
| LD-325 (5) (c): two pin tests | `net::tests::ld325_5c_pinned_leaf_with_another_name_and_old_dates_is_accepted`, `ld325_5c_read_fingerprint_gives_the_leaf` | Am5d, Am5c | |
| LD-325 (5) (d): the guard text for `scripts/check.sh` | `test_keychain_imports` in `scripts/check.sh`, and the tool's mirror: `import_screen` passed, 156 reads, 0 refusals, tools equal | None | No plant of mine |
| LD-324 (3), F-241: `load` refuses an unknown key | `larsal_ffi::local_state::tests::f241_load_refuses_a_key_it_does_not_know`, `state::tests::syn03_3_state_refuses_a_key_or_value_it_does_not_know` | Am3 | |
| LD-319 (4), F-226: record the written version | `larsal_ffi::copies::tests::f226_a_version_3_file_put_back_keeps_this_macs_settings` | Am4a | |
| LD-319 (4), F-227: open a copy outside the save lock | `f227_a_copy_opens_outside_the_save_lock`, `f227_a_key_change_while_the_copy_opens_merges_nothing` | Am4c, Am4b | |

## V2-1: what may go up

**The rule.** `Session::sync_read`, `crates/larsal-ffi/src/saving.rs:958`. It reads the file once, then requires:

1. SHA-256 equal to `sv.proven`, the file this unlock last opened with its key parts or wrote (`saving.rs:987`).
2. The open vault's root id equal to the unlock's root; an unknown root fails closed (`saving.rs:987`).
3. An exact frame (`saving.rs:993`, `crates/larsal-format/src/integrity.rs:80`): the outer header is byte for byte what the header writer makes of its values, and the block stream ends at the last byte.

Failing 1 or 2 gives `MSG-SYNC-LOCAL-FILE`. Failing only 3 gives `MSG-SYNC-SAVE-FIRST`.

**Where it sits.** Every upload of a file crosses it. The 304 branch reads through `crates/larsal-sync/src/sync.rs:493` and `crates/larsal-ffi/src/sync.rs:433`. The first upload reads at `crates/larsal-ffi/src/sync.rs:772`. The 200 branch uploads only the bytes its own save just wrote. `sv.proven` moves only when a key opens the bytes or a save writes them: `edit.rs:115`, `saving.rs:573`, `saving.rs:847`.

**Attacks, on the candidate's code.** Output of my probes, demo vaults, loopback only:

| Attack | Route | Result |
|---|---|---|
| V2's probe: 59 bytes of plain text at the path | 304 | `puts=1 status=Some(Error) version=1 size=9963 ids=["MSG-SYNC-LOCAL-FILE"]`: only the first upload ever went up |
| The same | First upload | `ok=false puts=0`, "The vault file on this Mac is not the vault Larsal has open. Nothing was uploaded." |
| V2's probe: another demo vault's file at the path | 304 | `puts=1 status=Some(Error) ids=["MSG-SYNC-LOCAL-FILE"]` |
| The same | First upload | `ok=false puts=0` |
| Plain bytes written right after the check, before the PUT | 304 | The PUT body equals the saved vault file; the plain bytes are in no request |
| The same, written in place | First upload | `ok=true puts=1`, with the checked bytes. The next run reads Error and sends no PUT |
| The same, by rename | First upload | `ok=false puts=0`, "The local vault file changed. Try again." |
| Truncated copy, 7 cuts down to 0 bytes | 304 and first upload | Error, `MSG-SYNC-LOCAL-FILE`, no PUT; first upload refused 7 of 7 |
| This root id, another key | 304 and first upload | Refused, no PUT |
| This root id, another key, and the user types that key at unlock | 304 | It goes up: this unlock opened it with its own key parts. Encrypted bytes only |
| Link moved to a path holding plain bytes | 304 | Error, `MSG-SYNC-LOCAL-FILE`, no new PUT |
| Link naming another root's path | Tick | `puts_added=0 status=None` |
| File moved, plain bytes in its place | 304 | Error, `MSG-SYNC-LOCAL-FILE`, no new PUT |
| State file forged by a local writer: link file and root both changed | Tick | `puts_added=1`. What goes up is this unlock's proven encrypted vault, never plain text. It needs write access to the settings folder |
| Another vault under the same key loaded by the disk check, with a newer copy on the server | 200 | `MSG-SYNC-OTHER-VAULT`, no PUT, also after a save in that vault |
| Tail after the final block | 304 | `MSG-SYNC-SAVE-FIRST`, no PUT |
| A data block spliced before the final block | 304 | The frame passes; the hash refuses it and an open refuses it |

**The rule undone, in my private copy.** U1 turns off hash, root and frame. 19 tests go red:

- `syn03_14_t31_a_plain_file_at_the_path_never_goes_up`
- `syn03_14_t32_another_vaults_file_at_the_path_never_goes_up`
- `syn03_14_t33_another_vault_the_disk_check_loaded_never_goes_up`
- `syn03_14_t34_a_corrupt_copy_at_the_path_never_goes_up`
- `syn03_14_t35_first_upload_of_a_plain_file_another_vault_or_a_corrupt_copy_is_refused`
- `syn03_14_t37_a_run_before_the_disk_check_is_refused_and_the_event_still_comes`
- `syn03_14_t39_keep_mine_writes_the_vault_and_it_goes_up`
- `syn03_14_t45_a_tail_appended_while_unlocked_never_goes_up`
- `syn03_14_t46_a_tail_present_at_unlock_never_goes_up`
- `syn03_14_t47_a_tail_at_the_first_upload_never_goes_up`
- `syn03_14_t48_room_in_the_outer_header_goes_up_only_after_a_save`
- `syn03_14_t49_a_wizard_vault_has_its_root_and_another_root_stays_off`
- `syn03_14_t52_every_shape_of_file_is_refused_and_the_good_bytes_come_back`
- `syn03_14_t53_another_root_stays_off_at_a_first_upload_and_after_a_relock`
- `syn03_14_t55_a_key_change_on_disk_goes_up_after_the_new_key`
- `syn03_14_t58_an_older_copy_never_goes_up`
- `syn03_14_t59_a_vault_larsal_never_wrote_has_a_clear_path_up`
- `syn03_2_t64_a_download_with_a_tail_never_links`
- `syn03_5_t62_the_file_is_read_once_and_those_bytes_come_back`

The first test to name is T31: it is V2-1 in one test. All of these ran ok in the run's sync lane.

## Mutants

54 mutants in a private copy, each built and run. 51 red, 3 green and explained. No build failure and no timeout counted as a kill. Lanes: larsal-sync lib whole; larsal-ffi lib with `sync`, filtered to `sync::tests`, `f261_`, `app_05_6`, `ld_310_7`, `f241_`, `f226_`, `f227_`; larsal-format `integrity::`; larsal-platform `device_key`, `ld325_5c`. Baseline before and after: larsal-ffi 97 passed with my 12 probes, 0 failed, 1 ignored; larsal-sync 39 passed; larsal-format 6 passed. At the end the private copy's crates equal the commit's, but for the probes added to one test file (0 lines removed).

| ID | What I changed | Red |
|---|---|---|
| U1 | No hash, no root, no frame | The 19 above |
| U2 | Hash off | T31, T32, T34, T35, T37, T39, T45, T52, T55, T58, T62 |
| U3 | Root off | T33, T49, T53 |
| U4 | Frame off | T45, T46, T47, T48, T59, T64 |
| U5 | An unknown root passes | T49 |
| U6 | First upload only: a refused read uploads the file | T35, T47, T48, T49, T53, T59 |
| U7 | 304 branch only: a refused read uploads the file | T31, T32, T33, T34, T37, T39, T45, T46, T48, T52, T55, T58 |
| U8 | larsal-sync: a refused read ends Synced | `syn03_14_t31_a_file_not_proven_sends_no_put_and_ends_in_an_error`, and 14 others in both crates |
| U9 | Bytes past the final block pass | T45, T46, T47, T59, T64, `syn03_5_t60_any_byte_after_the_final_block_is_not_exact` |
| U10 | Room in the outer header passes | T48, `syn03_5_t60_room_in_the_outer_header_is_not_exact`, `syn03_5_t60_field_12_passes_only_as_a_save_writes_it` |
| U11 | A save does not move the proven hash | 23 tests, T36 among them |
| U12 | A reload does not move the proven hash | T37, T45, T47, T48, T55 |
| U13, U15 | The frame checked on a second read; a second read returned | T62 |
| U14, U16 | A Save As does not mark the run; the merge does not stop for it | T51 |
| V2-5 | A Save As does not tell the sync | T42, T51, T56, T57 |
| R1, R2, R3 | Rollback guard off; a lower version passes; the same version with other bytes passes | T10 |
| R4 | List check off | T10, T44 |
| R5 | The list result never reaches the open vault | T44 |
| T1, T2, T3, T4 | 4 tries; 2 tries; no wait; plain error lost | T08 and T29 each; T2 also `f282_warnings_survive_conflict_rate_limit_and_transport_failure`; T3 also `syn03_6_the_wait_is_random_from_1_to_3_s`; T4 also `f282_warnings_precede_the_final_report_after_a_retry` |
| L1, L2 | The schedule's guard off; a lock clears nothing | larsal-sync T09 |
| L7 | All three guards of the session off | Session T09 |
| L6 | An open editor or a disk question does not hold a run | `syn03_4_unsaved_changes_or_an_open_editor_hold_the_run`, T38, T58, 2 others |
| L3 | Sync now while locked asks | Green. Equivalent: `start` returns at its first line while locked, and the next unlock overwrites `asked` |
| L4, L5 | One and two of the session's three lock guards off | Green. They overlap: `slot.vault`, the saver and the schedule each stop the run. L7 turns all three off and is red |
| A1 | A second 401 signs in again and again | `syn04_6_a_401_after_the_new_sign_in_is_signed_out` |
| A2 | No new sign-in | T19, `syn04_6_a_401_after_the_new_sign_in_is_signed_out` |
| A3 | A refused sign-in reads Offline | T19, `syn04_4_signs_in_through_device_key_and_a_changed_signature_gets_401`, `syn03_10_each_reply_has_its_status` |
| A4 | The server takes any signature | `syn04_4_signs_in_through_device_key_and_a_changed_signature_gets_401` |
| C2 | The merge result drops this Mac's changes | T04, T11, T12, T28, T13 and T24's test |
| C3 | The content merge with no deletion pass | T05, T12 |
| V2-2 | A PUT reply whose version does not move up | T43 |
| V2-7 | A hash compared with `==` | `cry04_11_t19_hashes_and_pinned_keys_are_compared_in_constant_time` |
| Z2 | SHA-256 of the password, as hex, in every request | T13 and T24's test |
| F314 | F-261's early guard off | `f261_the_group_editor_answers_busy_before_the_file_is_looked_at` |
| K1 | The sync state written in place | `syn03_3_t26_a_kill_while_the_state_is_written_leaves_old_or_new` |
| Am3, Am4a, Am4b, Am4c, Am5a, Am5b, Am5c, Am5d, Am6a, Am6b | One per amendment clause, in the table above | The named test of that clause |

Am4c also hangs `f227_a_key_change_while_the_copy_opens_merges_nothing`, because that test's own hook waits for the lock the mutant holds. I stopped that test program by its PID. The red that counts is `f227_a_copy_opens_outside_the_save_lock`.

## Gates, planted in a private clone

| Plant | Gate | Result |
|---|---|---|
| None | `scripts/check-sync-link.sh` | exit 0, PASS |
| `scripts/build-core.sh` asks for `--features net,sync` | The same | exit 1, "asks for sync" |
| `crates/larsal-ffi/Cargo.toml`: `net` pulls `dep:larsal-sync` | The same | exit 1, "with feature 'net' links larsal-sync" |
| `scripts/repro-build.sh:22` asks for `--features net,sync` | The same | **exit 0, PASS. The gate does not read this file** |
| None | `scripts/check-vendor.sh` | exit 0, PASS |
| A listed file gone from disk | The same | exit 1, "files its list names are missing: README.md" |
| `vendor/crates-io/tinyvec-1.10.0/Cargo.lock` out of the index | The same | exit 1, "not tracked: Cargo.lock" |
| `vendor/crates-io/unicode-normalization-0.1.25/Cargo.lock` out of the index | The same | exit 1, "not tracked: Cargo.lock" |

## Zero knowledge (LD-340)

**What leaves the Mac.** One full two-Mac run through a recording proxy:

| Request | Headers | Body |
|---|---|---|
| `GET /v1/health` | accept, host, user-agent | None |
| `POST /v1/accounts` | accept, content-length, content-type, host, user-agent | `device_public_key`, `device_name` |
| `POST /v1/signin/challenge` | The same | `device_id` |
| `POST /v1/signin` | The same | `device_id`, `nonce`, `signature` |
| `GET /v1/vaults` | accept, authorization, host, user-agent | None |
| `GET /v1/vaults/{id}` | The same, with if-none-match after the first | None |
| `PUT /v1/vaults/{id}` | accept, authorization, content-length, host, user-agent, if-match or if-none-match | The vault file. My probe asserts an exact frame on every PUT |

The user agent is the product name only (`crates/larsal-platform/src/net.rs:79`). The device name is the fixed word "Mac". The vault id is random.

**Does any byte of a secret or plain text go up?** No byte of the master password, an entry password or an entry title of 6 bytes or more, raw or encoded, in any request or reply (T24's test, every entry, bin and history included). No value made from the password either: its part, the composite key or the derived key, each raw, hex and base64 (T13's half, Z2 red). No token in any file of either Mac. V2's plain-bytes route is closed above.

Limits of that search: titles under 6 bytes are not searched, and user names, URLs and notes are not searched. They stay inside the encrypted file.

**What does go up in clear:** the outer header, by format. That includes field 12. My probe put a demo public name in field 12: `field 12 in clear on the server: true; in a request: true`, and a save keeps it. Text a user typed there reaches the server.

**What a server can do today:** test a password guess. My probe, with only the server's bytes: right password opens, wrong password gives `WrongKey`. So the server copy of a password-only vault can be attacked offline.

**What E16-S7b still has to close:**

- Add the key-file part, so the server copy needs the master password plus the 256-bit part (SYN-03.1, T01, T02). The guess test must then give the same answer for a right and a wrong password.
- Run T13, T14, T15, T16, T18 and T23, its own rows.
- Run T24 again on T13's run, with `demo2` and the part bytes as needles.

**What E16-S7b does not close:** field 12. The lead rules, or FMT-03.22 changes, and E13-S8's proof must state it.

**Is sync off in the app build? Yes.** `scripts/build-core.sh:27` asks for `net` only. The run's own app library, `LarsalFFI.xcframework/macos-arm64/liblarsal_ffi.a` (sha256 a4f77f6d5c47220fb4b6f8a9acc9e07db2fd900115dac571a297a6803575e5f7, 138,111 symbols):

| Looked for | Count |
|---|---|
| Symbols `larsal_sync`, `larsal_server`, `device_key`, `sync_tick`, `sync_put_vault`, `sync_read`, `SecKey`, `SecItem` | 0 each |
| Bytes `/v1/vaults`, `signin/challenge`, `MSG-SYNC-LOCAL-FILE`, `MSG-SYNC-SAVE-FIRST` | 0 lines each |

The Xcode project names cargo 0 times, and no Swift file calls a sync function.

**Does a gate hold that? Partly.** `scripts/check-sync-link.sh` is in G1 and goes red on `scripts/build-core.sh` and on the feature tree. It is a text match. It does not read `scripts/repro-build.sh`, so a planted `sync` there passes. SYN-03's table says so.

## Findings rows

| Row | Closes? | Proof |
|---|---|---|
| F-299, V2-1 | Yes | The rule, the attacks and U1 above |
| F-300, V2-2 | Yes | `syn03_5_t43_a_put_reply_whose_version_does_not_move_up_is_an_error`, V2-2 red |
| F-301, V2-3 | Yes | `syn03_7_t44_a_listed_rollback_reaches_the_open_vault_and_downloads_nothing`, R4 and R5 red |
| F-302, V2-4 | Yes | T13's `made_from_the_password`, Z2 red |
| F-303, V2-5 | Yes, as a stated rule | After Save As the link stays on the old file and the new file sends nothing: T42, T56, T57, V2-5 red. Moving a link is E16-S9's (LD-355) |
| F-304, V2-6 | Yes, with a limit | The gate is in G1, plants above. It does not read `scripts/repro-build.sh` |
| F-305, V2-7 | Yes | `ct_eq` at each compare; T19, V2-7 red. T19 reads source text and proves no timing. `write_back`'s `*current != link` trusts nothing from the compare |
| F-307 | Yes, with a limit | Both halves red in a git clone, plants above. Under the guarded tool the tree has no `.git`, so the tracked half prints "not a git repository: the check that listed files are tracked did not run". The tool exports only what `git ls-tree` lists (`scripts/guarded/guarded_check.py:75`), so an untracked file is missing there and the disk half catches it. That last point is by reading |
| F-314 | Yes | `f261_the_group_editor_answers_busy_before_the_file_is_looked_at`, F314 red |
| V2-8 | Yes | This page is the E16 parity report. No tool cache is tracked at this commit: 0 tracked paths under `__pycache__`, `.DS_Store`, `.swiftpm`, `.build` or `DerivedData`; the only `cache` names are source files in `vendor/`. The stale rows close with the words the lead writes at merge |

## Not mixed in

The diff against f831ef2 touches no file in `macos/`, `larsal-server` or `larsal-proto`. There is no key-file part and no bookmark: the one mention is a comment at `crates/larsal-sync/src/state.rs:76`. T01, T02, T13 to T16, T18 and T23 have no sync test of their number, and T22 and T25 are tagged to their stories. `Status::ReplacedPassword` has no setter in product code (it predates this story).

## Routed, and safe while sync stays off

Each item below reaches no user today: the app library holds no sync code. Each must be closed or ruled before E16-S9 turns sync on.

| Item | Why it is safe today | Why it must close first |
|---|---|---|
| C2E-7: a failed write of the state file is ignored | Nothing runs | By reading: a restart after a lost write loses the guard's highest version, so a rollback to that version would pass the guard. The merge still keeps newer data |
| `MSG-SYNC-SAVE-FIRST` has no action | Swift has no sync | Swift guards saving on `changes > 0` (`Saving.swift` lines 94 and 313), so a user could not get out |
| Stop syncing has no call (T25) | Nothing to stop | A link could not be ended |
| Native bookmarks (LD-355, not passed) and moving a link after Save As (T42) | The direct path is a software seam | The sandbox needs the bookmark |
| C1-7, C1-8, C2E-5, the status while a disk question is up, a corrupt last byte, a good cloud copy reading Error | No screen reads these | The status line must say the right thing |
| C2E-8: a download with a tail is refused in silence | Hostile server only; it never links | The status line must say so |

Turning sync on before E16-S7b is blocked by the guess test, whichever story does it.

## Proposed rows the lead must carry

These came from the builder's notes in a private folder and would be lost:

- **E13-S8's checks, field 12:** "a known text in a demo vault's field 12 goes to the server in clear (SYN-03.14): the run states that this one text is found, by the lead's ruling, or the check fails; no other demo secret is".
- **E13-S8's checks, the guess test:** "from a vault put on the server by E16-S7b's flow, with only the bytes the server holds, a right and a wrong master password give the same answer (SYN-03 T01)".
- **E16-S7b's checks, T24 again:** "E16-S7b runs SYN-03 T24 on T13's run, with `demo2` and the part bytes as needles."

## Secrets (rule 4), on the delta since V2

I read the product delta line by line.

- Added lines hold no log or print call. The `MSG-SYNC-LOCAL-FILE` and `MSG-SYNC-SAVE-FIRST` words hold no path, name or content, and `refused(message.text("", ""))` adds none (`crates/larsal-ffi/src/sync.rs:774`).
- `Unproven` holds a message id only. `proven` is a hash of an encrypted file, not a secret.
- `merge_server`'s credential copies stay in wiping types, and its compares go through `SecretBytes`.
- Proof by test: T13 and T24's test, T20, T08, Am6a, Am6b, Z2. T35 and `refused_with` assert the message names nothing of the file.

No secret reaches a log, an error text or the screen layer on this delta.

## Limits of this signature

- The real keychain path of `device_key.rs` was not run, by the rules. The tests use the software seam.
- Native bookmarks are not passed (LD-355).
- T19, T20 and `ld325_5b` read source text. They prove no timing and no wipe.
- T26's kill test has no floor on kills. K1 was red on this commit, but a very slow machine could kill less often.
- T24 searches what is listed above and no more.
- Mutants ran on filtered lanes and under a private guard, not under the guarded tool. The tool's run is the proof that the tests pass; the mutants prove the tests can fail.

## Evidence

| Item | SHA-256 |
|---|---|
| Run `summary.json` | 33a63bb999b801a4374183eeba6f096c3beca711a8179f41cddf831750e45aa0 |
| Run `summary.txt` | 032d08a11594098069a73e11d01a0e98ce922dd8fb4169f794d827f3c1586a3f |
| Run `test-names.json` | 6cc9e298e1b6bbfbed03dfbad1a7c3ca02db1f66c5f5239a521dcc97ae881685 |
| Run `run.json` | 5b2358f1df2b3e90b1fc46b6d554e9b5a705501ab993c7ba09e014890e14756c |
| Sync lane, larsal-ffi: 386 passed, 0 failed, 7 ignored | 535f56fd4d449ac984765a9e337f44f36f1a544987098cede31acf1311cb3cb1 |
| Workspace lane, larsal-sync: 39 passed | 9324ed995aea3b80b64214d242824d7570d93ae325b6bbdfba18cec52b349939 |
| Workspace lane, larsal-ffi: 315 passed, 6 ignored | 08b1aaabe01dd10554931bd052474eadfe4c636e01570a310c9eada2ae0abd9e |
| Workspace lane, larsal-format: 33 passed | de38859e9f81ceb08a84307504c401bd040f54f18c5c59387f75634a10a2edd9 |
| Workspace lane, larsal-platform: 66 passed, 7 ignored | 70c5981ba658b5dfd98d161441179c9be5e27a29811df10ee7ca5ac99a34e953 |
| Net lane, larsal-platform: 66 passed, 7 ignored | ca1aed25d09ec186743cde5ec74ecbdc3ec5ae12247fbdff85bf4e47044fc9b3 |
| Sync-link log, PASS | 1db7f0cb5254747eeef10cbcac73f60fa5ee5d7088dd62eb05e9266a66a26304 |
| Vendor log | b1babef9ec98f8acc835ecb86b43ff15c5912479850fa5cf68531fb00f0977e0 |

## Report end

- **Story:** E16-S7a.
- **Files changed:** none in the project by me. This page is proposed for `security/parity/E16-S7a-sync-client.md`.
- **Proof:** the tables above.
- **Open issues:** the guess test (E16-S7b), field 12 (the lead, E13-S8), the gate's limit on `scripts/repro-build.sh`, and the routed list above.
- **Next step:** the lead adds this page, writes the rows and sets the story Done. E16-S7b is next on this line.

# Decision rows in full, as proposed by the Builder (the lead numbered them LD-422 to LD-426)


## Row 1: what may go up

E16-S7a amended (SYN-03.5 step 2, SYN-03.1 step 3, SYN-03.14; F-299, LD-340). A file goes up only when all three hold, on the bytes that are sent, read once, with no key derivation:

1. Its SHA-256 equals the SHA-256 of the file this unlock last opened with its own key parts or wrote itself.
2. The open vault's root group id is the one it had at unlock. No root known means refused: it fails closed.
3. Its frame is exact (`larsal_format::integrity::exact_frame`): the outer header is, byte for byte, what the header writer makes of the values it read, and the block stream ends at the file's last byte. The values themselves are not judged: a minor version no save would write passes (T60).

Failing 1 or 2 gives `MSG-SYNC-LOCAL-FILE`. Failing only 3 gives the new `MSG-SYNC-SAVE-FIRST`: "This vault's file is not in the exact form Larsal writes. Save the vault in Larsal, then sync again. Nothing was uploaded." Neither holds a path or content.

The check sits in the one read every upload of a file crosses (`Session::sync_read`): the 304 branch, Sync now, the tick and the first upload. The merge branch uploads the bytes its own save just wrote.

## Row 2: why this rule

What the format allows:

| Room | Who can write it | Card | What Larsal does now |
|---|---|---|---|
| Bytes after the final block | Anyone, no key | FMT-01.20, LD-01 | Opens. Refused. A save drops them |
| Gaps between blocks | Nobody: each block follows the last | FMT-06.7 | None exist |
| Comment (field 1), unknown fields 13 to 255 | Key holder: the header HMAC covers them | FMT-02.21, LD-21 | Opens. Refused. A save drops them |
| End field data | Key holder | FMT-02.3 | Opens. Refused. A save drops it |
| Extra map entries, bytes after a map's end | Key holder | FMT-03.6 | Opens. Refused. A save drops them |
| Field 12, public custom data | Key holder | FMT-03.22, FMT-03.23, SF-12 | Opens. Goes up as it is, in clear, and it can hold text a user typed. A save keeps it: public by design. Named in SYN-03.14 and in the server-sees table; routed to the lead and E13-S8 |
| Chosen minor version, seed, IV, salt, ciphertext | Key holder | FMT-02, FMT-06 | Goes up. No shape rule can see it. Such a writer can read the vault anyway |

Rule chosen: the exact frame. A file Larsal never wrote can go up after an open, if its frame is exact. A file that merely opened, with room in it, must be saved by Larsal first. The clear path for a vault from the reference app: open it; if its frame is exact it goes up untouched (T59, `rich-v4`), otherwise one save, then it goes up.

Why not "only bytes Larsal wrote this unlock": it refuses a vault saved here, closed, and opened again, and a good save from another Mac through a cloud folder (T37, T55), and a record of "my own hash" kept in a plain state file can be forged by the same local writer. It would not remove field 12 either, because a save keeps it. Why not decrypt and encrypt again and compare: that is a key derivation per tick, and the frame rule already gives the same answer on room. SYN-03.1 step 1 already has Larsal save before a first upload once E16-S7b lands, so the cards allow it.

Opening stays as the cards say: tolerant, for compatibility (FMT-01.20, LD-01, LD-21). Only sync is stricter.

So a writer without the key cannot add one byte that goes up: everything up to the final block is authenticated by the open that recorded the hash, and the frame rule refuses what the open skips.

## Row 3: a save ends the disk question

SYN-03.4 holds runs while a disk question is pending. Keep mine followed by a save ended the question for the user, but `disk.asked` stayed set until the next reload, so sync stopped for the rest of the unlock. A save that wrote the file now clears it (SYN-03 T39).

## Row 4: Save As

1. SYN-03.3 names one local file per link, and LD-355 gives the bookmark to E16-S9. So after Save As the new file has no link: its saves send nothing, the old file keeps its link and status when opened again. Moving a link to a new file stays with E16-S9 (T42, T56, T57).
2. The path and the hash move together under the save lock, so a read never meets the new hash with the old path: no false refusal (T50, C1-3).
3. A Save As that lands during a run: the run reads and merges nothing more, and its report does not reach the new file (T51). Bytes it already read go up under the old link. They are this session's encrypted vault. A first upload that read before the Save As can leave those bytes under a fresh id with no link.
4. An unlock during a run: the run began under the unlock before it, so it ends as a Save As ends it. It reads and merges nothing more and its report is dropped; the run the unlock asks for reads as usual (T61). That holds with a Save As before the unlock, with another root's file at the path, and with nothing. The mark is set from `schedule.running()` at unlock rather than carried from the old `Open`: the mark is only ever true during a running run, so this covers every carried case and also the plain relock and another root, in one line.
5. A report belongs to its root, not to the slot. A relock keeps the report of the same root (F-287); another root at the path, such as a new wizard vault at a formerly linked path, reads no status (T63).

## Row 5: gates and small closes

1. Check 7 of E16-S7a is a gate: `scripts/check-sync-link.sh`, in `scripts/check.sh` G1. It covers default features, `net` and every other feature in larsal-ffi's Cargo.toml. A cargo that fails, a missing feature and a list cut short are red. So is `scripts/build-core.sh` naming `sync` or `--all-features`, or being gone, which holds Row 6 item 1 by a check and not only by story order; E16-S7b and E16-S9 take that line out when they turn sync on.
2. `scripts/check-vendor.sh` also needs every file a `.cargo-checksum.json` names to be on disk and tracked by git (V4-02).
3. Hash and pinned-key compares of the client use `larsal_crypto::secret::ct_eq` (CRY-04.11), and so does the rollback guard's hash in `local_state.rs`. T19 reads that file. `larsal-platform`'s `device-key` feature now turns on its optional `larsal-crypto` dependency for this; `Cargo.lock` does not change.
4. A PUT reply whose version does not move up is worded in SYN-03.5 step 4: `MSG-SYNC-ERROR`, nothing recorded.
5. SYN-04 T13 searches the password itself and the values a test can work out from it, each raw, as hex and as base64.
6. A vault the wizard made registers its schedule and root as an unlock does (`adopt`, T49). So its schedule now runs, which it did not before.
7. T19's word list gains `sha(`, so a plain compare of a hash made in place is red, and the files it reads may make no `.eq` or `.ne` call at all, by method or by path.
8. SYN-03 T26's kill half is a real kill: the test's own child saves the state in a loop through the one save there is, and is killed by its handle. The row no longer says "test hook".

## Row 6: what stays open

1. Until E16-S7b adds the key-file part, the server copy of a password-only vault lets a server test a password guess (LD-340, SV-03). SYN-03 says so at the edge line, at T59 and in a route table. Sync stays off in the app build until then: `scripts/build-core.sh` line 27 builds `larsal-ffi` with `net`, or with nothing under `--no-net`, never with `sync`, and `scripts/check-sync-link.sh` goes red if it ever does.
2. Field 12 goes to the server in clear and can hold text a user typed. SYN-03 no longer says it holds nothing secret, and SV-01, SYN-01, SYN-04.10, AT-L08 and SYN-03's security note now name it. The lead rules; FMT-03.22 would have to change to remove it.
3. SYN-03 T24 is split. E16-S7a holds the master password and every entry title and password, raw and encoded as SYN-04 T13 does, across every request of a run with no key change. `demo2`, the part bytes and T13's run are E16-S7b's, which runs T24 again; nothing of that half is credited here. T14, T15, T16, T18 and T23 are tagged to E16-S7b in their rows.

## Sources

- spec/research/sync-server.md section 1, Enpass: a client downloads the encrypted vault, opens it, merges and uploads only when it has its own changes; the cloud is a plain drive. That is the pattern kept here.
- What is compared and how is Larsal's own, from its cards: FMT-01.20, FMT-02.3, FMT-02.21, FMT-03.6, FMT-06, LD-01, LD-21. No research note covers a file check before an upload, so this row does not claim other managers do it. The old candidate's words on what proven managers do came from memory, and they are gone.
- RFC 9110 for conditional writes (already cited by SYN-03).
- NIST FIPS 180-4 for SHA-256 (already the hash of SYN-03.3).

# Findings from the rounds, as proposed by the Builder (the lead numbered the open ones F-321 to F-339)


## New, found and fixed in this round

- **Keep mine stopped sync for the rest of the unlock** (Medium, closed by this patch). `s.disk.asked` was cleared only when a disk version was taken. After Keep mine and a save, `sync_busy` stayed true, so no run started until the next unlock. The base has the same code. Mutant M20 proves SYN-03 T39 holds it.
- **C1-1, a tail after the final block reached the server** (High, closed). Now also room in the outer header of a file made with the key (found while answering C1-1). SYN-03 T45 to T48, T59, T60.
- **C1-2, C2-3, a wizard vault skipped the root compare** (Low, closed). `adopt` registers it, and the compare fails closed. T49. Side effect: a wizard vault's schedule now runs from its creation, as an unlock's does.
- **C1-3, a false refusal when Save As races a read** (Low, closed). The path moves under the save lock with the hash. T50.
- **A Save As during a run** (Low, closed, was routed). No read, merge or report after the move. T51. What stays is in "Noted" below.
- **C1-4, C2-1, the link check read a failed or cut-short tree or a missing feature as not linked** (Low, closed). `proof/gate-plants.txt`.
- **C1-5, C2-4, a plain compare in `local_state.rs`** (Low, closed). It decides whether the file is the one last seen, for the rollback guard, so it is a compare for trust: `ct_eq`, and T19 reads the file.
- **C2-2, T13 did not search the password itself** (Low, closed). The test now does, raw, as hex and as base64; the card row stays as it was written. Mutants N07a, N07b, N08.
- **C1-6, the card's words said more than the proof** (Low, closed). The security note and source line are rewritten.

## Closed in the closing round (Checker rounds b and Verify)

- **C2b-1, C1B-2, a lock and unlock during a run lost the Save As mark** (Low, closed). The mark is set from `schedule.running()` at unlock. `syn03_3_t61_an_unlock_during_a_run_sends_nothing_more` has the Save As arm from C2b's probe, the other-root arm from C1B's p23, and a plain relock. Mutants N01, N02.
- **C2b-5, a wizard vault at a formerly linked path read Synced** (Low, closed by one line). A report now belongs to its root. `syn03_13_t63_a_wizard_vault_at_a_formerly_linked_path_reads_no_status`. Mutants N03, N04.
- **C2b-6, the words on what a save writes** (Low, closed). SYN-03.5 and T60 now match `integrity.rs`. `syn03_5_t60_a_chosen_minor_version_is_a_value_and_passes`. Mutant N27.
- **C2b-4, O1, the T19 word list** (Low, closed). It gains `sha(`. `cry04_11_t19` is red on G9, G10 and O1. Mutants N05, N06.
- **C1B-3, S10, read once** (Low, closed). `syn03_5_t62_the_file_is_read_once_and_those_bytes_come_back`. Mutant N07.
- **C1B-4, T50 hung if its loop panicked** (Low, closed). A guard sets the stop flag on drop. Mutant N08 ends by itself, red.
- **C2b-7, A10, A11, the recents note and change signal after a Save As** (Low, closed). `app_05_6_save_as_moves_the_vault_to_the_new_file` now checks both. Mutants N09, N10.
- **A9, a failed Save As moved the path** (Low, test added). `app_05_6_a_failed_save_as_moves_nothing`. Mutant N11.
- **L6, a download past the refusal** (Low, test added). `syn03_2_t64_a_download_with_a_tail_never_links`. Mutant N12.
- **T28, no test carried the row** (Verify, closed). `syn03_7_t28_this_macs_own_edit_is_no_rollback`. Mutants N13, N14.
- **T12, the second run had no coverage** (Verify, closed). `syn03_7_t12_both_runs_warn_and_the_settings_time_picks_the_result`. Mutants N15 to N19.
- **T03, T24, T27, T60, no test carried the row** (found by this round's listing, closed). `syn03_2_t03_another_mac_takes_the_vault_and_links_it`, `syn03_13_t27_each_case_shows_its_status`, the rename to `syn04_t13_t08_syn03_t24_no_password_in_any_request_and_no_token_in_any_file`, and the `syn03_5_t60_*` renames. Mutants N20 to N26.

## Closed in the second closing round (Checker 1 and Sensitive Checker 2 on the closing candidate)

Each test is named with its mutants; the red names are in this root's proof/mutants.txt.

- **C1-1, T26's kill half had no test** (Medium, closed). `syn03_3_t26_a_kill_while_the_state_is_written_leaves_old_or_new`, with its child `t26_kill_child`. Mutants R1, R1b.
- **C1-2, T24's test searched no entry password** (Medium, closed). `syn04_t13_t08_syn03_t24_...` now searches every entry password, and every title of 6 bytes or more, bin and history included, raw, as hex and as base64. Mutants R24b, R24h, R24x, R24p, R24u, R24t.
- **C1-3, T07 and T11 ran on a stand-in** (Low, closed). `syn03_5_t07_on_real_vaults_a_takes_bs_change_and_sends_nothing`, `syn03_7_t11_on_real_vaults_an_old_file_loses_nothing_newer`. Mutants R30, R31, R32, R33.
- **C1-4, T61's third arm** (Low, closed). It now asserts no status and the link as it was. Mutants D5, D6.
- **C1-5, T62 and T19** (Low, closed). T62 refuses any answer but `MSG-SYNC-LOCAL-FILE` for plain text, so a second read for the frame check shows. T19 refuses `.eq` and `.ne` calls in the files it reads. Mutants R6, R7, R7b. T19 still reads source text and proves no timing.
- **C1-6, LD-325 (5b) had no guard** (Low, closed). `ld325_5b_the_signin_reply_moves_into_the_wiping_buffer`. Mutants A4, A4b. It reads source text: it holds the move, not the wipe.
- **C1-9, T14, T15, T16, T18, T23 had no tag** (Low, closed). Each row says E16-S7b.
- **C1-10, C2E-6, words** (Low, closed). SV-01, SYN-01's "What the server sees" and SYN-04.10 name the outer header and field 12; SYN-03.2 says "from E16-S7b" on `F`.
- **C2E-2, no check held "sync stays off in the app build"** (Low, closed). `scripts/check-sync-link.sh` is red when `scripts/build-core.sh` names `sync` or `--all-features`, or is gone. Plants in proof/gate-plants.txt.
- **C2E-3, one note overstated what stays back** (Low, closed). SYN-03's note and AT-L08 name the outer header and field 12.
- **C2E-4, T24 credited a second-factor half** (Low, closed here; the rerun is routed below). The row says what E16-S7b holds.

## Routed, not fixed here

- **C2E-1, the guarded run on the merge** (Medium; lead, before the run). Sensitive Checker 2's finding stands: on this patch merged at fe6f481 (Main has since moved to f831ef2, which changes that tool again), LD-421's tool withholds grants and counts one test lost, the rename of `syn04_t13_t08_no_password_in_any_request_and_no_token_in_any_file`. The lead adds the reviewed `scripts/guarded/tables` change and the waiver in the story's commit. This round removes no other test name and adds no path the tool routes that the patch did not already change. `scripts/guarded` was not touched.
- **Proposed row for E13-S8's checks in plan/epics.md: field 12** (lead; not edited in plan/epics.md). The check line would gain: "a known text in a demo vault's field 12 goes to the server in clear (SYN-03.14): the run states that this one text is found, by the lead's ruling, or the check fails; no other demo secret is". Why: the line's "hold none of the secrets" would otherwise hide or trip on it.
- **Proposed row for E13-S8's checks in plan/epics.md: the guess test** (lead; not edited in plan/epics.md). The check line would gain: "from a vault put on the server by E16-S7b's flow, with only the bytes the server holds, a right and a wrong master password give the same answer (SYN-03 T01, Sensitive Checker 2's P3)". Why: the line names AT-L06, but not this case, which today answers differently for a password-only copy and is why sync stays off in the app build.
- **Proposed row for E16-S7b's checks: T24 again** (C2E-4; lead). E16-S7b runs SYN-03 T24 on T13's run, with `demo2` and the part bytes as needles. Its checks do not name that yet.
- **C1-7, the status after a relock reads Synced with no time** (Low; route to E16-S9). Against SYN-03.13's "with the time". T63 pins the kept status. The time belongs to the status line, which E16-S9 draws.
- **C1-8, a vault with no link reads Syncing while an old run is open** (Low; route to E16-S9). By reading. It lasts as long as the old run; what the line shows then is E16-S9's.
- **C2E-5, `sync_tick` reports a closed vault** (Low; route to E16-S9). Not one line: `close` shares `locked` with a lock, so dropping the `Open` needs a new call and its caller, and it also changes which paths a download claim refuses (`unavailable` reads `vaults`). No secret in it, and no screen reads it until E16-S9.
- **C2E-7, a failed write of the state file is ignored** (Low; route to E16-S9). By reading. Not one line: keeping the guard's highest version over a restart needs a retry, words for the user and a test seam that fails the write. E16-S9 owns the words. Until then a lost write only loses guard history: nothing is uploaded on the strength of it.
- **C2E-8, a download with a tail is refused silently** (Low; route to E16-S9). The same finding as C2b-8 and C1B-6, below.

- **Field 12 reaches the server in clear** (C2b-2, C1B-1; route to the lead and E13-S8, Medium). This is public custom data (FMT-03.22, FMT-03.23, SF-12, MOD-12.4). A save keeps it, and it goes up as part of the vault, including a public name the user typed for the vault and any text a key holder put there. The frame rule cannot refuse it: it is what a save writes. No fix without changing FMT-03.22. E13-S8's zero-knowledge proof should state it. Words done here: "holds nothing secret" is gone from SYN-03, and SYN-03.14 and plan/architecture.md's "What the server sees" name it. plan/security.md SV-01, SYN-01 line 111, SYN-04.10, AT-L08 and SYN-03's security note now name it too; the rows for E13-S8 are above. Proof that it goes up: C2b's P3, C1B's p08 and C2E's P2, in their roots; no test here ports them.
- **A server can test a password guess** (C2b-3; route to E16-S7b, Medium). The server copy of a password-only vault lets a server test a guess until E16-S7b adds the key-file part (LD-340, SV-03, T01). SYN-03 says so at the edge line, at T59, at SV-03 and in a route table. Sync stays off in the app build until then (`scripts/build-core.sh` line 27: `features=(--features net)`; `--no-net` gives none; never `sync`), and `scripts/check-sync-link.sh` now goes red if that changes. If sync is turned on before E16-S7b, this finding blocks it.
- **A download with a tail stays pending in silence** (C2b-8, C1B-6; route to E16-S9, Low). A hostile server only. Links none, the entry stays pending, no status, no PUT, after the unlock and after a save. `syn03_2_t64_a_download_with_a_tail_never_links` states today's behaviour. What the status line says and when the entry clears is E16-S9's.
- **Stop syncing has no call in `larsal-ffi`** (SYN-03.15, T25; route to E16-S9, Low). No test can carry T25 yet. The row is tagged in the card.
- **Status line action for `MSG-SYNC-SAVE-FIRST`** (route to E16-S9, Low). A Rust save works with no changes (T45, T59). Swift guards saving on `changes > 0` (`macos/`'s Saving.swift lines 94 and 313), and Swift has no sync yet, so E16-S9 must offer a save for this message. `macos/` was not touched.
- **Moving a link after Save As** (route to E16-S9, Low). After Save As the new file has no link (SYN-03 T42). SYN-03.3 keys the link on a security-scoped bookmark, and LD-355 gives that bookmark to E16-S9, so it decides with its native proof.
- **Status while a disk question is up** (route to E16-S9, Low). When the disk check runs first, the run is held and the status keeps the last run's Synced, with its old time (SYN-03 T38, SYN-03.13). It is true of the last good run and nothing is sent, but the status line could say that it is waiting.
- **A corrupt last byte gives no disk event** (route to E16-S9, Low). A copy with the same first 1,024 bytes and the same length is invisible to APP-05.24, so the status stays Error until the next save heals it (SYN-03 T34). Nothing goes up. A tail changes the length, so it does give an event (T45).
- **A good copy from a cloud folder reads as Error until the disk check opens it** (route to E16-S9, Low, T37). No data is at risk. The words are harsh for that case.

## Noted, no change

- **A kill during a state write leaves its temp file in the settings folder** (Checker 1's side note on C1-1: 51 files after 150 kills). It holds the state, which has no secret (T26), under a random name. By reading `create_temp` and a search of `storage.rs`, I found nothing that sweeps such files; `storage.rs` is out of bounds in this round.
- **Limit of the frame rule.** A writer with the key can put chosen bytes in the minor version, the master seed, the IV, a salt or the ciphertext. No shape rule can see that, and such a writer can read the vault anyway. Said in SYN-03's security note.
- **A hostile server's download with a tail** never links: it fails the same check at the unlock that would link it, so nothing goes up (T64). The silence is routed above.
- **A first upload that read before a Save As** can leave this session's encrypted bytes under a fresh `vault_id` with no link. Bytes under an old link stay this session's encrypted vault. No plain text and no other vault can go up this way.
- `write_back`'s `*current != link` in `crates/larsal-ffi/src/sync.rs` compares two whole links only to decide whether to write the state file. Nothing is trusted from it, so it stays `!=`.
- `crates/larsal-ffi/src/sync/tests.rs` signs in once per server per case in T35, because the server limits how often one address signs in. A fresh server per case is the existing pattern. Checker 1's probes P8, P8b and P8c were not ported: they flood that limit or take 17 s of real sleeps. T50 holds the same rule at the read.
