# E21-S2 Show as QR Code in the Mac app: Verify sign-off

Story: E21-S2 (plan/epics.md). Card: FEA-10, with FEA-04.23. Decisions: LD-337 (1), LD-359 to LD-363, LD-198, LD-220. Checkers: C1 and Sensitive C2, four rounds.
Date: 2026-11-07.
Role: Verify. I read the lead's guarded run of this commit and did not rerun it. I ran Rust tests and Rust mutants in a private copy of the tree, under the guard profiles, and read the Builders' raw Swift mutant logs. I changed no product code and ran no xcodebuild. The logs and scripts named here lived in private folders under /private/tmp that do not last, so this page copies what must survive.

**Result: signed with limits.** Commit `e808d32db8d354ce9e0eb338d68f3b2a07e800c5`, three commits on Main 6ad5422: b8c6883 (Rust), 64d017d (Swift), e808d32 (the lead's tables). The guarded tool's run of this commit reads PASS. Checks 1 to 12 and 16 below hold by named tests that ran and passed in that run. Checks 13 to 15 stay OPEN in the board's own words: functional Share (LD-360), Mac QA with a real menu bar and a visible window, frames included (W-08), and named-receiver enterprise joins (LD-361). None of them is passed by a refusal or by the disabled Share… button. Of my 17 Rust mutants, 15 went red and 2 stayed green; both are explained (V-1, V-2). The Builders' Swift mutants went red wherever I could read their raw logs.

In the app, Show as QR Code draws a code from the entry list, the entry view, every protected field, the editor's draft and the Wi-Fi join. Save Image… writes only after its warning, from Rust. Share… ships disabled with MSG-QR-SHARE-UNAVAILABLE because no route is proven (`qrShareRoutes` is empty).

## The whole difference

| Item | Result |
|---|---|
| Base | Main `6ad5422d7ccffb5b678e1d7182a37b55dc0cc263` |
| Commits | `b8c68838b985a368474bd6c3b2a42a9b7138b3b2` (Rust), `64d017d164b97a040b55aee15467dcf450422086` (Swift), `e808d32db8d354ce9e0eb338d68f3b2a07e800c5` (the lead's tables). The owner is the only author of all three |
| The Builder's patch | fix.patch, SHA-256 `590a06efa1d6446db2a7e6ea0452b2d5258d96e737c1e35727a85fea5b40051b`, 54 paths. Applied with `git apply --index` on a fresh worktree of 6ad5422 it writes tree `bbbd48d59e31febb087f8624d9cb57b635027aef`, the tree of 64d017d |
| The tables commit | e808d32 changes exactly three paths: `scripts/guarded/tables/native-expected.txt`, `pins.json` and `programs.json`. Its tree is `acb10306a1491d7af9d2e55696180c57fefb0825` |
| What the patch touches | crates/larsal-core (one function made public: `icons::encode_png`), crates/larsal-ffi (new `src/qr.rs`, `tests/qr.rs` and `tests/qr_wipe.rs`; changed `src/edit.rs`, `src/session.rs`, `src/views.rs`, `src/lib.rs`, `API.md` and `tests/edit.rs`), crates/larsal-platform (a memory probe for tests), macos/. No spec, plan, design, sync, share, merge, files or `scripts/guarded` path. No `Cargo.toml` or `Cargo.lock` change |

## The run

The guarded tool ran the full check of this commit once. The lead started it at 21:01 from a copy of the tool at /private/tmp/larsal-m5-iuO5cjY0/c, with the baseline of 109ef36's run and the waiver file below. I read its results and did not rerun it.

| Item | Result |
|---|---|
| Overall | PASS, 3197.8 s. Hold wait 0.0 s, not partial, no failures |
| Commit and tree | The run's commit is this commit. The run's tree equals this commit's tree, `acb10306a1491d7af9d2e55696180c57fefb0825` |
| Tool | 23 files. Each `tool_sha256` in `run-start.json` equals this commit's `scripts/guarded` file (0 differ). Custody: 0 changed, 19 executables, 23 tool files. Tool drift: none |
| Tables | `pins.json` `6c4a08de42d124976d6cf7c022f68877957ecb5c081f074c04fee5ef2d9fd51a`, `programs.json` `1e79fb363aa353b0d212c6f8607c82ccf356340fe7e6a53dab3cc9330eee871f`, `native-expected.txt` `b0fd5b4cda44f7c3f73d1c6cc71387bbb7837b471a50bd79b2ab052d3af45142`, each equal in this commit, in the run's tool copy and in the run's tree |
| Grants | 59 rows read, 0 withheld. Reviewed commit 64d017d; the only commit after it changes the three tables alone |
| Lanes | source exit 0; static exit 0, 670.7 s; rust exit 0, 1303.4 s; native exit 0, 610.6 s; docs exit 0, 245.0 s; fuzz exit 0, 349.2 s |
| Static | 18 of 18 steps. Names PASS, 12198 files, 19 vault files by name only. Unsafe count 458 in 19 crates. Advisories, bans, licenses and sources ok |
| Rust | 4352 passed, 0 failed, 92 ignored, 158 of 158 programs. Workspace 3399/0/76 (132 programs), sync 562/0/9 (17), net 71/0/7 (2), release 275/0/0 (6), release-browser 45/0/0 (1). Guard library requests 0 in every lane. All lanes reconcile PASS |
| This story's Rust programs | Workspace: `larsal_ffi` lib 336 passed, 6 ignored; `qr` 21 passed; `qr_wipe` 1 passed (23.9 s). Sync: lib 408 passed, 7 ignored; `qr` 21 passed; `qr_wipe` 1 passed (19.3 s). The 89 story test names (`qr::`, `qr_t`, `fea_10`, `f_064`, `qr_wipe`) are all ok in `test-names.json` |
| Swift | The log reads 462 tests in 68 suites, passed. The bundle reads 462 passed, 0 failed, 0 skipped. The result database (SHA-256 `b43e463f5b4dae2e10982aae208b0260f2a7158afd8ed5147d3b4d28ae164ad2`) holds 462 cases and 606 runs (parameters included), every run Success. The 61 cases of the Qr suites are all Success; `QrSnapshotTests/frame(_:)` ran 8 times. APP-09: 18 passed |
| Docs | 15 passed, 0 failed |
| Fuzz | 30 routes, all exit zero, fewest runs 832 (`strength_estimate`), no artifacts and no marks, no route new to the tool |
| Test names against the earlier run | Baseline from 109ef36. 4789 compared, 0 lost, 0 newly ignored, 2 waived, 0 waivers unused, 152 new |
| Windows | The test attempt took 105 window samples. The 100 kept in its record hold 3,634 window rows, each one off screen with zero width and height. The gate passed in all three attempts |
| General board | See "Rule 4 and rule 3" |
| Crash reports | 6 new while the run went. 4 are on purpose, from the guard's own test children. 2, `larsal_platform-18047525b28ae096` at 21:19:37 and 21:47:35, are not this run's: the run lists no own report that is not on purpose, the reporter masks the folder, and that binary is not in my target folder either. Another process on this Mac |
| Limit the run states | Yanked status not proven for 11 crates, as the index is offline: aes-kw, aes-siv, bech32, chacha20poly1305, cmac, dbl, hpke, httpdate, scrypt, x25519-dalek, zeroize_derive. Advisories 1395, newest 2026-10-30 |

The same code ran once before, with the tables of Main (root `larsal-gc-2d2f5c9-3CLH`). That run read FAIL only because the new programs `qr` and `qr_wipe` ran at base with no row (see "The grant"), and because the moved test was lost with no waiver. Its Swift lane passed 462 and APP-09 18. The 16 frame images this run drew (8 frames, light and dark) and their 16 accessibility files are byte for byte those of that run and of the round 4 Builder's run `larsal-gc-27d2ddf-YBfc`.

## The story's checks

Each test below ran in the run's own logs and passed there (Rust by its program log, Swift by the result database). "Red" names a mutant that went red: V rows are mine, in my private copy; S rows are the Builders', read in their raw `xcode-test.stdout`.

| # | Check (plan/epics.md, E21-S2) | Tests | Red | Result |
|---|---|---|---|---|
| 1 | 1,000 fitting random demo values, letters, digits, symbols, spaces, emoji and other scripts, the longest generated results among them, drawn by the app and read back by Core Image to the exact UTF-8 bytes; only exact readbacks count | Swift `QrReadbackTests.thousandReadbacks` | S15 (no ECI: "round N: bytes read back different" at QrReadbackTests.swift:101, raw log), S54 (no long generated value) | Verified |
| 2 | ECI 26 and one byte segment from the recovered descriptor, headers, terminator and padding excluded | Swift `QrRead.parse` in every readback (one ECI header, mode 0100, count, data, zero terminator, only 0xEC/0x11 pads, else nil; `eci == 26` expected); Rust `edit::tests::fea_10_8_eci_26_before_one_byte_segment_and_fea_10_7_setup_code_has_none`, `qr_t05_smallest_version_by_capacity_at_level_h`; Swift `otpUnchanged` (FEA-04.23 stays byte only, no ECI) | V01, V02, S15 | Verified |
| 3 | UI, core and CLI maxima, built-in and custom lists, Unicode and case expansion, maximum separators: each fitting result decodes exactly, only oversize refuses; 999 ASCII and the 999-byte phrase decode | Swift `uiMaxima`, `customListShapes`; Rust `qr_t31_generator_limits_stay_and_core_and_cli_maxima_refuse` (the generator constants pinned unchanged: 999, 10,000, 1,024, 100, 1,000, 64, 4 MiB, 500,000, 256) | V05, S54 | Verified. Core and CLI fitting results are checked to encode, not decoded, in Rust; the same byte path is decoded in Swift |
| 4 | 1,272 and 1,273 bytes after Show resolution and after Wi-Fi escaping and wrapping | Rust `qr_t05_exact_capacity_after_resolution_literal_and_wifi`, `fea_10_9_size_is_decided_before_the_encoder`; Swift `exactCapacity` | V02, V03, V04, V05 | Verified |
| 5 | Refusal before any matrix, file or share item; no truncation, no lower correction, no generator limit lowered | Rust `fea_10_9_size_is_decided_before_the_encoder`, `qr_t02_refusals_leave_no_old_matrix_and_no_unrelated_value`, `qr_t06_the_work_bound_fallback_is_encoded_exactly_and_oversize_refuses`, `qr_t31…`; Swift `expectTooLarge` in `uiMaxima`, `customListShapes`, `exactCapacity`, and `QrPopupTests.refusals` | V03, V05. V06 stays green (finding V-2, Info) | Verified |
| 6 | A Wi-Fi entry's join code reads back with its fields | Swift `wifiReadback`; Rust `qr_t07_personal_join_and_hidden`, `qr_t08_each_special_escaped_once`, `qr_t09_only_even_hex_ssid_and_password_get_wrappers`, `qr_t10_every_alias_wep_and_open`, `qr_t10_an_open_network_with_no_password_joins`, `qr_t12_invalid_and_unsupported_never_downgrade`, `qr_t11_qr_t12_control_characters_in_every_join_field_are_invalid`, tests `qr_t07_join_is_read_from_the_entry_and_password_show_stays_apart`, `qr_t12_demo_wpa3_is_unsupported_and_its_fields_stay_offered` | V11, V12 | Verified |
| 7 | The pop-up hides on its timer, on lock and when the window is hidden | Swift `QrLifeTests.timer`, `warningKeepsDeadline`, `lockRequests`, `hiddenWindow`, `sourceChanges`; `QrWaysOutTests.waysOut`, `flushed`, `screenLockAtOnce`, `noRestoration` | S9 (QrLifeTests.swift:36-41), S4 (:154), S5 (:105 and QrWaysOutTests.swift:39), S3, S36 to S40, S45, S63 to S65 | Verified offscreen. A real window, Dock tile and menu bar stay Mac QA |
| 8 | No image write but an explicit warned Save; no clipboard call, metadata included | Swift `QrExportTests.noWrites` (temporary, caches, saved state and the run's folders listed before and after; no new file holds the marker or decodes to it; Rust's own record shows the session's board never written), `sourceScan` (no pasteboard, file write, drag, log or network word in the QR sources), `save`, `saveRefused`; Rust `qr_t19_consent_is_per_attempt_action_and_ticket`, `qr_t20_save_is_full_private_plain_and_refuses_links` | S10, S11 (QrExportTests.swift:269), S41 (:242, the PNG written at paint is found by its decode), V07, V08 | Verified. The run's guard records general-board lookups by AppKit, see "Rule 4" |
| 9 | Share uses only an in-memory item: no staging request, silent save or upload | Swift `QrExportTests.share` (`registeredTypeIdentifiers == ["public.png"]`, no file representation; bytes made only while live; nil past the deadline and after a revoke), `sharePolicy` (no service offered with no proved route); Rust `qr_t21_share_bytes_are_in_memory_and_fail_closed_after_revocation` | S16 (QrExportTests.swift:161-162), S8 (:155), V07 | Verified for the code path. Functional Share is row 13 |
| 10 | Warnings before every fresh single-use consent, bound to source or draft revision and the original deadline; ended at the lock request before reload or save waits; recheck before commit and the earliest receiving API; fail closed after | Swift `QrExportTests.consent`, `QrLifeTests.warningKeepsDeadline`, `lockRequests` (ticket not current at the question), `QrExportTests.saveRefused`, `share`; Rust `qr_t19…`, `qr_t18_a_stale_ticket_takes_no_consent_and_gives_no_image`, `qr_t18_a_ticket_found_stale_is_dropped_for_good`, `qr_t18_an_undone_edit_brings_back_no_ticket_and_no_consent`, `qr_t18_every_source_change_and_lock_makes_the_ticket_stale`, `qr_t20_the_last_check_before_the_commit_refuses_a_stale_ticket`, `qr_t18_a_move_of_any_group_above_the_entry_ends_the_ticket`, `qr_t29_a_late_older_request_never_goes_live`, `qr_t29_tickets_do_not_cross_vaults_and_debug_hides_the_matrix` | V07, V08, V09, V10, V17, S7, S16, S17, S4. V16 stays green (finding V-1) | Verified. The deadline lives in Swift; the Rust ticket holds a hash and a consent only (R2C2-5) |
| 11 | LD-361: the selected WPA2-EAP / TTLS / MSCHAPV2 serialization does not activate Join | Rust `qr_t11_enterprise_serializes_but_join_stays_unavailable`; Swift `QrEntryPointTests.wifiItems` | V13 | Verified for the refusal. Named-receiver association is row 15 |
| 12 | F-064 carried by the moved test | Rust `qr::tests::f_064_join_text_is_made_in_one_buffer` | V14 (buffer sized without escapes), V15 (one byte too large) | Verified, see "The waiver" |
| 13 | Functional Share on compliant targets, with the known Copy, Print and staging exclusions | None can run: `qrShareRoutes` is empty in production and Share… is disabled with MSG-QR-SHARE-UNAVAILABLE | | CARRIED_OPEN (LD-360, W-08) |
| 14 | Mac QA matches the frames, light and dark; real menu bar and visible window | Offscreen only: `QrSnapshotTests.frame` (8 frames, light and dark), `denseWidths` | | CARRIED_OPEN (W-08, owner's go). See "Frame parity" |
| 15 | Named-receiver enterprise association, CA and server-name validation, wrong-server refusal | None | | CARRIED_OPEN (LD-361) |
| 16 | Tests launch hidden (rule 10) | The run's window samples; every snapshot test renders into a window that is never ordered in | | Verified: 105 samples in the test attempt, every window row off screen with zero size, and the gate passed in all three attempts |

What the main tests do, from reading them:

- **The 1,000.** One loop of exactly 1,000 rounds over a seeded generator. Sizes: one round in twenty takes 800 to 1,272 bytes, four take 200 to 800, the rest 1 to 200. Values are ASCII letters, digits, symbols and spaces, Arabic, CJK, Cyrillic, Devanagari, emoji and mathematical letters, in one script or mixed. One round in ten is the app's own generator (passwords up to 999, phrases up to 100 words, each case mode), and at least five of each reach 999 characters or 100 words. Each value goes into a draft's Password, `qrShowDraft` makes the code, the app's own `QrCodeNSView` draws it at FEA-10.12's 2× pitch, Core Image's detector finds exactly one code at level H, and the parser reads the descriptor's corrected payload. A round counts only when the ECI is 26 and the bytes equal the value's UTF-8. A refusal throws and fails the test. It expects 1,000 exact, 100 generated, and that one-, two-, three- and four-byte scalars were all walked.
- **The parser** accepts one ECI header at most, then mode 0100 and its count, then the bytes, then only zero terminator bits and the alternating 0xEC, 0x11 pads. A second segment or anything else is nil.
- **The maxima.** Rust pins every generator constant and walks 999 and 10,000 ASCII, 999 and 10,000 four-byte scalars, the 1,024-scalar excluded set, 100 and 1,000 nine-byte words, 64 ASCII and 64 four-byte separators at 100 and 1,000 words, and 256-scalar custom words under every case mode: each either fits and encodes, or is over 1,272 and refuses with MSG-QR-TOO-LARGE. Swift decodes the 999 ASCII password, the four 100-word case modes, a 999-byte built-in phrase, four maximal custom words, U+0390 upper-cased and U+0130 lower-cased 100 times, and a three-word four-byte separator phrase; the 1,998-byte extended password and the long separators refuse.
- **1,272 and 1,273.** A literal draft of 1,272 `a` and 318 four-byte emoji decode and give version 40; 1,273 refuses. A saved `{USERNAME}` resolving to 1,272 decodes; 1,273 refuses. A Wi-Fi wire of exactly 1,272 bytes, with all five escapes and the hex wrapper, decodes; one more byte refuses. Even and odd hex lengths are counted with and without the wrapper.
- **Consent.** Rust: no consent, a made-up one, the other action's, an earlier one, a spent one and one of a dead ticket are each refused, and no file appears. A ticket found stale stays dead after the change is undone, and its consent with it. Swift: each attempt shows the warning; Escape and Cancel give no panel; a double click gives one panel; past the deadline no panel and no file; a lock request revokes before its question, and the ticket is no longer current there.

## Mutants

### Rust, mine

In `/private/tmp/larsal-e21s2-vr2-XoMy3m7I/mut`, a `git archive` of e808d32, target outside it. Built under compile.sb; run under run-key.sb with the roots changed and one added line, `(allow file-write* (subpath "<root>/target/tmp"))`, the same line the tool's `harness-runtime-target-tmp.sb` gives these programs (see "The grant"). Each mutant was one exact replacement, asserted unique, then undone; after the last, `diff -r` of the copy against a fresh `git archive` of e808d32 exits 0. Programs: the lib filtered to `qr::`, `fea_10_8`, `f_064` (22 tests) and `tests/qr.rs` (21 tests).

| Id | Mutant | Result | Red tests |
|---|---|---|---|
| V00 | none | 22 and 21 pass | |
| V01 | no ECI designator (`edit.rs` `symbol`) | Red | `fea_10_8…`, `qr_t05_smallest_version…` |
| V02 | level L instead of H | Red | `fea_10_8…`, `fea_10_9…`, both `qr_t05` |
| V03 | limit 1,273 | Red | `fea_10_9…`, `qr_t05_exact_capacity…` |
| V04 | limit 1,271 | Red | both `qr_t05` |
| V05 | truncate to 1,272 instead of refusing | Red | `fea_10_9…`, `qr_t31…`, `qr_t05_exact_capacity…`, `qr_t06_the_work_bound…` |
| V06 | a refused value still holds a ticket (hold before the size check) | Green | finding V-2 |
| V07 | an export without its consent | Red | `qr_t19…`, `qr_t21…` |
| V08 | Save's consent not single use | Red | `qr_t19…` |
| V09 | an export ignores the revision | Red | `qr_t18_a_stale_ticket_takes_no_consent_and_gives_no_image` |
| V10 | a stale ticket is not dropped | Red | `qr_t18_a_move_of_any_group…`, `qr_t18_a_ticket_found_stale…`, `qr_t18_the_share_door…`, `qr_t18_a_move_to_the_bin…`, `qr_t18_an_undone_edit…` |
| V11 | the double quote not escaped | Red | `qr_t08…`, `qr_t09…`, `qr_t05_exact_capacity…` |
| V12 | no hex wrapper | Red | `qr_t09…`, `qr_t05_exact_capacity…` |
| V13 | the enterprise join served | Red | `qr_t11_enterprise_serializes_but_join_stays_unavailable` |
| V14 | F-064: the join buffer sized without the escapes | Red | `f_064_join_text_is_made_in_one_buffer` |
| V15 | F-064: the join buffer one byte too large | Red | `f_064_join_text_is_made_in_one_buffer` |
| V16 | the holding group left out of the place | Green | finding V-1, the Checkers' C1R4-1 and R4C2-1 |
| V17 | the whole place left out of the revision | Red | `qr_t18_a_move_of_any_group…`, `qr_t18_the_revision_moves…`, `qr_t18_a_move_to_the_bin…` |

A lock needs no mutant of its own in Rust: every QR call goes through `with_qr`, which refuses a locked vault, and unlock makes a fresh `EditState`, so no ticket outlives a lock. The lock request's early revoke is Swift's, S4.

### Swift, the Builders'

Swift mutants run only in a guard root's private tree under its sealed profile. I read their raw `xcode-test.stdout`:

- `/private/tmp/larsal-gc-d0a0309-AMsU/lane-out/` (round 2 code, S0 to S53): S0 51 tests passed. S4, S5, S7, S8, S9, S10, S11, S15, S16, S17 and S41 each fail the test and line named in the table above, and no other.
- `/private/tmp/larsal-gc-37f11c4-qLww/lane-out/` (round 3, S31, S53, S66 to S88) and `/private/tmp/larsal-gc-27d2ddf-YBfc/lane-out/` (round 4, S0, S89, S90).
- Round 3 reran S1 to S88 on round 3's code; its summary reads all red, S0 59 passed. Its raw logs for S1 to S65 were not kept; the summary lines name the failing tests. Round 4 changed 5 files: S89 and S90 cover the two Swift changes, S0 passed 61.

## Frame parity

`QrSnapshotTests.frame` renders the 8 Mac frames of E21-S1 (`e21-s1-qr-popup`, `-wifi`, `-save-warning`, `-share-warning`, `-dense-1x`, `-dense-2x`, `-size`, `-entry`) offscreen, never ordered in, in light and dark at each frame's own scale, and writes the PNG and its accessibility tree. `denseWidths` checks the dense dialog is 599 pt wide with a 555-pixel panel at 1× and 460 at 2×. `-browser-unavailable` belongs to E21-S4 and S5.

These tests do not compare against design/option-a. They assert only that each PNG exists and is over 2,000 bytes. The frames are proposals in `design/option-a/proposals.html`; they are not in `manifest.json`, have no exported reference, and the owner's one-pass review of them is pending (LD-363). The comparison that exists is the round 3 Builder's stand-in: each frame and theme against a rendering of the proposal. Same width everywhere; the code box at the same place within a pixel for popup and the dense frames. The heights differ by 1 to 60 points: the proposal draws "Layout illustration · not a valid QR code" under its fake code, which the app does not, and the Wi-Fi frame's panel is sized by the real code's version in whole pixels (FEA-10.12). Changed pixels beyond one pixel: 0.21 % to 6.37 % above the code, 0.56 % to 2.94 % below it. I looked at popup light and Wi-Fi dark side by side; every string, button, order and colour matches apart from those two. Round 4 changed no drawing code. This is not BUILD-AND-VERIFY's per-frame parity (pixel diff, strings against the manifest, geometry within 2 pt). The story's own words put the frames under "Mac QA matches the frames, light and dark", which waits for W-08, so check 14 stays open.

## The tables

The lead's commit e808d32 changes three tables and nothing else. I checked each line against this commit.

| Table | Change | True for this commit? |
|---|---|---|
| `native-expected.txt` | `399 18` to `462 18` | Yes. The run counted 462 Swift tests (log, bundle and database agree) and 18 APP-09 tests |
| `programs.json` | Four rows added: `workspace:larsal-ffi/qr`, `workspace:larsal-ffi/qr_wipe`, `sync:larsal-ffi/qr`, `sync:larsal-ffi/qr_wipe`, each `{"classes": ["session"], "profile": "harness-runtime-target-tmp.sb"}` | Yes. These are the same as the `larsal-ffi/edit` rows. The run admitted each of the four programs under that profile with class session, and each passed. See "The grant" |
| `pins.json` | `reviewed_commit` ed1947d to 64d017d; a `reviews."E21-S2"` entry; 55 rows to 59 | Yes. The 4 new rows are the four programs above. Each pins `crates/larsal-ffi` at `983979f13a96f8c85a61ec5d8fa707ae994cd24b`, with the checks `class larsal-session-` and `target-tmp`. 46 old rows moved their pins, and each of them was relabelled E21-S2. No row was relabelled without a pin change, and no pin changed without a relabel. Every pin equals the object at this commit (0 differ). No `why` or `checks` text changed, and no row was removed |

The moved pins, by path: `crates/larsal-ffi` 26 (plus the 4 new rows), `macos/Larsal.xcodeproj` 14, `macos/LarsalTests` 6, `macos/Larsal` 5, `crates/larsal-ffi/src/lib.rs` 3, `crates/larsal-platform` 3, `crates/larsal-ffi/src/session.rs` 2, `crates/larsal-core` 1. The patch changes each of these paths, so a row pinning one of them has to move or the tool withholds its grant. No other row moved. Nothing went beyond the story's need.

## The grant to qr and qr_wipe

The first run of the same code (2d2f5c9, root `larsal-gc-2d2f5c9-3CLH`) read FAIL: all 21 tests of `qr` and the one of `qr_wipe` failed in both lanes, as new programs run at base. My run of `tests/qr.rs` under run-key.sb alone gives the same: 0 passed, 21 failed, each `PermissionDenied` at `tests/qr.rs:29`, the `create_dir_all` under `CARGO_TARGET_TMPDIR`. With the one target/tmp line: 21 passed. `qr_wipe` writes its demo vault under `CARGO_TARGET_TMPDIR/qr-wipe` (`tests/qr_wipe.rs:70`) the same way. Both make a `Session::new()`, whose private open-copies folder `larsal-session-<pid>-<n>` is the `session` class. Neither touches the pasteboard, a key, a socket or a window: their row's profile, `harness-runtime-target-tmp.sb`, has none of those. In the run, each of the four ran under that profile with class session and passed. Workspace: `qr` 21, `qr_wipe` 1. Sync: `qr` 21, `qr_wipe` 1. Guard requests were 0 in both lanes. The run's copy of that profile (SHA-256 `ebbd5bdf9facee340d57bf5719e645aa459214513abdfad991d41fca9f585ac3`) differs from `harness-runtime-base.sb` by exactly one line, `(allow file-write* (subpath "<root>/r/target/tmp"))`. So target/tmp with the session class is what they need, and nothing more. The rows are the same as `larsal-ffi/edit`'s: same profile, same classes, same checks (`class larsal-session-`, `target-tmp`), the same `crates/larsal-ffi` pin.

## The waiver

The lead's waiver file (`waivers.json`, SHA-256 `15cc202dfa1f238af9c24544835f1ac9778e06019be5cabf2bf3974bb7926fae`) names two lost tests, `edit::tests::f_064_wifi_text_is_one_buffer_of_the_exact_size` in the workspace and sync lanes. A waiver only excuses a lost or newly ignored name; it cannot hide a failure (`gc_summary.py` `compare_baseline`).

The old test asserted three things of `wifi_join`: the escaped text of one network, that its capacity equals its length, and the same for a WEP join with empty name and password. The function is gone; `wifi_qr` and its helpers left `edit.rs` for `qr.rs`'s `join_buffer`, which sizes the buffer with `room()` and fills it with `push()`. The new `qr::tests::f_064_join_text_is_made_in_one_buffer` asserts capacity equals length for three wires that use every sizing branch: a personal join with escapes in both the name and the password and Hidden true, an enterprise wire with even-hex S and P (the wrapper's two bytes) and an anonymous identity, and an open network with a stale password (no P). V14 (escapes not counted, so the buffer grows) and V15 (one byte too many) each turn it red, and nothing else. The escaped text is now held by `qr_t08_each_special_escaped_once` (V11 red). The empty WEP case cannot happen any more: FEA-10.6 makes an empty SSID or an empty WEP password INVALID before any buffer. So the new test carries F-064's rule. The run applied the file. It compared 4,789 names, with 0 lost and 0 newly ignored. It waived 2, exactly these two names, and left 0 waivers unused. The new test ran and passed in both lanes, in the `larsal_ffi` lib (336 passed in workspace, 408 in sync). The old name appears nowhere in the run's `test-names.json`. The waiver is sound.

## The open Low and Info rows

| Row | Severity | Safe to leave open? |
|---|---|---|
| C1R4-1 = R4C2-1 = V-1 | Low | Yes. The code hashes the whole chain from the root to the holding group (`qr.rs:104-109`); only the test is missing. My V16 confirms it stays green. A later edit that drops the holding group would let a ticket live across a move between sibling groups (C1's probe: `set_group` between two root groups). Fix: one case in `qr_t18_a_move_of_any_group_above_the_entry_ends_the_ticket`, `begin_edit`, `set_group` to a sibling, `commit_edit`, expect stale |
| R4C2-2 | Info | Yes. A merge that points the Recycle Bin at the holding group puts the entry "in the bin" without a move; the ticket stays live. The shown value did not change, and FEA-10.14 binds to the value's source, not to the bin's meaning. State it, or hash the bin id later |
| R4C2-3 | Info | Yes. The revision is a SHA-256 copied into a plain `Vec` that is not wiped (`qr.rs:96`, `:131`). It never crosses the bridge. Anyone who can read this process's memory reads the open vault's values directly; the digest adds nothing |
| R3C2-3 | Info | Yes. Hidden to the icon, `qrInFront` answers yes; no menu reaches the shortcut because Larsal is then an accessory app with no menu bar (`WindowRules`). Stated, not tested. Mac QA |
| ParityFontTests/codeFont | Low | Yes. A Main test whose glyph measure depends on the one-time code's live digits; one guarded run of this story failed it at 0.1316 against 0.1278. This story does not touch that row or its font. Its owner pins the digits or the clock |
| MenuKeysTests/searchArrows | Low | Yes. A Main test that held a search field across a wait while another never-ordered window took the field editor; the test now takes the field again with a bound and still goes red with the search box's arrows removed. No product change; a real window has one key window |

None blocks this story.

## Rule 4 and rule 3, on the delta

- **Across the bridge.** `QrShown` crosses as the ticket number and the matrix (`Qr`, whose `Debug` hides its modules; `qr_t29…debug_hides_the_matrix`). `qr_share_png` returns PNG bytes only for a live Share consent, and no production route calls it (`qrShareRoutes` is empty). `qr_save_png` writes the file in Rust and returns nothing. No value, join text or revision crosses. A matrix or PNG of a value is that value: these are LD-220 crossings, the one value the user asked for, and the LD-220 and LD-198 wording rows below name them.
- **Logs.** No new log, print or `os_log` call in the delta; `Logger.app` and `message(_:)` moved into `Copy.swift` unchanged. `sourceScan` bans them in the QR sources. Rust errors are fixed messages with no value.
- **Files.** Only an explicit warned Save writes, in Rust, 0600, through `storage::write_export`, refusing a link at the target. `noWrites` lists the temporary, caches, saved state and run folders before and after show, resize, cancel and expiry: no new file holds the value or decodes to it. `WindowRules.attach` sets `isRestorable = false`.
- **Pasteboard.** No pasteboard word in the QR sources (`sourceScan`, S10 red). The session's own board is never written (`noWrites`). In the run's test attempt, the guard library logged 55 general-board lookups. Every one comes from AppKit's own code: 54 from its paste-verification telemetry and 1 from `NSApplication`'s first setup. The library had replaced both lookup methods in each process it loaded into, and the gate reads 0 bad. The build attempt and the format attempt logged 0, and the Rust lanes made 0 guard requests. The Builder's R2C2-6 row says the same of earlier runs.
- **Wiping.** `qr_wipe.rs` (QR-T29, native) searches all writable memory of the test process after request, checks, PNG, Save and release, for the join text, the working bits, the matrix, the RGBA rows and the PNG, with live controls. It passed in my run (1 test, 36.7 s) and in the guarded run (workspace 23.9 s, sync 19.3 s). Swift's copy of the matrix is released, not wiped, which FEA-10.10 allows; UniFFI's buffer on its way and other threads' stacks are not measured (the Builder's finding row).
- **Rule 3.** No new crate and no manifest change. `qr.rs` reaches hashing and secret types only through `larsal_crypto::hash` and `larsal_crypto::secret`. The QR crate stays imported only in `edit.rs` (`symbol()`, reached by `qr()` and `qr_eci26()`); LD-198's row must say so.

## The Checkers

| Round | C1 | Sensitive C2 |
|---|---|---|
| 1 | REQUEST_CHANGES, seal `39281e883eae2811ac0f23fe3bb94d594d34e1793dee310938e37b4e7f90ccbf` | APPROVE_EXACT_CANDIDATE, `d721f0098dd383aabeb7de86065c291e10715087079232676c82bdb05bb2a63b` |
| 2 | REQUEST_CHANGES, `ab06fa34f65f757c1355c30961b6597e0ab61c485686531c52594435613f165c` | APPROVE_EXACT_CANDIDATE, `34d55575d8c1a2f61d1115c8c4043d6a8998d9f954edf988bd56cf8703d72927` |
| 3 | REQUEST_CHANGES, `370f62b40dde3d982548e8b1bdc718f2f6644611bd3b2185ddeac327234bf44e` | APPROVE_EXACT_CANDIDATE, `2be2b8c1c8fe0b1714c3a0a09d490daa6fa865ba2bad0b98198730d7a64d0a92` |
| 4 | APPROVE_EXACT_CANDIDATE, 0 blocking, `c624217731ce0f8dd0405ae3fb327166bfedde5b53ac54525f5696f823d1b0a8` | APPROVE_EXACT_CANDIDATE, 0 blocking, `1ea1036065438f2da6aa1693bc6c98b5563a622e898af152e04d35d661f85e41` |

Round 4 approved tree bbbd48d5, the tree of 64d017d. Every round 1 to 3 finding is either fixed or carried as a row, in the Builder's proposed findings or on this page. Both round 4 Checkers proved the patch identity themselves. Neither read the tables commit; I did.

## Findings rows, mine

The lead numbers these.

| Finding | Severity | What | File, input, result | Status |
|---|---|---|---|---|
| V-1 (C1R4-1, R4C2-1) | Low | No test pins the holding group in the ticket's revision | `crates/larsal-ffi/src/qr.rs:108`. Mutant V16, `chain.iter().take(chain.len().saturating_sub(1))`: lib 22 of 22 and tests/qr 21 of 21 pass | Open. One test case, above |
| V-2 | Info | No test pins that a refused Show holds no ticket | `qr.rs:240-241`. Mutant V06, the hold before the size check: all pass. No output can follow: every export makes the payload again and passes it through `encode` (`qr.rs:293`), which refuses at `qr.rs:140` | Open. One assertion after a MSG-QR-TOO-LARGE show: no ticket held |
| V-3 | Low | The frame comparison is a stand-in, not BUILD-AND-VERIFY's parity report | `QrSnapshotTests.swift:59` asserts only a PNG over 2,000 bytes. The proposal frames are not in `manifest.json` and have no reference export | Open, with W-08 and the owner's proposal review (LD-363) |
| V-4 | Info | The briefed run-key.sb with only roots changed cannot run `tests/qr.rs` or `qr_wipe.rs` | It denies the target folder; 21 of 21 fail at `tests/qr.rs:29`. A later Verify or Checker needs the target/tmp line, as the tool's row has | Note for later briefs |
| V-5 | Info | Two of the Builder's proposed LD rows say no new grant came with the story | proposed-LD.md, rows "E21-S2 matrix and PNG crossings" ("no new grant") and "Merge step for the guarded check" ("No new grant"). The first run without the tables commit failed all 22 tests of `qr` and `qr_wipe` in both lanes. The merge needed four `programs.json` rows | Fix the words at merge: "Four `programs.json` rows (workspace and sync, `larsal-ffi/qr` and `qr_wipe`) give the two new test programs `harness-runtime-target-tmp.sb` with class session, the same as `larsal-ffi/edit`'s rows" |

## Rows the lead carried

LD-447 to LD-475 are the Builder's rows, adopted with this signature's one change (LD-476). LD-477 is the waiver, LD-478 the grant to qr and qr_wipe, LD-479 the frames rule. LD-220 (1) and LD-198 carry the amended words. F-371 to F-399 are the Builder's findings rows; F-400 to F-405 are the rows above, V-1 first. The story status line is in plan/epics.md.

## Limits of this signature

1. **Functional Share** is not proven anywhere: no route is in `qrShareRoutes`. The item, the warning, the consent and fail-closed paths are proven behind a fake presenter only. Required functional Share stays OPEN (LD-360), not passed by the disabled button.
2. **Mac QA and frames** need a visible window: VoiceOver, Escape and click-outside in a real key window, large text, the right-click menu as drawn, ⌃⌥⌘Q through the real menu bar, the Dock tile, a real Save panel, the Saved Application State folder, and a person's look at the frames. All wait for W-08 and the owner's go (rule 10).
3. **One decoder.** Every readback uses Core Image, the decoder the story names. No second decoder, phone or camera scan ran.
4. **Capture.** QR-T25 reads the window's guard property; no real capture ran (APP-10, FEA-10.21).
5. **Named-receiver enterprise joins** stay OPEN (LD-361).
6. **Swift mutants** are the Builders'. I read their raw logs where kept (rounds 2 and 4, and round 3's S31, S53, S66 to S88) and round 3's summary for the rest. I ran no Swift.
7. **Rust in my runs** used run-key.sb plus one target/tmp line, which allows the SecurityServer lookup the tool's row does not; the run's own lanes are the proof under the exact rows.
8. **arm64 only**, offline. The run's own stated limits apply (yanked status, advisory date).

## Evidence

| What | SHA-256 |
|---|---|
| fix.patch | `590a06efa1d6446db2a7e6ea0452b2d5258d96e737c1e35727a85fea5b40051b` |
| The lead's waiver file, `/private/tmp/larsal-m5-iuO5cjY0/waivers.json` | `15cc202dfa1f238af9c24544835f1ac9778e06019be5cabf2bf3974bb7926fae` |
| The Builder's CANDIDATE-NOTES.md | `594e99866e62ad90d1f4e0cf146e0938f2d075b7774c7a1d450cb13f13fbf7c4` |
| The Builder's proposed-LD.md | `70eec7cf9a957e55b5f00a82d7a09c34ca3e5c5ba3d0fe677bcbecab5a50f682` |
| The Builder's proposed-findings.md | `babcd3f4b05fea3afb0cbda25be64d9884ebc21b670ac4cc1a54904df34ca166` |
| Run `summary.txt` | `b978bb81f494e4366b4373d17ecf768be65b82ee07f70e815c43a1eaf4eed7cd` |
| Run `summary.json` | `40ff9b13d9ddcaef20ac4b77a8c66f0d3d651289c800fdc4450da4be99fedb85` |
| Run `test-names.json` | `16d5ddcc055e580f99223b55d2be1c09e6d68a553907bfcd0a9c6398464572aa` |
| Run `run-start.json` | `be95d158096cc5a275eadf0d31371f906300bbc5f95b39fc054d2138dd7322ba` |
| Run `results/rust.json` | `77e82b1725468923fa91ebbc621bf3d6702fcfd3d594a090166be33917cce42b` |
| Run `results/native.json` | `3db8b17acc6c47de486498b0afa9433d8e24ec085f5ed2e35f01f61ba8f0c6a0` |
| Run Swift result database | `b43e463f5b4dae2e10982aae208b0260f2a7158afd8ed5147d3b4d28ae164ad2` |
| Run Swift `xcode-test.stdout` | `eaf62fc3cdeb3f4b6cc3a94f5e8d0661e54cff6f632fab99c9a7fb0ecb8619c1` |
| Run APP-09 `app09.stdout` | `38742e7d7b028da8135449a38a9034e61f3a5fe48ed42665048e30a260e4e69d` |
| Run guard `general-board.log` | `6703d21b94ff04358d7d2600f406abfc3e8956b1144e9f049f3e37b44f8ca8a0` |
| Run admissions | `47e8d36445e9fe4c793316c3ad5e4b33c6980d7e5f017fd560d031572462809f` |
| Run `qr` stdout, workspace and sync | `4b87a6edc2e22c0d4323087191ae389f9a52859560f2404140550e251ee75da9`, `eba2c31c602807c8ec45570eaec3adfd8454005c4bb5672eb83f9f9ad340e622` |
| Run `qr_wipe` stdout, workspace and sync | `cfb6a1e73443cf1e56fa19e6e8957eabb24a265c2818220fac0644c7f7dad5c9`, `cd469984f71ee1eb2aa2dcdf3c195997d318d2c6bc7f211af07296fe870815ba` |
| Run `larsal_ffi` lib stdout, workspace and sync | `fea5dd1fdfde5969485df0c2c3066ccca8ed60106349a975873955620eb50bf0`, `7e38a29e6040254a261f3c5689b21f929c518a54d01a6684e1dfe04bc2d28fa4` |
| The first run of the same code, `summary.txt` | `e149d72d5c37c651982d5d744217c15ea4a07650126f1c64df841dff4244616e` |
| Verify's seal | `/private/tmp/larsal-e21s2-vr2-XoMy3m7I/FINAL-SEAL.json`; it hashes every file of the proof, scripts, profiles and logs named here |

## Report end

- Story: E21-S2.
- Files changed by Verify: none in the project. This page is proposed for `security/parity/E21-S2-show-as-qr.md`.
- Proof: this page; commit `e808d32db8d354ce9e0eb338d68f3b2a07e800c5`; guarded run PASS at `/private/tmp/larsal-gc-e808d32-KG04` with 4352 Rust tests, 462 Swift, 18 APP-09, 15 docs and 30 fuzz routes; 17 Rust mutants, 15 red.
- Open: checks 13 to 15; V-1 to V-5; the open rows in "The open Low and Info rows"; the Builder's open findings rows.
- Next step: the lead copies this page to `security/parity/E21-S2-show-as-qr.md`, sets E21-S2's status line, and adds the LD and findings rows, all in one commit. Then the lead runs the name guard.
