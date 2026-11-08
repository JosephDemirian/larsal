# E21-S3 `larsal show --qr`: Verify sign-off

Story: E21-S3 (plan/epics.md). Card: FEA-10 (FEA-10.22, FEA-10.23, QR-T26 to QR-T29, QR-T31), with INT-10. Decisions: LD-198, LD-361, LD-193, LD-340. Checkers: C1 and Sensitive C2, two rounds.
Date: 2026-11-08.
Role: Verify, in two passes. The first pass signed commit a53bf9a with limits: it proved the carried patch from a private clone, checked every moved pin, ran the run's own `larsal` binary against a demo vault under the guard profile and read every printed code back with a QR reader of its own. Its guarded run read FAIL by one Swift test outside the story (F-440). The second pass, on this page's amended form, proves the commit that landed with F-440's test fix, `ed97e9c3e0c5081c095b7f15508a7b4e2dec31fa`, and reads the lead's full guarded run of it, which is now the run of record. Neither pass changed product code, built anything or ran xcodebuild or cargo. The logs and scripts named here live in private folders under /private/tmp that do not last, so this page copies what must survive.

**Result: signed with limits.** Commit `ed97e9c3e0c5081c095b7f15508a7b4e2dec31fa`, six commits on Main dbe98a5: beb7418 (the larsal-qr crate and larsal-ffi), 7c973eb (the command line part), a53bf9a (the guarded tool's pins for E21-S3), then F-440's fix: bc180eb and 522afbd (Swift test code only) and ed97e9c (its pins). The guarded run of ed97e9c reads **Overall PASS**: Rust 4501 passed and 0 failed, Swift 462 of 462 with `QrFocusReturnTests/shortcutInTheEditor()` among them, APP-09 18, docs 18, fuzz 31 routes, 0 names lost, 2752.0 s of the 60-minute cap. Checks 1 and 2 hold: named tests ran and passed in that run, and the first pass's own runs of the built tool, read back by its own reader, give the same result. Check 3 holds once the docs commit adopts the `qrcode` row below: at ed97e9c, plan/architecture.md line 332 still says "larsal-ffi `edit.rs` only", and the code fact the new row states is proven by a test that ran.

`larsal show --qr` prints one selected value as a QR code in block characters. It needs a terminal large enough for the code, or `--stdout`, which writes plain cells to anything. It takes its matrix from the new crate larsal-qr, the same encoder the Mac app uses (E21-S2's, moved out of larsal-ffi with its `qrcode` calls unchanged).

## The whole difference

| Item | Result |
|---|---|
| Base | Main `dbe98a5ef05cccb3ce8b3d7ec99dc2b881d94c38` (E23-S3 Done, pushed) |
| Commits | `beb741836347b5cae5cb88ade2cfb9ecb3687be2` (larsal-qr and larsal-ffi), `7c973ebc7c7aacda5348dcfb05203af55a4e28c5` (larsal-cli and larsal-platform), `a53bf9a933e31076635cd86473c776ee5a2cfd93` (pins), `bc180ebba5859936e5b530e15ca9b81f9ab6157d` (F-440: the editor walk), `522afbd0043b7c6688fed2e3af0663078a4cba4c` (F-440: the list test's seams), `ed97e9c3e0c5081c095b7f15508a7b4e2dec31fa` (F-440's pins). Each has author and committer `Joseph Demirian <hello@JosephDemirian.com>` |
| The reviewed patch | fix.patch, SHA-256 `101698237e78797e8c661f42a5070e521a7c301f4c33eb08f26015048b9ee0a4`, 17 paths. With `git apply --cached` on 3d4ac36 it writes tree `8bf1eff7eefc434eba72782e06e9e87d07a48ccf`, the tree both round 2 Checkers approved |
| Carried onto Main | The same fix.patch, with `git apply --cached` and no three-way merge, on dbe98a5 writes tree `556cc12e2847655ab36899767c3d61dba7f5cbd6`. That is exactly the tree of 7c973eb. So the diff dbe98a5..7c973eb is the reviewed patch and nothing else |
| Path by path | The same 17 paths. 15 have the same blob before (3d4ac36 = dbe98a5) and after (8bf1eff7 = 7c973eb). The two files E23-S3 also changed keep exactly the reviewed lines: Cargo.lock 11 added or removed lines, crates/larsal-platform/src/macos/mod.rs 2, byte for byte the same as the reviewed diff's |
| The pins commit | a53bf9a changes one path, `scripts/guarded/tables/pins.json`. Tree `7eebaf785c9779ed15ae8fdc4e8c3d8e4b3e09b1` |
| F-440's fix on top | a53bf9a..ed97e9c changes exactly four paths: macos/LarsalTests/QrFocusReturnTests.swift, QrFocusTests.swift and QrSupport.swift, and scripts/guarded/tables/pins.json. No crate, Cargo file or product Swift file changes, so the Rust code of the story is the same at a53bf9a and ed97e9c. Tree of ed97e9c `a942f99dff90d66a8f0ddd0835acc196db7687bc`. Details in The F-440 fix below |
| What the story's patch touches | Cargo.toml, Cargo.lock; new crate crates/larsal-qr; crates/larsal-ffi (Cargo.toml, src/edit.rs, src/qr.rs); crates/larsal-cli (Cargo.toml, src/args.rs, src/commands.rs, src/main.rs, new src/qr.rs, tests/int10.rs, new tests/qr/mod.rs and tests/qr/read.rs); crates/larsal-platform (src/macos/terminal.rs `window_size`, src/macos/mod.rs). No path under macos/, spec/, plan/ or scripts/ |
| One note on the commits | beb7418 alone does not resolve: larsal-ffi's Cargo.toml inherits `larsal-qr` from the workspace, and the workspace entry comes in 7c973eb (V-1). Only the trees of a53bf9a and ed97e9c were run |

## The run of record: ed97e9c

The guarded tool ran the full check of ed97e9c once, from the lead's tool copy at /private/tmp/larsal-m8-xEAGZ9gp/c, with the baseline of 971870b's run. Root `/private/tmp/larsal-gc-ed97e9c-yCQR`. Verify read its results and did not rerun it.

| Item | Result |
|---|---|
| Overall | **PASS**, not partial, 0 failure lines. `summary.txt` SHA-256 `e2c0db50a2b98f5fe7d2b693dfab482d510dee6b139b42fee58aee6695b05ccb` |
| Time | 2752.0 s of the owner's 60-minute cap (3600 s). The 870.2 s hold wait before the native step is not counted, as the tool's `--hold` rule says (README). From start (09:28:42) to `summary.txt` (10:29:04) 3622.5 s |
| Commit and tree | The run's commit is ed97e9c (in `run-start.json`, `summary.json` and `test-names.json`). Its tree is `a942f99dff90d66a8f0ddd0835acc196db7687bc`, this commit's tree |
| Tool | 23 files. Each `tool_sha256` in `run-start.json` equals the file of `scripts/guarded` at ed97e9c (0 differ, none missing). Custody: 0 changed, 19 executables, 23 tool files. Tool drift: none |
| Tables | `pins.json` `575e869e7efe3864d31546949a3e3af8e1ea3b8c6e865118a18190ef9d55596f`, `programs.json` `1e79fb363aa353b0d212c6f8607c82ccf356340fe7e6a53dab3cc9330eee871f`, `native-expected.txt` `b0fd5b4cda44f7c3f73d1c6cc71387bbb7837b471a50bd79b2ab052d3af45142`, `routes.json` `a85702cf7688e34f0422632ea51317da28b27732764e9f4e98c83cf741e1567e`, `needs.json` `a02932df82e628e9e05f11bb5b46ad1d859a73634f2c9012b80b059d475d4ed6`: each the same in this commit and in the run's tool copy. Only `pins.json` differs from a53bf9a's run |
| Grants | 59 rows read, 0 withheld; `reviewed_commit` 522afbd |
| Lanes | source exit 0; static exit 0, 589.7 s; rust exit 0, 1080.4 s; native exit 0, 1440.5 s (the 870.2 s hold wait in it; A1 192.8 s, B1 311.6 s, G1 lint 4.3 s); docs exit 0, 165.9 s; fuzz exit 0, 321.8 s |
| Static | 18 of 18 steps. Names PASS, 12289 files, 19 vault files by name only. Unsafe count 509 in 21 crates (larsal-qr among them, 0 unsafe, `#![forbid(unsafe_code)]`). Advisories, bans, licenses and sources ok |
| Rust | 4501 passed, 0 failed, 101 ignored, 166 of 166 programs. Workspace 3545/0/85 (140 programs), sync 562/0/9 (17), net 74/0/7 (2), release 275/0/0 (6), release-browser 45/0/0 (1). Guard library requests 0 in every lane. All lanes reconcile PASS |
| This story's Rust programs | larsal-cli unit program (`workspace:larsal-cli/larsal`): 18 passed, 1 ignored; its three `qr::tests` names: `qr::tests::qr_t29_cli_release_leaves_no_value_bits_codewords_matrix_or_rows` ok, `qr::tests::fea_10_23_two_modules_a_cell_and_the_odd_row` ok, `qr::tests::qr_t29_child` ignored (it runs only as that test's child). int10 (`workspace:larsal-cli/int10`, its own row with the PTY line): 141 passed, 1 ignored; its 24 `qr::` names are 23 ok and `qr::qr_t29_b_child` ignored, "a child of qr_t29_b_the_matrix_and_the_join_text_wipe_on_drop", which is ok. larsal-qr has no test program of its own (`test = false`); larsal-ffi's `qr` and `qr_wipe` programs drive it, in both lanes: 44 of 44 names ok |
| Swift | The log reads "Test run with 462 tests in 68 suites passed after 302.432 seconds" and TEST EXECUTE SUCCEEDED. The bundle reads 462 passed, 0 failed, 0 skipped. The database holds 462 cases and 606 runs, 462 ok. No "Expectation failed" line in the log. By name: `QrFocusReturnTests/shortcutInTheEditor()` ok, passed after 9.819 s; `QrFocusReturnTests/textControlGetsFocusBack()` ok, 181.319 s; `QrFocusTests/listTakesFocus()` ok, 18.080 s. Suites QrFocusTests 278.3 s, QrFocusReturnTests 295.8 s. All 63 `Qr*` names ok, `QrReadbackTests` among them: the 1,000 Core Image readbacks of QR-T31 read codes made through larsal-qr |
| APP-09 | 18 passed, 0 failed |
| Docs | 18 passed, 0 failed, 23 result lines |
| Fuzz | 31 routes, all exit zero, fewest runs 2028, no new route |
| Test names | Baseline `/private/tmp/larsal-gc-971870b-yQ24/test-names.json` (SHA-256 `9fcd274cb1b290a2ef3ac767e5d929a66095620a1c87b9a4ce3cafd7e8f63b3d`), made from 971870b. 5073 compared, **0 lost**, 0 newly ignored, 0 waived, 27 new. Verify's own count from the two files agrees. The 27 are this story's: 24 int10 `qr::` names (with `qr_t29_b_child`) and 3 larsal-cli unit names (with `qr_t29_child`). `test-names.json` holds 5100 names: 4999 ok, 101 ignored, 0 failed. Against a53bf9a's run, one name changed state: `swift:QrFocusReturnTests/shortcutInTheEditor()`, FAILED to ok |
| Windows and guard | B1 took 102 window samples, no gate failure; A1, B1 and G1 left no descendant or survivor, changed no sentinel, and wrote no crash report of their own. The guard library saw 55 requests in B1, none bad, the same count as in the Builder's native run A of b78483e |
| Crash reports | 4 new, all on purpose (the guard's prompt and guard children); own and not on purpose: none |
| Limit the run states | Yanked status not proven for 11 crates, as the index is offline: aes-kw, aes-siv, bech32, chacha20poly1305, cmac, dbl, hpke, httpdate, scrypt, x25519-dalek, zeroize_derive. Advisories 1395, newest 2026-10-30 |

## The earlier run: a53bf9a (history)

The first pass read the guarded run of a53bf9a, from the lead's tool copy at /private/tmp/larsal-m7-NrAiUSYd/c, root `/private/tmp/larsal-gc-a53bf9a-SXtL`.

| Item | Result |
|---|---|
| Overall | **FAIL**, 2669.0 s of the cap (hold wait 90.0 s), not partial. All 8 failure lines are the native lane's one Swift test |
| The one failure | `QrFocusReturnTests/shortcutInTheEditor()` (QR-T01, FEA-10.3): `QrFocusReturnTests.swift:229` "Expectation failed: QrFocus.shared.held == button" (held is nil), then line 289; failed after 42.5 s, its suite after 330.4 s. The log read 462 tests in 68 suites, failed; the bundle 461 passed, 1 failed; the database 462 cases, 606 runs, 461 ok. These are F-440's lines; the same test failed the same way in the run of 971870b, before this story. Load 7.6 to 12.2 when sampled |
| Everything else | Commit and tree a53bf9a's (`7eebaf785c9779ed15ae8fdc4e8c3d8e4b3e09b1`); 23 tool files and 5 tables equal the commit; `pins.json` `4a953d1285e99cb4ed4672f02378c60177fee52c967e568fb3f933cb71bcf51b`; grants 59 read, 0 withheld. Static 18 of 18, names PASS. Rust 4501 passed, 0 failed, 101 ignored, 166 of 166 programs, with the same per-lane counts as the run of record. APP-09 18, docs 18, fuzz 31 routes (fewest runs 1606). Baseline 971870b: 5073 compared, 0 lost, 27 new |
| Its hashes | `summary.txt` `e4c6a26f16e8ef78cf2a0d227322498b609c141ea7e7dbb026f1e0be0bee81ea`, `summary.json` `16983e2a56467ba2495d5b00e8e103618512f68c44fb0407772e8b4f299cd096`, `test-names.json` `136f9219fe6ec5888fb11dbaeaaac44aea5af3a3963c5a8b3afd8138ab47371a`, `run-start.json` `25a89d2060966c47ddf1f31e8efbd2f3dc537b92081c5bcfb2783ed9a68f43e8` |

The story changes no Swift file, and the failure did not touch it. F-440's fix landed with the story, and the run of record above passes the same test.

## The story's checks

| # | Check (plan/epics.md, E21-S3) | Proof | Result |
|---|---|---|---|
| 1 | The printed blocks, turned back into a matrix by a test, give the value | In the run of record, int10: `qr::e21s3_a_printed_blocks_give_the_value` (pipe with `--stdout`, and a 40 × 80 pseudo-terminal with the colours), `qr::qr_t31_c_exactly_1272_and_1273_bytes` (1,272 bytes print and read back at version 40, 1,273 refuse), `qr::qr_t31_a_generated_passwords`, `qr::qr_t31_b_passphrases`, `qr::qr_t26_a…` to `qr::qr_t26_f…`, `qr::qr_t28_a_adequate_terminal_pty`. The test's reader (`tests/qr/read.rs`, from ISO/IEC 18004) is proven first: `qr::e21s3_reader_reads_e21s2_matrices_at_every_version` (versions 1 to 40, all 8 masks, broken modules refused), `qr::e21s3_reader_refuses_a_non_canonical_eci_designator`. All ok, as in a53bf9a's run. **Verify's own reader** (first pass), written for this sign-off and sharing no code with the test's: 9 codes printed by a53bf9a's run binary, read back to the exact demo bytes, ECI 26 then one byte segment, level H, the Reed-Solomon check of every block passing, format and version bits valid, quiet zone white, odd pad row white. Versions 1, 3, 4, 6, 9 and 12 (2 to 11 blocks; 8-bit and 16-bit counts): the Password (17 bytes), the Notes with line feeds (48), the `otp` field (84), a Unicode password (24), a 143-byte Unicode title, and the current one-time code, equal to text `show --totp`. The Rust code is the same at ed97e9c | Verified |
| 2 | It refuses to print to a pipe or a file unless asked | In the run of record, int10 `qr::e21s3_b_a_pipe_or_a_file_needs_stdout` (pipe and file refused with MSG-QR-CLI-PIPE, the file left empty; with `--stdout` the file and the pipe get the same cells), `qr::qr_t28_c_raw_output_and_the_note_with_q`, `qr::qr_t27_a_conflicts_are_refused_before_the_unlock`. All ok. **Verify's own runs** (first pass) of a53bf9a's run binary under run-key.sb, the demo vault rich-v3: without `--stdout`, stdout to a pipe, to a file, to /dev/null and with `-q`: exit 1, stdout empty, stderr exactly "larsal show: QR output needs a terminal. Use --stdout to allow a pipe or file." and no password prompt, so it refuses before the unlock. With `--stdout`: exit 0, stderr the prompt then MSG-QR-CLI-NOTE (with `-q` the note alone), stdout only the four cells and LF with no escape byte, and the same 1,352 bytes to a pipe, to a file and with `-q` | Verified |
| 3 | The `qrcode` crate's row in plan/architecture.md names larsal-cli too | At ed97e9c the row (plan/architecture.md:332) still reads "larsal-ffi `edit.rs` only". The row below names larsal-cli and must land in the docs commit. The fact it states is proven: int10 `qr::e21s3_c_qrcode_reaches_the_cli_through_larsal_qr` passed in the run of record (only larsal-qr lists `qrcode` in `[dependencies]`; larsal-cli lists larsal-qr); the manifests agree (larsal-ffi lists `qrcode` under `[dev-dependencies]` only, for `edit::tests::fea_10_8_eci_26_before_one_byte_segment_and_fea_10_7_setup_code_has_none`, `edit.rs:2785-2786`). The builder's mutant M26 (larsal-cli importing `qrcode`) goes red | Carried open to the docs commit. Closed when that commit holds the row exactly as below |

"Under the same rules as `larsal show` for secrets", checked too. In the run of record: `qr_t26_d_no_echo_prompt_on_a_terminal_pty` (the password prompt without echo), `qr_t27_b_disclosure_needs_s_or_one_field`, `qr_t27_c_field_errors_stay_int10`, `qr_t27_d_the_shell`, `qr_t28_b_small_or_unknown_terminal_pty`, `qr_t28_d_write_failures_exit_1`, all ok. In the first pass's runs: the default Password needs `-s` (`--qr --stdout` alone and `--qr --wifi` without `-s` give exactly MSG-QR-CLI-AUTH, exit 1, no prompt); `--stdout` without `--qr` and `--qr --all` give exactly MSG-QR-CLI-OPTIONS before the unlock; one explicit `-a Password` without `-s` prints the protected value as text Show does (FEA-10.22), and the QR code of it reads back to the same bytes; text `show -s` still prints to a pipe, unchanged.

Wiping (LD-361, per target), in the run of record: `qr::tests::qr_t29_cli_release_leaves_no_value_bits_codewords_matrix_or_rows` (the tool's own allocator: no copy of the value, the input bits, the interleaved codewords, the matrix or the printed rows after `larsal show --qr --stdout -s` of 1,272 bytes) and int10 `qr::qr_t29_b_the_matrix_and_the_join_text_wipe_on_drop` (larsal-qr's own wipe on drop, under the system allocator) ok; larsal-ffi's `qr_t29_native_release_leaves_no_input_bits_matrix_rgba_or_png` ok in both lanes. The order "wiped before output" is in the code but no test proves it (C1-F2, C2r2-1).

## How the first pass read the codes

`qrread.py` (SHA-256 in the first pass's seal): the four cells give two module rows each; the quiet zone of 4 must be white; the 15 format bits are read from both copies, which must agree and form a valid BCH word; for version 7 and up the version bits must match in both blocks; the data modules are read in the standard zigzag, skipping finder, timing, alignment, format, version and dark modules, and unmasked; the codewords are split into level H blocks and each block's error correction must equal the Reed-Solomon remainder of its data; the bit stream must be ECI (one-byte designator) then byte mode with its count, then zero fill and only 0xEC, 0x11 pads. It refuses everything else. A reader with a wrong table would fail the Reed-Solomon check, not return the demo value.

## The tables

The lead's commit a53bf9a changes `pins.json` and nothing else. The first pass checked every line against 7c973eb.

| Change | True for this commit? |
|---|---|
| `reviewed_commit` 4a405fe to 7c973eb; a new `reviews."E21-S3"` entry; no other review, `note` or `byte_checks` change | Yes |
| 59 rows before and after, none added or removed. 36 rows change: each moved pin is relabelled E21-S3, and no row is relabelled without a pin change | Yes |
| 39 pin changes: `crates/larsal-ffi` 983979f1… to `33f9b18cbd5b6da2e28168fbc6f0473c596bee70` in 30 rows; `crates/larsal-platform` b8094dac… to `77154b96f32927ce135bc6274f35c2d55ffb5c2f` in 3 (`net:larsal-platform/larsal_platform`, `workspace:larsal-platform/larsal_platform`, `workspace:larsal-sshagent/own_agent`); `Cargo.toml` 01d23aff… to `31738bcd8351ab2f449355566da00f0c856d033d` in 3 (`needs:larsal-window`, `needs:xctest-window`, `own_agent`); `crates/larsal-cli` dd369874… to `3b336bd0d0b6e9ce7ecaf06cc82a6712c7537aa2` in `workspace:larsal-cli/int10`; `Cargo.lock` 1ce8a384… to `07c6982c535fa3e019e0fcd693599557998b8bf5` in `own_agent`; and one new pin, `crates/larsal-qr` `9870bba6ef1fe89fd2f5536069527054a90f70b7` in `own_agent` | Yes. Each new value equals the git object of that path at 7c973eb, and at a53bf9a (0 differ) |
| `own_agent`'s `why` adds "larsal-qr," to the folders the workspace lane builds that no other row pins; no other `why` or `checks` text changes | Yes, by that row's own rule |
| Every pin of the new table equals the object at a53bf9a | Yes, 0 differ. No row pins a path the diff changed and kept its old value |

ed97e9c then changes `pins.json` for F-440 only (below). Every pin of the table at ed97e9c equals the git object at ed97e9c: 59 rows, 0 differ. So E21-S3's pins stand unchanged at ed97e9c.

No `programs.json`, `routes.json` or `needs.json` change was needed: the CLI wipe test is in larsal-cli's existing unit program and QR-T29 b in int10, and both ran under their rows in both runs.

## Rule 4 and rule 3, on the delta

- **Outputs.** The value goes only into the matrix; the matrix only into the rows; the rows only to stdout in one checked write. Errors are the card's fixed words, `larsal: ` with the encoder's or Show's fixed message, or "cannot write to standard output" with an io::Error. No clipboard, log, temp file or network call in the delta. The note goes to stderr before any cell.
- **Wiping.** The selected value is a `SecretString`, dropped right after `encode()` (`commands.rs:566`), with the vault this command unlocked (`:567`). The matrix is larsal-qr's `Matrix` over a `SecretBytes`, dropped once the rows are made (`qr.rs:97`). The rows are one `SecretBytes` of fixed capacity. `qrcode`'s own copies are freed through the tool's zeroing allocator (`main.rs:27-29`). QR-T29 proves all five gone once the command returns.
- **Rule 3.** One new crate, larsal-qr, with no new outside dependency: it uses `qrcode` (already approved, LD-198), larsal-crypto and larsal-model. It reaches wiping only through larsal-crypto's secret types. `#![forbid(unsafe_code)]`. The one new `unsafe` block is `window_size` in larsal-platform's macos/ module (TIOCGWINSZ), with its SAFETY note.
- **Zero knowledge (LD-340).** The command is local; nothing leaves the Mac. F-440's fix is test code only and adds no output path.

## The Checkers

| Round | C1 | Sensitive C2 |
|---|---|---|
| 1 | REQUEST_CHANGES (no CLI wiping proof), seal `bb63374a3d85326a06d727d0ddc5add2f512ad743034d15ad3319467f1d20c48` | APPROVE_EXACT_CANDIDATE with a merge gate, seal `e9981c3193071f2ba944c79ee04d8c82d4103744ad79dc34032480b60c45a36c` |
| 2 | APPROVE_EXACT_CANDIDATE, 0 blocking, seal `fe0ebaf05ff77a20ae4d5371a68904ebe8485e0386ac6a833c5fafdefffe429e` | APPROVE_EXACT_CANDIDATE, 0 blocking, seal `b448e71dd58422f7693ecaa4c57dd0d7429c308e520c8e524fc3f5a490094f6f` |

Round 2 approved tree 8bf1eff7, which is the reviewed patch on 3d4ac36. The Builder ran 40 mutants, 40 red; C1 ran its own (M1 to M8 and the ruling mutants), all red but M6 and M7, which are C1-F2; C2 ran its own, all red but V2, V4 (C2r2-1) and V5 (C2r2-2). C1's 1,248 planted cases passed, and its 33 values and 6 one-time codes printed by the tool equal base E21-S2's matrices module for module. Neither Checker read the carried commits or the tables commits; Verify did.

## The F-440 fix that landed with it

F-440: `QrFocusReturnTests/shortcutInTheEditor()` (QR-T01, FEA-10.3, E21-S2's test) failed in the guarded runs of 971870b and a53bf9a, the one failure of each, at lines 229 and 289.

**Cause, proved by the Builder.** `QrFocus` (macos/Larsal/QrWiring.swift) is one object for the whole process, and every QR button anywhere adds its id to `QrFocus.shared.there` when it appears. Suites run side by side on the main actor and meet at each await. The test walked that process-wide set as if it were its own window's, and its page wait (`there.count != 2`) could be satisfied by another suite's button before the page switch was laid out; so it walked the old page's button and another window's button, `held == button` failed at line 229, and the shortcut asked for Password (line 289). A second race of the same kind: `QrFocusTests/listTakesFocus()` gave `QrFocus` turns without holding QrSeams, while `textControlGetsFocusBack()` counts turns exactly.

**The fix (test code only).** `QrKeyWindow.layOut(after:)` (QrSupport.swift) makes a change and lays the window out with no await between, and keeps the QR button ids that appeared in that span as the window's `buttons`. `shortcutInTheEditor` places its host and switches to the advanced page through `layOut`, walks `host.window`'s buttons, drops the reset of the process-wide set and the count wait, and shows another window's QR button on purpose before its walks. `listTakesFocus` holds QrSeams. No product file, no test added, removed or renamed; every expectation stays.

**Other process-wide state, surveyed by the Builder** (suites meet only at awaits, so a value can change under a test only there):

| State | Can it fail like F-440? |
|---|---|
| `QrFocus.shared.there` | It did. Fixed: the editor test reads only its own window's buttons |
| `QrFocus.shared.turn`, `model`, `button` | Yes, by `listTakesFocus` giving turns without the seams (turn-red1..2). Fixed: it holds the seams. Pop-ups, whose closing gives a turn (QrPopup.swift:288), are shown only by seams tests |
| `QrFocus.shared.held` | No: after the fix nothing outside the seams moves focus onto a QR button |
| VaultModel QR seams (qrCenters, qrWindow, qrClock, qrSavePanel, qrShareRoutes, qrSharePresenter) | No: written only under QrSeams |
| NewVaultModel.openKeyFile, keyFileSavePanel, chooseFolder; AuxWindows.present | No: the same no-op answers, or swapped and used with no await between (DataSafetyTests, WindowFixesTests) |
| VaultModel.saveAsPanel; VaultSettingsModel reveal, export, preview and group-editor panels; KeyTouch.shared | No: each written by one serialized suite, or the same no-op |
| Clock.now | No: ParityTests and SnapshotTests set the same value |
| WindowRules.shared | No: swapped and restored with no await between (LD-241) |
| ScreenProtection.shared | No: ScreenProtectionTests/menuAction is synchronous and ends at false |
| Keyboard access (AppleKeyboardUIMode, volatile domain) | No: AccessWalk and QrFocusReturnTests both set 2; `realKeys` passes alone |

| Item | Result |
|---|---|
| Builder | Root /private/tmp/larsal-qrfocus-FvXUBkYi. Base 3d4ac36; candidate b78483e (commits 7c557de, the editor walk, and b78483e, the list test's seams), tree `102df59bd70bffce7a686b262056561848f4bed5`. fix.patch SHA-256 `bdeda39798bc81e6b5bf5e5c60345432ae5da130c4d94c818d4e54ec384e1aa5`, 3 files, +23 −9. source-seal.json SHA-256 `f8748db45a6b975597b48a12cffa23c4d152ed8e688c274646862e35c03317db` |
| Builder's probes (guarded native profile, offscreen, only the named tests) | Base, the test alone: pass (2.8 s). Base plus a probe that shows one other window's QR button once the editor window is up: red 3 of 3 (base-red1..3; the third with the full runs' exact signature, 229 twice then 289). The fix plus the same probe: green 3 of 3 (about 2.9 s each). Mutant, the walk put back to the process-wide set, no probe: red 2 of 2 (lines 228 and 288 of the new file), as the test now plants its own foreign button. The turn race: a probe gives one turn without the seams, red 2 of 2 on base in `textControlGetsFocusBack` (lines 44 and 59); under the seams green 2 of 2; the two real tests together pass; `realKeys` passes alone. Verify read each of these 17 logs' result lines |
| Builder's guarded native runs of b78483e | Run A, no load: native exit 0, Swift 462 of 462, APP-09 18 of 18, lint clean. Run B, 10 spinning threads: the same. Each NEEDS_REVIEW only because the running tool's `pins.json` differed from the commit's |
| Checker 1 | APPROVE_EXACT_CANDIDATE, 0 blocking; patch reproduced byte for byte; cause and repro checked; isolation surveyed across all suites. FINAL-SEAL.json SHA-256 `3e28e28c3d53ce872b2c54ad57520e0d0daaa1860206c5c5d0199b7afed84d0d`, REPORT.md `263e2d6f14985bdf3fc87b16af1a851f325d97e9cde0e80f3279b65d1f6a8fa6`. Its 35 evidence hashes still match their files |
| Checker 2 (rule 10 and product safety) | APPROVE_EXACT_CANDIDATE, 0 blocking; no product code, the one new window borderless at −20000, never ordered or made key; no pasteboard call added. FINAL-SEAL.json SHA-256 `b7d624b1987725b4f492417bf5bbee6e1282da5a6d01ae8c0b1520ee529e306d`, REPORT.md `db46889c231e54710708828f30f09a0f6bee44657d682b563361beab8c6d2fd4`. Its 28 evidence hashes still match their files |
| Carried onto Main | macos/ is the same tree (`9c99689e`) at 3d4ac36 and a53bf9a, so no merge. bc180eb changes QrFocusReturnTests.swift and QrSupport.swift; its macos/LarsalTests equals the builder's 7c557de (`702cd5e8`). 522afbd changes QrFocusTests.swift; its macos/LarsalTests equals b78483e's (`3b65ead7`). At ed97e9c the three files are byte-equal to tree 102df59b: blobs `8e9071026ebacdf2cf477c25e960af70a09ed3ec`, `89a3aa09c492e36f5c768c1a88bba3e9b2c091ae`, `eeb1f7f9dd79e87440262de859d648291e293f21`, SHA-256 as in source-seal.json. macos/Larsal (`35a15b68`) and macos/Larsal.xcodeproj (`1541b80c`) do not change |
| Tables (ed97e9c) | `pins.json` only. `reviewed_commit` 7c973eb to 522afbd; a new `reviews."F-440"`; six rows move one pin each, `macos/LarsalTests` 688a6b3265db2fce413a8647f484c6e3c6e27a88 to 3b65ead715ed8ca2df103596eb6142432e973974, and are relabelled F-440: `needs:unix-bind`, `needs:unix-connect`, `needs:xctest-lsd`, `needs:xctest-nsird`, `needs:xctest-pasteboard`, `needs:xctest-window`. No other pin, `why`, `checks`, `note` or `byte_checks` changes. Each value equals the object at ed97e9c. `native-expected.txt` stays `462 18` |
| The run of record | Overall PASS; Swift 462 of 462; `shortcutInTheEditor` ok after 9.819 s, `textControlGetsFocusBack` ok after 181.319 s, `listTakesFocus` ok after 18.080 s; 0 names lost |

Checker notes, judged: C1-1 and C2-1 (the editor test no longer sees an entry-page button that outlives the page switch) and C1-3 (`textControlGetsFocusBack` line 59 does not assert the list's turn) are real test-power gaps, Low and Info. C1-2 and C2-4 (a pop-up left open by ParityEditorPagesTests/wifiQr, or by EditorSnapshotTests on a failure, could give a turn outside the seams) are real but unlikely, Info. C2-2 (`QrFocus` is process-wide) is a design note, Info, merged with the Builder's `held` row. C1-4 (the `realKeys` alone run used the build of the editor fix) needs no row: `realKeys` is the same in both builds, as b78483e adds only three lines to `listTakesFocus`. C2-3 (native-only runs passed on base too, so the full run decides) is answered by the run of record. The rows are in the lead's copy of this signature's proposed rows.

## The open and carried rows

| Row | Severity | Safe to leave open? |
|---|---|---|
| C1-F1 = C2r2-3 | Low | Closed by the docs commit: the `qrcode` row and the LD-198 words below |
| C1-F2 = C2r2-1 | Low | Yes. The code drops the value and the matrix before the note and the write (`commands.rs:566`, `qr.rs:97`); the test proves them wiped once the command returns, not the order. FEA-10.23 asks only that Rust buffers drop on success. The LD-198 Secrets words below say exactly that |
| C2r2-2 | Info | Yes. QR-T29 runs the `-s` path only; `-a`, `--totp` and `--wifi -s` reach the same `drop(value)`, and the join text's own wipe is QR-T29 b |
| C2r2-4 | Info | Yes. Two comments leave out larsal-ffi's dev-only `qrcode` import: `Cargo.toml:89` "larsal-qr only (larsal-ffi and larsal-cli use it; E21-S3)" and `crates/larsal-qr/src/lib.rs:4` "The only crate that imports `qrcode`." The LD-198 words below state it right |
| C2r2-5 | Info | Process. C2 ran heavy steps while BUSY-native was present; its results are independent of timing. No row |
| Builder rows 2 to 6 | Info | Yes, as stated: flush-only failure untested; fd 2 closed at exec; `--wifi -s` on a non-Wi-Fi entry; the PTY lane; QR-T29's span sizes |
| V-1 | Info | Yes. beb7418 alone does not resolve (above). A bisect across it fails at that one commit |
| V-2 | Low | Closed with F-440: the run of a53bf9a read FAIL by F-440's Swift test alone; its fix landed in this commit and the run of record passes it. No row of its own |
| V-3 | Info | Yes. AGENTS.md's Rust crates row lacks larsal-files (E22) and larsal-folders (E23), as it did before this story. This story adds only larsal-qr |
| F-440's checker notes | Low and Info | Yes. Test-power gaps and design notes in the QR focus tests, none in product code (The F-440 fix, above) |

None blocks this story.

## Words adopted with this signature

The Builder's proposed-cards.md (SHA-256 `4b38790cc8e19587c15e3ad4b06588988698baa4e4ae124e6dc574de6d1485b4`) gives each place, its current words and the new words. Every "current" text it names is still on Main at ed97e9c, word for word (ed97e9c changes no file under plan/, spec/ or AGENTS.md since a53bf9a). The first pass adopted its items as written, with two changes:

1. The `qrcode` row: "which larsal-ffi (…) and larsal-cli (…) call" becomes "which larsal-ffi (…) and larsal-cli (…) reach": larsal-cli calls `encode()` and `join_text()`, not `symbol()`. The row is at line 332 now, not 300.
2. LD-198's Secrets part: its last sentence becomes "In the `larsal` tool the code drops the selected value and the matrix before it writes the note and the cells, and drops the rows of block characters after one checked write; QR-T29 proves each wiped once the command returns, not that order (C1-F2, C2r2-1). What the terminal, a pipe or a file keeps after that is outside Larsal (MSG-QR-CLI-NOTE)."

The exact words are in the lead's copy of the first pass's proposed rows; the new `qrcode` row is:

| QR symbols (FEA-04.23, FEA-10, D-04-9) | `qrcode` =0.14.1 without default features (no `image`, `svg`, `pic`: the module matrix only; imported only by `larsal-qr` `src/lib.rs` `symbol()`, which larsal-ffi (the Mac app's authenticator setup code and Show as QR Code) and larsal-cli (`larsal show --qr`, E21-S3) reach: larsal-cli reaches the matrix through larsal-qr, never by importing `qrcode`; larsal-ffi keeps it as a dev-dependency for one test; MIT OR Apache-2.0, no dependencies, no `unsafe`, no build script; passively maintained, 0.14.1 of 2024-07-05 the newest; the matrix and the join text larsal-qr hands out are a `SecretBytes` and a `SecretString`, wiped on drop; the crate's own copies of the secret are freed unwiped and wiped by the zeroing allocator (LD-193) of the program: the `larsal` tool and larsal-cli's unit test program (larsal-cli `main.rs`) and the larsal-ffi library with every program that links it (the Mac app, larsal-ffi's test programs) install it; larsal-cli's `int10` test program links larsal-qr without it and encodes demo values only; AT-J03 signed with conditions by the E5-S5 Checker 1 and co-signed by the lead, LD-198, its reach amended for E21-S3) |

## Limits of this signature

1. **Check 3 is a words check.** It holds only on the docs commit that carries the row above; the lead greps that commit for `larsal-cli` in the `qrcode` row and runs the name guard.
2. **The CLI runs and the reader** of the first pass used a53bf9a's run binary (SHA-256 `62ffb1246fa4a126693c368d15fef65073161046859b200f38e01660687a40a3`) under run-key.sb with only the roots changed, stdin and stdout on pipes and files. ed97e9c's run built its own binary (`98c1da7799f3c73071eb3eb6fc5ed9bc56d5ec34fffbe1c812b76aaffaaba4d6`) from the same Rust code (no crate or Cargo file changes a53bf9a..ed97e9c); the second pass did not run it. Terminal cases (the colours, the size rule, the no-echo prompt) come from the run's PTY tests only; run-key.sb has no PTY line.
3. **One reader of Verify's**, level H only, as the encoder uses only H. No phone or camera scan ran.
4. **Wiping order** is read from the code, not tested (C1-F2, C2r2-1). The fd 2 closed at exec case prints with exit 0 and the note on /dev/null (Builder row 3).
5. **What the terminal keeps** (scrollback, logs, recordings) is outside Larsal, as MSG-QR-CLI-NOTE says.
6. **F-440's closure** rests on the Builder's probes (red on base, green with the fix, mutants red), two native runs of the candidate (one under load) and one full guarded run of ed97e9c. A load-dependent flake can be shown absent only for the runs made.
7. **The time cap** is the tool's count, 2752.0 s; the 870.2 s hold wait is outside it by the `--hold` rule, so the run took 3622.5 s from start to summary.
8. **arm64 only**, offline. The run's own stated limits apply (yanked status, advisory date).

## Evidence

| What | SHA-256 |
|---|---|
| Story fix.patch | `101698237e78797e8c661f42a5070e521a7c301f4c33eb08f26015048b9ee0a4` |
| The story Builder's CANDIDATE-NOTES.md, proposed-cards.md, proposed-LD.md, proposed-findings.md, source-seal.json | `6d69e08e05800967254e8f0169783a71e57db0a05ebaf88963cde67ad7174cb3`, `4b38790cc8e19587c15e3ad4b06588988698baa4e4ae124e6dc574de6d1485b4`, `24b0cb89706c1d81186c3f7ff9eb259fae75d45a87c6629e5ddcd0e494f74bc4`, `688b5afd33ff3c3eedee208b7355d03faacd498b24f88f5e0d7a51271f1f2f42`, `72817a53f9e1714d32ab5447015d3887d5624fb55bb5d09be472360bcadcc9b0` |
| Story round 2 C1 and C2 REPORT.md | `589bf0b4ebd525db8454dfd1d05d54064b54dc136c7edb4ea634e8dba4595634`, `da11412a85fc3acdc7768c3675ddb0b0f5563adc561e0357fbf187634d403d6b` |
| Run of record (ed97e9c) `summary.txt`, `summary.json`, `test-names.json`, `run-start.json` | `e2c0db50a2b98f5fe7d2b693dfab482d510dee6b139b42fee58aee6695b05ccb`, `5989ee9a8c850e9ae4b691877777d14322935d2c182f3e759b3c26c4cc586705`, `c193f11e6586618b74bb637584f52e670011be7455a6cb767321b6ba3f93d465`, `cbf9652e1ba27cbe76d21a732038276bf504e365012bd65b513796bad4de2455` |
| Run of record `results/rust.json`, `native.json`, `docs.json`, `fuzz.json`, `static.json`, `source.json` | `d3ed5864e3b511d976994c7c3e9bca61f820b2250d558774c6b8ab3bcf02e729`, `234816afee71ef5061c0132316ad6234e2879ccf6b33d4628e25ee345283c574`, `3dca3f14d88b3b69848fa8827cd09f7cbf1081ac5bf35157791ee7b9283c681f`, `9b0f02c819807be2be6695a8165ec69b7189e386983b497c5c69c66ead3ad45a`, `6b4d89bbb3bc0a299426a72f4bb6067bc52edc01d9c522a83be766a47a627e52`, `69c3e06b6328e63af80d7d1ae5df6c7591b0ccdb8995c3e6954b2c880d40f183` |
| Run of record larsal-cli unit stdout, int10 stdout | `9339dd43a7570f0528b07803596402d8250bcb12c5bd1e746e76607ca358a645`, `02169ce4803dc5a9ef7625c4bb414191142cd6bc0af286f95d5828c9d9738d26` |
| Run of record Swift `xcode-test.stdout`, `results.stdout`, `app09.stdout` | `784919c864e9bb1af8119228488cd88d47cb93c56bc9545cab00f9a1a4627b2f`, `0d073d50a20dba74b0fdaa64a90ccf0eb47339d2fa1b99399f7dded090f507c0`, `40d3f97c0e212c5d4e43269460f6c9da5d296628996246e560c97d9f7a26f99a` |
| Earlier run (a53bf9a) `summary.txt`, `summary.json`, `test-names.json`, `run-start.json` | `e4c6a26f16e8ef78cf2a0d227322498b609c141ea7e7dbb026f1e0be0bee81ea`, `16983e2a56467ba2495d5b00e8e103618512f68c44fb0407772e8b4f299cd096`, `136f9219fe6ec5888fb11dbaeaaac44aea5af3a3963c5a8b3afd8138ab47371a`, `25a89d2060966c47ddf1f31e8efbd2f3dc537b92081c5bcfb2783ed9a68f43e8` |
| Earlier run Swift `xcode-test.stdout` (the failure) | `2d00fa94e4687761fa82f608664116e7278931f2163b17a40f1aa815208465bf` |
| Baseline (971870b) `test-names.json` | `9fcd274cb1b290a2ef3ac767e5d929a66095620a1c87b9a4ce3cafd7e8f63b3d` |
| a53bf9a's run `larsal` binary, as the first pass ran it | `62ffb1246fa4a126693c368d15fef65073161046859b200f38e01660687a40a3` |
| F-440 fix.patch, source-seal.json, CANDIDATE-NOTES.md, proposed-findings.md | `bdeda39798bc81e6b5bf5e5c60345432ae5da130c4d94c818d4e54ec384e1aa5`, `f8748db45a6b975597b48a12cffa23c4d152ed8e688c274646862e35c03317db`, `d497b937baab3dc54c2c614b5c4c28d1ecc2377735e19c7f9a80fbc4be66d892`, `f6282a973d502881342e72c9d704c4c9b50a45c641f18e1cb423777bd4f22461` |
| F-440 Checker 1 and Checker 2 FINAL-SEAL.json | `3e28e28c3d53ce872b2c54ad57520e0d0daaa1860206c5c5d0199b7afed84d0d`, `b7d624b1987725b4f492417bf5bbee6e1282da5a6d01ae8c0b1520ee529e306d` |
| First pass's seal | `/private/tmp/larsal-e21s3-vr-in41rdA7/FINAL-SEAL.json`, SHA-256 `23e234cfd9fdaa83245b9efe9d4ed5a8cb2244e5df9432efa6d9a0a1fb47bbdd`; its 133 hashes matched their files when the second pass checked them at 09:42. The run root of a53bf9a was removed later that morning; the first pass's copies of its summary, test names, run start and results, in that pass's proof/run, keep the sealed hashes |
| Second pass's seal | `/private/tmp/larsal-e21s3-vr2-3RgZpE4K/FINAL-SEAL.json`; it hashes every file of its proof named here |

## Report end

- Story: E21-S3, with F-440's fix.
- Files changed by Verify: none in the project. This page is proposed for `security/parity/E21-S3-show-qr-command-line.md`.
- Proof: this page; commit `ed97e9c3e0c5081c095b7f15508a7b4e2dec31fa`; guarded run at `/private/tmp/larsal-gc-ed97e9c-yCQR`, Overall PASS, Rust 4501 passed and 0 failed, Swift 462 of 462, APP-09 18, docs 18, fuzz 31 routes, 0 names lost, 2752.0 s; the run of a53bf9a kept as history (FAIL by F-440 alone); the first pass's CLI runs and reader, all pass.
- Open: check 3 until the docs commit; C1-F2 = C2r2-1, C2r2-2, C2r2-4, the Builder's rows 2 to 6, V-1, V-3; F-440's checker notes as their own rows.
- Next step: the lead puts this page at `security/parity/E21-S3-show-qr-command-line.md` and, in the same docs commit, adopts the `qrcode` row, the LD-198, FEA-10.10, INT-10, architecture and AGENTS.md words, sets E21-S3's status line, closes F-440, and adds the LD and findings rows; then runs the name guard and checks that the `qrcode` row names larsal-cli.
