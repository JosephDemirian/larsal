# E7-S7c Extension core and channel, Chrome build: Verify sign-off

Story: E7-S7c (plan/epics.md), amended by LD-278 (3). Cards: INT-11 (INT-11.1 to INT-11.12, INT-11.42, INT-11.43, T01, T07, T14, T15, T20, T21), INT-01 (INT-01.5, INT-01.8 to INT-01.10, INT-01.20 to INT-01.28, INT-01.44, INT-01.46, INT-01.49, INT-01.50, T79). Decisions: LD-272, LD-274, LD-276, LD-278, LD-340. Checkers: C1 and the channel's C2, three rounds.
Date: 2026-11-09.
Role: Verify. It proved the carried patch from a private clone, checked every moved pin, read the lead's full guarded run of the commit, and ran the extension's own suites, which the guarded tool does not run, from its clone: headless Chrome only, behind the window guard, against the test Larsal built under the guard profile. It changed no product code and ran no xcodebuild. The logs and scripts named here live in a private folder under /private/tmp that does not last, so this page copies what must survive.

**Result: signed with limits.** Commit `f9c45cc83c3260d56fcc9a3bfbc91694e5281a46`, two commits on Main baa9452: 2ed2b0b (the story) and f9c45cc (the guarded tool's pins). The guarded run of f9c45cc reads **Overall PASS**: Rust 4501 passed and 0 failed, Swift 462 of 462, APP-09 18, docs 18, fuzz 31 routes, 0 names lost against ed97e9c, 2745.0 s of the 60-minute cap. The extension's suites, run by Verify: test_extension.py 34 of 34 in two whole runs (run 1 with one tearDownClass rule-10 note naming two of the owner's own apps, run 2 clean), test_driver.py 39 of 39, test_channel_vectors.py 2 of 2 on its first run, pure_test.js under macOS's jsc all passed. Every story check has a test that ran and passed. Two checks are carried as the reviews ruled: the run against Larsal.app itself (the tests ran against the test Larsal, `crates/larsal-browser/examples/test_larsal.rs`), and T77.

The background keeps one native messaging port to larsal-bridge, says hello on connect and after each `onDisconnect`, makes a fresh X25519 key pair per hello in WebCrypto, derives one request key and one reply key with HKDF-SHA256 (non-extractable, encrypt only and decrypt only), matches each reply by `req`, type and nonce, turns Larsal's notices into one `{"notice":"state"}` to its own pages, and takes runtime messages only through one routing table that classes each sender from `MessageSender` alone. The identification key is a non-extractable X25519 pair in IndexedDB, written with `add`, so the first stored key wins.

## The whole difference

| Item | Result |
|---|---|
| Base | Main `5a6032b280bcc5995bc75bff085027098b7e6ea5` for the reviews; Main `baa9452ccaf9070b1f37654f6554469ff42e88c3` for the merge (5a6032b..baa9452 changes only plan/epics.md and spec/decisions.md) |
| Commits | `2ed2b0b5423df78ef796d4e93e17274936d47e03` (the story, tree `c26ab2b0cda5423975ab85593e66e75a435dfe1f`), `f9c45cc83c3260d56fcc9a3bfbc91694e5281a46` (pins, tree `b914209b68796c4b703180d7525b8a8065f4f677`). Each has author and committer `Joseph Demirian <hello@JosephDemirian.com>` |
| The reviewed patch | fix.patch, SHA-256 `65299b0afa7dc3a80c39da9f0fc5526b70e66265efe6085e97f4c181fcf39fbe`, 15 files, +2377 −10. Both round 3 Checkers: on 5a6032b it gives tree `8199972c8a40af745a5d54ed4723545d1f4b1aed` |
| Carried onto Main | `git cherry-pick --no-commit 2ed2b0b` on a fresh branch at 5a6032b writes tree `8199972c8a40af745a5d54ed4723545d1f4b1aed`, the approved tree. `git diff 5a6032b 2ed2b0b` without plan/epics.md and spec/decisions.md hashes to `65299b0a…fbe`, the reviewed patch's own SHA-256. baa9452..2ed2b0b changes the same 15 paths and no other |
| Subtrees | `extension` `109018cefc0108122e54344b7efad689ebd654f5` and `crates/larsal-browser` `a2a492773529438e6c359af0fab8aacddbc5de02` at 2ed2b0b and at f9c45cc, as both Checkers recorded |
| What the patch touches | New: extension/background.js, channel.js, idkey.js, routes.js, wire.js, manifest.json.in, build.py, _locales/en/messages.json, test/test_extension.py, test/pure_test.js, test/page/options.html, crates/larsal-browser/examples/test_larsal.rs. Changed: extension/test/driver.py, test_driver.py, test_channel_vectors.py. No path under macos/, spec/, plan/ or scripts/ |
| The tables commit | f9c45cc changes `scripts/guarded/tables/pins.json` only (below) |

## The run of record: f9c45cc

The guarded tool ran the full check of f9c45cc once, from the lead's tool copy at /private/tmp/larsal-m10-PTnYPpnd/c, with the baseline of ed97e9c's run. Root `/private/tmp/larsal-gc-f9c45cc-vGFs`. Verify read its results and did not rerun it.

| Item | Result |
|---|---|
| Overall | **PASS**, not partial, 0 failure lines. `summary.txt` SHA-256 `1edc9c3901d8201e57e28aa66dc151139a49b124cc44afbff98565e0d2c00f65` |
| Time | 2745.0 s of the owner's 60-minute cap (3600 s); hold wait 90.0 s, not counted (the tool's `--hold` rule); 2835.5 s from start (00:41:58) to the end |
| Commit and tree | f9c45cc in `run-start.json`, `summary.json` and `test-names.json`; tree `b914209b68796c4b703180d7525b8a8065f4f677`, this commit's tree |
| Tool | 23 files. Each `tool_sha256` in `run-start.json` equals the file of `scripts/guarded` at f9c45cc (23 of 23). Custody: 0 changed, 19 executables, 23 tool files. Tool drift: none. Nothing left under the root; no source change; no sentinel changed |
| Tables | `pins.json` `16ff9ca7aeb27049ce190d925adf84a8fd862b114213bd0e656f139f946c64c6`, `programs.json` `1e79fb363aa353b0d212c6f8607c82ccf356340fe7e6a53dab3cc9330eee871f`, `routes.json` `a85702cf7688e34f0422632ea51317da28b27732764e9f4e98c83cf741e1567e`, `needs.json` `a02932df82e628e9e05f11bb5b46ad1d859a73634f2c9012b80b059d475d4ed6`, `native-expected.txt` `b0fd5b4cda44f7c3f73d1c6cc71387bbb7837b471a50bd79b2ab052d3af45142`: each the same in this commit and in the run's tool copy |
| Grants | 59 rows read, 0 withheld; `reviewed_commit` 2ed2b0b |
| Lanes | source exit 0; static exit 0, 572.0 s; rust exit 0, 1088.9 s; native exit 0, 671.0 s (A1 197.3 s, B1 327.4 s with 108 window samples and 0 gate failures, G1 4.5 s); docs exit 0, 170.0 s; fuzz exit 0, 322.8 s |
| Static | 18 of 18 steps. Names PASS, 12302 files, 19 vault files by name only. Unsafe count 509 in 21 crates. Advisories, bans, licenses and sources ok |
| Rust | 4501 passed, 0 failed, 101 ignored, 166 of 166 programs. Workspace 3545/0/85 (140 programs), sync 562/0/9 (17), net 74/0/7 (2), release 275/0/0 (6), release-browser 45/0/0 (1). Guard library requests 0 in every lane |
| larsal-browser's programs | The three rows whose pin moved ran at the new pin: `workspace:larsal-browser/int01` 102 ok, `int01_setup` 28 ok, `larsal_browser` 4 ok. Also int02 59 ok, int03 42 ok and 3 ignored, fuzz_seeds 2 ignored, release-browser int03 45 ok |
| Swift | Log 462 tests in 68 suites, passed; bundle 462 passed, 0 failed, 0 skipped; database 462 cases, 606 runs, 462 ok |
| APP-09 | 18 passed, 0 failed |
| Docs | 18 passed, 0 failed, 23 result lines |
| Fuzz | 31 routes, all exit zero, fewest runs 2487, no new route |
| Test names | Baseline `/Users/josephilhan/Documents/Code/larsal-checkpoints/resume-2026-11-06/test-names-ed97e9c.json` (SHA-256 `c193f11e6586618b74bb637584f52e670011be7455a6cb767321b6ba3f93d465`, made from ed97e9c). 5100 compared, **0 lost**, 0 newly ignored, 0 waived, 0 new. `test-names.json` holds 5100 names: 4999 ok, 101 ignored |
| Crash reports | 4 new, all on purpose (the guard's prompt and guard children); own and not on purpose: none |
| Limits the run states | Yanked status not proven for 11 crates (the index is offline): aes-kw, aes-siv, bech32, chacha20poly1305, cmac, dbl, hpke, httpdate, scrypt, x25519-dalek, zeroize_derive. Advisories 1395, newest 2026-10-30 |
| What it does not run | The extension's suites (no lane in scripts/guarded) and the `test_larsal` example (built by `cargo test` as an example, never run). So 0 new names: none of this story's tests is in the run of record. Verify ran them, below |

## The extension's suites, run by Verify

From the private clone at f9c45cc, after the run's native step and while neither hold file existed. Verify put its own mark (`BUSY-native` holding "verify e7s7c", made with noclobber) for each run and removed it after, checking it still held those words. Python was the pinned `Python3.framework/Versions/3.9` with `-B -I`; HOME, TMPDIR, the cargo folders, `CFFIXED_USER_HOME`, `CLANG_MODULE_CACHE_PATH` and `SWIFT_MODULECACHE_PATH` were under Verify's root; Chrome 156.0.8078.81, the installed one, headless, through E7-S7b's driver with its throwaway profile, test HOME, mock keychain and window guard.

| Step | Result |
|---|---|
| Build | `cargo build --offline --locked -j 3 -p larsal-bridge`, then `-p larsal-browser --example test_larsal`, each under compile.sb (the E16-S7b guard profile with only the root changed), CARGO_HOME empty at the start (the repo vendors every crate). Both exit 0. SHA-256: larsal-bridge `5c5c19757d71bfdb400e2a79025a516039f89d8a6d22e1be5c3df9b0438fe975`, test_larsal `6a5afc421dd7e90fea84eef0fd9572d942c221198b6fcafc8b12e647d6f48a8c` |
| `test_larsal vectors` alone, under run-key.sb | exit 0. C `8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a` and A `de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f` (RFC 7748's Alice and Bob public keys); CV-4, CV-5, CV-6 and CV-9 equal INT-01.50's table byte for byte |
| pure_test.js under `/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc -m` | exit 0, 16 `ok` lines, "pure: all passed", no FAIL |
| test_extension.py, run 1 (load about 7.5) | 34 tests ran, 34 ok (PackageChecks 9, ChromeWithLarsal 24, ChromeWithoutX25519 1), 65.5 s. One `ERROR: tearDownClass (ChromeWithLarsal)`: "rule 10: the frontmost app changed from 3265 to 15780 (if you switched apps, run again)". pid 3265 (parent pid 1, started 00:39:51) and pid 15780 (parent pid 1, started 00:51:24) are two browsers of the owner's under /Applications, both started before this run (01:30:07) and not by it. The tool says run again; Verify did |
| test_extension.py, run 2 (load about 9.1) | 34 of 34, **OK**, 63.5 s, no error |
| test_driver.py | 39 of 39, OK, 20.3 s |
| test_channel_vectors.py (T79) | Run 1: 2 of 2, OK, 5.1 s (`test_t79_webcrypto_gives_int_01_50s_bytes`, `test_the_run_ends_with_the_keychain_check`). It is known to be flaky (below); it passed at the first try here, so no second run was needed |
| LD-276, LD-278 (3) | `driver.check_keychain_log` ran in every suite's tearDownModule and raised nothing; `test_the_suite_run_ends_with_the_keychain_check` ok |
| Network | The per-test lsof check (loopback only) raised nothing; `test_the_loopback_check_reports_any_other_address` ok |
| The owner's files | lstat (inode, mtime, ctime) of ~/Library/Developer, its Xcode/DerivedData, ~/.swiftpm, ~/Library/Caches/org.swift.swiftpm, ~/Library/org.swift.swiftpm, ~/Library/Caches, Chrome's own profile folder and preferences, ~/Library/Keychains, ~/.cargo and ~/.cargo/registry: the same before the first run and after the last. ~/Library/Keychains' folder time was 01:20:07, before Verify's first run and inside the guarded run's native step; Verify's runs did not move it, and the run's own sentinels do not include it |
| Leftovers | No /tmp/larsal-ext-*, /tmp/larsal-chrome-* or /tmp/larsal-guard-* folder before or after; no Chrome, host or test Larsal process left. No window shown, no focus taken by the run (run 2 clean), no clipboard used |

## The story's checks

| # | Check (plan/epics.md, E7-S7c) | Proof | Result |
|---|---|---|---|
| 1 | In headless Chrome through E7-S7b's driver, against Larsal with a test settings file and a test HOME: hello, connect (Larsal's dialog answered by a test seam), check and status work from a test page of the extension | test_03 (hello, `check` with the proof, `status` from the test options page; `check` error 8 before a connection; the vault list) and test_04 (`popup.connect`, Larsal's Connect question answered with `allow` on the test Larsal's standard input, the seam; then `check` ok with the connection's name), both ok in both runs. Against `test_larsal`, which runs larsal-browser's own Bridge, VaultSide, Prompts and Server with a test settings file (`browser.enabled`) and a test HOME | Verified against the test Larsal; the run against Larsal.app is carried to E7-S7d's checks |
| 2 | With Larsal not running the background reports it as not reachable, and Larsal started later is reached without a reload | test_02 (44 from larsal-bridge, the port kept, one host process), test_03 (Larsal started while the page holds its port: `check` and `status` within 2 s with no page asking, T14; one `{"notice":"state"}`; still one host process), test_10, test_19, test_01 (a missing host: one reconnect, no loop), all ok | Verified |
| 3 | The channel's known-answer vectors give the same bytes in WebCrypto and in larsal-crypto | test_07 (the packaged /channel.js in Chrome against `test_larsal vectors`, which calls larsal-crypto's `bridge` functions: C, A, CV-4, CV-6 and CV-9 equal, and CV-4 to CV-9 equal INT-01.50; CV-5 opens to P2 with the reply key; the keys AES-GCM 256, non-extractable, encrypt or decrypt only) ok in both runs; T79 in test_channel_vectors.py ok; Verify's own `test_larsal vectors` under run-key.sb gives INT-01.50's bytes | Verified |
| 4 | `exportKey` on the identification key fails | test_05 (raw, pkcs8, jwk and spki each InvalidAccessError; X25519, extractable false, usages deriveKey; storage.local holds only `last_app_version`; Larsal saw this key proven) and test_20 (the first key stored wins), ok | Verified |
| 5 | A content-script message that names another URL or origin changes nothing (the background uses `MessageSender`) | test_06 (a body naming site-b: the one `logins.find` carries site-a's URLs from `MessageSender`, the site-b frame asks nothing, the reply is `{}`; P routes from a content script get no reply and reach nothing; a content script's `page` port is closed; the options page in a subframe is refused) ok; the sender rules in pure_test.js under jsc | Verified |
| 6 | The built manifest has the default CSP and only B2's permissions | `test_built_manifest_has_the_default_csp_and_only_b2s_permissions` (`script-src 'self'; object-src 'self'`; nativeMessaging, storage, activeTab, scripting; `http://*/*`, `https://*/*`; no optional permissions, `externally_connectable`, `key`, content scripts or `update_url`), `test_key_only_in_development_builds_and_its_id_is_the_debug_id`, `test_a_package_holds_only_the_files_it_uses`, ok | Verified |
| 7 | No file uses `innerHTML`, `eval` or a remote URL (a grep check) | `test_no_file_of_a_package_holds_inner_html_eval_or_a_remote_url` and `test_the_search_finds_each_banned_use` (INT-11.1's list, `console.` included), ok. Verify's own grep of the seven package source files found only the two host patterns of manifest.json.in; `connectNative` appears once, in background.js | Verified |
| 8 | Pure modules pass under macOS's `jsc` | `test_pure_modules_pass_under_macos_jsc` ok, and Verify's own jsc run: "pure: all passed" | Verified |
| 9 | Two Checkers (the channel) | Round 3: C1 APPROVE_EXACT_CANDIDATE, 0 blocking (7 findings: 2 Low, 5 Info); C2 (the channel) APPROVE_EXACT_CANDIDATE, 0 blocking (3 Low, 2 Info). Both on fix.patch `65299b0a…` and tree 8199972c | Verified |
| LD-278 (3) | A driver helper `check_keychain_log(start)` for the LD-276 after-run check | `driver.check_keychain_log` in every suite's tearDownModule; driver tests `test_check_keychain_log_stops_on_a_write_by_a_pid_of_the_run_only` and `test_a_keychain_write_by_this_run_stops_the_suite_run` ok in test_driver.py | Verified |

## The tables

f9c45cc changes `pins.json` and nothing else.

| Change | True for this commit? |
|---|---|
| `reviewed_commit` 522afbd to 2ed2b0b; a new `reviews."E7-S7c"` entry; no other review, `note` or `byte_checks` change | Yes |
| 59 rows before and after. 3 rows change: `workspace:larsal-browser/int01`, `workspace:larsal-browser/int01_setup` and `workspace:larsal-browser/larsal_browser`, each relabelled E7-S7c with `crates/larsal-browser` `3f1006df64e6f068ad70e607d5c9c69c65c43a41` to `a2a492773529438e6c359af0fab8aacddbc5de02`; no `why` or `checks` text changes | Yes |
| The new pin equals the git object of `crates/larsal-browser` at 2ed2b0b (and at f9c45cc); the old one equals it at 5a6032b and baa9452 | Yes |
| Every pin of the table at f9c45cc equals the git object at f9c45cc | Yes: 59 rows, 148 pins, 0 differ |

No `programs.json`, `routes.json` or `needs.json` change: the example is not a test program, and extension/ has no row.

## Security, on the patch

- **Who can reach the port.** Only background.js calls `connectNative`. The manifest has no `externally_connectable`, the code no `onMessageExternal` or `onConnectExternal`. `classify` reads `sender` only; content scripts reach `fields.found` alone, from frame 0, and get `{}`; the `page` port is taken from P senders only.
- **Keys.** A fresh X25519 pair per hello (background.js:113); request and reply keys non-extractable, one per direction; dropped when the session ends (port closed, new hello, plain 3, 4, 41, 44 or 45). The identification key is non-extractable, in IndexedDB only. AES-GCM nonces are 12 random bytes per box; a resend always goes to a new session with new keys.
- **Nothing secret leaves.** No console call (banned by the package check), storage.local holds `last_app_version` only, `fields.found` answers `{}`, and pages get only the state reply.
- **Zero knowledge (LD-340).** The extension's only way out is INT-01's channel to the local Larsal; it makes no network request.

## The Checkers

| Round | C1 | C2 (the channel) |
|---|---|---|
| 1 | APPROVE_EXACT_CANDIDATE (second C1 run; the first left no result) | REQUEST_CHANGES |
| 2 | APPROVE_EXACT_CANDIDATE | REQUEST_CHANGES |
| 3 | APPROVE_EXACT_CANDIDATE, 0 blocking; 3 runs of test_extension.py 34 of 34; 12 own mutants, X02, X03, X04 survive | APPROVE_EXACT_CANDIDATE, 0 blocking; 34 of 34; its own mutants S01 to S22 and the round 2 survivors: S09 and S20 survive, S21 is equivalent; a silent-host probe |

The round 3 Builder ran 87 mutants on the final code, 87 red. Their folders and seals were under /private/tmp and were lost when the Mac restarted on 2026-11-09; their structured results and reports survive as text in larsal-checkpoints/resume-2026-11-06/recovery (hashes below).

## The open and carried rows

| Row | Severity | Safe to leave open? |
|---|---|---|
| Acceptance check 1 against Larsal.app (review C1b-2, C2-5, ruling 9) | Low | Yes, carried to E7-S7d's checks: test_larsal runs the same larsal-browser code; the Swift and FFI layer is not exercised here |
| T77, the dynamic origin of frame pages (review C1b-1, C2-4, ruling 8) | Low | Yes, carried to E7-S7g: no F route exists, and routes.js fails closed |
| INT-11.10 words and the third hello (C1r3-1) | Low | Closed by the INT-11.10 words adopted with this signature (below), which say what the code does |
| test_channel_vectors.py flaky (C1r3-2) | Low | Yes: test_07 makes the same comparison and passed every run; it passed at its first try here |
| Surviving mutants X02, X03, X04 (C1r3-3 to C1r3-5) | Info | Yes: test gaps on behaviour that matches the card |
| hello() has no time limit (C1r3-6, C2r3-3) | Low | Yes for this story (fails open to waiting, leaks nothing); needs the lead's ruling before E7-S7d shows frames |
| No test of a new key pair per hello (C2r3-1, S09) | Low | Yes: the code makes one per hello |
| The `sent: 0` reset untested (C2r3-2, S20) | Low | Yes: without it the result fails safe |
| E7-S7d's Cancel must end the old session first (C2r3-5) | Info | Yes, carried to E7-S7d |
| A host answering every box with plain 4 (Builder) | Low | Yes: no real Larsal does it; the card sets no limit |
| test_01's count under very high load (Builder) | Low | Yes: this run's load was about 7.5 |
| The guarded tool does not run the extension's suites (V-1) | Low | Yes for this story, which Verify ran by hand; every later extension story needs the same until a lane exists |
| The rule-10 note in run 1 (owner's app switch) | Info | No row: the guard says run again, and run 2 was clean |

None blocks this story.

## Words adopted with this signature

The round 3 Builder's proposed-cards.md was lost with its folder; its rows survive in the Builder's transcript (its tools/edit_docs.py and the round 2 file it edited). Verify adopts them with one change: in INT-11.10, round 3's sentence "so is a second plain 3 or 41 while a request sent once more waits. A second failure reports Larsal as not reachable, and no further hello is said until the next need" does not match the code (C1r3-1: on that later 41 the background says a third hello and `check`, then fails the twice-sent request; test_15 asserts exactly that). The adopted words say so. The exact words are in Verify's proposed rows.

## Limits of this signature

1. **The test Larsal.** Every browser test ran against `test_larsal`, not Larsal.app (ruling 9). Larsal.app's own bridge side is E7-S7d's.
2. **One machine, one Chrome.** Chrome 156.0.8078.81, arm64, headless; no Chrome for Testing, no other browser.
3. **Two whole runs** of test_extension.py, one of test_driver.py and one of test_channel_vectors.py. A load-dependent flake can be shown absent only for the runs made; the vectors suite passed 2 of 7 Builder runs, and Checker 1's 1 of 3 on the candidate and 2 of 3 on base 5a6032b.
4. **Mutants** were not rerun by Verify; their results are the Builder's and Checkers' own, as text.
5. **The driver's /tmp folders.** The suites make their throwaway folders under /tmp by design (INT-01.10, E7-S7b) and remove them; none was left.
6. **The guarded run** does not cover the extension; the run of record proves only that the Rust, Swift, docs and fuzz checks still pass with this commit.

## Evidence

| What | SHA-256 |
|---|---|
| The reviewed fix.patch (equals `git diff 5a6032b 2ed2b0b` without the two docs files) | `65299b0afa7dc3a80c39da9f0fc5526b70e66265efe6085e97f4c181fcf39fbe` |
| Round 3 builder result, C1 result and report, C2 result and report (recovery/wf_56dfc73f-805) | `0dcee9c1bd79897b96e3443c0fac4c7c913bec0e45036a86dcec5ac03008eb54`, `bd42a081d5bdb4bd3cc6599b6f0202310cd7895da4585e04b8f3deefcf851dfe`, `e388ab836b5bb5b3198b8eee147410f1213946e76ed39f113f977295311aa39e`, `56eb5d89402ef32302f2876cf64d51dd565d5ba974fb75d653fee9f07a1f64da`, `5fa440a8d66170b631b9186e6fb89c47adf94626202da1ce8fb6a9d4a3b34bf1` |
| Round 2 builder, C1 and C2 results (recovery/wf_d280a044-8b0) | `fad0d51b4f41e1ffc816745f7adeb8843936ac48f76bd97145b53690d973678e`, `4d10be13fe871422d62f83ff8e7d0bd823d9be7c36f21ffbd1d8372477d75f0a`, `33da0e8e6ed6f77ab66c2844f7c04eebb74bd9476a5cbf8899632c3f44c00ab7` |
| Round 1 builder, C1 and C2 results (recovery/wf_4741398a-c6b, wf_3b6e5980-a84) | `687806c7f667af049d58b39598fbf935b86cf05325a2b69f61608829141a0a39`, `550c1e93ce868c5d897d111420a30c35c68cf6da9b981bc328d0db28c7e1d2ff`, `6f5d4ed3f2475c4d345ea2ad604cea6dcbbb66f63d1ba78f80546a7fcfa5c221` |
| Run of record `summary.txt`, `summary.json`, `test-names.json`, `run-start.json`, `run.json` | `1edc9c3901d8201e57e28aa66dc151139a49b124cc44afbff98565e0d2c00f65`, `4296ccee3d4b10b731556df6a76d854a0e6a6136b31977da379719aa454394fe`, `efc387916701e5cf218ddab7473425ec0ceb8af9c0ae2075423b0cba40424ae8`, `31969fb6964330488671995775fc7474cb296d3aedc246b15596cb7c53c60460`, `0a910e9c4f681d6175b7ff815362bcc1e137b5d772143f02463a563d17ad3d39` |
| Run of record `results/` static, rust, native, docs, fuzz, source | `63c27cc6aa6e7b4e10aacca7789384a10ad7728948efd8db775de23081b84904`, `a34e784e5b460f09ac4c08de341bd0fe735d86f223c27e008417a52e685a1f89`, `2bee5e95f60d04ab57105adf563de8a5e98fe4481bfc3858dbf07cb51e3b408b`, `eea428a0140f60bb1487b42077d299dbdd7644e47cf5f66fa1f2093110406de2`, `16a49231fcbedc7e0918c07512049f55f1d3c765ca65e0e1dabe96efe4ab5d63`, `5bd7e921e11643f18d9bc840ac86dd0ff791738371a95014104bf421a4d38f8c` |
| Baseline (ed97e9c) `test-names.json` | `c193f11e6586618b74bb637584f52e670011be7455a6cb767321b6ba3f93d465` |
| Verify's build: larsal-bridge, test_larsal | `5c5c19757d71bfdb400e2a79025a516039f89d8a6d22e1be5c3df9b0438fe975`, `6a5afc421dd7e90fea84eef0fd9572d942c221198b6fcafc8b12e647d6f48a8c` |
| Verify's logs | In its seal: `/private/tmp/larsal-e7s7c-vr-GZ4Nzrs1/FINAL-SEAL.json` hashes every file of its proof/ |

## Report end

- Story: E7-S7c.
- Files changed by Verify: none in the project. This page is proposed for `security/parity/E7-S7c-extension-core.md`.
- Proof: this page; commit `f9c45cc83c3260d56fcc9a3bfbc91694e5281a46`; guarded run at `/private/tmp/larsal-gc-f9c45cc-vGFs`, Overall PASS, Rust 4501 passed and 0 failed, Swift 462 of 462, APP-09 18, docs 18, fuzz 31 routes, 0 names lost, 2745.0 s; Verify's runs of the extension's suites: 34 of 34 twice, 39 of 39, 2 of 2, jsc all passed.
- Open: the Larsal.app run (E7-S7d), T77 (E7-S7g), and the rows above.
- Next step: the lead puts this page at `security/parity/E7-S7c-extension-core.md` and, in one docs commit, sets E7-S7c's status line, adopts the card, architecture and epics words, adds the LD and findings rows, and runs the name guard.
