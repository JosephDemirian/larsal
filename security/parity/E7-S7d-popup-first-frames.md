# E7-S7d First popup frames, Chrome build: Verify sign-off

Story: E7-S7d (plan/epics.md, with its "Carried from E7-S7c" text), and the lead's LD-520 items (1) to (5). Cards: INT-11 (INT-11.8, INT-11.10, INT-11.22 to INT-11.26, INT-11.39, INT-11.43, D-INT11-1, D-INT11-3, T01, T51, T68), INT-01 (INT-01.20, INT-01.44). Frames: `extension-popup-app-not-reachable`, `extension-popup-first-connection`, `extension-popup-vault-locked` of design/option-a/mockup.html. Checkers: C1 and C2, two rounds.
Date: 2026-11-09.
Role: Verify. It proved the merged commit equals the patch both round 2 Checkers approved, read the lead's full guarded run of the commit, built the two stand-ins under the guard profile, ran the extension's own suites (which the guarded tool does not run, F-482) from its private clone in headless Chrome behind the window guard, ran PopupParity itself and looked at its images, and probed the focus ring and the "Other vaults" line. It changed no product code and ran no xcodebuild. Its logs live under /private/tmp, which does not last, so this page copies what must survive.

**Result: signed with limits.** Commit `b5bfaca29581b72b85d4c12fbdccf05992916e02`, one commit on Main 27d28955009623f59619ad673264593170cf2a84. The guarded run of b5bfaca reads **Overall PASS**: Rust 5045 passed and 0 failed, 177 of 177 programs; Swift 488 of 488; APP-09 18; docs 18; fuzz 32 routes; 0 names lost against e2c32e1 (5700 compared); 2795.4 s of the 60-minute cap. The extension's suites, run by Verify: test_extension.py 43 of 43, test_popup.py 18 of 18, test_driver.py 41 of 41, test_channel_vectors.py 2 of 2 in each of three runs in a row, pure_test.js under macOS's jsc all passed. All six parity rows PASS (at most 0.028 % changed pixels; every part's tokens equal; largest box offset 0.0 pt). Every story check and every LD-520 item has a test that ran and passed, except the run against Larsal.app, carried to E7-S2 with E7-S6 as the lead ruled. Verify found one new Low parity difference: a focused Try Again, Open Larsal or Cancel draws its focus ring with 8 px corners where the mockup draws 6 px (below).

The popup keeps no state of its own: each read asks the background (`popup.status`) and draws the one frame `choose(state)` gives (popup/state.js, INT-11.23). Its four routes (`popup.status`, `popup.connect`, `popup.cancel`, `popup.unlock`) take P senders only. Every word is a message of `_locales/en/messages.json` named after INT-11's id, set with `textContent` or `setAttribute('aria-label', …)`. Unlock sends `unlock` with no field (B8), at most one at a time; Open Larsal calls `tabs.create({url: "app.larsal.desktop://open"})` and nothing else; the background tells its pages to read the state again whenever Larsal's reach changes, both ways.

## The whole difference

| Item | Result |
|---|---|
| Base | d6179b1571e1a56613bbce38db56439d1deb71ea for the reviews; Main 27d28955009623f59619ad673264593170cf2a84 for the merge. d6179b1..27d2895 (E11-S6, E22-S4, six commits) touches nothing under extension/, spec/integrations/INT-11 or INT-01, design/option-a/mockup.html or BUILD-AND-VERIFY.md; of design/option-a it changes proposals.html only (+4 lines). crates/larsal-ffi changed, but browser.rs still hands Larsal.app's bridge `Box::new(NoVaults)` (line 255) |
| Commit | `b5bfaca29581b72b85d4c12fbdccf05992916e02`, parent 27d2895, tree `0073c41a8530ec32e0a4964afde45ecbd5f6eaa6`, branch candidate-m14; author and committer `Joseph Demirian <hello@JosephDemirian.com>`; "feat: the browser extension popup first frames, Chrome build (E7-S7d)" |
| The reviewed patch | round 2 fix.patch, SHA-256 `e2726a57b11f6a3bcadd55d8ef714fafb738156262ba06c7aebf6dfc3054f30b`; both round 2 Checkers APPROVE_EXACT_CANDIDATE |
| Patch on its base | `git apply --index --binary fix.patch` on a worktree at d6179b1, then `git write-tree`: `285e82ee9ff0619fae4e1f56e60addd067bfe71f`, the approved tree |
| Merge equals the patch | `git diff --binary 27d2895 b5bfaca` and `git diff --binary d6179b1 285e82ee` are byte-identical (`cmp`); `git patch-id --stable` of fix.patch and of the merge diff are both `c70615be062137baa027f08b364d791ba35b1dd2` |
| Paths | 21 files, all under extension/, +1796 −43: background.js, build.py, words.js, _locales/en/messages.json, popup/ (popup.html, popup.css, popup.js, state.js, fonts/ with six WOFF2 files and two licence texts), test/ (driver.py, pure_test.js, test_driver.py, test_extension.py, test_popup.py). No path under crates/, macos/, spec/, plan/ or scripts/ |
| Fonts | The six WOFF2 files are byte-identical to design/option-a/vendor's (SHA-256 compared); IBM-Plex-OFL.txt equals vendor/fonts/OFL.txt and Phosphor-LICENSE.txt equals vendor/phosphor/LICENSE (`cmp`) |
| Tables | No change: no pin covers extension/. The run's 23 tool files, the five tables among them (tables/pins.json, programs.json, routes.json, needs.json, native-expected.txt), each equal the file of scripts/guarded at b5bfaca (23 of 23 SHA-256 equal) |

## The run of record: b5bfaca

Started by the lead at 14:20:42; root `/private/tmp/larsal-gc-b5bfaca-JqK2`, tool copy /private/tmp/larsal-m14-NGP1/c. Verify read its results and did not rerun it.

| Item | Result |
|---|---|
| Overall | **PASS**, not partial, 0 failures. `summary.txt` SHA-256 `400fe664dc732feaf6f1f40cf34106853f75f94cc689ba6f283631a39aacd85f` |
| Commit and tree | b5bfaca in `run-start.json`, `run.json`, `summary.json` and `test-names.json`; tree `0073c41a8530ec32e0a4964afde45ecbd5f6eaa6`, this commit's tree |
| Time | 2795.4 s of the owner's 60-minute cap (3600 s); hold wait 150.0 s, not counted |
| Custody | 0 changed, 19 executables, 23 tool files; tool drift none; nothing left under the root |
| Grants | 59 rows read, 0 withheld |
| Lanes | source exit 0; static exit 0, 557.7 s; rust exit 0, 1159.3 s; native exit 0, 704.2 s (A1 176.9 s, B1 328.2 s with 108 window samples and 0 gate failures, G1 3.6 s); docs exit 0, 182.4 s; fuzz exit 0, 333.9 s |
| Static | 18 of 18 steps; names PASS, 12368 files, 19 vault files by name only; unsafe count 512 in 21 crates; advisories, bans, licenses and sources ok |
| Rust | 5045 passed, 0 failed, 131 ignored, 177 of 177 programs: workspace 3988/0/109 (151), sync 650/0/15 (17), net 74/0/7 (2), release 288/0/0 (6), release-browser 45/0/0 (1). Guard library requests 0 in every lane. The 30 "new programs" are E11-S6's and E22-S4's, not this story's |
| Swift | log 488 tests in 74 suites, passed; bundle 488 passed, 0 failed, 0 skipped; database 488 cases, 645 runs, 488 ok |
| APP-09 | 18 passed, 0 failed |
| Docs | 18 passed, 0 failed, 23 result lines |
| Fuzz | 32 routes, all exit zero, fewest runs 1192, no new route |
| Test names | Baseline `/Users/josephilhan/Documents/Code/larsal-checkpoints/resume-2026-11-06/test-names-e2c32e1.json` (SHA-256 `d0d748ebe1ecc1a62dddcff62300eab3a9c2ca883abfaca96918974fd890767cf`, made from e2c32e1). 5700 compared, **0 lost**, 0 newly ignored, 0 waived, 0 new. `test-names.json` holds 5700 names |
| Crash reports | 1 new, on purpose (`prompt_child`); own and not on purpose: none |
| Limits the run states | Yanked status not proven for 11 crates (offline index): aes-kw, aes-siv, bech32, chacha20poly1305, cmac, dbl, hpke, httpdate, scrypt, x25519-dalek, zeroize_derive. Advisories 1395, newest 2026-10-30 |
| What it does not run | The extension's suites (F-482). So none of this story's tests is in the run of record; Verify ran them, below |

## The extension's suites, run by Verify

From the private clone at b5bfaca. Python was the pinned `Python3.framework/Versions/3.9` with `-B -I`; HOME, TMPDIR, XDG_CACHE_HOME, CARGO_HOME, CARGO_TARGET_DIR, `CFFIXED_USER_HOME`, `CLANG_MODULE_CACHE_PATH` and `SWIFT_MODULECACHE_PATH` under Verify's root; Chrome 156.0.8078.81 (the installed one), headless, through E7-S7b's driver with its throwaway profile, test HOME, mock keychain and window guard. Verify held `BUSY-native` ("verify e7s7d", made with noclobber) while it ran, and removed it only while it still held those words.

| Step | Result |
|---|---|
| Build | `cargo build --offline --locked -j 3 -p larsal-bridge`, then `-p larsal-browser --example test_larsal`, each under compile.sb (the E16-S7b guard profile with only the root changed), CARGO_HOME absent at the start. Both exit 0 (39.7 s for test_larsal). SHA-256: larsal-bridge `4058af608a54bd5d975073b762dd5eff42c0a324dae06233eb3f8b87f50e2e52`, test_larsal `42b32c8b4fc24ddca5f1ff54eed91e3fd7b278954830ec059c2f444a32da8ec9` |
| `test_larsal vectors` alone, under run-key.sb | exit 0. C `8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a`, A `de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f` (RFC 7748's public keys, the same as E7-S7c's Verify); CV-4, CV-5, CV-6 and CV-9 as E7-S7c's |
| pure_test.js under `/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc -m` | exit 0, "pure: all passed" (the INT-11.23 frame-choice and words cases included) |
| test_extension.py (15:10:28 to 15:11:47, load about 3.6) | **43 of 43 OK**, 78.7 s: PackageChecks 12, ChromeWithLarsal 30, ChromeWithoutX25519 1 |
| test_popup.py | **18 of 18 OK**, 39.0 s: PopupWithLarsal 10 (test_01 to test_10), PopupParity 8 |
| test_driver.py | **41 of 41 OK**, 14.5 s (WorkerReady's two tests among them) |
| test_channel_vectors.py, three runs in a row | **2 of 2 OK** each (4.7 s, 4.7 s, 4.7 s): F-476's flake did not show |
| Focus and hover probe (Verify's own, tools/focus_probe.py) | Each control reached by a keyboard Tab (`Input.dispatchKeyEvent`, focus emulated, no window): outline style, width, colour and offset equal the mockup's in every frame and theme; the ring's corner radius differs on the 36 px buttons (below). MI11-20: `pointer-events: none`, its background the same before and after the mouse moves over it, and the point under it hits what lies beneath: no hover, light and dark |
| LD-276 | `driver.check_keychain_log` ran in each suite's tearDownModule and raised nothing |
| The owner's files | lstat (inode, mtime, ctime) of ~/Library/Developer, its Xcode/DerivedData, ~/.swiftpm, ~/Library/Caches/org.swift.swiftpm, ~/Library/org.swift.swiftpm, ~/Library/Keychains, ~/.cargo and ~/.cargo/registry: identical before the suites (15:10:28) and after (15:13:03). ~/Library/Keychains' folder time moved once, to 14:57:16, inside the guarded run's native step and outside both of Verify's windows (14:50:43 to 14:51:27, and the suites) |
| Leftovers | Verify's first start was stopped at 14:51:27 (below) while test_extension.py was starting, and left three folders (/tmp/larsal-chrome-adr_mw4s, /tmp/larsal-ext-svv2tf_8, /tmp/larsal-guard-0mrd3324, all made at 14:51:25, no process alive); Verify removed them. After the suites: no /tmp/larsal-{ext,popup,parity,guard,chrome}-* folder of the run, no Chrome, host or test Larsal process left |

Verify's own note: its first start waited only for `BUSY-native` to be absent. The tool makes its busy mark only around each native attempt, so between the rust lane and attempt A1 the file was absent, and Verify held it from 14:50:43 to 14:51:27 to build the stand-ins and run `vectors` and jsc. Verify then stopped its run (its own task, by its handle), waited for `results/native.json`, and ran the suites after the run's docs and fuzz hold lifted. The run reports 150.0 s of hold wait, not counted in its cap; it does not say whether A1 waited on Verify's mark. Native passed.

## Parity (BUILD-AND-VERIFY.md, light and dark)

PopupParity, rerun by Verify: both sides in the same headless Chrome, the popup opened with `action.openPopup()` and drawn from fed demo states (seam "fed-state", the test package only), the mockup served by the driver's https demo server at `?only=extension` (`&theme=dark`), zoom 1, each clipped to its `.xp` box.

| Frame | Theme | Size (popup = mockup) | Changed pixels (item 5) | Parts with equal tokens (item 3) | Largest box offset (item 4) | Controls in tab order (item 7) | Result |
|---|---|---|---|---|---|---|---|
| extension-popup-app-not-reachable | light | 360×416 | 16 of 149760, 0.011 % | 21 of 21 | 0.0 pt | Try Again, Open Larsal | PASS |
| extension-popup-app-not-reachable | dark | 360×416 | 0 of 149760, 0.000 % | 21 of 21 | 0.0 pt | Try Again, Open Larsal | PASS |
| extension-popup-first-connection | light | 360×311 | 31 of 111960, 0.028 % | 17 of 17 | 0.0 pt | Cancel | PASS |
| extension-popup-first-connection | dark | 360×311 | 12 of 111960, 0.011 % | 17 of 17 | 0.0 pt | Cancel | PASS |
| extension-popup-vault-locked | light | 360×314 | 16 of 113040, 0.014 % | 11 of 11 | 0.0 pt | Unlock in Larsal | PASS |
| extension-popup-vault-locked | dark | 360×314 | 0 of 113040, 0.000 % | 11 of 11 | 0.0 pt | Unlock in Larsal | PASS |

Where Verify looked (the PNGs under its proof/parity): each popup image beside its mockup image, light and dark. Not reachable: the gray plug tile, title, two text lines, the three checks with their marks (done green, failed red, unknown gray, the 44 state), hints ("Version 1.0 in Applications", "Open Larsal, then click Try Again", "Settings › Browser Integration"), the rules between rows, Try Again and Open Larsal (primary, dark in light theme, light in dark theme): the same. First connection: the teal tile, "Connect Chrome to Larsal", the four mono word chips, the hourglass line "Waiting for Larsal…", Cancel: the same. Vault locked: the large teal keyhole tile, "Personal is locked", the three-line text, "Unlock in Larsal" with the fingerprint glyph, "Other vaults: Work, Family" with its caret: the same. The diff images show changed pixels only at the panel's rounded corners and in the anti-aliasing of "for" in "Waiting for Larsal…".

Item 2 (text): every string is matched as a part by its words (item 3's set of parts is equal), and `test_each_message_is_int_11s_text_under_its_id` ties each message to INT-11's text. Item 6 (behaviour): PopupWithLarsal test_01 to test_10 and `test_open_larsal_asks_for_larsals_url_and_nothing_else`. Item 7: names and tab order in the DOM and in Chrome's accessibility tree (`Accessibility.getFullAXTree`), the dialog named MI11-101 a; contrast follows from item 3 (every token equals the mockup's); the focus ring by Verify's probe:

| Control | Outline in both (style, width, colour light / dark, offset) | Corner radius of the focused control: popup / mockup |
|---|---|---|
| Try Again, Open Larsal (not reachable) | solid 2px rgb(27, 108, 128) / rgb(82, 182, 201), 1px | 8px / 6px |
| Cancel (first connection) | the same | 8px / 6px |
| Unlock in Larsal (locked) | the same | 10px / 10px |

Why: popup.css line 40 has app.css's rule as `:focus-visible { …; border-radius: 6px; }`, one class weight, which `.btn { …; border-radius: 8px; }` (line 65, the same weight, later) overrides; the mockup's `.win :focus-visible` weighs two and wins over `.btn`. `.btn.xl` (two, later) gives 10 px in both. So a keyboard-focused 36 px button draws its ring with 8 px corners where Option A draws 6 px. Known differences: MI11-20 is a line, not a control (lead ruling 5); design/option-a/reference/*.png are stale and not used (the test renders the live mockup).

## The story's checks

| # | Check (plan/epics.md, E7-S7d) | Proof | Result |
|---|---|---|---|
| 1 | With Larsal not running the popup shows the not-reachable frame, and once Larsal starts it changes without a reload | popup test_01 (no host: the first check failed), test_02 (44: the marks change on Try Again), test_03 (Larsal started while the popup is open: the same document changes frame), test_09 (after a plain 4 the open popup comes back by itself, `window.marker` kept, three notices); ext test_02, test_03, test_19, test_21 | Verified |
| 2 | A first connection shows its frame until Larsal's dialog (test seam) is answered | popup test_04 (the words equal the test Larsal's Connect question; MI11-13 until `allow`), test_06 (Cancel closes, the next popup asks once on a new session), test_07 (Larsal's Deny: MI11-61 with Try Again); ext test_04, test_14, test_15f, test_15h | Verified, against the test Larsal |
| 3 | A locked vault shows the locked frame, whose button sends `unlock` and nothing else (B8) | popup test_05 (the sealed plaintext is `{type, req}` only; Larsal logs one `unlock`), test_10 (eight clicks while one unlock is held 6 s: one sealed unlock, `status` answers in under 4 s) | Verified |
| 4 | The words come from INT-11's message ids and are set with `textContent` only | PackageChecks `test_the_popup_takes_every_word_from_a_message_and_sets_it_with_text_content_only`, `test_each_message_is_int_11s_text_under_its_id`, `test_no_file_of_a_package_holds_inner_html_eval_or_a_remote_url`; PopupParity `test_other_states_draw_their_messages` (FROM_MESSAGES empty) | Verified |
| 5 | The three frames match Option A in light and dark (parity report, BUILD-AND-VERIFY.md) | PopupParity's six frame tests, rerun by Verify (table above), Verify's look at the images, Verify's focus and hover probe | Verified with one Low difference: the focus ring's corners on 36 px buttons (V-1) |
| 6 | Carried from E7-S7c: the Swift and FFI layer of Larsal.app is exercised in this story's checks and by Verify | Not run (lead ruling 8). Larsal.app cannot reach any of the three frames today: crates/larsal-ffi/src/browser.rs lines 69 to 85 (`NoVaults`: `status` lists no vault, every other request error 1) and line 255 (`Box::new(NoVaults)` in `Browsers::with`), unchanged on b5bfaca | Carried open to E7-S2 with E7-S6 |
| 7 | Carried from E7-S7c: Cancel (INT-11.25) ends the old session before the new hello | ext test_15h (the waiting connect is told `ended` at once; the next box after Cancel is the new hello; the next connect is a new dialog with new words) | Verified |

## LD-520's items

| Item | Proof | Result |
|---|---|---|
| (1) A hello with no answer ends after 60 s and reports Larsal not reachable, in the card and the code | Code: background.js hello() timer (WAIT, 5 s under the test seam), test_21 (two state reads each end after the wait; one host, the port kept; two hellos). Card words: section 1 of the proposed card words, written at the docs commit | Verified (code); the card words go in with this signature |
| (2) A second plain 4 in a row reports Larsal not reachable | test_15d (relay log `box 4, hello pass, box 4`, then no hello until the next need) | Verified |
| (3) Tests for a new key pair per hello, the `sent: 0` reset, a queued `connect`, a 44 answer at a 3 or 41 | test_12 (four hellos, four different keys: S09), test_15e (S20), test_15f (X02), test_15g (X03); the Builder's mutants B-S09, B-S20, B-X02, B-X03 each killed by them | Verified |
| (4) driver.Chrome.worker waits for a trivial evaluate first | test_driver WorkerReady `test_worker_waits_for_a_trivial_evaluate_before_the_first_real_one` and `test_a_worker_that_never_answers_fails_within_its_bound`; test_channel_vectors.py 3 of 3 runs | Verified |
| (5) Cancel ends the old session before the new hello | test_15h; background.js cancel() `if (session) end('ended'); await ready();` | Verified |
| The guarded lane for extension/test | Carried to the tool round with F-368, F-369 (F-482) | Carried open |

## Security, on the patch

- **Who can reach the popup's routes.** `popup.*` and `options.status` take P senders only; test_06 sends each from a content script and gets no reply. popup.html is not web-accessible. Only background.js calls `connectNative`; there is no external listener.
- **What the popup is told.** The state reply is `{reach, app, check, status, connecting, refused}` and, at a first connection, `words`: no key, no `sid`, no proof (background.js state()). No test pins its keys (C2 F1).
- **Whose notice the popup takes.** Only its own background's (`sender.id` is the extension's, no tab): test_08.
- **Unlock.** `unlock` carries no field (B8); the extension never sees a master password. One waits at a time.
- **Open Larsal.** One constant URL, `app.larsal.desktop://open`, through `tabs.create`; nothing of the page or the vault goes into it.
- **Zero knowledge (LD-340).** The popup's only way out is the background, whose only way out is INT-01's channel to the local Larsal; the popup makes no network request and loads only packaged fonts.

## The Checkers

| Round | C1 | C2 (popup and channel) |
|---|---|---|
| 1 | changes asked (F1 to F8) | changes asked (F1 to F7) |
| 2 | APPROVE_EXACT_CANDIDATE, 0 blocking; 18 and 43 twice, 41, 2, jsc; 21 own mutants, 15 killed, X01, X04, X06, X09 survive, K11 and X13 equivalent | APPROVE_EXACT_CANDIDATE, 0 blocking; 18, 43, 41, 2 three times, jsc; 14 mutants, 11 killed, S1, S2, S7 survive, K11 equivalent |

The round 2 Builder ran 67 mutants on the final code: 64 killed, K11 and K11b equivalent, K12 superseded by K12b (killed). Verify did not rerun them.

## Checker notes, judged

| Note | Real? | Where it goes |
|---|---|---|
| C1 F1: the rejection path of one-unlock-at-a-time is untested (X04 survives) | Real, Low. `.finally` is right today; a `.then` would leave a rejected unlock stuck until the worker restarts | Carried to E7-S7f (next edits the popup and its routes): a test that ends the session while an unlock waits, then expects a new `unlock` |
| C1 F2: no focus-ring test (item 7) | Real. Verify's probe measured it: the ring is there with the mockup's style, width, colour and offset, but with 8 px corners on 36 px buttons where the mockup has 6 px (V-1) | Carried to E7-S7f with V-1: fix the selector and add the probe's check to PopupParity |
| C1 F3: test_09 shows not-reachable after a plain 4, against INT-11.10's `ended` clause | Real, a card gap. A plain 4 names no request, so the code fails every waiting caller as not reachable (E7-S7c's test_13 pinned it) | Closed by a card amendment: Verify's section 2 words say so (LD-567) |
| C1 F4 = C2 F2: "a read that ended as `ended` changes nothing" is untested (X01, S2 survive) | Real, Info: at most one extra notice and state read after a Cancel | Card words state it (section 10); the test is carried to E7-S7f |
| C1 F5: the no-hover half of ruling 5 is untested (X06) | Real, Info | Closed by Verify's probe for this commit (no hover, light and dark); the automated check goes to E7-S7f with V-1 |
| C1 F6: screen readers cannot tell the not-reachable checks' state | Real, Low, a spec gap: the marks are `aria-hidden` as in the mockup, and INT-11.22 has no message for done, failed or unknown | Carried to E7-S7f: MI11 messages for the three mark states, set as each row's accessible name |
| C1 F7, C2 F6: K11 and X13 equivalent; reference PNGs stale | K11 and X13 equivalent: not defects. Stale reference PNGs: real, Info | Equivalents closed; the stale references go to design/ (export-reference.mjs), not this story |
| C2 F1: no test pins the `popup.status` reply's shape (S7 survives) | Real, Low: a `sid` or key could later reach the popup unseen | Carried to E7-S7f: assert the reply's keys |
| C2 F3: no live in-page-frame sender test of `popup.*` (S1 survives) | Real, Info, equivalent today: extension/frames/ does not exist | Carried to E7-S7g, which adds the frame pages: extend test_06's loop to an F sender |
| C2 F4: the real `tabs.create` was not exercised | Real, Info: a real call could make macOS ask on the owner's screen | Carried to E7-S6 with the app's URL type (`CFBundleURLTypes`) |
| C2 F5: Larsal.app not run | Real, Low (F-460) | Carried to E7-S2 with E7-S6 (lead ruling 8) |

## The open and carried rows

| Row | Severity | Safe to leave open? |
|---|---|---|
| The run against Larsal.app (F-460, LD-556, C1 F1 r1, C2 F3 r1 and F5 r2, ruling 8) | Low | Yes: Larsal.app's bridge answers only `status` (no vault) and error 1 until E7-S2 wires the vault side; the same larsal-browser code ran here as the test Larsal |
| The app's URL type for `app.larsal.desktop://open` (LD-557, F-540, C1 F2 r1, C2 F4) | Info | Yes: until E7-S6 the button asks the browser for a URL no app answers (a known difference in the card words) |
| The guarded lane for extension/test (F-482, F-368, F-369) | Low | Yes for this story, which Verify ran by hand |
| V-1 (F-535): the focus ring's corners on 36 px buttons | Low | Yes: the ring shows with the right colour, width and offset; only its corners differ by 2 px |
| C1 F1, C1 F6, C2 F1 (test and spec gaps; F-536, F-538, F-537) | Low | Yes: the code does what the card says |
| C1 F4/C2 F2, C1 F5, C2 F3 (F-539) | Info | Yes |
| The Builder's own rows (worker API readiness, pixelmatch needs item 3 for colours, the test Larsal's question format, stale references, /tmp folders, no unlock panel seam; F-541 to F-544) | Low or Info | Yes |

None blocks this story.

## Limits of this signature

1. **The test Larsal.** Every browser test ran against `test_larsal`, not Larsal.app (ruling 8).
2. **One machine, one Chrome.** Chrome 156.0.8078.81, arm64, headless; WebKit is E7-S7e's.
3. **One whole run** of test_extension.py, test_popup.py and test_driver.py, three of test_channel_vectors.py; a load-dependent flake is shown absent only for these runs (load about 3.6 to 4.1).
4. **Mutants** were not rerun by Verify; their results are the Builder's and Checkers' own.
5. **The guarded run** does not cover the extension; it proves the Rust, Swift, docs and fuzz checks still pass with this commit.
6. **Card words** for INT-11.10, INT-11.24 to INT-11.26, INT-11.43, T01 and T68 are proposed with this signature and written by the lead; until then the card lags the code where the proposed words say.

## Evidence

| What | SHA-256 |
|---|---|
| Round 2 fix.patch, delta.patch, source-seal.json | `e2726a57b11f6a3bcadd55d8ef714fafb738156262ba06c7aebf6dfc3054f30b`, `b3eddc50eb86ceb64f1909ff1045257f954b0f3c9b950d3307fb4f94656bbcb9`, `1dbf6f24a3cfbab8fba918cd23ac837fa72e3a5e803430f1b6af2a4fa5ace89f` |
| Round 2 CHECKER1-REPORT.md, CHECKER2-REPORT.md, workflow-result.json, MUTANTS.md | `d3cb81cb700040288ccfd83a4f19d925e649f42e9a29da3f8be5c43ee60a4395`, `459971774648e1798a07ca780313b246dc6cb9d14f60563e5814ab01e1a1672b`, `58d9c8fde0473844fb9a333734a77219b868087b7c7ae49c5ec6c376edd50877`, `0567e35cdf69a08dfee894735f5ff7b9d1a8366141d529f61cb77aa54041b45e` |
| Round 2 proposed-cards.md, proposed-LD.md, proposed-findings.md | `5c137fea9a275081784f1eaf9c67751b86aaef933fc7d76ef2e9ba3c4b22169c`, `d932ce652ffcc5a5fbe49bce7c827b74910b3d2af80aa5ee43494ac9ac3eabc4`, `769f8ff98747f15bfb07a0f468ce3500bb333ce54089edb0f4132fd77e730398` |
| Run of record `summary.txt`, `summary.json`, `test-names.json`, `run-start.json`, `run.json` | `400fe664dc732feaf6f1f40cf34106853f75f94cc689ba6f283631a39aacd85f`, `386fdd6cb7d243c4a33f3c8473429ff6d59f16cf5291e93522a8efd6c9312ae2`, `aaf13a2228695564c0c13176f86dc65db3b8f4db135c5ef316fd552bc387a6b0`, `7a87491cd01838a6754bbdceebeae0b001e22cfcfa316c8bc7025a2ed4ab3eaf`, `32f52892c9e8ffd017cfa514dfca62e0e1d2ce31dc1a6e5f5d809cdb9b7f8538` |
| Run of record `results/` static, rust, native, docs, fuzz, source | `28a20859c2ddeb30c9ef25d327a48376b109bb3e1672178f599da73db859e23c`, `97641c51c5ac07d8ea50241af35c271c0ec58eb65bdeaab3de0b0645120aac2d`, `b92f3f09076777fc8b671942e2f44faa87d97204e1bfa0c1bd5c03b28f23861b`, `b9d0b7a478621a10cbebf13202b757a2d5f1aaf033c5402fb9f3bab775d2124d`, `00f1d7a81386ff1c38a7c031c6341c8159e234cb4c27e46da2ab8c92c9029cee`, `8970665126987e9ef6d58f84112333cfcf27f9c28413cf2382f27559a071e72e` |
| Baseline (e2c32e1) `test-names.json` | `d0d748ebe1ecc1a62dddcff62300eab3a9c2ca883abfaca96918974fd890767cf` |
| Verify's build: larsal-bridge, test_larsal | `4058af608a54bd5d975073b762dd5eff42c0a324dae06233eb3f8b87f50e2e52`, `42b32c8b4fc24ddca5f1ff54eed91e3fd7b278954830ec059c2f444a32da8ec9` |
| Verify's logs and parity images | In its seal: `/private/tmp/larsal-e7s7d-vr-7s0g8zWJ/FINAL-SEAL.json` hashes every file of its proof/ and proposed/; a copy is in larsal-checkpoints/resume-2026-11-06/builds/e7s7d-verify/ |

## Report end

- Story: E7-S7d.
- Files changed by Verify: none in the project. This page is proposed for `security/parity/E7-S7d-popup-first-frames.md`.
- Proof: this page; commit `b5bfaca29581b72b85d4c12fbdccf05992916e02`; guarded run at `/private/tmp/larsal-gc-b5bfaca-JqK2`, Overall PASS, Rust 5045 passed and 0 failed, Swift 488 of 488, APP-09 18, docs 18, fuzz 32 routes, 0 names lost, 2795.4 s; Verify's runs: 43 of 43, 18 of 18, 41 of 41, 2 of 2 three times, jsc all passed; six parity rows PASS.
- Open: the Larsal.app run (E7-S2 with E7-S6), the URL type (E7-S6), the guarded extension lane (tool round), V-1 and the Checker gaps (E7-S7f, E7-S7g).
- Next step: the lead puts this page at `security/parity/E7-S7d-popup-first-frames.md` and, in one docs commit, sets E7-S7d's status line, writes the INT-11 and epics words, adds the LD and findings rows, and runs the name guard.
