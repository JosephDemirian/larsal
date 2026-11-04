# E8-S2 Window matching, global shortcut, confirm-before-typing option (INT-05.19 to INT-05.31, AT-G01, AT-G02)

Story: E8-S2. Card: [INT-05](../../spec/integrations/INT-05-auto-type.md). Decisions: LD-176, LD-184, LD-186, LD-191, LD-195, LD-196, LD-207, LD-219.

## Round 3 (2026-10-29 21:27 to 22:05, signed)

Role: Verify, round 3, for the whole story, after the Builder's fixes of the three round-2 findings and Checker 1's pass. I did not build or check this story. I used no reference access.
Result: **signed.** The three round-2 findings are fixed, and each fix has a story test that fails when the fix is undone. Every round-2 check holds again: the case map, my own probes, AT-G01 and AT-G02 at the model level, LD-186, rule 4, the seams, the frame and the mutants. Real global hot keys, real window titles, real key events and the real panels on screen belong to E8-S3 and Mac QA.

### R3 numbers

- **Round-2 fails, re-checked first.** (1) My V7 probe, now Y-V7, passes. The new story test "INT-05.29: after a panel flow that typed at once, a later picker closed untyped brings no app back" passes. Mutant S0 (`back = nil` taken out of `AutoType.fired()`) fails it at AutoTypeUnlockTests.swift:122 (`log.activated.isEmpty`), and it fails Y-V7 (`activated after the later Escape: [4343]`) and Y-V8 (`[4545]`, after a panel flow that failed). (2) Whole-tree SwiftLint 0.65.1 in the shared tree: `cd macos && DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer ~/.local/share/swiftlint/0.65.1/swiftlint lint --strict --quiet` gave `swiftlint --strict exit=0` (21:28). With `--strict --no-cache` it printed `Done linting! Found 0 violations, 0 serious in 115 files.` and `exit=0`. (3) Mutant R15 (`by_url: true`) fails `s_at_02_url_matching_from_the_settings_store`. So do R15b (`by_url: false`) and R15c (`by_url: flag("autotype.match_title")`). My probe y13 fails with all three.
- **Rust** (copy): `cargo test -p app-autotype -p app-ffi -p app-core` gave `cargo test exit=0`: 1,052 passed, 26 ignored. That is 1,034 tree tests plus my 18 probes. `tests/autotype.rs` 15 passed, int05_match 37, int05 51, app-ffi lib 108. `cargo clippy -p app-autotype -p app-ffi -p app-core --all-targets -- -D warnings` gave `clippy exit=0`. Shared tree: `cargo fmt --all -- --check` exit 0. After the mutants, `cargo test -p app-ffi -p app-autotype --no-fail-fast` gave `rust exit=0`.
- **Swift** (copy, own build-core, warnings as errors, AppUITests skipped). First full run: `Test run with 279 tests in 38 suites`. That is the tree's tests plus my 9 probes. Every E8-S2 test passed: AutoTypeTests 14 of 14 (with the 5 in AutoTypeUnlockTests.swift), ScreenProtectionTests, SnapshotTests and MenuBarIconTests. Two of my probes failed through my own setup errors, which I then fixed. Y-V1 counted "admin" and "root", which are also parts of titles. Y-V8's new entry was not saved before the lock. After the mutants, a final full run gave the same 279 tests. All five suites above passed, and so did my 9 probes. Its only 2 issues are in other stories' tests (see "Other stories' failures").
- **Probes:** Rust y01 to y18, 18 of 18 pass. Swift Y-V1 to Y-V9, 9 of 9 pass.
- **Mutants:** 33 in total, 18 Rust and 15 Swift. Story tests catch 30. My probe y08 catches R17. Nothing catches R18 or S5 (notes N8 and N9). Every file was restored, and `cmp` showed it equal to the shared tree at that moment.
- **Frame `menubar-auto-type-picker`:** `compare.mjs menubar` gave `menubar: 2/2 PASS`, picker light 0.63 % and dark 1.41 % (outside accepted, the same). 9 texts found, 0 missing. 1 extra colour, the search field's focus halo, as in round 2. Boxes and text runs over 2 pt: 0 and 0. The tool lists the hint line's early wrap (N1) apart. 42 contrast pairs, the lowest 4.87:1. Behaviour: both rows ok. The PNGs written by the copy's run are byte-equal to the shared `app-shots` in both themes.
- **Other lint:** `swift format lint --strict --recursive macos` exit 0. `scripts/check-names.sh` gave `names: PASS (3146 files scanned, 15 vault files name-only)`.

### R3 setup

- **Private copy.** I ran `rsync -a --exclude /target --exclude /app-shots --exclude /fuzz/target --exclude /fuzz/corpus --exclude /fuzz/artifacts` to `/tmp/e8s2y-verify-copy` at 21:28:07 (136 MB). The copy used `CARGO_TARGET_DIR=/tmp/e8s2y-verify-target`, its own `scripts/build-core.sh` (`build-core exit=0`) and `-derivedDataPath /tmp/e8s2y-verify-dd`. Mutant runs used `TMPDIR=/tmp/e8s2y-verify-tmp`.
- **The verified snapshot** (md5 at the sync): AutoType.swift `8221bf2c…`, AutoTypePicker.swift `acb52cb2…`, UnlockView.swift `f20b83c2…`, AutoTypeTests.swift `909ae361…`, AutoTypeUnlockTests.swift `28407bfc…`, tests/autotype.rs `59e87c9a…`, src/autotype.rs `076abfb7…`.
- **The shared tree changed after my sync.** From 21:44, another agent building E8-S3 (typing) changed `crates/app-ffi/src/autotype.rs`, `crates/app-autotype/src/lib.rs`, `macos/App/AutoType.swift`, `AutoTypeTests.swift`, `AutoTypeUnlockTests.swift` and `tests/autotype.rs`, and added typing files. `int05.rs` and `int05_match.rs` got CPU-time timing (F-090, F-092). My proof covers the 21:28 snapshot. AutoTypePicker.swift and UnlockView.swift are still equal at the end. N10 is the follow-up.
- **Rule 10.** No real hot key, no real window title or front app, no key event, no Accessibility prompt, no window ordered front. Views were rendered in borderless windows at x −20000. The general pasteboard was not touched: Y-V2 reads only `com.app.clipboard.<pid>.<n>`.
- **Rule 11.** Each process I started ended by itself. Mutants ran only in the copy. In the shared tree I wrote only this section and the E8-S2 status line.
- **CPU.** The longest single run was the final Swift full run, 214 s. The mutant batches took about 25 minutes of wall time.

### R3 1. The round-2 findings: fixed

| Round-2 finding | Fix in the tree | Story test | Mutants it catches |
|---|---|---|---|
| (1) INT-05.29 stale target | `fired()`: `back = nil` before `run(target)` | s-u "INT-05.29: after a panel flow that typed at once, …" | S0 (also Y-V7, Y-V8) |
| (2) SwiftLint `--strict` | picker model in AutoTypePicker.swift, observer parameters on the brace line, `unlockRow` extension, AutoTypeUnlockTests.swift, `masked` | whole-tree lint exit 0 | – |
| (3) S-AT-02 untested | f `s_at_02_url_matching_from_the_settings_store` | as named | R15, R15b, R15c |

The fix for (1) is safe in every path. `fired()` is the only place a new flow starts. `vaultsChanged` sets `back` again before its own `run`. Y-V9 shows that a later panel flow still brings back its own target (`activated: [4646]`) and not the old one. Mutant U7 fails both the story test "INT-05.25 step 5, T62…" and Y-V9.

### R3 2. Case map

Round 2's map (section 2 below) still holds. The tests it names under `s:` for the panel and the flow (T60, T61, T62, the APP-06.27 Cancel test, SR-16/T68/T69) now live in `macos/AppTests/AutoTypeUnlockTests.swift`, an `AutoTypeTests` extension (`s-u:` in this round). All of them passed. New rows: T52/S-AT-02 → f `s_at_02_url_matching_from_the_settings_store` (finding 3 closed). INT-05.29 after a panel flow → s-u "INT-05.29: after a panel flow that typed at once, …" (finding 1 closed).

### R3 3. Own probes (copy only; public API and fakes only)

Rust, `crates/app-ffi/tests/verify_e8s2y.rs`. `cargo test -p app-ffi --test verify_e8s2y` gave `18 passed; 0 failed`.

| Probe | What it checks | Result |
|---|---|---|
| y01 | `NoVault`; Personal locked gives `Locked{Personal}`, even with Work unlocked; Work shown gives Work's rows only; after Personal's unlock, rows of both (T61, T62) | pass |
| y02 | AT-G01: 8 lookalike or odd titles all open the picker; handles 0 to 9 are `Gone` before the choice; after Return, 71 keys | pass |
| y03 | S-AT-03 off: one match is `Type`; 2 rows, no match, a title over 8 KiB and a title over 64 KiB all open the picker with every candidate | pass |
| y04 | T72: a direct match is not remembered; T70: the last row is highlighted, a search that drops it gives 0, clearing the search brings it back; T71: S-AT-08 = 0 | pass |
| y05 | T73: Work's lock keeps Personal's choice; Personal's own lock and lock-all drop it | pass |
| y06 | SR-16: lock, lock-all and close each empty the list, give `Gone` and drop the made plan | pass |
| y07 | AT-G02: `Stopped{n}` after exactly n+1 checks for n = 0, 1, 2, 3, 15, 29; the plan is used once; unchanged focus gives 30 keys and 30 checks | pass |
| y08 | one plan at a time (the old handle is `Gone`); ⌘1 8, ⌘2 20, ⌘3 6, ⌘4 24, Return 30, ⌘5 30 keys; an index past the list is `Gone` | pass |
| y09 | LD-186 through the bridge for `{DELAY 0}` and `{DELAY=0}`: 9,900 keys + 101 zero waits give MI05-21; + 100 give `Finished{9900}` | pass |
| y10 | rule 4: 4 titles × 9 searches show no sequence token, no GitHub password, no `DEMOGITHUB`, `demo-pass`, `otpauth` or the probe's own password; a user name `{PASSWORD}` shows the mask | pass |
| y11 | LD-196 (1): the title `{S:otp}` of a one-time password set by `set_totp` is the mask; the plain user name shows; no secret or link | pass |
| y12 | renamed while the picker is open: still typed (8 keys); Auto-Type switched off while open: `Gone` (INT-05.19), then never listed or found | pass |
| y13 | S-AT-01 and S-AT-02 from the store: a host-in-title lists Intranet alone; S-AT-01 off: the title match goes, the URL match stays; both off: every candidate; S-AT-01 on and S-AT-02 off: title only | pass |
| y14 | T56: expired row marked; S-AT-05 on: not listed and not found by search | pass |
| y15 | S-AT-07: ⌃⌥V code 9; ⌘⌥A 0, ⌃1 18, ⌃⇧Z 6, ⌘; 41; `⇧V`, `⌥⇧V`, `V`, `⌃`, `⌘⌘`, `⌃⌥VX` and empty give none | pass |
| y16 | search finds Work's Team wiki; a 70,000-character search gives nothing; empty search gives the 2 matches | pass |
| y17 | LD-114: `//{S:Pin}//` and `//^Quiet{S:Pin}$//` match no title holding the value | pass |
| y18 | a failed choice (`{TAB 101}`) is not remembered; an earlier plan never types twice | pass |

Swift, `macos/AppTests/VerifyE8S2YTests.swift`: `✔ Test run with 9 tests in 1 suite passed`.

| Probe | What it checks | Result |
|---|---|---|
| Y-V1 | LD-219 (1): log `mask true: 13 user names, 0 in tree, hidden true`; `mask false: 13 … 13 in tree` | pass |
| Y-V2 | T66: ⇧⌘2, ⇧⌘1 and ⇧⌘4 land on a private board (`true` ×3); ⇧⌘5 keeps the picker; 4 captures, no key check, no alert | pass |
| Y-V3 | AT-G01: 5 titles from "Evil" (pid 5151) each open the picker with 1 read; App's own pid with S-AT-03 off gives no picker and no panel | pass |
| Y-V4 | AT-G02: `FocusCheck` gives yes for the same pid and window (also with a new title); no for another window, another pid or no window | pass |
| Y-V5 | rule 4: the picker's tree has no sequence token, no password, no `otpauth`; it does have `alex-dev` | pass |
| Y-V6 | T62 panel: M06-40, Cancel before Unlock, no "Switch vault"; two presses read no window; a wrong password keeps the panel; the right one opens the picker with no new capture; Return types 30 keys and brings nothing back; lock-all cancels a panel | pass |
| Y-V7 | INT-05.29 after a panel flow that typed at once: `activated after the later Escape: []` | pass (round-2 fail fixed) |
| Y-V8 | the same after a panel flow that failed with MI05-10 (`{TAB 101} repeats more than 100 times.`): `[]` | pass |
| Y-V9 | a later panel flow (Safari, pid 4646) after a stale one: Escape brings back `[4646]` only | pass |

### R3 4. AT-G01, AT-G02, LD-186, rule 4, seams

- **AT-G01:** f `at_g01_…`, s "AT-G01…", y02, y03, Y-V3. Mutant R1 (`Picker::single` ignores S-AT-03) fails m `t58_t59_always_ask_off`, f `at_g01_…` and 9 more story tests. Mutant S2 (App in front allowed) fails s "INT-05.25 T60, T61, T62…" and Y-V3.
- **AT-G02:** f `at_g02_…`, s "AT-G02 T90, T91", y07, Y-V4. Mutant R2 (only the first key checked) fails f `at_g02_…`. Mutant S1 (pid only) fails s "AT-G02 T90, T91".
- **LD-186 zero waits counted, 2 of 2 kinds:** m `ld186_2_zero_waits_and_pauses_count` and y09. Mutant R9 (`{DELAY 0}` free) and mutant R10 (`{DELAY=0}` free) each fail m `ld186_2_…`.
- **Rule 4:** rows carry no sequence and no value (f `int_05_26_t63_…`, y10, Y-V5). A protected or one-time-password title or user name shows the mask: R6 and R14 fail f `ld_207_…`. The panel's typed password is cleared: U8 fails s "…APP-06.27: Cancel…". LD-219 (1): M1 and M2 fail s "LD-219 (1)…".
- **Seams, by grep over the shared tree:** `RegisterEventHotKey` appears only at AutoType.swift:94. `frontmostApplication` and `AXUIElementCopyAttributeValue` appear only at AutoType.swift:34–43. `CarbonHotKeys()`, `SystemWindows()` and `AutoTypePanel.present` are built only at AppDelegate.swift:62, inside `if !launchHidden()`. AppDelegate.swift is not among the test target's 83 files (pbxproj `membershipExceptions`). Tests build `AutoType` only with `FakeHotKeys` and `FakeWindows`, and replace `alert`, `unlock`, `activate` and `stopped` before the first press. No E8-S2 Swift file names `NSPasteboard.general`. Mutant U9 (the unlock panel shown before screen protection) fails ScreenProtectionTests "APP-10.1, APP-10.3, AT-D04…".

### R3 5. Mutants (private copy; one exact replace each; restored, `cmp` equal)

The Rust runs covered app-ffi `--lib`, `tests/autotype.rs` and my probe, plus `-p app-autotype` for app-autotype files. The Swift runs covered `AutoTypeTests` (with AutoTypeUnlockTests.swift) and my probe suite, plus ScreenProtectionTests for U9. A runner mistake of mine: the first Rust batch restored files with their old mtime, so cargo kept R1's build for R2 to R18. I fixed the runner (`os.utime` after each restore) and ran R2 to R18 again. The rows below come from the second batch. R15, R15b, R15c and R1 ran before the mistake.

| # | Mutant | Story tests that fail | Probes |
|---|---|---|---|
| R1 | `single` ignores S-AT-03 | m `t58_t59_…`; f `at_g01_…`, `int_05_31_t72_…`, `ld_207_…`, `s_at_01_…`, `s_at_02_…`, `s_at_05_…`, `int_05_15_…`; f-lib `r05_1_…`, `int_05_19_…` | y02, y10, y11, y13, y14 |
| R2 | only the first key's window check | f `at_g02_…` | y07 |
| R4 | a lock keeps the picker | f `sr_16_…` | y06 |
| R4b | a lock keeps the plan | f `sr_16_…` | y06 |
| R6 | row title not masked | f `ld_207_…` | y11 |
| R7 | S-AT-05 not read | f `s_at_05_…` | y14 |
| R8 | S-AT-01 not read | f `s_at_01_…` | y13 |
| R9 | `{DELAY 0}` free | m `ld186_2_…` | y09 |
| R10 | `{DELAY=0}` free | m `ld186_2_…` | y09 |
| R12 | a picker choice not remembered | f `int_05_28_…`, `int_05_31_t72_…` | y04, y05 |
| R13 | INT-05.19 check removed in `autotype_choose` | f-lib `int_05_19_…` | y12 |
| R14 | row user name not masked | f `ld_207_…` | y10 |
| R15 | `by_url: true` | f `s_at_02_…` | y13 |
| R15b | `by_url: false` | f `s_at_02_…` | y13 |
| R15c | `by_url: flag("autotype.match_title")` | f `s_at_02_…` | y13 |
| R16 | S-AT-08 fixed at 15 s | f `int_05_28_…` | y04 |
| R17 | `autotype_type` takes any handle | **none** | y08 |
| R18 | `autotype_start` keeps an old picker | **none** | – |
| S0 | no `back = nil` in `fired()` | s-u "INT-05.29: after a panel flow…" | Y-V7, Y-V8 |
| S1 | `FocusCheck` pid only | s "AT-G02 T90, T91" | Y-V4 |
| S2 | the shortcut works with App in front | s-u "INT-05.25 T60, T61, T62…" | Y-V3 |
| S3 | ⇧⌘1 to ⇧⌘4 copy nothing | s "Return confirms… ⇧⌘2 copies" | Y-V2 |
| S5 | `appChanged` keeps `back` | **none** | – |
| M1 | `Text(verbatim: row.username)` | s "LD-219 (1)…" | Y-V1 |
| M2 | S-VIEW-06 not read | s "LD-219 (1)…" | Y-V1 |
| U1 | no resume after the unlock | s-u "INT-05.25 step 5, T62…", "INT-05.29: after a panel flow…" | Y-V6 to Y-V9 |
| U2 | Cancel brings the target back no more | s-u "…APP-06.27: Cancel…" | – |
| U3 | `lockAll` posts nothing | s-u "…APP-06.27: Cancel…" | Y-V6 |
| U4 | no step-2 guard for the panel | s-u "INT-05.25 step 5, T62…" | Y-V6 |
| U5 | no M06-40 line | s-u "INT-05.25 step 5, T62…" | Y-V6 |
| U7 | `vaultsChanged` does not set `back` | s-u "INT-05.25 step 5, T62…" | Y-V9 |
| U8 | the panel's typed password not cleared | s-u "…APP-06.27: Cancel…" | – |
| U9 | the unlock panel shown before screen protection | ScreenProtectionTests "APP-10.1, APP-10.3, AT-D04…" | – |

### R3 other stories' failures (not E8-S2)

- F-069 `ShownPasswordFieldTests.swift:57` (`!Self.typingCanUndo(editor)`) failed in all 3 of my runs in the copy. Another agent is changing that file in the shared tree (7.1 KB in my copy, 7.5 KB in the shared tree).
- The generator-passphrase parity test (`GeneratorTests.swift:268`) failed once, then passed alone.
- The editor-entry Expires test (`ParityEditorPagesTests.swift:291`, `< 5` s against the clock, the test took 34 s) failed once under load.
- One R15 run had the app-ffi lib test `reports::tests::ld_137_…` fail once; it passed in every other run.

### R3 notes, not blocking

- **N8. S5.** `appChanged` clears `back`, so a picker that closes because the user activated another app brings no app back. No test pins this. INT-05.29's last sentence, read word for word, would bring the target back in that case too. The code's choice (the user's own activation wins) is the sensible one. A Spec line should say which.
- **N9. R17 and R18.** The handle check in `autotype_type` and the picker reset at the top of `autotype_start` are defensive: Swift holds only the last handle and closes every picker. Only my y08 pins the first; nothing pins the second. INT-05.46 is E8-S3's, which could add a story test.
- **N10. E8-S3 now changes this story's files.** E8-S3's Checker and Verify should run E8-S2's story tests and the S0, R15, R1, R2 and R9/R10 mutants again on the new code. The INT-05.29 test now expects one activation before the first key (INT-05.38 step 1) and none after the later Escape.
- **N11.** UnlockView.swift is 398 lines and AutoTypeTests.swift 391; SwiftLint's file_length limit is 400 under `--strict`.
- **N12.** SwiftLint exits 133 without `DEVELOPER_DIR` (`xcode-select -p` is `/Library/Developer/CommandLineTools`). check.sh G1 needs `DEVELOPER_DIR` exported on this Mac.
- **N13.** `$TMPDIR/app-ffi-reports-61790` (21:33:16) is probably from my first full Rust run, the one run I did without my own TMPDIR. I cannot prove that, so I left it, as I did the older ones.
- Round 2's notes N1 to N6 still hold: the hint line wraps one word early, LD-195 (3), the MOD-09.14 badge, INT-05.32, INT-05.33, the recorder and ⌘5's memory still without owners, APP-06.27's switcher, and INT-05.38 step 1, which E8-S3 is now building.

## Round 2 (2026-10-28 23:59 to 2026-10-29 00:45, failed (3))

Date: 2026-10-28 23:59 to 2026-10-29 00:45.
Role: Verify, round 2, for the whole story: the Rust part (Checker 1 passed, LD-196) and the Swift part, with the Builder's fixes of the three round-1 findings. I did not build or check this story. I used no reference access. Note: the status line ended "Checker next" after the fixes; the workflow sent the story to Verify without a Checker re-check, so this round re-proves the fixes itself.
Result: **failed (3).** The three round-1 findings are fixed and each fix has a story test that fails without it. Matching, the picker, the seams, AT-G01, AT-G02, LD-186, the secrets and the frame all hold. Three new things block Done:

1. **A stale "bring back" app (INT-05.29).** After an unlock-panel flow that typed at once or failed, the next, unrelated picker closed with Escape brings the old target app to the front.
2. **SwiftLint `--strict` fails (check.sh G1).** 7 errors, all in this story's files. The Builder's proof said "no output".
3. **S-AT-02 has no story test that fails without it.** Its key in the bridge's `settings()` can be wired wrong and every story test still passes.

Real global hot keys, real window titles, real key events and the real panels on screen belong to E8-S3 and Mac QA. This story types nothing: `autotype_type` only counts the key events it would post.

## Numbers

- **Rust:** `cargo test -p app-autotype -p app-ffi -p app-core` in the copy → `cargo test: 1027 passed, 25 ignored (48 suites, 124.80s)`.
- **Own Rust probes:** `crates/app-ffi/tests/verify_e8s2.rs`, 26 tests (683 lines, 90 assert statements, many in loops), public API only → `test result: ok. 26 passed; 0 failed`.
- **Swift:** full run (`-skip-testing:AppUITests`) → `Test run with 272 tests in 38 suites failed after 154.117 seconds with 1 issue`. 265 are the tree's tests, all pass (AutoTypeTests 13 of 13, ScreenProtectionTests, the frame test); 7 are my probes; the 1 issue is my probe V7, which is finding (1).
- **Mutants:** 27 (14 Rust, 13 Swift). Story tests catch 26. R15 (S-AT-02 unwired) is caught only by my probe P20: finding (3). Each file restored; `cmp` equal to its backup and to the shared tree.
- **Frame `menubar-auto-type-picker`:** PASS, light 0.63 %, dark 1.41 %, 0 missing strings, 0 boxes or runs over 2 pt.
- **Lint:** `cargo fmt --all -- --check` exit 0; `cargo clippy -p app-autotype -p app-ffi -p app-core --all-targets -- -D warnings` clean; `xcrun swift-format lint --strict` on the 6 changed Swift files exit 0; **SwiftLint 0.65.1 `lint --strict --quiet` in macos/ exit 2, 7 errors** (finding 2); `scripts/check-names.sh` → `names: PASS (3122 files scanned, 15 vault files name-only)`.

## Setup

- **Private copy:** `rsync -a --exclude /target --exclude /app-shots --exclude /fuzz/target --exclude /fuzz/corpus --exclude /fuzz/artifacts` to `/tmp/e8s2-verify-copy` at 23:59:32 (135 MB). Its `target` is a link to `/tmp/e8s2-verify-target`; its own `scripts/build-core.sh` (`build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`); Xcode `-derivedDataPath /tmp/e8s2-verify-dd`. `CARGO_TARGET_DIR=/tmp/e8s2-verify-target`.
- **Shared tree unchanged under me:** md5 of the 10 story files at the start and at the end: 9 equal. `macos/App/MainWindowModel.swift` changed at 00:01 by another agent, in the Edit menu's target lookup only; this story's `lockAll` line (`post(name: .appLockedEverything, object: session)`, line 161) is unchanged.
- **Probes existed only in the copy:** `crates/app-ffi/tests/verify_e8s2.rs` and `macos/AppTests/VerifyE8S2Tests.swift` (222 lines, 38 expectations). I wrote them from the card; from the Builder's tests I used only the fakes `FakeHotKeys`, `FakeWindows` and the offscreen `SnapshotTests` renderer.
- **Rule 10:** no real hot key registered, no real window title or front app read, no key event posted, nothing asked for Accessibility permission, no window ordered front. The general pasteboard was not touched: V2 reads only `com.app.clipboard.<pid>.<n>`. Chrome ran headless. Views rendered in borderless windows at x −20000 never ordered front.
- **Rule 11:** every process I started ran in the foreground of its command or as a background job of this session and ended by itself. Mutants ran only in the copy. In the shared tree I wrote only this file, a Verify section appended to `design/parity/menubar/report.md`, and the E8-S2 status line in `plan/epics.md`.
- **CPU:** longest single run the Swift full suite, 154 s; all mutant runs together about 25 min of wall time in four batches.

## 1. The round-1 findings: fixed

| Round-1 finding | Fix in the tree | Story test | Mutant that it catches |
|---|---|---|---|
| (1) LD-219 (1): picker ignores Mask User Names | `AutoType.run` reads `display.hide_usernames` into `AutoTypePicker.maskUserNames`; `AutoTypePickerView` sets `\.maskUserNames`; rows draw `MaskedUser` | s "LD-219 (1), APP-01.23 …" | M1 (`Text(verbatim: row.username)`), M2 (flag not read) |
| (2) T62: no unlock panel, flow does not go on | `AutoTypeUnlock` + `AutoTypeUnlockPanel` (shared `UnlockView` with M06-40 and Cancel), `waiting` state, resume in `vaultsChanged`, `cancelUnlock`, `.appLockedEverything` | s "INT-05.25 step 5, T62 …", "… APP-06.27: Cancel, lock everything …" | U1 (no resume), U2 (Cancel brings nothing back), U3 (lockAll posts nothing), U4 (no step-2 guard), U5 (no M06-40), U7 (untyped picker after the panel brings nothing back), U8 (the typed password not cleared), U9 (panel shown before adopting screen protection: AT-D04) |
| (3) T72, S-AT-05, S-AT-01, T66 untested | f `int_05_31_t72_…`, `s_at_05_…`, `s_at_01_…`; `confirmTypes` reads the private pasteboard after ⇧⌘2 and ⇧⌘1 | as named | R3, R7, R8, S3 |

My own checks of the fixes: V1 (empty title, 13 user names: 0 in the tree with the mask on, "hidden" read; with it off the user name shows), V2 (⇧⌘2, ⇧⌘1 and ⇧⌘4 land on the private pasteboard; ⇧⌘5 is no action; 5 captures, no key check), V6 (panel tree has M06-40, Cancel before Unlock, no "Switch vault"; two presses while it shows read no window; a wrong password keeps the panel; the right one opens the picker for the captured target with no new capture; Return types and brings nothing back; lock-all cancels the panel).

## 2. INT-05 case map (T42 to T73, the R05 and LD rows)

`m:` = `crates/app-autotype/tests/int05_match.rs`; `f:` = `crates/app-ffi/tests/autotype.rs`; `f-lib:` = app-ffi unit tests; `s:` = `macos/AppTests/AutoTypeTests.swift`; `P..`/`V..` = my probes. Every story test named here passed in this round.

| Case | Story tests | My probes | Left |
|---|---|---|---|
| T42 INT-05.19 | m `t42_candidates`, `candidates_walk_agrees_with_app_core` | P18 (bin), P23 (Auto-Type off) | – |
| T43 | m `t43_pattern_types_directly` | – | real typing: E8-S3 |
| T44, T45, T46 | m `t44_…`, `t45_…`, `t46_lookbehind_matches_nothing` | – | – |
| T47, T48 | m `t47_…`, `t48_…` | – | – |
| T49, T50 | m `t49_only_star_is_special`, `matching::tests::glob_cases`, `t50_…` | – | – |
| T51 | m `t51_title_match_setting`; f `s_at_01_title_matching_from_the_settings_store` | P20 | – |
| T52 | m `t52_url_and_host_in_the_title` | P20 (S-AT-02 off through the bridge) | **finding (3)**: S-AT-02's bridge key has no story test |
| T53, T54 | m `t53_…`, `t54_…`; f `int_05_26_t63_…` | – | – |
| T55, R05-1 | m `t55_empty_effective_sequence`, `ld196_actions_of_an_entry`; f-lib `r05_1_…`, `int_05_19_…` | P24 | Type Login is INT-05.33, not built |
| T56 | m `t56_expired_entries`; f `s_at_05_hide_expired_entries_from_the_settings_store` | P19 | note N3: no expired badge |
| T57 | m `t57_…`; s "keys move, typing searches all…" (`Type into Notes`) | P04, V1 | – |
| T58, T59 | m `t58_t59_always_ask_off`; f `at_g01_…`; s "AT-G01…" | P04 | – |
| T60 | s "INT-05.25 T60, T61, T62…" | V3 | – |
| T61 | f `int_05_25_step_5_…`; s same | P01 | – |
| T62 | f `int_05_25_step_5_…`; m `t62_rows_from_every_unlocked_vault`; s "INT-05.25 step 5, T62…", "…APP-06.27: Cancel…" | P02, V6 | the panel on a real screen: Mac QA |
| T63 | f `int_05_26_t63_…`; m `t63_t65_…`; s the frame test | P15, V5 | the app name line is W-06 |
| T64 | f `int_05_27_…`; m `t64_…`; s "keys move…" | P23 | – |
| T65 | f `int_05_29_actions_…`; m `t63_t65_…` | P17 | – |
| T66 | f `int_05_29_actions_…`; s "Return confirms… ⇧⌘2 copies" (private pasteboard) | V2 | – |
| T67 | s "keys move…" | – | – |
| T68 | f `sr_16_…`; s "SR-16, INT-05.29…" | P10 | – |
| T69 | s "SR-16, INT-05.29…" | – | the real notifications: Mac QA |
| T70 | f `int_05_28_int_05_31_…`; m `t70_t73_…`; s "INT-05.28, INT-05.31 T70…" | P06, P08 | – |
| T71 | f `int_05_28_…` (S-AT-08 = 0); m `t70_t73_…` | P07, P08 | – |
| T72 | f `int_05_31_t72_a_single_match_typed_directly_is_not_remembered` | P05 | – |
| T73 | f `int_05_28_…` (lock and unlock) | P08, P09 | – |
| R05-5 | m `r05_5_host_in_both_forms` | – | – |
| LD-114 | m `ld114_no_protected_value_in_a_pattern` | P25 (`//{S:Pin}//`, `//^Quiet{S:Pin}$//` match nothing; `*{S:Pin}*` may) | – |
| LD-184 (4) | m `ld184_4_editor_check_with_the_vaults_own_entry` | – | – |
| LD-186 (2) | m `ld186_2_zero_waits_and_pauses_count` | P13, P14 | – |
| LD-191 R02-2, rule 4 | m `r02_2_rows_hold_no_secret`; f `int_05_26_t63_…` | P15, V5 | – |
| LD-196 (1) to (3), sort | m `ld196_1_…`, `ld196_2_…`, `ld196_3_…`, `ld196_sort_…` | P16, P21 | – |
| LD-207 | f `ld_207_…` (title and user name) | P15, P16 | – |
| LD-219 (1) | s "LD-219 (1), APP-01.23…" | V1 | – |
| R05-6, D-INT05-12, -14, -16 | – | – | W-06: wait for the owner's mockup changes, not built |

## 3. Own probes

### Rust: `tests/verify_e8s2.rs` (copy only)

Public API: `Session::autotype_start`, `autotype_rows`, `autotype_choose`, `autotype_close`, `autotype_type`, `autotype_hot_key`, the editing calls, `app_autotype::{Memory, Row, plan}`, and a counting fake `AutoTypeFocus`. `cargo test -p app-ffi --test verify_e8s2` → `test result: ok. 26 passed; 0 failed`.

| Probe | What it checks | Result |
|---|---|---|
| P01 | no vault: `NoVault`; every vault locked: `Locked{shown}` | pass |
| P02 | T62: shown locked, Work unlocked: `Locked{Personal}`; after the unlock, rows of both; Work shown, Personal locked: Work's rows only | pass |
| P03 | AT-G01: 8 titles (lookalikes, frame title, empty, none, `wiki`) all give the picker; plan handles 0 to 8 are `Gone` before the choice; after Return the plan types | pass |
| P04 | S-AT-03 off: one match types at once; several rows, no match, a title over 64 KiB and one over 8 KiB open the picker | pass |
| P05 | T72: the direct single match is not remembered | pass |
| P06 | T70: the choice is highlighted among every candidate; a search that drops it gives 0; clearing brings it back | pass |
| P07 | T71: S-AT-08 = 0 remembers nothing | pass |
| P08 | model clock: 14 s held, 16 s gone; same entry other sequence: its first row; 600 s capped (59 s held, 61 s gone); 0 forgets; `forget_vault` only its vault | pass |
| P09 | T73 through the bridge: Work's lock keeps Personal's choice; Personal's lock and lock-all drop it | pass |
| P10 | SR-16: lock, lock-all and close each empty the list, give `Gone`, drop a made plan | pass |
| P11 | AT-G02: `Stopped{n}` after exactly n+1 checks for n = 0, 1, 2, 3, 15, 29; the plan is never retried; unchanged: `Finished{30}` with 30 checks | pass |
| P12 | one plan at a time: a new choice makes the old handle `Gone` | pass |
| P13 | LD-186 through the bridge, for `{DELAY 0}` and `{DELAY=0}`: 9,900 keys + 101 zero waits → MI05-21 "The sequence has more than 10,000 keys, waits and pauses."; + 100 → `Finished{9900}` | pass |
| P14 | LD-186 in the model: 10,000 zero waits pass, 10,001 give `TooManyKeys`, for 2 of 2 kinds | pass |
| P15 | rule 4: 4 titles × 9 searches hold no `{USERNAME}`, `{PASSWORD}`, `{TAB}`, `{ENTER}`, `{TOTP}`, GitHub's password, `DEMOGITHUB`, `demo-pass`, `otpauth`; a user name `{PASSWORD}` shows the mask | pass |
| P16 | LD-196 (1): a title `{S:otp}` of a one-time password set through `set_totp` is the mask; the plain user name shows; no secret | pass |
| P17 | ⌘1 8, ⌘2 20, ⌘4 24, Return 30, ⌘5 30, ⌘3 6 keys; an index past the list `Gone` | pass |
| P18 | renamed while open: still typed (8 keys); moved to the bin while open: `Gone`; never listed or found from the bin | pass |
| P19 | T56: expired row marked; S-AT-05 on: not listed and not found | pass |
| P20 | S-AT-01 and S-AT-02 from the store: a URL-host title matches by URL; S-AT-02 off: every candidate; S-AT-01 off: the title match goes, the URL match stays | pass |
| P21 | sort: `Alpha`/a, `alpha`/b, `beta`/a | pass |
| P22 | S-AT-07: ⌃⌥V code 9; ⌘⌥A 0, ⌃1 18, ⌃⇧Z 6, ⌘; 41; `⇧V`, `⌥⇧V`, `V`, `⌃`, `⌘⌘`, `⌃⌥VX` none | pass |
| P23 | search finds Work's entry; an entry with Auto-Type off is never found or matched; a 70,000-character search gives nothing | pass |
| P24 | INT-05.19: Auto-Type switched off while the picker is open: `Gone` | pass |
| P25 | LD-114 (see the map) | pass |
| P26 | a failed choice (`{TAB 101}`) remembers nothing and leaves no plan | pass |

### Swift: `VerifyE8S2Tests.swift` (copy only, fakes only)

| Probe | What it checks | Result |
|---|---|---|
| V1 | LD-219 (1): log `VERIFY-V1 title '' mask true: 13 user names, 0 in tree, hidden true`; frame title on: 0 of 1, off: 1 of 1 | pass |
| V2 | T66: `VERIFY-V2 ⇧⌘2 on a private board: true`, `⇧⌘1 … true`, `⇧⌘4 URL … true`; ⇧⌘5 keeps the picker; 5 reads, no alert | pass |
| V3 | AT-G01: 5 titles from "Evil" (pid 5151) each open the picker with 1 read; App's own pid with S-AT-03 off: no picker, no typing | pass |
| V4 | AT-G02: `FocusCheck` yes for the same pid and window (also with a new title); no for another window, another pid, no window | pass |
| V5 | rule 4: the picker tree has no sequence and no password, has `alex-dev` | pass |
| V6 | T62 panel flow (section 1) | pass |
| V7 | INT-05.29 after a panel flow that typed at once | **fails**: `VERIFY-V7 activated after the later Escape: [4343]`, issue at VerifyE8S2Tests.swift:220 |

## 4. AT-G01 and AT-G02 at the model level

Both are proven at the model level with fake windows only. The real typing half (posting key events, the real focus check over the Accessibility API, INT-05.38 step 1) is E8-S3's.

**AT-G01 (lookalike window).** Another program shows `Inbox – Proton Mail`. With S-AT-03 on (default) the picker shows, nothing is typed, and exactly one window read happens: f `at_g01_…`, s "AT-G01…", P03, V3. No plan exists before the user's choice (P03: handles 0 to 8 `Gone`). With S-AT-03 off the picker still opens for several rows, an empty title, no match and over-long titles (P04, s "AT-G01…"); a limited run never types directly (`ld196_2`). Mutant R1 (`single` ignores S-AT-03) fails m `t58_t59_always_ask_off`, f `at_g01_…` and 7 more story tests.

**AT-G02 (focus change during typing).** `autotype_type` asks `AutoTypeFocus.same_window()` before every key and stops at the first no (f `at_g02_…`, P11: n+1 checks). Swift's `FocusCheck` compares the pid and the focused window's identity (s "AT-G02 T90, T91", V4); a stop plays the alert sound. Mutants: R2 (one check before the first key only) fails f `at_g02_…`; S1 (pid only) fails s "AT-G02 T90, T91".

## 5. LD-186: zero waits counted

`{DELAY 0}` and `{DELAY=0}` each count as one action: 10,000 pass, 10,001 give MI05-21 (P14, m `ld186_2`); through the bridge, 9,900 keys plus 101 zero waits fail and plus 100 type 9,900 keys, for both kinds (P13). Zero waits counted: 2 of 2 kinds. Mutants R9 (`{DELAY 0}` free) and R10 (`{DELAY=0}` free) each fail m `ld186_2_zero_waits_and_pauses_count`, P13 and P14.

## 6. Secrets (rule 4, LD-191 R02-2, LD-207)

- `AutoTypeRow` (crates/app-ffi/src/autotype.rs:32) has ids, title, user name, expired, host, icon; no sequence, no value. Host is empty for a protected URL.
- The plan stays in Rust behind a `u64`, used once, dropped on lock, lock-all and close (R4, P10).
- No sequence or value in any list, search or accessibility tree (P15, V5, f `int_05_26_t63_…`).
- A title or user name that reads a protected or one-time-password value is the mask (f `ld_207_…`, P15, P16). Mutants R6 (title) and R14 (user name) each fail f `ld_207_…`.
- The unlock panel reuses the shared form; Cancel, the vault closing and lock-everything clear its typed password (s "…APP-06.27: Cancel…" checks `panel.form.password.isEmpty`; mutant U8 fails it).
- Mask User Names now reaches the picker (V1, M1, M2).

## 7. The shortcut and window seams (rule 10)

Read in the tests and the code, then checked with `grep` over the shared tree:

- `RegisterEventHotKey` only at `macos/App/AutoType.swift:94` (`CarbonHotKeys`); `frontmostApplication` and `AXUIElementCopyAttributeValue` only at `AutoType.swift:34–43` (`SystemWindows`).
- `CarbonHotKeys()`, `SystemWindows()` and `AutoTypePanel.present` are built only at `AppDelegate.swift:62`, inside `if !launchHidden()`.
- The test target compiles 83 files listed in `project.pbxproj` `membershipExceptions`; `AppDelegate.swift` is not among them (grep count 0).
- Tests build `AutoType(session:…)` only with `FakeHotKeys` and `FakeWindows` (`AutoTypeTests.swift:113`, my probe). They replace `alert`, `unlock`, `activate` and `stopped` with recorders before the first press, so the real panel, beep, activation and MI05-10 alert never run. No test calls `AutoType.start()`, where the workspace observers are added. `AutoTypePanel.present`, `AutoTypeUnlockPanel.present`, `activate` and the MI05-10 alert return early in a hidden launch.
- No E8-S2 Swift file names `NSPasteboard.general`; the copies go to the session's private pasteboards.
- The shortcut through the seam: T75 (⌃⌥V registered once as 0x09 with ⌃⌥; the fake press opens the picker; a second press does nothing); T77, T78 (refused key reported; cleared or invalid S-AT-07 unregisters); S-AT-07 parsing (f `int_05_30_…`, P22).

## 8. Frame `menubar-auto-type-picker` (BUILD-AND-VERIFY "Prompt for the Verify fleet")

Commands, in the copy:

1. `node design/option-a/tools/export-reference.mjs` → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames` (57 s, headless). manifest.json byte-equal to the shared one. The picker reference against the shared one: pixelmatch 0 changed pixels in both themes (raw 36 light, 7,147 dark: render noise), so the shared reference is current.
2. `node design/parity/tools/mockup-dom.mjs menubar` → `light: 2 frames, 30 text runs`, `dark: 2 frames, 30 text runs`.
3. `scripts/build-core.sh`; `xcodebuild … -derivedDataPath /tmp/e8s2-verify-dd build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` → `** TEST BUILD SUCCEEDED **`.
4. `xcodebuild … test-without-building -skip-testing:AppUITests` → `✔ Test "Option A frame menubar-auto-type-picker, offscreen, light and dark" passed`, `✔ Suite AutoTypeTests passed`. The PNG and .ax.json it wrote are byte-equal to the shared app-shots in both themes.
5. `swift design/parity/tools/ocr.swift app-shots/{light,dark}/menubar-*.png` → 4 images read.
6. `node design/parity/tools/compare.mjs menubar` (behaviour.log = step 4's log) → `menubar: 2/2 PASS`, `menubar-auto-type-picker PASS L 0.63% (0.63) D 1.41% (1.41)`.

| Check | Light | Dark |
|---|---|---|
| 1 Present | yes | yes |
| 2 Text: 7 texts, 1 name, 1 placeholder | 9 found, 0 missing, 0 extra | same |
| 3 Tokens | 1 extra colour `#e2eff2` accent-soft 0.94 %: the search field's focus halo (INT-05.26 gives it the focus; noted in notes.mjs); glyphs keyboard, magnifying-glass; GitHub logos | same, `#10303a` |
| 4 Boxes, text runs > 2 pt | 0 + 0 (dialog 480 × 263 against 264; rows exact) | 0 + 0 |
| 5 Pixels (outside accepted) | 0.63 % (0.63 %) | 1.41 % (1.41 %) |
| 6 Behaviour | "keys move, typing searches all, Escape clears, then closes" and "Return confirms; the run checks the window per key; ⇧⌘2 copies": ok | same |
| 7 Accessibility | header as heading; field "Search all entries"; rows as buttons "GitHub, alex-dev, GitHub, Type login ⏎", first selected, action "Type login"; contrast 42 pairs, lowest 4.87:1 | same |
| Verdict | PASS | PASS |

Rows added to `design/parity/menubar/report.md` (section "Verify, E8-S2 round 2"); the menubar-menu-bar-icon rows were left as they are. Images: `design/parity/menubar/{app,diff}/<theme>/menubar-auto-type-picker.png`.

Card words against mockup words (none built; all W-06):

| Place | Card | Mockup (drawn) | Built |
|---|---|---|---|
| Under the header | the target app's name (D-INT05-16 (3)) | nothing | the mockup's |
| Row small line | ` · ‹sequence›`, ` · ‹vault›` (D-INT05-16 (4)) | user name only | the mockup's |
| Hint line | R05-6 "↑↓ to choose · ⏎ types the login · ⇧⏎ types the password only" | MI05-43 "… ⏎ types username, password and code …" | the mockup's |
| Empty list | MI05-45 | no state drawn | nothing |
| Row menu | MI05-44 | no state drawn | not built; its keys work |

The unlock panel has no Option A frame, so its pixels cannot be proven against one (Builder's note for the lead). V6 proves its words and order offscreen.

## 9. Mutants (private copy, own target, own derived data)

Exact one-place replace; tests run (Rust: app-ffi `--lib`, `tests/autotype.rs`, my probe, plus `-p app-autotype` for app-autotype files; Swift: `AutoTypeTests` and my probe, U9 `ScreenProtectionTests`); file restored, `cmp` equal to backup and shared tree (U3: equal to backup; the shared MainWindowModel.swift had another agent's unrelated edit). V7 fails in the baseline and is left out below.

| # | Mutant | Story tests that fail | Probes |
|---|---|---|---|
| R1 | `Picker::single` ignores S-AT-03 | m `t58_t59_…`; f `at_g01_…`, `ld_207_…`, `int_05_15_…`, `s_at_01_…`, `s_at_05_…`, `int_05_31_t72_…`; f-lib `r05_1_…`, `int_05_19_…` | P03 and 11 more |
| R2 | one window check before the first key | f `at_g02_…` | P11 |
| R3 | direct single match remembered | f `int_05_31_t72_…` | P05 |
| R4 | a lock keeps the picker | f `sr_16_…` | P10 |
| R6 | row title not masked | f `ld_207_…` | P16 |
| R7 | S-AT-05 not read | f `s_at_05_…` | P19 |
| R8 | S-AT-01 not read | f `s_at_01_…` | P20 |
| R9 | `{DELAY 0}` free | m `ld186_2_…` | P13, P14 |
| R10 | `{DELAY=0}` free | m `ld186_2_…` | P13, P14 |
| R12 | a picker choice not remembered | f `int_05_28_…`, `int_05_31_t72_…` | P06, P09 |
| R13 | INT-05.19 check removed in `autotype_choose` | f-lib `int_05_19_…` | P24 |
| R14 | row user name not masked | f `ld_207_…` | P15 |
| R15 | S-AT-02 not read (`by_url: true`) | **none** (lib 105, autotype 14 pass) | P20 |
| R16 | S-AT-08 not read (15 s fixed) | f `int_05_28_…` | P07 |
| S1 | `FocusCheck` pid only | s "AT-G02 T90, T91" | V4 |
| S2 | shortcut works with App in front | s "INT-05.25 T60, T61, T62" | V3 |
| S3 | ⇧⌘1 to ⇧⌘4 copy nothing | s "Return confirms… ⇧⌘2 copies" | V2 |
| M1 | `Text(verbatim: row.username)` | s "LD-219 (1)…" | V1 |
| M2 | S-VIEW-06 not read | s "LD-219 (1)…" | V1 |
| U1 | no resume after the unlock | s "INT-05.25 step 5, T62…" | V6 |
| U2 | Cancel brings the target back no more | s "…APP-06.27: Cancel…" | – |
| U3 | `lockAll` posts nothing | s "…APP-06.27: Cancel…" | V6 |
| U4 | no step-2 guard for the panel | s "INT-05.25 step 5, T62…" | V6 |
| U5 | no M06-40 line | s "INT-05.25 step 5, T62…" | V6 |
| U7 | untyped picker after the panel brings nothing back | s "INT-05.25 step 5, T62…" | (V7 passes) |
| U8 | the panel's typed password not cleared on close | s "…APP-06.27: Cancel…" | – |
| U9 | unlock panel shown before screen protection | s ScreenProtectionTests "APP-10.1, APP-10.3, AT-D04: every kind…" | – |

## Findings (the story fails until they are fixed)

1. **INT-05.29: a stale target is brought to the front by a later, unrelated picker.**
   - `vaultsChanged` sets `back = waiting.target.pid` before `run(waiting.target)` (macos/App/AutoType.swift:230). Only `finish` (line 268) and `appChanged` clear it. When that run does not open a picker (S-AT-03 off with one match: `.type`; or `.failed`), `back` stays set.
   - Probe V7: Personal locked, S-AT-03 off, Mail (pid 4343) in front with `Inbox – Proton Mail`; the panel unlocks, the single match types at once. Later the user is in Safari (pid 4242), presses the shortcut, gets the picker, presses Escape. `activate` is called with 4343: Mail comes to the front over Safari. Log `VERIFY-V7 activated after the later Escape: [4343]`; INT-05.29 brings the target back only when App was made active for the unlock panel of that flow.
   - Smallest fix: `back = nil` in `fired()` before `run(target)` (no flow is open there), and V7 as a story test (fails without the fix).
2. **SwiftLint `--strict` fails on this story's files (check.sh G1 `swiftlint`, Swift rule 2).** `cd macos && swiftlint lint --strict --quiet` (0.65.1, DEVELOPER_DIR set) → exit 2, 7 errors, all in E8-S2's files:
   - `App/AutoType.swift:161:23` and `:161:29` closure_parameter_position (the `.appLockedEverything` observer's `[weak self] _ in` on its own line);
   - `App/AutoType.swift:427:1` file_length 427 > 400;
   - `App/UnlockView.swift:8:1` type_body_length 253 > 250 (the panel additions);
   - `AppTests/AutoTypeTests.swift:479:1` file_length 479 > 400, `:79:1` type_body_length 339 > 250, `:418:13` identifier_name `on`.
   - The Builder's proof said "swiftlint lint --quiet on the 6 changed Swift files: no output"; without `--strict` the same 7 lines print as warnings.
   - Smallest fix: move `AutoTypeUnlock` (and the notification name) or `AutoTypePicker` into its own new file; put the observer closure's parameters on the brace line; move the panel's Cancel/Unlock row out of `UnlockView`'s body (a small extension); split the unlock-panel tests into a new `AutoTypeUnlockTests.swift`; rename `on` to `masked`. Then `swiftlint lint --strict` exit 0.
3. **S-AT-02's key in the bridge has no story test that fails without it.** Mutant R15 (`by_url: flag("autotype.match_url")` → `by_url: true`, crates/app-ffi/src/autotype.rs:207) passes every story test (app-ffi lib 105, `tests/autotype.rs` 14); only my P20 fails. Same kind as round-1 finding (3) for S-AT-01 and S-AT-05. Smallest fix: copy P20's URL half into `tests/autotype.rs`: an entry with URL `https://zeta-portal.example/login`, title `Login at zeta-portal.example — Safari` lists it alone; with `autotype.match_url` off the picker lists every candidate.

## Notes, not blocking

- **N1.** The hint line still wraps one word early (app run 385.5 pt against the mockup's 437 pt). The frame passes.
- **N2.** LD-195 (3) says the Swift picker sorts with `localizedStandardCompare`; the code keeps Rust's order (MOD-07.5 natural order, LD-196), which it must because a choice names a row by its position. Spec or the lead should update LD-195 (3).
- **N3.** MOD-09.14's expired badge is drawn nowhere (strike-through and VoiceOver "Expired" only). A Spec or lead line for the whole app.
- **N4.** Still without an owner: INT-05.32 S-AT-06 (T74), INT-05.33 Type Login with MI05-50 (T79 to T82), the shortcut recorder (T76 to T78, W-06), and the Spec line on what ⌘5 remembers.
- **N5.** APP-06.27's vault switcher for several locked vaults and the Touch ID auto-start are not in the Auto-Type panel (INT-05.25 step 5 asks only the shown vault; Touch ID is E6-S3). Escape on the panel is `.keyboardShortcut(.cancelAction)` on Cancel; the real key in a real panel is Mac QA.
- **N6.** INT-05.38 step 1 (make the target active before the first key) is E8-S3's; until then a pick after the unlock panel stops at the first window check, because App is in front.
- **N7.** Leftover temp folders (the known `reports.rs:1104` issue, and the R05-1 and INT-05.19 tests that clean up only when they pass): my baseline run left `$TMPDIR/app-ffi-reports-36390` (00:05, the only one in its window), and my 14 Rust mutant runs left 14 `app-ffi-reports-<pid>` plus `app-ffi-int-05-19-54360` (R13), `app-ffi-int-05-19-55864` and `app-ffi-r05-1-55864` (R1); count, order and times match my runs one for one. I deleted these 18 (demo data only). Older folders are not mine and stay.

## Round 1 (2026-10-28 23:00, failed (3))

Round 1 found: (1) LD-219 (1) Mask User Names not in the picker; (2) T62's unlock panel not built and the flow not going on; (3) T72, S-AT-05's and S-AT-01's bridge keys and T66's ⇧⌘ copies without a failing story test. All three are fixed (section 1). Round 1 also passed the case map, 23 Rust and 5 Swift probes, AT-G01, AT-G02, LD-186, the seams and the frame, with 18 mutants.
