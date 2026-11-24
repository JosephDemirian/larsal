# E13-S6 part l: re-test of F-130 and the Auto-Type follow-ups (LD-234 (1), LD-242 (1))

Story: E13-S6 part l ([plan/epics.md](../../plan/epics.md)). Row: F-130 in [security/findings.md](../findings.md). The Auto-Type follow-ups are notes N1 to N6 of [E8-S3-autotype-typing.md](E8-S3-autotype-typing.md); they have no rows of their own. Rulings: LD-234 (1), LD-242 (1), LD-170 (4), LD-231 (3), LD-220 (1).
Date: 2026-10-29 (the runs took place from 10:45 to about 11:05 on 2026-10-30 by the Mac's clock). Role: Verify, round 1. I did not find, build or check these fixes.

| Item | Result | One line |
|---|---|---|
| F-130 (Low): a reference search reads protected values | **fixed, re-tested** | In display mode, a `{REF:…}` search that compares a protected or never-shown value sets `Resolved::masked`. The row's URL is refused (MSG-08-4) whether the guess is right or wrong, and a key file path built that way is secret. Auto-Type's `reads_protected` asks only the flag. |
| N1: the `not-in-front` and `keys-held` lines, and a stop during those waits | **fixed, re-tested** | `end()` maps every stop raised during a wait to `stopped`. Rust and Swift tests check both lines. |
| N2: INT-05.38 step 4 (Larsal's own secure input off before typing) | **fixed, re-tested** | AutoType has a `secureInput` seam. A test with the fake system sees `disable` before the run starts. |
| N3: the target is asked forward before Rust waits for it | **fixed, re-tested** | A test with a fake target that comes forward only after `activate` types to the end. |
| N4: story tests for the four probe-only guarantees | **fixed, re-tested** | Waits end on a stop, a hidden launch never posts, `cg_flags` is checked for all 16 modifier sets, and no app in front stops the run. Each has a story test now. |
| N5: `KeyboardLayoutTable.current()` leaks a TIS copy | **fixed, re-tested** | Each copy is made only when it is reached, and always taken retained. My probe saw 50 calls add 0 retains (before: +50). |
| N6: a shortcut press before the run's stop flag is lost | **fixed, re-tested** | The stop flag is made with its plan. A press after the plan is made but before the typing thread starts stops that run. |
| The unused `front:` parameter of `type(_:into:front:)` | **fixed, re-tested** | It is gone. `type(_:into:)` asks macOS for `target.pid`. |

All 8 items were re-tested, and none failed. Three test-strength advisories (V-R3, V-R13, V-R10) are listed at the end. None of them blocks.

## Setup

- **Private copy.** `rsync -a --exclude target --exclude larsal-shots` of the tree to `/tmp/e13s6l-verify-copy` at 10:45:21 (143 MB). It had its own `CARGO_TARGET_DIR=/tmp/e13s6l-verify-target` and `-derivedDataPath /tmp/e13s6l-verify-dd`, and `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`. Probes and mutants lived only in the copy.
- **The verified snapshot** (SHA-256, first 12 digits): refs.rs `5c70791b7d5f`, auto_open.rs `5bee9d5a1e39`, matching.rs `d008d87b8d99`, int05_match.rs `46741274ca55`, autotype_typing.rs `c6c3a9883ffc`, autotype.rs `91aa1268651e`, tests/autotype_typing.rs `c5b206129312`, AutoType.swift `69b41ad13697`, AutoTypeTyping.swift `701433de97ea`, AutoTypeFollowUpTests.swift `b15d1e1bf475`. After the mutants, `shasum -a 256 -c` showed all 10 unchanged in the shared tree. `cmp` showed the copy's 8 product files equal to the shared tree.
- **Demo data only.** The vaults are built in the tests: entry "Target" with password `demo-s`, guesses `demo-s`, `nope` and `wrong`, a PIN `4711`, a one-time password field `otpauth://demo`, and user name `alice`.
- **My probes** (copy only, deleted with it):
  - larsal-core `tests/verify_e13s6l_probe.rs`: `v_f130_row_steps_default_protection`, `v_f130_other_codes` and `v_f130_index_copy_and_bound`.
  - larsal-autotype `int05_match.rs`: `v_e13s6l_rows_by_flag`.
  - LarsalTests `AutoTypeFollowUpTests.swift`: "Verify probe N5: KeyboardLayoutTable.current() keeps no TIS copy". The probe added one import line, so copy line numbers in that file are 1 higher than the shared tree's. The lines given below are the shared tree's.
- **Rule 10.** No key event was posted. No permission prompt, no real hot key, no real window title, no visible window, and never the general pasteboard. The only system read was the current keyboard input source (TIS, read-only), which the tree's own `layoutTable` test already reads. The hidden-launch test runs its own test binary again as a child with `LARSAL_TEST_HIDDEN=1`; nothing posts there either. **Rule 11:** I stopped no process. Every process I started ended by itself.

## Numbers

- **Rust** (copy): `cargo test -p larsal-core -p larsal-autotype -p larsal-ffi` gave `test exit 0`: 51 suites, **1127 passed, 0 failed, 28 ignored**. Run with the filter `f_130 ld_234 v_f130 v_e13s6l`: the 9 new story tests pass (the hidden child is ignored and run by its parent), and so do my 4 probes.
- **Lint** (shared tree):
  - `cargo clippy -p larsal-core -p larsal-autotype -p larsal-ffi --all-targets -- -D warnings`: `clippy exit 0`.
  - `cargo fmt --all -- --check`: `fmt exit 0`.
  - `swift format lint --strict` on AutoType.swift, AutoTypeTyping.swift and AutoTypeFollowUpTests.swift: exit 0.
  - SwiftLint 0.65.1 `lint --strict --quiet` on the same three files: exit 0. AutoType.swift has 400 lines.
- **Swift** (copy):
  - `scripts/build-core.sh`: `build-core exit 0`.
  - `xcodebuild test -only-testing:LarsalTests/AutoTypeTests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: `✔ Test run with 27 tests in 1 suite passed`, `** TEST SUCCEEDED **`. That is the 26 story tests plus my N5 probe.
  - After the mutants, `-only-testing:LarsalTests/AutoTypeTests -only-testing:LarsalTests/SecureInputTests` passed too (see Cleanup).
- **Mutants:** 23 in total, 17 Rust and 6 Swift. One Swift mutant did not compile and was redone, so 22 counted mutants ran. Story tests catch 19. My probes catch 2 more (V-R3, V-R10). One survives (V-R13, a loose time bound). V-S5 is the N5 "before" run, which the probe catches.

## F-130: a reference search over a protected field

Steps (demo data, the row's own probe). The vault keeps its default protection (Password on), and the password field has no flag of its own. Entry "Target" has password `demo-s`. Then resolve with `larsal_core::auto_open::resolve_field`, the function the open-URL action (`url_of`) and auto-open's key file use:
1. A URL `https://example.com/?t={REF:T@P:demo-s}` (right guess) and a URL `…?t={REF:T@P:nope}` (wrong guess).
2. A user name `{REF:T@P:demo-s}.larsalkey` as the key file path.
3. Other search codes, on a probe entry:
   - `{REF:T@A:https://t.example}` (A is the URL), `{REF:T@U:alice}`, `{REF:T@O:4711}` (O searches every field, and PIN is protected), and `{REF:T@T:{REF:T@P:nope}}` (nested).
   - `{REF:T@I:0101…}` (by id).
   - Then the same again with the vault's URL and UserName flags on.
   - Then again with no protection at all.
4. Auto-Type's indexed path: a display `Context` with an `EntryIndex`, then copy mode, then the work bound hit right after the search.
5. Auto-Type rows (picker over window title "Match"):
   - titles `{REF:T@P:wrong}`, `{REF:T@O:4711}`, `{REF:T@U:alice}` and `{REF:T@O:otpauth://demo}`;
   - a user name `{REF:U@I:<Target's id>}`.

Before (the fix undone in the copy: `self.mask_copied |= read` taken out of `reference_step`):
- `PROBE right: full=https://example.com/?t=Target shown=https://example.com/?t=Target secret=false`
- `PROBE wrong: full=https://example.com/?t= shown=https://example.com/?t= secret=false`
- `PROBE keyfile: full=Target.larsalkey secret=false`

So the URL opens, and it shows by its text whether the guess was right: the finding as filed.

After:
- Step 1: `PROBE right: full=https://example.com/?t=Target … secret=true` and `PROBE wrong: full=https://example.com/?t= … secret=true`. `open_url` turns `secret` into `UrlAction::Refused { MSG-08-4 }` for an http(s) URL, so neither guess opens and nothing tells them apart.
- Step 2: `PROBE keyfile: full=Target.larsalkey secret=true`, so the key file is used but never remembered or named (SR-12).
- Step 3:
  - With the default flags: A plain, U plain, O secret, the nested search secret, and the id search plain.
  - With the URL and UserName flags on: A and U secret.
  - With nothing protected and no hidden field: O plain. `PROBE other codes ok`.
- Step 4:
  - The indexed P search is masked for the right guess and for the wrong one. The indexed T search is plain.
  - Copy mode still gives `Target`, with `masked` false.
  - The bound: `PROBE bound: min units 110, at min-1 bounded=true masked=true`.
- Step 5:
  - `PROBE row 2: title="" hidden=true` (the wrong guess, hidden by the vault's Password flag).
  - `PROBE row 3: title="" hidden=true` (the PIN).
  - `PROBE row 4: title="Target" hidden=false` (the U search, shown).
  - `PROBE row 5: title="" hidden=true` (the one-time password field).
  - `PROBE row 6: title="ById" hidden=false user="alice" user_hidden=false` (by id, shown).

Reading the code: `reference_step` is the only caller of `find` and `find_indexed`, and both call `visit` on every entry before comparing it. `search_reads_withheld` answers false for code I. For a field code it asks only that field. For O it asks every field. Its answer is `masked()` (display mode and the field's own flag or the vault's flag), or display mode and a field `hidden` names. The flag is set before `charge` and `spend`. Only `resolve_field` and Auto-Type's `reads_protected` read `masked`. Auto-Type's plain and display contexts differ only in `display` and `hidden`. Every branch that depends on them (`mask()`, `{S:}` of a hidden field, and the search) now sets the flag. So the flag alone is enough, and the old text compare is not needed.

Story tests (pass): larsal-core `refs::f_130_tests::f_130_reference_search_over_protected_field_is_masked`, and larsal-autotype `f_130_reads_protected_uses_the_masked_flag`. Older tests that also guard this: `ld196_1_no_one_time_password_or_passkey_in_rows`, `r02_2_rows_hold_no_secret` and `ld114_no_protected_value_in_a_pattern`.

Mutants (copy; each run with `cargo test -p larsal-core --lib refs::`, then the probe and `--test mod08`, plus `cargo test -p larsal-autotype --test int05_match`):

| ID | Change | Caught by |
|---|---|---|
| V-R1 | no `mask_copied \|= read` in `reference_step` | core f_130 (refs.rs:1196), autotype f_130 (int05_match.rs:1173), probe |
| V-R2 | `find` calls `visit` only on the hit entry | core f_130 at refs.rs:1197 (the wrong guess) |
| V-R3 | `find_indexed` calls `visit` only on the hit entry | story: **survived**. Caught by probes `v_f130_index_copy_and_bound` (indexed wrong guess) and `v_e13s6l_rows_by_flag` (row 2). Advisory A1 |
| V-R4 | the search counts a protected field also in copy mode | core f_130 at refs.rs:1214 (copy mode unchanged) |
| V-R5 | the hidden-field part left out of the search | core f_130 at refs.rs:1198 |
| V-R6 | code O reads nothing | core f_130 at refs.rs:1198, probe |
| V-R7 | a field code reads nothing | core f_130 (:1196), autotype f_130 (:1173), probe |
| V-R8 | `reads_protected` without `d.masked` | ld196_1 (:1082), ld114 (:724), f_130 (:1173), r02_2 (:747), probe |
| V-R9 | a display `{S:}` of a hidden field sets no flag | ld196_1 at int05_match.rs:1082 |
| V-R10 | the flag set after `charge` and `spend` (after the bound) | story: **survived**. Caught by probe `v_f130_index_copy_and_bound` (:133). Advisory A3: no effect that can be reached |

## N1: the `not-in-front` and `keys-held` lines, and a stop during those waits

Steps:
1. larsal-ffi unit test `ld_234_not_in_front_and_keys_held_lines_and_a_stop_during_their_waits`: `end()` for NotInFront, Held and Changed, each with and without a stop.
2. larsal-ffi `tests/autotype_typing.rs` `ld_234_a_stop_during_step_1_logs_stopped`: a fake whose target never comes forward, with `autotype_stop` raised at its third check. Then the same with no stop.
3. Swift "the target never comes back: nothing typed, the not-in-front line".

Before (E8-S3 Verify, mutant R21 survived): no story test checked either line. A stop during step 1's or step 3's wait was logged as `not-in-front` or `keys-held`, because only `Changed` looked at the flag.

After:
- `not-in-front after 0 keys` and `keys-held after 0 keys` with no stop, and `stopped after 0 keys` with a stop. `window-changed after 3 keys`, or `stopped after 3 keys` with a stop.
- Step 2 gives `Stopped { keys: 0, reason: "stopped" }` with at most 3 window checks. With no stop it gives `not-in-front` after exactly 41 checks.
- Swift logs `Auto-Type stopped: not-in-front after 0 keys` with one alert sound, after 1 + 41 window reads.

Mutants:
- V-R11 (the stop arm only for NotInFront and Changed, so Held with a stop reads `keys-held`): caught at autotype_typing.rs:259.
- V-S4b (Swift logs `not-in-front` as `keys-held`): caught by notInFrontLine at AutoTypeFollowUpTests.swift:35.
- V-S4 (the reason dropped from the line) did not compile: `reason` was unused, and warnings count as errors. So I redid it as V-S4b.

## N2: INT-05.38 step 4, Larsal's own secure input off before typing

Steps: Swift "Larsal's own secure input is off before typing starts". `SecureInputTests.Rig` gives a `SecureInput` with a fake system. The rig focuses a secure field (`enable`). The test runner records the system calls at the moment the run starts.

Before (E8-S3 Verify, mutant S5 survived): `SecureInput.shared.release()` had no test.

After: the calls at the run's start are `["enable", "disable"]`, and the run types to the end with no alert.

Mutants:
- V-S1 (`secureInput.release()` moved after the run): caught at AutoTypeFollowUpTests.swift:74 (`atStart == ["enable", "disable"]`).

## N3: the target is asked forward before Rust waits for it

Steps: Swift "the target is asked forward before Rust waits for it". The fake shows Larsal's own window in front until `activate(4242)` is called, and the target after that.

Before (E8-S3 Verify, mutant S6 survived): `targetAskedBack` proved only that macOS was asked, because the fake ignored activation.

After: `activated == [4242]`, more than 3 window reads, no alert and no stop line. The run typed to the end.

Mutants:
- V-S2 (`activate(target.pid)` moved after the run): caught at AutoTypeFollowUpTests.swift:54. The run waited 2 s and stopped as not-in-front.

## N4: story tests for the four guarantees only Verify's probes caught

Steps and results:
- **The waits end at once on a stop (LD-231 (3)).** `ld_234_waits_end_at_once_on_a_stop`: a 10 s `wait_unless_stopped` with the stop already up returns in under 1 s. With the stop raised at 100 ms, it returns in under 5 s. Passes. Mutant V-R13b (no slicing: one 10 s sleep) is caught at autotype_typing.rs:289. V-R13 (4 s slices) survives: advisory A2.
- **A hidden launch never posts (rule 10).** `ld_234_a_hidden_launch_never_posts` runs `ld_234_hidden_child` as a child with `LARSAL_TEST_HIDDEN=1`. The child calls `autotype_post_events` and sees `post` still false (`hidden: recorder kept`). The parent's control sees `post` turn on without the variable; nothing is typed. Passes. V-R14 (`autotype_post_events` ignores the hidden launch) is caught at :318 and in the child at :297.
- **`cg_flags` for every modifier set (INT-05.43).** `ld_234_cg_flags_for_every_modifier_set` checks all 16 sets against the `Events.h` bits. Passes. V-R15 (⌃⌥ sent as ⌥ alone, a set the old `int_05_43` test never tries) is caught at :238.
- **No app in front stops typing (AT-G02 T103).** Swift "no app in front during typing stops the run": windows are the target 4 times, then no app. The run reads 5 times, logs `Auto-Type stopped: window-changed after 2 keys`, and sounds the alert once. Passes. V-S3 (`FocusCheck` counts no app in front as the same window) is caught at AutoTypeFollowUpTests.swift:93 and :94.

Before (E8-S3 Verify): mutants R15, R17, R26 and S13 survived the story tests.

## N5: `KeyboardLayoutTable.current()` releases its TIS copies

Steps: my probe "Verify probe N5" takes the current and the ASCII-capable input source (on this Mac they are the same object). It reads `CFGetRetainCount` on each, calls `KeyboardLayoutTable.current()` 50 times, and reads the counts again. These are read-only TIS calls.

Before (V-S5: the old code put back in the copy, both copies made up front and only the one used was taken): `PROBE TIS retain: first 7->57 ascii 7->57 same=true`. That is one leaked reference per call. The probe fails at its expectation.

After: `PROBE TIS retain: first 7->7 ascii 7->7 same=true`. No reference is kept. The code: `let copies = [TISCopyCurrentKeyboardLayoutInputSource, TISCopyCurrentASCIICapableKeyboardLayoutInputSource]`, then `copy()?.takeRetainedValue()` inside the loop. The ASCII-capable copy is made only when the first copy gives no table. The tree's own layoutTable test (US and French tables) still passes.

## N6: a shortcut press before the run's stop flag

Steps:
1. larsal-ffi `ld_234_a_press_before_the_typing_thread_starts_stops_the_run`: make a plan, call `autotype_stop` (Swift's `fired()` while `typing` is true), then `autotype_type`.
2. `int_05_39_t92_a_lock_or_the_shortcut_again_stops_typing`: a stop before a run does not reach the next run.

Before (E8-S3 Checker, N6): `autotype_type` made a fresh flag, so a press between `typing = true` and that point was lost.

After:
- Step 1 gives `Stopped { keys: 0, reason: "stopped" }`. Step 2 passes.
- `make_plan` makes the flag (`at.stop = Arc::new(AtomicBool::new(false))`). `autotype_type` clones it with the plan.
- In Swift, a plan is made and `type(_:into:)` sets `typing = true` in one main-thread turn (`run` or `finish`). `fired()` returns at once while `typing` is true (INT-05.46). So no new plan can replace the flag of a run that is typing.
- A lock between the plan and the run removes the plan (`Gone`). A lock during the run sets the run's own flag.

Mutants:
- V-R12 (a fresh flag again in `autotype_type`): caught at tests/autotype_typing.rs:208.
- V-R16 (no fresh flag in `make_plan`, so an earlier stop leaks into the next run): caught by `int_05_39_t92` (:113) and `ld_234_a_stop_during_step_1_logs_stopped` (:193).

## The unused `front:` parameter

Steps: read AutoType.swift and grep for it.

Before: `private func type(_ plan: UInt64, into target: FrontWindow, front: pid_t?) { activate(front ?? target.pid)`.

After:
- `private func type(_ plan: UInt64, into target: FrontWindow) { activate(target.pid)`.
- `grep -n "front:" macos/Larsal/AutoType*.swift` finds nothing.
- Both callers (`run`'s `.type` case and `finish`) pass the captured target.
- `targetAskedBack` and the new activate test both expect `[4242]` and pass.

## Advisories for the lead (not blocking)

- **A1 (V-R3).** The story tests do not pin that `find_indexed` (the path Auto-Type uses) visits entries that do not match. Auto-Type's story test uses only a right guess (`{REF:T@P:demo-s}`). If the visit moved inside the hit branch, a wrong guess in a row title would show as an empty title instead of hidden. The code is right, and my probes prove it. The row's open-URL path (`find`) is pinned by the core test's wrong guess. Smallest fix: add a title `{REF:T@P:wrong}` to `f_130_reads_protected_uses_the_masked_flag` and expect it hidden.
- **A2 (V-R13).** `ld_234_waits_end_at_once_on_a_stop` allows 5 s for a stop raised at 100 ms, so 4 s slices would pass. The code uses 20 ms slices, and E8-S3's probe measured 215 ms. Smallest fix: lower that bound to 2 s, which would still pass under load.
- **A3 (V-R10).** Setting the flag after the work bound would not be caught by a story test. It also has no effect that can be reached. In `resolve_field`, the display run costs more than the copy run only when it wrote a mask, and writing a mask sets the flag. Auto-Type counts `bounded` as protected anyway. My probe pins the current order. No action.

## Cleanup

- **The last Swift run** (copy, after every mutant was put back): `-only-testing:LarsalTests/AutoTypeTests -only-testing:LarsalTests/SecureInputTests` gave `Test run with 36 tests in 2 suites passed`, `** TEST SUCCEEDED **`.
- **Shared tree.** I wrote this file, the F-130 row's Status and Fix proof, and the E13-S6 status line, each with an exact edit. No product code was changed.
- **Name guard.** After those edits, `scripts/check-names.sh` gave `names: PASS (3206 files scanned, 16 vault files name-only)`, exit 0.
- **/tmp.** I deleted `/tmp/e13s6l-verify-copy`, `-target`, `-dd`, `-work`, and the log and sum files. Then `ls -d /tmp/e13s6l-verify*` gave `no matches found`.
