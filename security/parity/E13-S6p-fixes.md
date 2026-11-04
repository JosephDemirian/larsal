# E13-S6 part p: the F-065 clean child test races the open-copy test (Builder, 2026-10-30)

Story: E13-S6 part p ([plan/epics.md](../../plan/epics.md)). Ruling: LD-250 (3). Row: F-133 (Low) in [security/findings.md](../findings.md). Role: Builder. I did not find this problem. Rust only: no Swift file changed, so no Swift build or Swift lint ran.

| # | Item | Result | Test |
|---|---|---|---|
| 1 | F-133: the start-up clean child wipes the opened-attachment folder while other tests in the same unit binary use it | fixed (test-only lock) | `edit::tests::f_133_the_start_up_clean_test_waits_for_the_folder_lock`, `saving::tests::f_133_the_open_copy_test_waits_for_the_folder_lock` |

## 1. F-133

**Cause.** `edit::tests::f_065_start_up_clean_reads_only_the_users_own_folder` runs a child process (`f_065_clean_child`) that calls the real `clean_open_copies()`. The clean overwrites and deletes every file in the user's own `App/open-attachments` folder. The unit binary runs tests on parallel threads, and `saving::tests::f_086_an_outside_edit_of_an_open_copy_is_asked_and_saved` keeps a copy in that folder and reads it back. A clean that lands inside f_086 changes or removes its copy, and f_086 fails.

**Every user, by grep** (`open_folder`, `clean_open_copies`, `open-attachments`, `open_attachment` in crates/app-ffi/src and crates/app-ffi/tests):

| User | Binary | What it does in the folder | Lock |
|---|---|---|---|
| `edit::tests::f_065_start_up_clean_reads_only_the_users_own_folder` (child `f_065_clean_child`) | unit (lib) | wipes every file | yes |
| `saving::tests::f_086_an_outside_edit_of_an_open_copy_is_asked_and_saved` | unit (lib) | keeps one copy, writes and reads it | yes |
| `edit::tests::f_065_opened_attachments_live_in_the_users_own_temp_folder` (child `f_065_child`) | unit (lib) | only makes the folder and prints its path; keeps no file, and the clean never removes the folder | no (nothing to lose) |
| `start::start` (product) | not run by any unit test | the clean at App start | not a test |
| tests/edit.rs (open_attachment tests) | integration binary `edit` | keep copies | out of scope, below |
| tests/app09.rs (starts the built App) | integration binary `app09`, `test = false` | each primary App start runs the clean (start.rs:182) | out of scope, below |

**Out of scope: other test binaries.** cargo runs test binaries one after another, never two at once, so the integration binary `tests/edit.rs` never runs beside the unit binary's clean. tests/app09.rs starts the built App, and each primary start runs the clean (start.rs:182); app09 is `test = false` and check.sh runs it on its own after the other binaries, so it never runs beside the unit binary. (Text corrected by Verify 2026-10-30, from Checker 1's note: the first wording said app09 never calls `start::start`.)

**Fix.** A test-only lock in `crates/app-ffi/src/test_dir.rs` (compiled only under `cfg(test)`): `open_folder_lock()` returns the guard of one static `Mutex<()>`. A poisoned lock (a test that failed while it held it) is taken anyway, so one failure does not fail the others. The clean parent and f_086 take it as their first line and hold it for the whole test, so the child's clean never runs while f_086 has its copy. No product code changed.

**Test.** `test_dir::waits_for_open_folder_lock(test)` holds the lock, runs `test` on a thread, checks that it has not finished after one second, then drops the lock and checks that it passes. Both tests take under half a second alone (f_086 0.43 s, the clean parent 0.01 s, load 9.01), so a test that skips the lock has ended by then; with the lock it cannot end early at any load (it passed at load 29). The two f_133 tests call it with the clean parent and with f_086.

**Mutant proof** (private copy /tmp/e13s6p-builder-copy, own target dir, shared files compared after):

| Mutant | Run | Result |
|---|---|---|
| A: the clean parent skips the lock | `cargo test -p app-ffi --lib -- f_133` (load 4.69) | `edit::tests::f_133_the_start_up_clean_test_waits_for_the_folder_lock` FAILED at test_dir.rs:73 ("the test ran without the lock") |
| B: f_086 skips the lock | same (load 6.43) | `saving::tests::f_133_the_open_copy_test_waits_for_the_folder_lock` FAILED at test_dir.rs:73 |
| C: no lock anywhere, plus a racer test that repeats the clean parent for 4 s | f_086 and the racer together, `--test-threads=32`, 15 runs (load 7.90) | 14 of 15 runs failed: f_086 panicked at `assert!(s.changed_attachments(v).unwrap().is_empty())`, its copy overwritten by the clean's wipe |
| C with the fix (locks in, same racer) | same, 15 runs (load 9.14) | 0 of 15 failed |
| Unchanged tree, no racer | `f_086 f_065`, `--test-threads=32`, 40 runs (load 7.47) | 0 of 40 failed: the one clean runs about 10 ms in, before f_086 opens its copy, so the race shows only when a clean lands inside f_086 (mutant C) |

**Runs on the shared tree** (CARGO_TARGET_DIR=/tmp/e13s6p-builder-target):

- `cargo test --offline --locked -p app-ffi --lib`: 166 passed, 4 ignored (load 10.97).
- `f_086 f_065 f_133` together, `--test-threads=32`, 10 runs: 0 failed (load 29.27).
- `cargo clippy --offline --locked -p app-ffi --all-targets -- -D warnings`: no issues. `cargo fmt --all -- --check`: clean. `scripts/check-names.sh`: PASS.

**Left as it is.** The clean child still wipes the real per-user folder, so a unit test run on a Mac where App has an attachment open removes that copy, with any outside edit not yet taken into the entry (the attachment in the vault is unchanged). Tests and App on this Mac use demo vaults only (AGENTS.md rule 5). A folder seam in `clean_open_copies` would stop it, but the F-065 test then no longer proves that the real start-up path ignores `TMPDIR`. Sent to the lead as a decision.

## Verify (2026-10-30, round 1)

Role: Verify. I did not find, build or check this fix. I read AGENTS.md, plan/team.md, the full F-133 row, LD-241, LD-249, LD-250 and this file. No product code changed. Rust only: no Swift build ran. Mutants ran only in a private copy (/tmp/e13s6p-verify-copy, CARGO_TARGET_DIR=/tmp/e13s6p-verify-target); shared-tree runs used CARGO_TARGET_DIR=/tmp/e13s6p-verify-shared-target. The real clean ran many times, so this Mac's per-user `App/open-attachments` folder was wiped each time, as every unit-test run does; only demo data was there.

| # | Item | Result |
|---|---|---|
| 1 | F-133 | fixed, re-tested |

### 1. F-133

**Steps.** (a) grep `open_folder`, `clean_open_copies`, `open-attachments`, `open_attachment`, `open_folder_lock`, `current_exe` in crates/app-ffi/src and tests, and the whole of crates/ and macos/. (b) Show the mechanism on the unchanged binary: run the real child, `<unit binary> --exact edit::tests::f_065_clean_child --ignored --test-threads=1`, in a loop for 40 s, and beside it `<unit binary> --exact saving::tests::f_086_an_outside_edit_of_an_open_copy_is_asked_and_saved` 15 times. (c) Show the in-binary race and the fix: a racer test `zz_verify_racer` (private copy only) that repeats `f_065_start_up_clean_reads_only_the_users_own_folder` for 4 s; run `-- f_086 zz_verify_racer --test-threads=32` with the fix and with mutants. (d) Mutants of the lock lines against the f_133 tests. (e) The shared tree: full unit binary, the touched tests at 32 threads, clippy, rustfmt, names.

**Before.** On the unchanged binary, f_086 beside the looping real child: 12 of 15 runs failed, each at saving.rs:1837 `assert!(s.changed_attachments(v).unwrap().is_empty())`: the child's wipe overwrote the copy f_086 had just opened (load 7 to 9). This is the finding's mechanism. A child run from outside the binary does not take the in-process lock; inside the binary the child runs only from the clean parent, which holds it.

**After.**

| Run (private copy) | Result |
|---|---|
| Unchanged, `cargo test --offline --locked -p app-ffi --lib` | 166 passed, 4 ignored (load 7.49 to 9.94) |
| Unchanged, `-- f_086 f_065 f_133 --test-threads=32`, 10 runs | 0 failed (load 9.31) |
| Fix + racer, `-- f_086 zz_verify_racer --test-threads=32`, 15 runs | 0 of 15 failed (load 8.41) |
| Mutant C: both lock lines removed + racer, 15 runs | 14 of 15 failed, f_086 at saving.rs:1836 (load 6.98); `-- f_133`: both f_133 tests FAILED, test_dir.rs:73:5 "the test ran without the lock" (load 6.03) |
| Mutant 1: the clean parent's lock line removed, `-- f_133`, 3 runs | 3 of 3 failed: the edit f_133 test FAILED at test_dir.rs:73:5; the saving f_133 test passed (load 7.22) |
| Mutant 2: f_086's lock line removed, `-- f_133`, 3 runs | 3 of 3 failed: the saving f_133 test FAILED at test_dir.rs:73:5; the edit f_133 test passed (load 7.19). With the racer, 9 of 10 failed (load 16.38): both tests need the lock |
| Mutant 4: f_086 takes the lock after `open_attachment`, not first | f_133 0 of 3 failed, racer 0 of 10 failed (load 17.71 to 18.98). Harmless: a wipe before the lock ends before the lock is granted (the parent holds it until its child exits), and a wiped copy reads as unchanged and is written again by the test's next step |
| Mutant 5: f_086 takes the lock at its end, before `commit_edit` | f_133 0 of 3 failed (a survivor: the f_133 test proves the lock is taken, not where); the racer catches it, 10 of 10 failed (load 9.41) |

Alone, 3 runs each (load 9.93): f_086 0.42 to 0.43 s and the clean parent 0.016 to 0.018 s, each with the process start, against the f_133 test's 1 s wait.

Shared tree (CARGO_TARGET_DIR=/tmp/e13s6p-verify-shared-target): `cargo test --offline --locked -p app-ffi --lib` 166 passed, 4 ignored (load 8.64 to 14.98); `-- f_086 f_065 f_133 --test-threads=32`, 10 runs, 0 failed (load 12.22); `cargo clippy --offline --locked -p app-ffi --all-targets -- -D warnings` no issues; `rustfmt --edition 2024 --check` on test_dir.rs, edit.rs, saving.rs exit 0; scripts/check-names.sh PASS (11622 files). The shared edit.rs, saving.rs, test_dir.rs, Cargo.toml, Cargo.lock and deny.toml match the sums taken before the copy (shasum -c OK x6); `zz_verify_racer` appears 0 times in the shared tree.

**Reading.** lib.rs:25-26 `#[cfg(test)] mod test_dir;`. The lock is the first line of `f_065_start_up_clean_reads_only_the_users_own_folder` (edit.rs:3361) and of f_086 (saving.rs:1825), both inside `#[cfg(test)] mod tests` (edit.rs:2784, saving.rs:858), bound to `_folder`, so it is held until the test ends. `open_folder` and `clean_open_copies` are unchanged. The three `current_exe` child tests all use `--exact` (edit.rs:3332, 3366, autotype_typing.rs:309), so no child runs the clean parent outside the lock. No other crate's Rust test uses the folder. The Swift tests (macos/AppTests) and app09 run in later check.sh steps, never beside the unit binary.

**Text fixes made here** (Checker 1's three notes): the app09 sentence and its table row above, test_dir.rs:72 to :73 in the mutant table, and in the F-133 row "(lead's decision)" to "(proposed to the lead as accepted; no LD yet)". None changes the fix.

**Known limit.** The f_133 tests prove each test takes the lock before it ends, not that it takes it first (mutant 5). Where the lock sits is proven by reading (first line in both), and the racer run catches a late lock. Not a finding: the brief accepts reading plus a test that fails when the lock is skipped.

**Proof result.** F-133 fixed, re-tested. The second half of the row (a unit-test run wipes the real per-user folder, so a running App's open copies go) is still open for the lead's ruling.
