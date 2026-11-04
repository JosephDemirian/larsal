# E13-S6 part q: the damaged speed record test depends on the Mac's speed (Builder, 2026-10-30)

Story: E13-S6 part q ([plan/epics.md](../../plan/epics.md)). Rulings read: LD-241, LD-249, LD-250 (no ruling names this part). Row: F-134 (Low) in [security/findings.md](../findings.md). Role: Builder. I did not find this problem. Rust only, test only: no product code, no crypto call and no Swift file changed, so no Swift build or Swift lint ran.

| # | Item | Result | Test |
|---|---|---|---|
| 1 | F-134: `damaged_speed_record_is_measured_again` fails in a release build on this Mac | fixed (test only) | `f_134_damaged_speed_record_is_measured_again` (crates/larsal-crypto/tests/kdf.rs) |

## 1. F-134

**Cause.** The test stores a damaged AES-KDF speed record (`ms: 0`), so `assess` must measure again (CRY-02.14 calibration). It then checks that a billion rounds still ask, against the shared test ceilings with `ask_ms: 10_000`. The new record is this Mac's real speed. On this Mac a billion rounds are estimated at 7 to 17 s in release and about 12 s in debug, so with a 10 s limit the result depends on the Mac's speed and load: a quiet release run is under the limit and gets `Run`, not `Ask`. The product is right; the test's limit was too close to the real speed.

**Every caller, by grep.** The test name appears only in kdf.rs, the F-134 row and security/parity/E0-S7-step1.md (the run that found it, kept as history). No script runs it by name. `ask_with` and `CEILINGS` stay for the other tests; this test no longer calls `ask_with`.

**Fix.** The test gets its own ceilings, `Ceilings { ask_ms: 1_000, ..CEILINGS }`, and calls `assess` with them. A billion rounds in 1 s would need 1,000,000 sequential AES-KDF rounds per ms, about 8 times what this Mac does (MAX_AES_ROUNDS_PER_MS in src/kdf.rs puts the fastest believable record at 2,000,000), so "a billion rounds still asks" holds on any Mac; a busy Mac only makes the estimate longer. The damaged record still gives an estimate of 0 ms, which never asks, so the test still fails when the record is not measured again. The checks on the new record (`ms > 0`, `count >= 100_000`) are kept. The test is renamed `f_134_damaged_speed_record_is_measured_again`.

**Probe** (private copy only, an `eprintln!` of the estimate and the new record):

| Build | Load (uptime) | Estimate | New record |
|---|---|---|---|
| release, 3 runs | 6.07 | 7,110 ms each | 12,800,000 rounds in 91 ms |
| debug, 3 runs | 6.07 | 12,344, 12,188, 12,188 ms | 6,400,000 rounds in 78 to 79 ms |

So the estimate is at least 7 times the new 1,000 ms limit.

**Runs of the fixed test** (private copy /tmp/e13s6q-builder-copy, CARGO_TARGET_DIR=/tmp/e13s6q-builder-target, `--offline --locked`; the copy's kdf.rs is the shared file):

| Command | Load (uptime) | Result |
|---|---|---|
| `cargo test --offline --locked --release -p larsal-crypto --test kdf f_134`, 4 runs | 3.73 | 4 of 4 passed |
| same, 3 runs, after the comment edit | 5.99 to 6.15 | 3 of 3 passed |
| `cargo test --offline --locked -p larsal-crypto --test kdf f_134` (debug), 3 runs | 6.39 | 3 of 3 passed |
| same, 3 runs, after the comment edit | 6.14 | 3 of 3 passed |
| `cargo test --offline --locked --release -p larsal-crypto --test kdf` | 6.67 | 35 passed, 3 ignored |
| `cargo test --offline --locked -p larsal-crypto` (debug, whole crate) | 6.67 | every binary ok (kdf: 35 passed, 3 ignored) |
| `cargo clippy --offline --locked -p larsal-crypto --all-targets -- -D warnings` | | no issues |
| `rustfmt --edition 2024 --check crates/larsal-crypto/tests/kdf.rs` | | exit 0 |
| `scripts/check-names.sh` (shared tree) | | PASS |

**Mutant proof** (private copy; each mutant undone after its run):

| Mutant | Run | Load (uptime) | Result |
|---|---|---|---|
| A: the old limit back (`ask_ms: 10_000`) | release, `-- f_134`, 4 runs | 5.49 to 5.62 | 4 of 4 FAILED at kdf.rs:451: 'expected Ask, got Ok(Run(Cleared(AesKdf { rounds: 1000000000, ...})))', as in the row |
| A | debug, 2 runs | 5.49 | 2 of 2 passed: the old shape passes in debug (check.sh), as in the row |
| B: `assess` keeps any stored record (`Some(record) => *record`, src/kdf.rs, private copy only) | release, 2 runs | 5.50 to 5.70 | 2 of 2 FAILED at kdf.rs:451, 'expected Ask, got Ok(Run(...))': the test still catches a damaged record that is not measured again |

After the runs the shared crates/larsal-crypto/src/kdf.rs and tests/kdf.rs match the copy's restored files (cmp), and the shared src/kdf.rs, Cargo.lock and Cargo.toml match the sums taken before the copy (shasum -c OK).

## Verify (2026-10-30)

Role: Verify. I did not find, build or check this fix. Private copy /tmp/e13s6q-verify-copy (rsync with anchored excludes `/target`, `/fuzz/target`, `/larsal-shots`), CARGO_TARGET_DIR=/tmp/e13s6q-verify-target, every build `--offline --locked`. Before the copy I took sums of the shared Cargo.lock, Cargo.toml, crates/larsal-crypto/Cargo.toml, src/kdf.rs and tests/kdf.rs; at the end `shasum -c` was OK for all five, cmp showed the shared src/kdf.rs and tests/kdf.rs match the copy's restored files, and both /tmp folders are deleted. Result: **1 re-tested, 0 failed.**

### 1. F-134

**Steps.** The row's own command, `cargo test --offline --locked --release -p larsal-crypto --test kdf damaged_speed_record_is_measured_again` (the filter still matches the renamed test), then the same in debug. For "before", the old test (old name, `ask_with` with the shared CEILINGS, `ask_ms: 10_000`) was put back in the copy only.

**Before** (old test, copy only):

| Run | Load (uptime) | Result |
|---|---|---|
| release, 4 runs | 4.81 to 6.35 | 4 of 4 FAILED at kdf.rs:97:18: 'expected Ask, got Ok(Run(Cleared(AesKdf { rounds: 1000000000, ...})))', as in the row |
| debug, 2 runs | 6.00 | 2 of 2 passed: why check.sh's debug run did not see it |

**After** (the shared kdf.rs, unchanged in the copy):

| Run | Load (uptime) | Result |
|---|---|---|
| the row's command, release, 4 runs | 5.54 | 4 of 4 passed (`f_134_damaged_speed_record_is_measured_again ... ok`) |
| same, debug, 3 runs | 5.31 to 5.34 | 3 of 3 passed |
| `cargo test --offline --locked --release -p larsal-crypto --test kdf` | 5.56 | 35 passed, 3 ignored |
| `cargo test --offline --locked -p larsal-crypto` (debug, whole crate) | 5.44 | every binary ok (kdf: 35 passed, 3 ignored) |
| `cargo clippy --offline --locked -p larsal-crypto --all-targets -- -D warnings` | | no issues |
| `rustfmt --edition 2024 --check crates/larsal-crypto/tests/kdf.rs` | | exit 0 |
| `scripts/check-names.sh` (shared tree) | | PASS (11624 files) |

**Probe** (an `eprintln!` of `estimated_ms()` and the new record, copy only):

| Build | Load (uptime) | Estimate | New record |
|---|---|---|---|
| release, 3 runs | 6.25 to 7.03 | 8,125 ms each | 6,400,000 rounds in 52 ms |
| debug, 3 runs | 7.03 | 13,125, 13,438, 12,969 ms | 6,400,000 rounds in 83 to 86 ms |

So in release a billion rounds is under the old 10,000 ms limit and at least 8 times over the new 1,000 ms limit. The calibration uses wall time, so load only makes the estimate longer and keeps the test on Ask.

**Mutants** (copy only; each undone after its run):

| Mutant | Run | Load (uptime) | Result |
|---|---|---|---|
| B: `assess` keeps any stored record (`Some(record) => *record`, src/kdf.rs) | release 2, debug 2 | 6.28 to 6.51 | 4 of 4 FAILED at kdf.rs:451:18, 'expected Ask, got Ok(Run(...))' |
| C: the new record is measured but not stored (`_ => calibrate(params, n)?`, src/kdf.rs) | release 2, debug 2 | 5.67 to 5.98 | 4 of 4 FAILED at kdf.rs:455:5, 'assertion failed: fresh.ms > 0 && fresh.count >= 100_000': the kept checks on the new record still bite |

(Mutant A, the old limit, is the "before" table above.)

**Scope.** The product code under test did not change: crates/larsal-crypto/src/kdf.rs was last written 2026-10-28, and tests/kdf.rs (18:38 today) is the only file of the fix. By grep, the test name is used in no script, Swift file or CI file. No other test checks a real calibration against the 10 s limit and expects Ask: the other billion-round tests (kdf.rs:503, :560) use the fixed host() record, and `missing_aes_record_is_calibrated_once` uses 1,000 rounds and expects Run.

**Proof result.** F-134 row set to "fixed, re-tested (Verify 2026-10-30)".
