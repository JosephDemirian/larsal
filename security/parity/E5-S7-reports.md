# E5-S7 Reports: Verify proof

Story: E5-S7 Reports (plan/epics.md): Health Check, breach check (opt-in), Statistics, Passkeys, Browser statistics.
Checks: numbers match app-core tests; the breach check sends nothing until the user starts it. Health Check and Statistics run in the background with progress and cancel on lock; the session fills the rating cache in the background and re-runs an `is:weak` search that showed the limit notice once the cache is full (LD-137, LD-139).
Cards: FEA-05, FEA-06, FEA-07, INT-04 (passkeys report), INT-02 (browser report). Decisions: LD-126, LD-137, LD-139, LD-140, LD-163, LD-207, LD-208.

## Round 2 (Verify agent, 2026-10-28): signed

I did not build or check this story before. This round checks the Builder's fix of round 1's Fail 1 and runs every acceptance check again.

**Verdict: signed (Done).** Every acceptance check passes with proof. Two items need Mac QA with the owner's go, and they are not fails: the network capture of a real online check (SN-01, rule 7) and the keyboard focus ring on a real key window.

| Check | Result |
|---|---|
| A. Design parity, section `reports` | **5 of 5 frames PASS**, light and dark, with the same numbers as round 1. Pixels light / dark: health 1.78 / 1.92 %, breach 1.49 / 1.54 %, statistics 0.78 / 0.82 %, passkeys 0.70 / 0.73 %, browser 0.59 / 0.69 %. 0 missing strings, 0 token mismatches, 0 boxes or text runs off by more than 2 pt, 0 unnamed controls. Static tokens 45 of 45; contrast 42 pairs, lowest 4.87:1. [design/parity/reports/report.md](../../design/parity/reports/report.md), section "round 2". |
| B1. Numbers match app-core | PASS. The ratings now come from copies made outside the lock. After the product's `rate(max: 25)` steps, the bridge's Health Check rows (both Show Skipped settings), its 12 Statistics numbers and all 21 list ratings equal app-core computed with a fresh cache on the real entries. |
| B2. Breach check sends nothing until the press | PASS. Only `breach_start` (button only) makes the client. The fake service sees 5-character prefixes and the two headers only. A socket watch of the test process saw 0 internet sockets in 163 samples; the control listener was seen. |
| B3. Background, progress, cancel on lock | PASS. **Round 1's Fail 1 is fixed.** During a 470 ms `rate(max: 25)` step of 100-character passwords, `list()` waited at most 2.4 ms over 299 calls (round 1: 789 ms). A lock during a step takes 0.1 ms; the step then answers `Locked`, and nothing it rated survives the next unlock. |
| B4. Rating cache fill and the `is:weak` re-run | PASS. Through the product path (`enter()` → worker → `rated()`), a typed `is:weak` on a cold cache shows the limit notice, then the 6 weak rows. |
| B5. No secret crosses into Swift (rule 4) | PASS. No binding changed. The rating copies (password, title, user name, URL) are secret strings in Rust only. 102 distinct secret strings were searched in 39,805 bytes of report records: 0 found. |
| Fix tests fail with the fix undone | PASS. M1 (rating back inside the lock): `ld_137_a_list_does_not_wait_for_a_rating_step` FAILED, "a list waited 927.563459ms". M2 (keep checks only the key): `ld_137_a_rating_of_a_changed_password_is_dropped` FAILED, left 2, right 1. Both run in the private copy, then restored; `cmp` equals the tree. |

### How I worked

- **Private copy.** `rsync -a --exclude /target --exclude /fuzz/target --exclude .build --exclude node_modules --exclude /app-shots` of the tree to /tmp/e5s7-verify2-copy at 15:48. `target` was linked to /tmp/e5s7-verify2-target (`CARGO_TARGET_DIR` the same), with `-derivedDataPath /tmp/e5s7-verify2-dd`. All three were deleted at the end.
- **The code checked is the code in the tree.** After the mutations were restored, `cmp` showed the copy equal to the shared tree for these files:
  - `crates/app-ffi/src/views.rs`, `reports.rs`, `session.rs`, `lib.rs`, `tests/reports.rs`
  - `crates/app-core/src/breach.rs`, `health.rs`
  - `macos/App/ReportsModel.swift`, `ReportsView.swift`, `ReportTabs.swift`, `ReportParts.swift`, `VaultModel.swift`
  - `macos/AppTests/ReportsTests.swift`

  The SHA-1 sums taken at copy time also still match.
- **My own tests lived only in the copy.**
  - `crates/app-ffi/src/verify_e5s7r2.rs`: 5 tests, pulled into the reports test module with one `include!` line.
  - `macos/AppTests/VerifyE5S7R2Tests.swift`: 2 tests.

  I did not edit any product code or tool file in the shared tree. In the shared tree I wrote only design/parity/reports/ (report.md, report.html, findings.json, app/ and diff/ images), this file and the E5-S7 status line in plan/epics.md.
- **Rules 7, 10, 11.**
  - No window opened and nothing took focus: Chrome ran headless and the snapshots rendered offscreen.
  - The general pasteboard was not touched: the test sessions use `Clipboard::private()`.
  - Nothing left this Mac: every breach request went to the in-process fake transport.
  - Processes stopped, each by its PID: my loopback control listeners, and one mutation test binary (PID 43437) that looped on purpose under mutation M3.
  - The reference app and its command line tool were not run this round.

### Part A: design parity

I followed design/option-a/BUILD-AND-VERIFY.md, "Prompt for the Verify fleet". The full list is in design/parity/reports/report.md, "Verify run for E5-S7, round 2".

```
node design/option-a/tools/export-reference.mjs
  → light: 91 frames / dark: 91 frames / manifest.json: 91 frames, exit 0, 3:08.72 total
    (manifest and the 10 reports images byte-equal to the tree's)
scripts/build-core.sh
  → build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift
node design/parity/tools/mockup-dom.mjs reports
  → light: 5 frames, 419 text runs / dark: 5 frames, 419 text runs
xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS \
  -derivedDataPath /tmp/e5s7-verify2-dd test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES
  → ✔ Test "Option A reports frame, offscreen, light and dark" with 5 test cases passed after 48.316 seconds.
  → ✔ Test run with 166 tests in 29 suites passed after 88.420 seconds.   ** TEST SUCCEEDED **
swift design/parity/tools/ocr.swift app-shots/light/reports-*.png app-shots/dark/reports-*.png → 10 images read
node design/parity/tools/compare.mjs reports
reports: 5/5 PASS
reports-reports-health-check                   PASS                   L 1.78% (1.3) D 1.92% (1.39)
reports-reports-breach-check                   PASS                   L 1.49% (1.46) D 1.54% (1.51)
reports-reports-statistics                     PASS                   L 0.78% (0.64) D 0.82% (0.67)
reports-reports-passkeys                       PASS                   L 0.7% (0.64) D 0.73% (0.66)
reports-reports-browser                        PASS                   L 0.59% (0.52) D 0.69% (0.62)
```

findings.json and report.html are byte-equal to round 1's, and the 10 app images are byte-equal to the ones checked in round 1. The card-over-mockup differences are round 1's: accepted under LD-208 and LD-163 (4), and limited to their frames in notes.mjs.

Snapshots: app-shots/light/reports-reports-{health-check,breach-check,statistics,passkeys,browser}.png and .ax.json, and the same in app-shots/dark/. They were written in the copy; the checked copies are in design/parity/reports/app/ and the diffs in design/parity/reports/diff/.

### Part B: test runs (private copy)

```
cargo test -p app-ffi                  → 14 suites, 181 passed, 0 failed, 2 ignored (lib 80)
cargo test -p app-ffi --features net   → 14 suites, 181 passed, 0 failed, 2 ignored
cargo test -p app-core                 → 29 suites, 712 passed, 0 failed, 23 ignored (fea05 46 + 3 ignored, fea06 38, fea07 26)
cargo fmt -p app-ffi -p app-core -- --check                          → exit 0
cargo clippy -p app-ffi -p app-core --all-targets -- -D warnings     → No issues found
cargo clippy -p app-ffi --all-targets --features net -- -D warnings  → No issues found
cargo test -p app-ffi --features net --lib reports::tests::ld_137, 5 runs at load average 98 to 102
                                       → 3 passed each run (1.19 s to 2.02 s)
xcrun swift format lint --strict  (ReportsModel, ReportsView, ReportTabs, ReportParts, VaultModel, ReportsTests) → rc 0
swiftlint 0.65.1 lint --strict --quiet (the same files)                                                       → rc 0
```

Reports tests that passed:

- app-ffi `reports::tests`:
  - `fea_06_01_nothing_is_sent_before_the_press`, `fea_06_02_requests_and_findings`, `fea_06_11_nothing_to_check_sends_nothing`, `fea_06_12_first_failure_stops_the_check`, `fea_06_16_edit_from_the_results`, `fea_06_17_lock_drops_the_check_and_late_answers`
  - `fea_05_15_health_report_matches_the_sidebar`, `fea_05_26_expire_now_from_the_report`, `fea_07_statistics_and_the_frame_rows`
  - `int_04_52_passkeys_and_remove`, `int_02_32_browser_report`
  - `ld_137_rating_progress_counts_up`, `ld_137_a_list_does_not_wait_for_a_rating_step`, `ld_137_a_rating_of_a_changed_password_is_dropped`, `ld_139_which_searches_wait_for_ratings`, `ld_207_passkey_row_masks_the_vault_flag_user_name`, `short_times_and_grouping`
- app-ffi `tests/reports.rs`: `fea_05_rows_match_app_core`, `fea_07_t01_to_t09_match_app_core`.
- app-core: `fea06_ld207_own_flag_masks_the_title`, `fea06_ld207_vault_flag_masks_every_title`, `ld_207_protected_title_is_masked_in_the_report`.
- Swift:
  - `Option A reports frame, offscreen, light and dark` (5 cases) and the six `Parity reports-reports-…` tests
  - `FEA-06.12, AT-E07: a lock closes the reports and drops every report`, `FEA-05.18: Skip in Reports hides an entry…`, `LD-137, LD-139: an is:weak search runs again once the ratings are in`

My copy-only Rust tests: `cargo test -p app-ffi --features net --lib reports::tests::verify -- --nocapture --test-threads=1` → `test result: ok. 5 passed; 0 failed`.

### B1. Numbers match app-core

`verify_r2_numbers_match_app_core` fills the cache the way the app does (`rate(v, 25, 3600)` until true). It then compares the bridge with app-core computed on the same vault with a fresh `Ratings::new(&zxcvbn_bits)`. The check covers Health Check rows (id, score, level, expired, excluded, reasons), the 12 Statistics numbers, and every list row's bits and level against `entry_bits` of the real entry:

```
VERIFY r2 fill: 2 rate(max 25) calls; progress 21 of 21
VERIFY r2   health(show_skipped=false) Zalando score 0 level Bad bits 71 expired true excluded false
VERIFY r2   health(show_skipped=false) Amazon score 1 level Poor bits 16 …  eBay score 1 … Reddit score 11 … Router admin score 11 …
VERIFY r2   health(show_skipped=false) Slack score 23 level Poor bits 24 …  Server root · web-01 score 70 level Weak bits 71
VERIFY r2 health(show_skipped=false): bridge 7 rows, app-core fresh 7 rows; passwords 21 healthy 14 reused 1
VERIFY r2 health(show_skipped=true): bridge 7 rows, app-core fresh 7 rows; passwords 21 healthy 14 reused 1
VERIFY r2 stats bridge [entries groups unique reused max_reuse weak short expired totp passkeys avg_len excluded] = [23, 8, 20, 1, 2, 6, 0, 1, 7, 4, 19, 0]
VERIFY r2 stats app-core fresh                                                                                  = [23, 8, 20, 1, 2, 6, 0, 1, 7, 4, 19, 0]
VERIFY r2 list: 21 rated rows equal a fresh app-core estimate of the real entry
VERIFY r2 sidebar attention Some(7); health rows 7
```

These are the same numbers as round 1 and as the frame. The copy holds exactly the fields the estimate reads: app-core `with_inputs` reads Title, UserName and the URL host, and `RATED` is `["Password", "Title", "UserName", "URL"]`.

### B2. The breach check sends nothing until the user starts it

- **Code path**, read in the tree:
  - The HTTPS client is made only in `Net::new` (reports.rs:270), and only `Session::breach_start` calls it (reports.rs:871).
  - In Swift, the only `breachStart` call is in `ReportsModel.startBreach()`, which is the "Check passwords online" button. `refresh()`, Check again and tab changes only read `breachReport`.
  - `Slot::lock` sets `breach = None` (session.rs:206).
  - The network code exists only with feature `net` (Cargo.toml line 24). Without it, `get` answers "this build of App has no network code".
- **Tests:**
  - `fea_06_01_nothing_is_sent_before_the_press`: no client is made by any report call.
  - `fea_06_02_requests_and_findings`: the fake sees 5-character prefixes and exactly `User-Agent: App` and `Add-Padding: true`.
  - `fea_06_17_lock_drops_the_check_and_late_answers`.
  - `verify_r2_no_secret_in_report_records`: a full fake check, 20 requests.
- **Socket watch** of the test process: /tmp/e5s7-verify2-logs/sockwatch2.sh walked the process tree of its own `xcodebuild … test-without-building -only-testing:AppTests/ReportsTests -only-testing:AppTests/VerifyE5S7R2Tests` and ran `lsof -nP -a -i -p <pid>` every 0.2 s:

```
control pid=56624: TCP 127.0.0.1:55524 (LISTEN)
xcodebuild exit 0
processes sampled: 56668:DTServiceHub 56704:xctest
lsof_samples=163 samples_with_inet_socket=0
✔ Test run with 13 tests in 2 suites passed after 27.289 seconds.
```

During that run, the tests open Reports on every tab and the breach page (consent), press Turn off and Change password, run Check again, and lock. No internet socket was seen at any sample.

A first try sampled no process, because its name filter missed the test process: `lsof_samples=0`. I did not count it as proof.

The network capture during a real online check (SN-01) needs the owner's yes, so I did not run it (rule 7).

### B3. Background work, progress, cancel on lock: Fail 1 of round 1 is fixed

**The fix**, read in views.rs:

- `Session::rate` (views.rs:1261) takes the session lock only for `Rated::todo` (views.rs:485).
- `todo` copies up to `max` unrated entries with `rating_copy`: the Password, Title, UserName and URL fields as secret strings, the same uuid and the same modification time.
- `rate` then rates the copies with no lock held, and takes the lock again for `Rated::keep` (views.rs:540).
- `keep` stores a rating only if an entry with the same id, the same modification time and equal rated fields still exists.
- When nothing is left to rate, `todo` runs the Health Check once under the lock (all cached, so it does no estimate).

**Swift callers:**

- `VaultModel.rateAll` (VaultModel.swift:282) and `ReportsModel.refresh` (ReportsModel.swift:92) call `rate` on `Task.detached` workers.
- `leave()` and `close()` cancel them.
- After a lock, Rust answers `Locked`.

`verify_r2_list_during_a_step` and `verify_r2_lock_during_a_step_drops_it` (debug build, load average about 100):

```
VERIFY r2 one rate(max 25) step: 475.307042ms (done false); 299 list() calls meanwhile, worst wait 2.391834ms
VERIFY r2 tight loop: 3 rate calls in 653.541916ms; 407 list()+sidebar() pairs meanwhile, worst wait 378.125µs
VERIFY r2 lock during a step: lock() took 116.125µs; the step ran 622.970291ms and answered Err(Locked)
VERIFY r2 after unlock: progress 0 of 21 (cold)
```

Round 1 measured the same probe shape at 789 ms of `list()` wait for one 791 ms step (release build).

The same tests with the rating moved back inside the lock (mutation M1, copy only) give:

```
ld_137_a_list_does_not_wait_for_a_rating_step ... panicked: a list waited 927.563459ms
VERIFY r2 one rate(max 25) step: 470.681583ms (done false); 1 list() calls meanwhile, worst wait 468.065417ms
VERIFY r2 lock during a step: lock() took 484.327583ms; the step ran 507.989333ms and answered Ok(false)
test result: FAILED. 2 passed; 3 failed
```

**Other mutations:**

- **M2** (`keep` compares the id and time only): `ld_137_a_rating_of_a_changed_password_is_dropped` FAILED, `left: 2`, `right: 1`.
- **M3** (`rating_copy` copies the Password only): `keep` never matches, so the fill never ends. `ld_137_rating_progress_counts_up`, `ld_137_a_rating_of_a_changed_password_is_dropped` and my `verify_r2_repeated_id_ends` FAILED or hung. I stopped the hung binary by its PID.
- **M3b** (the copy is rated without its title, user name and host): only my `verify_r2_numbers_match_app_core` FAILED (Router admin score 15 against 11). All 181 Builder tests pass under M3b. See the open issues.

After each mutation, `views.rs` was restored and `cmp` equals the tree.

**Other proof:**

- **Repeated id:** `verify_r2_repeated_id_ends` gives two entries with one uuid and one time but different passwords. The output is `VERIFY r2 repeated id: fill ended after 25 rate(max 1) calls`.
- **Progress:** `ld_137_rating_progress_counts_up` counts (0, 21), then (5, 21), then (21, 21). Swift `Parity reports-reports-statistics: the progress note shows until the ratings are in (FEA-07.17)` passed.
- **Cancel on lock in Swift:** the copy-only `Verify E5-S7 r2: a lock while the fill and the reports work drops them; nothing fills later` ran `enter()`, opened Reports, then locked at once. After 2 s it printed `VERIFY r2 Swift lock: main nil, health nil, stats nil, progress nil, breach consent`, and `ratingProgress` throws.

### B4. Rating cache fill and the `is:weak` re-run (LD-137, LD-139)

`VaultModel.reload()` (VaultModel.swift:161) works as follows:

- While `sidebar.attention == nil`, a query for which `searchWaitsForRatings` is true shows the limit notice and runs no search.
- `rateAll()` fills the cache on a detached worker, and `rated()` reloads.

The copy-only `Verify E5-S7 r2: enter() fills the cache off the screen thread and re-runs a typed is:weak` goes through the product path. It types `is:weak` on a cold cache (notice shown, rows empty, `done == 0`), calls `enter()`, and polls `list()` on the main actor:

```
full run (29 suites sharing the main actor): VERIFY r2 Swift enter(): notice gone after 7.56 s, 1 main-actor turns, worst list() 0.000121 s; progress 21 of 21; weak 6, shown 6
alone (2 suites):                            VERIFY r2 Swift enter(): notice gone after 0.32 s, 1 main-actor turns, worst list() 0.000149 s; progress 21 of 21; weak 6, shown 6
```

The shown rows equal the `.weak` list, and the sidebar count is in. The 7.56 s comes from other suites rendering snapshots on the same main actor. The Rust fill itself takes about 0.3 s.

The Builder's `LD-137, LD-139: an is:weak search runs again once the ratings are in` and `ld_139_which_searches_wait_for_ratings` also pass.

### B5. No secret crosses into Swift (rule 4)

- **No binding changed.** In the copy's generated AppCore.swift, the lines for `rate`, `ratingProgress` and `searchWaitsForRatings` are identical to the tree's, and `rate` returns `Bool`.
- **The new copies stay in Rust.** They are `Entry` values whose fields are `SecretString` (`Field::duplicate`, wiped on drop). They live only inside `Session::rate` and are dropped at its end; `keep` keeps only `(uuid, time) → bits`.
- **Search of the report records.** `verify_r2_no_secret_in_report_records` collects every password and protected value of 4 or more characters, from the current entries and their history. It adds each password's full SHA-1 in upper and lower case and its 35-character suffix. It then searches the `{:?}` text of every record that crosses the bridge: the progress, list and sidebar while cold, mid-fill and filled; Health Check (both settings), Statistics, Passkeys and Browser; and the breach start, the progress and the report after a full fake check.

```
VERIFY r2 rule 4: 102 secret strings (values, full hashes, suffixes) against 39805 bytes of report records: 0 found; 20 requests to the fake service
```

### Open issues (not fails)

1. **Test gap (advisory).** No Builder test pins the background fill's ratings against app-core on an entry whose title, user name or host changes the estimate. Under mutation M3b, all 181 app-ffi tests pass. `tests/reports.rs` `fea_05_rows_match_app_core` calls `health_report` without `rate` first, so it rates under the lock with the full entry. Smallest fix: in that test, run `while !s.rate(v, 25, 0)? {}` before `health_report`, or add a check like my `verify_r2_numbers_match_app_core` on the Personal demo vault, where Router admin with user name "admin" rates 11 bits and not 15.
2. **Rating across a lock and re-unlock (note).** A step that is rating while the user locks and unlocks again can store its ratings into the new session's cache. This is because `rate` does not compare the slot's `epoch`. The values are still right: `keep` compares them with the current entries, and bits hold no secret. No change needed.
3. Not built, and not an acceptance check: FEA-05.16 "sort by any column" (the frame has no sort control; W-12).
4. Browser report host order: hosts are sorted, the card is silent, and the mockup shows stored order. For the lead, as in round 1.
5. **Needs Mac QA (owner's go):** the keyboard focus ring and Tab order on a real key window, and the SN-01 network capture during a real online check (owner's yes, rule 7).
6. crates/app-ffi/API.md has two "Reports (E5-S7, reports.rs)" sections. Merging them is a doc cleanup.
7. Optional reference CLI spot check: not repeated this round. The breach code it covered (app-core `breach.rs`) is unchanged by the round-2 fix, and round 1's comparison is below.

## Round 1 (Verify agent, 2026-10-28): failed (1), kept as history

Verify agent, round 1, 2026-10-28. I did not build or check this story before.

**Verdict: failed (1).** Everything passes except one item: the background rating fill holds the session lock for a whole step of 25 password estimates, so the screen thread waits for the whole step whenever it calls Rust during the fill (measured: 789 ms with 100-character passwords). Smallest fix below (Fail 1).

| Check | Result |
|---|---|
| A. Design parity, section `reports` | **5 of 5 frames PASS**, light and dark. Pixels 1.78 / 1.92 %, 1.49 / 1.54 %, 0.78 / 0.82 %, 0.70 / 0.73 %, 0.59 / 0.69 % (health, breach, statistics, passkeys, browser). 0 missing strings, 0 token mismatches, 0 boxes or text runs off by more than 2 pt after the card's row orders, 0 unnamed controls. Static tokens 45 of 45; contrast 42 pairs, lowest 4.87:1. Report: [design/parity/reports/report.md](../../design/parity/reports/report.md), report.html, findings.json. |
| B1. Numbers match app-core | PASS. app-ffi `tests/reports.rs` (card vault V3) and my own test on the Personal demo vault: Health Check rows (id, title, score, expired, excluded) and the 12 Statistics numbers equal app-core computed fresh without the cache; the sidebar's attention count equals the rows. |
| B2. Breach check sends nothing until the press | PASS. One code path makes the HTTPS client (`breach_start`, only from the button); Rust tests with a fake service; a socket watch of the test process while the Reports screen, every tab, Check again, Turn off and a lock ran: 0 internet sockets in 44 samples (control seen). Nothing contacted the real service or any internet host. |
| B3. Background with progress, cancel on lock | Progress and cancel PASS. **Background FAIL (Fail 1)**: the work is on a worker thread, but each step holds the session-wide lock for up to 25 estimates. |
| B4. Rating cache fill and the `is:weak` re-run (LD-137, LD-139) | PASS. On the product path (`enter()` → `rateAll()` → worker → `rated()`), a typed `is:weak` shows the limit notice on a cold cache and then the 6 weak rows, with no rating on the screen thread. |
| B5. No secret crosses into Swift (rule 4) | PASS. 292 secret strings (every password and protected value of 4 or more characters, current and history, their full SHA-1 in both cases and the 35-character suffix) searched in every report record that crosses the bridge, before and after a full breach check: 0 found. A mutation that puts the password into one row field is caught (10 hits). |
| B6. Reference spot check (offline breach list) | PASS. `app analyze --hibp` and the reference CLI's `analyze --hibp` print the same 6 findings in the same order with the same counts on the Personal demo vault. |

### How I worked

- **Private copy.** `rsync -a --exclude /target --exclude /fuzz/target --exclude .build --exclude node_modules --exclude /app-shots` of the tree to /tmp/e5s7-verify-copy at 14:47. `target` linked to /tmp/e5s7-verify-target (`CARGO_TARGET_DIR` the same), release probe in /tmp/e5s7-verify-target-rel, `-derivedDataPath /tmp/e5s7-verify-dd`.
- **The code checked is the code in the tree.** At 15:08 `cmp` showed the same bytes in the copy and the shared tree for `crates/app-ffi/src/views.rs`, `session.rs`, `tests/reports.rs`, `crates/app-core/src/breach.rs`, `tests/fea06.rs`, `macos/App/ReportsModel.swift`, `ReportsView.swift`, `ReportTabs.swift`, `ReportParts.swift`, `VaultModel.swift`, `VaultEdits.swift` and `macos/AppTests/ReportsTests.swift`; `crates/app-ffi/src/reports.rs` is equal except for the 4 lines I added in the copy to include my test module.
- **Tool files changed in the shared tree:** `design/parity/tools/notes.mjs` (the reports rules and notes, frame-limited) and one condition in `design/parity/tools/compare.mjs` (joined runs left out of the informational "extra strings" list, because a join spelled a banned product name and failed the name guard; verdicts never read that list). `scripts/check-names.sh` → `names: PASS (3035 files scanned, 15 vault files name-only)`.
- **My own tests lived only in the copy:** `crates/app-ffi/src/verify_e5s7.rs` (6 tests, included from reports.rs under `#[cfg(test)]`) and `macos/AppTests/VerifyE5S7Tests.swift` (3 tests). No product code was edited in the shared tree.
- **Rules 7, 10, 11.** No window was opened and nothing took focus (headless Chrome; offscreen borderless windows never ordered front). The general pasteboard was not touched. The only process I stopped was my own control listener, by its PID. Nothing left this Mac: every breach request in every test went to a fake transport in the test process. All /tmp folders were deleted at the end.

### Part A: design parity of section `reports`

Followed design/option-a/BUILD-AND-VERIFY.md, "Prompt for the Verify fleet". Full commands and per-frame findings: [design/parity/reports/report.md](../../design/parity/reports/report.md), section "Verify run for E5-S7".

1. `node design/option-a/tools/export-reference.mjs` → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`, exit 0, 45.9 s. Manifest byte-equal to the tree's. Of the 10 reports images, 8 byte-equal; light browser (97 bytes) and dark breach-check (8 bytes) differ with pixelmatch 0 pixels (0.000 %).
2. `scripts/build-core.sh` → `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`, exit 0.
3. `node design/parity/tools/mockup-dom.mjs reports` → `light: 5 frames, 419 text runs`, `dark: 5 frames, 419 text runs`.
4. `xcodebuild … test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES > target/parity/behaviour.log` → `✔ Test run with 161 tests in 28 suites passed after 126.513 seconds.`, `** TEST SUCCEEDED **`, exit 0.
5. `swift design/parity/tools/ocr.swift app-shots/{light,dark}/reports-*.png` → 10 images read.
6. `node design/parity/tools/compare.mjs reports` → first `reports: 1/5 PASS`. Every miss was checked against its card and written as a frame-limited rule in `design/parity/tools/notes.mjs` (an accepted string still needs the app's counterpart on screen), plus drawn-tile proofs in design/parity/reports/proof/. Second run:

```
reports: 5/5 PASS
reports-reports-health-check                   PASS                   L 1.78% (1.3) D 1.92% (1.39)
reports-reports-breach-check                   PASS                   L 1.49% (1.46) D 1.54% (1.51)
reports-reports-statistics                     PASS                   L 0.78% (0.64) D 0.82% (0.67)
reports-reports-passkeys                       PASS                   L 0.7% (0.64) D 0.73% (0.66)
reports-reports-browser                        PASS                   L 0.59% (0.52) D 0.69% (0.62)
```

Card-over-mockup differences (LD-208, LD-163 (4)), each checked against its card: health rows by FEA-05.15 and FEA-05.16 (7 rows, Zalando first), FEA-05.4 level pills, FEA-05.6 / 05.13 / 05.14 reasons, Weak KPI "under 75 bits", footer 14; breach exposure bands FEA-06.9; Statistics Groups 8 with the root (FEA-07.2), average 19 characters (FEA-07.12); passkeys by title (INT-04.52); browser rows by title (INT-02.32). Live values of the demo copy: bits, file size, key derivation, 3 attachments (measured: live 3, bin 0). One small point for the lead, not judged a fail: the browser report sorts an entry's hosts (gist.github.com before github.com, the editor's `site_access` of E5-S5); the card names no order, the mockup shows stored order.

Snapshots: app-shots/light/reports-reports-{health-check,breach-check,statistics,passkeys,browser}.png and .ax.json, the same in app-shots/dark/ (written in the copy; the checked copies are in design/parity/reports/app/, diffs in design/parity/reports/diff/).

### Part B: acceptance checks

#### Test runs (private copy)

```
cargo test -p app-ffi --features net   → 180 passed, 0 failed, 2 ignored (lib 79 incl. my first 4 tests; 14 suites; the timing probe and the attachment count were added later and run on their own)
cargo test -p app-ffi                  → 180 passed, 0 failed, 2 ignored
cargo test -p app-core                 → 712 passed, 0 failed, 23 ignored (fea05 46, fea06 38, fea07 26)
xcodebuild test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES → 161 tests passed, ** TEST SUCCEEDED **
xcodebuild test -only-testing:AppTests/VerifyE5S7Tests                     → 3 tests passed
```

Reports tests that passed: app-ffi `reports::tests::fea_06_01_nothing_is_sent_before_the_press`, `fea_06_02_requests_and_findings`, `fea_06_11_nothing_to_check_sends_nothing`, `fea_06_12_first_failure_stops_the_check`, `fea_06_16_edit_from_the_results`, `fea_06_17_lock_drops_the_check_and_late_answers`, `fea_05_15_health_report_matches_the_sidebar`, `fea_05_26_expire_now_from_the_report`, `fea_07_statistics_and_the_frame_rows`, `int_04_52_passkeys_and_remove`, `int_02_32_browser_report`, `ld_137_rating_progress_counts_up`, `ld_139_which_searches_wait_for_ratings`, `ld_207_passkey_row_masks_the_vault_flag_user_name`, `short_times_and_grouping`; app-ffi `tests/reports.rs` `fea_07_t01_to_t09_match_app_core`, `fea_05_rows_match_app_core`; `tests/edit.rs` `ld_139_an_edit_drops_the_ratings`; app-core `fea06_ld207_own_flag_masks_the_title`, `fea06_ld207_vault_flag_masks_every_title`, `ld_207_protected_title_is_masked_in_the_report`. Swift: `Option A reports frame, offscreen, light and dark` (5 cases), the six `Parity reports-reports-…` tests, `FEA-06.12, AT-E07: a lock closes the reports and drops every report`, `FEA-05.18: Skip in Reports hides an entry…`, `LD-137, LD-139: an is:weak search runs again once the ratings are in`.

#### B1. Numbers match app-core

`verify_numbers_match_app_core_on_personal` (copy only) computes app-core's `health_check` and `statistics` with a fresh `Ratings::new(&zxcvbn_bits)` (no cache) and compares them with what the bridge sends:

```
VERIFY health show_skipped=false: 7 rows; passwords 21, healthy 14, reused 1
VERIFY   row Zalando score 0 expired true excluded false
VERIFY   row Amazon score 1 … eBay score 1 … Reddit score 11 … Router admin score 11 … Slack score 23 … Server root · web-01 score 70
VERIFY stats tab  [entries groups unique reused max_reuse weak short expired totp passkeys avg_len excluded] = [23, 8, 20, 1, 2, 6, 0, 1, 7, 4, 19, 0]
VERIFY stats core = [23, 8, 20, 1, 2, 6, 0, 1, 7, 4, 19, 0]
VERIFY sidebar attention Some(7); health rows 7
test reports::verify_e5s7::verify_numbers_match_app_core_on_personal ... ok
```

The rows are equal by entry id, title, score, expired and excluded, for both Show Skipped settings; the passkeys report has 4 rows, equal to `stat.passkeys`. With the builder's V3 tests (FEA-07 T01 to T09, FEA-05 rows) this holds on the card's vault and on the demo vault.

#### B2. The breach check sends nothing until the user starts it

Code path (read in the tree): the HTTPS client is made only in `Net::new`, called only by `Session::breach_start` (reports.rs:872); `breach_step` sends only for a started check, outside the session lock, at most 6 at a time. In Swift the only call of `breachStart` is `ReportsModel.startBreach()` (ReportsModel.swift:128), whose only caller is the "Check passwords online" button (ReportsView.swift:243). `refresh()`, Check again and tab changes only read `breachReport`. A lock (`Slot::lock`, session.rs:206) and Turn off / close (`breach_stop`) drop the check; an answer for an older run is refused (`b.run == run`).

Tests:
- `fea_06_01_nothing_is_sent_before_the_press`: every report, the progress and an edit hook make no HTTPS client (`NETS` unchanged); a step without a start is refused.
- `verify_no_secret_crosses_and_only_prefixes_leave` (copy only), fake service: 21 passwords checked in 20 requests, each URL `https://api.pwnedpasswords.com/range/` plus 5 uppercase hex characters, headers exactly `User-Agent: App` and `Add-Padding: true`; findings Router admin 214,876, Amazon 18,442, eBay 18,442, Reddit 3,107 with the FEA-06.9 band words.
- `verify_lock_mid_check_drops_it` (copy only): with 6 requests held by the fake, a lock; the late step answers `Err(Locked)`; after unlock the report is `None` (consent text), a step is refused, no further request is sent (6 seen in all), and the rating cache is cold again (0 of 21).
- Swift `Parity reports-reports-breach-check: the page starts at the consent text; nothing is sent until the press`.

Socket watch of the test process (the way E6-S7 did, per process, no root): a loopback control listener I started was seen (`control pid=35033: 1 inet socket(s): TCP 127.0.0.1:54329 (LISTEN)`), then stopped by its PID. Then `xcodebuild … test-without-building -only-testing:AppTests/ReportsTests -only-testing:AppTests/VerifyE5S7Tests` ran while `lsof -nP -a -i -p <pid>` sampled every descendant `xctest` process of that xcodebuild:

```
xcodebuild exit 0
test pids: 35419 lsof_samples=44 samples_with_inet_socket=0
✔ Test run with 13 tests in 2 suites passed after 18.805 seconds.
```

The tests open the Reports screen on every tab, open the breach page, press Turn off and Change password, run Check again and lock: no internet socket at any sample. The network capture during a real check (SN-01) needs the owner's yes and was not run (rule 7).

#### B3. Background work, progress, cancel on lock

Passes:
- Progress: `ld_137_rating_progress_counts_up` (0, 5, 21 of 21); Swift `Parity reports-reports-statistics: the progress note shows until the ratings are in (FEA-07.17)`.
- Cancel on lock: `verify_rating_fill_stops_on_lock` (copy only): `VERIFY fill: 5 of 21 then lock; next step Err(Locked); progress Err(Locked)`, Health and Statistics `Locked`. Swift `FEA-06.12, AT-E07: a lock closes the reports and drops every report`, and my `a lock right after Reports opens (work started, nothing in) drops it; nothing fills later` → `VERIFY lock at once: cold 0 of 21; after 2 s health nil, stats nil, progress nil, breach consent`, and `healthReport` then throws.

**Fail 1: the fill blocks the screen thread for a whole step.** Both callers (`VaultModel.rateAll`, VaultModel.swift:282, and `ReportsModel.refresh`, ReportsModel.swift:92) call `session.rate(vault:max: 25, …)` on a worker. `Session::rate` (views.rs:1223) runs `Rated::fill` (views.rs:469) inside `with_open`, which holds the session-wide mutex while it rates up to 25 passwords. Every screen-thread call into the session (`list`, `search`, `entry`, the one-second `codes` ticker) waits for the whole step. LD-137 (4) asks for this work in the background because one estimate can take up to 200 ms; 25 of them can hold the lock for seconds.

Release-build probe (`verify_timing_session_lock_during_fill`, copy only, `cargo test --release -p app-ffi --features net --lib verify_timing -- --include-ignored --nocapture`): one thread runs one `rate` step on a cold copy of the Personal demo vault; 2 ms later another thread calls `list()`:

```
Personal, 21 passwords, cold:      rate(max 25) step 9.1 ms   → list() returned after 6.7 ms
                                   rate(max 1)  step 0.13 ms  → list() after 0.04 ms
100-character mixed passwords:     rate(max 25) step 791 ms   → list() returned after 789 ms
                                   rate(max 1)  step 22.9 ms  → list() after 20.5 ms
20-character mixed passwords:      rate(max 25) step 2.2 ms   → list() after 0.04 ms
100-character words and digits:    rate(max 25) step 109 ms   → list() after 107 ms
100-character repeated block:      rate(max 25) step 35 ms    → list() after 33 ms
```

(The passwords of the copy were replaced in memory only, 23 entries; LD-137's own sample is 10,000 entries of 100-character passwords.) With such a vault the window waits about 0.8 s at a time for minutes after an unlock, on every click, keystroke and code tick, which is what LD-137 (4) and LD-126 (8) rule out.

Smallest fix: give `Rated::fill` a time budget: stop the step once about 10 ms have passed and at least one password was rated (keep `max` as the upper bound), so a screen-thread call waits for at most one estimate. Test: 25 entries with 100-character mixed passwords, one thread in `rate(v, 25, 0)`, another thread's `list()` must return in under 100 ms (today 789 ms). A smaller but slower alternative: pass `max: 1` at the two Swift call sites (the probe above: 20 ms), at the cost of one scan over all entries per call.

Note on the Swift timing: in the full Swift run, my `enter()` test saw the notice go after 4.97 s because other suites shared the main actor at the same time; run alone it took 0.024 s on the 21-password demo vault. That small vault does not show Fail 1; the probe above does.

#### B4. Rating cache fill and the `is:weak` re-run (LD-137, LD-139)

- `VaultModel.reload()` (VaultModel.swift:161): while `sidebar.attention == nil`, a query for which `search_waits_for_ratings` (app-core `search::rates`) is true shows the limit notice and runs no search; `rated()` runs `reload()` again.
- My Swift test on the product path (copy only), `enter()` fills the rating cache off the screen thread and re-runs a typed is:weak: `VERIFY fill: cold 0 of 21; notice gone after 0.024 s, 2 main-actor turns while waiting; weak rows 6, shown 6`, the shown rows equal the `.weak` list, and the sidebar count is in.
- Builder's `LD-137, LD-139: an is:weak search runs again once the ratings are in` and `ld_139_which_searches_wait_for_ratings` (is:weak, IS:Weak, i:weak, is:"weak", -is:weak wait; weak, title:weak, *is:weak, is:expired, is:weakness do not).
- LD-139 forget: `Rated::forget` is called on every edit (edit.rs:1246, 1256, 2203; vault_settings.rs:578); `afterChange` then runs `rated()` and `rateAll()` again (VaultEdits.swift:225). Test `ld_139_an_edit_drops_the_ratings` passes.

#### B5. No secret crosses into Swift (rule 4)

The report records that cross the bridge (`RateProgress`, `HealthRow`/`HealthReport`, `StatsReport`, `PasskeyRow`, `BrowserRow`/`BrowserReport`, `BreachProgress`, `BreachRow`/`BreachReport`, reports.rs:36 to 248) carry entry rows, problem and level words, reasons, paths, bits, counts, hosts, dates and file facts. `verify_no_secret_crosses_and_only_prefixes_leave` (copy only) printed each record with `{:?}` after rating and after a full fake breach check, and searched for every password and protected value (4 characters or more, current and history entries), the full SHA-1 of each password in upper and lower case, and its 35-character suffix:

```
VERIFY rule 4: 292 secret strings (values, full hashes, suffixes) against 18452 bytes of report records: 0 found
```

Mutation (copy only): `level_tip: e.value("Password").to_owned()` in `health_report` → `VERIFY rule 4: … 10 found`, the test FAILED; restored, `cmp` equal. In Swift, ReportsModel calls only `rate`, `ratingProgress`, the five report calls, `breachStart/Step/Report/Stop/AfterEdit`, `removeEntryPasskey`, `expireEntries` and `toggleSkipInReports`; none returns a secret.

#### B6. Reference spot check (command line only)

The reference CLI ran with `env -i HOME=/tmp/e5s7-verify-ref/home`, on a copy of the Personal demo vault, against a local 5-line hash file made here (no download, no network), never its clip command:

```
app analyze --hibp hashes.txt personal.appvault
Leaked password: Devices/Router admin (in the list 214876 times)
Leaked password: Shopping/eBay (in the list 18442 times)
Leaked password: Shopping/Amazon (in the list 18442 times)
Leaked password: Social/Mastodon
Leaked password: Banking/Visa Debit
Leaked password: Social/Reddit (in the list 3107 times)

reference CLI analyze --hibp hashes.txt personal.appvault
Password for 'Devices/Router admin' has been leaked 214876 times!
Password for 'Shopping/eBay' has been leaked 18442 times!
Password for 'Shopping/Amazon' has been leaked 18442 times!
Password for 'Social/Mastodon' has been leaked!
Password for 'Banking/Visa Debit' has been leaked!
Password for 'Social/Reddit' has been leaked 3107 times!
```

Same entries, order (file order; eBay before Amazon for the shared hash, FEA-06.19) and counts; empty passwords match the empty hash with count 0 (FEA-06.18). The online check (B2) finds the same four non-empty passwords with the same counts.

### Open issues

1. **Fail 1** (above): time budget in `Rated::fill`, with its test.
2. Not built, not an acceptance check: FEA-05.16 "the user can sort by any column" (the frame has no sort control). For the lead with W-12.
3. Browser report host order (sorted, card silent, mockup in stored order): for the lead.
4. Needs Mac QA (owner's go): keyboard focus ring and Tab order on a real key window; the SN-01 network capture during a real online check (owner's yes, rule 7).
5. crates/app-ffi/API.md has two "Reports (E5-S7, reports.rs)" sections (doc cleanup, from the Builder).
