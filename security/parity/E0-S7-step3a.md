# E0-S7 step 3a: the zxcvbn copy with no outside package

Builder, 2026-10-30. Story E0-S7 (plan/epics.md), batch 3a of step 3 (spec/research/dependencies.md section 8, LD-255 (3)): R1 lazy_static, R2 itertools, R3 time, R7 regex, R11 fancy-regex, all in App's patched copy `vendor/zxcvbn` (LD-136), plus P1 of LD-255 (1). Checker next.

Work was done in a private copy (`/tmp/e0s7s3a-builder-copy`, rule 11), proven there, then applied to the shared tree in one step after a read-only process list showed no `scripts/check.sh` run and every shared file to be changed was still the state the copy was made from. Nothing left this Mac: `CARGO_NET_OFFLINE=true`, `RUSTUP_AUTO_INSTALL=0`, every build `--offline --locked`.

## 1. Files

| File | Change |
|---|---|
| `vendor/zxcvbn/Cargo.toml` | Changes 7 to 10 in its numbered list. `lazy_static`, `time`, `regex` and `fancy-regex` dependencies gone (no dependency is left but the optional `derive_builder` and `serde`, which no build turns on); `rust-version` 1.66 to 1.80 (`std::sync::LazyLock`); `build = false` (P1) |
| `vendor/zxcvbn/src/lib.rs` | Header list: changes 7 to 10, and change 2 no longer names the year regex table (it is gone). `extern crate lazy_static` gone. `pub use scoring::utc_year` |
| `vendor/zxcvbn/src/adjacency_graphs.rs`, `src/frequency_lists.rs` | The `lazy_static!` block becomes `LazyLock` statics (4 and 1). The bodies only lose 4 spaces of indent: `diff -w` against the old copy shows the header and end lines only |
| `vendor/zxcvbn/src/scoring.rs` | 6 `LazyLock` statics; `REFERENCE_YEAR` is `utc_year(SystemTime::now())`; new `pub fn utc_year` |
| `vendor/zxcvbn/src/matching/mod.rs` | 4 `LazyLock` statics; the 6 patterns become hand-written code: `find_repeat`, `shortest_unit`, `split_date` and the recent-year loop |
| `crates/app-core/tests/zxcvbn_copy.rs` | New: 2 tests (section 4) |
| `Cargo.lock`, `fuzz/Cargo.lock` | Rewritten by cargo offline (section 3) |
| `vendor/crates-io/` | 5 folders removed: `lazy_static-1.5.1`, `regex-1.13.1`, `fancy-regex-0.18.0`, `bit-set-0.8.0`, `bit-vec-0.8.0`. `diff -rq` against the tree before: these 5 "Only in" lines and nothing else. No crypto copy and no other copy changed (rule 3 untouched) |
| `plan/architecture.md` | The approved-crates rows "Strength estimate" and "Patterns" |

The copy's own `#[cfg(test)]` modules are left as upstream wrote them (they did not build before and do not build now; lib.rs says so). Two of their lines still name `time::OffsetDateTime` (scoring.rs line 877, matching/mod.rs line 1500); no build reads them. The MIT `LICENSE` is unchanged.

Diff size against the copy before (whitespace ignored): Cargo.toml 13 lines out, 9 in; lib.rs 5 out, 14 in; adjacency_graphs.rs 10 out, 9 in; frequency_lists.rs 4 out, 3 in; scoring.rs 12 out, 34 in; matching/mod.rs 78 out, 114 in.

## 2. The replacements

- **R1 lazy_static.** Each `lazy_static! { static ref X: T = e; }` is `static X: LazyLock<T> = LazyLock::new(|| e);`: the same lazy, once-only start. 15 statics; 6 more (the regex statics) are gone with R7 and R11.
- **R2 itertools.** Nothing to do: it left in step 1 (LD-136 change 6, LD-247 (5)). Confirmed: `vendor/zxcvbn` names it only in the two change-6 notes; `itertools` and `either` are in neither lockfile nor in `vendor/crates-io`.
- **R3 time.** `utc_year(t)`: whole seconds since 1970 (rounded down before 1970, so 1 ns before 1970 is 1969), whole days, then the days-to-civil steps on a calendar that starts on 1 March (the era, the day of the era, the year of the era, the day of the year), keeping only the year; a day of the year from 306 (1 January) on is the next calendar year. `i64` throughout, so no step overflows; a year outside `i32` saturates. Its source of time is `SystemTime::now()`, as `time::OffsetDateTime::now_utc()` used.
- **R7 regex** (3 patterns):
  - recent_year `19[0-9]{2}|20[0-9]{2}` with `captures_iter`: from left to right, 4 characters `19dd` or `20dd` (ASCII digits); after a match the search goes on after it, so matches never overlap (`201990` gives `2019` only). The pattern has no group, so `regex_match` is the token alone, as before.
  - `^[0-9]{4,8}$`: 4 to 8 bytes, all ASCII digits.
  - `^([0-9]{1,4})([\s/\\_.-])([0-9]{1,2})([\s/\\_.-])([0-9]{1,4})$`: `split_date` returns the token and its 5 groups numbered as the captures were (so the code after it is unchanged). No separator is a digit, so each number is the whole run of digits: the parse is unique. `\s` is Unicode White_Space in `regex`, and `char::is_whitespace` is the same property (proven over every character in section 5).
- **R11 fancy-regex** (3 patterns with a back-reference): `find_repeat(s, greedy)` is `(.+)\1+` (greedy) or `(.+?)\1+` (lazy): at the first start where a unit is followed by a copy of itself, the longest (greedy) or the shortest (lazy) such unit, then every copy that follows. `.` is any character but a line feed, so a unit and its first copy hold no line feed. `shortest_unit` is `^(.+?)\1+$` on the greedy match: the shortest unit whose copies make up all of it. Both searches stop at the same first start, as the patterns did, so the code that picks between them is upstream's. The old `.unwrap()` calls on the search result (fancy-regex's back-tracking limit) are gone with it; with 100 characters the limit was never near.
- **P1 (LD-255 (1)).** `build = false`. Before: a `build.rs` put into `vendor/zxcvbn` (the copy before this step) was compiled and ran (`cargo build --offline --locked -p zxcvbn -v`: its file was written). After: check-vendor still passes, as LD-254 (2) scopes it, but cargo does not build or run it (0 build-script lines, no file written; mutant P1, section 6).

## 3. Lockfiles, copies and who still needs what

- `Cargo.lock`: 207 entries to 202 (registry 194 to 189). Gone: lazy_static 1.5.1, regex 1.13.1, fancy-regex 0.18.0, bit-set 0.8.0, bit-vec 0.8.0; zxcvbn's dependency list. The only other lines that change: cargo writes 3 dependency names without a version now that one version is left (`"bit-vec 0.10.1"` to `"bit-vec"` in bit-set 0.11.1 and proptest, `"bit-set 0.11.1"` to `"bit-set"` in proptest). No entry added; every remaining entry keeps its version, source and checksum.
- `fuzz/Cargo.lock`: 121 to 111 (registry 111 to 101), removals only: the same 5 plus time 0.3.55, time-core 0.1.9, deranged 0.5.9, powerfmt 0.2.1, num-conv 0.2.2.
- No path package added (the new test is a file of app-core).
- `vendor/crates-io`: 197 to 192 copies; both lockfiles' registry packages and the folders match one to one (192, none missing, none extra).
- **Stay, and who needs them:**
  - time 0.3.55, time-core 0.1.9, deranged 0.5.9, powerfmt 0.2.1, num-conv 0.2.2: rcgen 0.14.10 and yasna 0.6.0, which make the test certificates of app-platform's `net` tests (a dev-dependency). They are no longer compiled into App. time 0.3.55 and yasna stay cut copies, so `cut_copies` in check-vendor.sh does not change.
  - aho-corasick 1.1.5: stays in both lockfiles and in `vendor/crates-io`, but nothing compiles it now (`cargo tree --workspace --all-features -e normal,build,dev,features --target all -i aho-corasick`: nothing to print). Cargo's lockfile keeps an optional dependency that a weak feature names: regex-automata 0.4.18 has `std = [..., "aho-corasick?/std"]` and `perf-literal-substring = ["aho-corasick?/perf-literal", ...]`. It can leave with the regex-automata trim (dependencies.md section 8, step 4.3).
  - memchr: quick-xml, regex-automata's lockfile entry and the others the research names.

## 4. App's tests for the new code

`crates/app-core/tests/zxcvbn_copy.rs` (app-core can reach the copy; its own test modules cannot build):

- `ld136_8_utc_year_around_1_january`: 12 fixed instants (1899/1900, 1969/1970, 1999/2000, 31 December 2000 of a leap year, 2000/2001, 2025/2026 at 1,767,225,600, 2099/2100); 1 ns before 1970; for every year 1601 to 2400, 1 January 00:00:00 and the second before, and 1 March 00:00:00 and the second before, against App's own calendar (app-model `Time::from_civil`); the clock's year against app-model's reading of the same instant.
- `ld136_9_hand_written_matchers_find_what_the_patterns_found`: 36 passwords; for each, every repeat (i, j, base, count), recent year (i, j, token) and date (i, j, year, month, day, separator) that `omnimatch` finds. The expected values were printed by the copy before the change (the patterns), not written by hand.

Mutants of the new code, each in the private copy, each restored (`diff -r` clean after): the test run fails on all 12. M1 a line feed may be in a unit; M2 only a space is white space; M3 years overlap; M4 the year starts a day early; M5 greedy is lazy; M6 no shorter unit; M7 any digit makes a no-separator date; M8 a 3-digit month; M9 no rounding down before 1970; M10 at most two copies; M11 a 5-digit last number; M12 no check that the token ends after the last number. (M8 and M11 passed the first version of the test, so `1/012/91` and `1/1/01991` were added, with their old answers.)

## 5. The comparison run (old copy against new)

One program under `/tmp` (not in the project), built twice, against the copy before (with lazy_static, time, regex, fancy-regex) and against the new copy, both `--release` with overflow checks on, from the same vendored sources, offline. For each password it prints the score, `guesses` and `guesses_log10` as their exact bits, the crack times, the feedback, the whole match sequence (every field of every match, repeats with their base matches), and App's own path (app-core `health.rs`): every match of `omnimatch` on the first 100 characters with its `estimate_guesses`.

- **Main run.** The copy's own test strings (every string literal after the first `#[cfg(test)]` of lib.rs, feedback.rs, scoring.rs, time_estimates.rs and matching/mod.rs: 180) plus the 59 passwords its tests build (`13{sep}2{sep}1921` for 7 separators, `1115yy`, the year-month-day forms, runs of `a`, `Z`, `4`, `&` of 3 to 12): 239, each without and with user inputs; then 100,000 generated passwords (splitmix64, seed `0x0E0573A05EED0001`) in 10 shapes: printable ASCII; small alphabets (repeats, with line feeds); a unit repeated 2 to 7 times with a cut tail; dates with 30 separators (all the Unicode white space kinds, line feed, zero-width space and others); digit runs with years; words with l33t changes and years; keyboard walks; sequences; mixed Unicode; and long joins past 100 characters. 100,478 records; 9,767 hold a line feed; 118,694 repeat, 98,045 date and 14,175 recent-year matches. Old and new output: 693,012,250 bytes each, SHA-256 `2f1738402a859d9b429baceab108407b48d322fe4bb0c8883364b2ef253a720f` both, `cmp` identical.
- **Extra run.** Every Unicode scalar value as a date separator (`1{c}1{c}91`) and as a repeat (`x{c}{c}{c}`): 2,224,128 passwords; every string over {a, b, line feed} up to length 9 and over {1, 9, 2, 0, space, /} up to length 7: 365,445. 2,589,573 passwords; 3,377,236,368 bytes each; SHA-256 `9c7c198da4d4ed86f32d36fcc321d89e7c5801e2c59f99f00246f4a4105bc793` both.

Both runs were made again at the end with the final program; the same four hashes. No difference: the batch stands.

## 6. Checks

In the private copy, a new empty cargo home, `RUSTUP_HOME` the user's, offline:

- `cargo build --workspace --offline --locked`: exit 0.
- `cargo test --offline --locked --workspace --no-fail-fast`: exit 0, 2,439 passed, 0 failed, 62 ignored, 102 result lines. Per binary as security/parity/E0-S7-step2.md section 5, plus app-core `zxcvbn_copy` 2. The strength cases (fea05) unchanged: 46 passed, 3 ignored, as before.
- `-p app-platform --features net`: lib 44 (7), net_start 1, doc-tests 0. `-p app-ffi --features net`: 297 passed, 6 ignored (lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7).
- Timed tests in release (`--release -p app-core --test fea01 --test fea05 --test fea06 --test fea07 --test mod08 --test mod11`): fea01 37, fea05 49, fea06 38, fea07 26, mod08 48, mod11 52, 0 failed.
- AT-B01 in release (`--release -p app-crypto`): 163 passed, 10 ignored: lib 47 (1), cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7. F-134's speed test passed in this run.
- `cargo fmt --all -- --check`, the fuzz workspace's fmt, the three clippy steps of check.sh (`-D warnings`), `cargo check --manifest-path fuzz/Cargo.toml --bins`: exit 0 (the first fmt and clippy run found the new test file unformatted and 2 clippy items in it; fixed, run again, exit 0).
- `cargo deny --offline --locked check` and the fuzz run of it: advisories, bans, licenses, sources ok, the same warnings as the tree before (2 and 16). `cargo audit -n` on Cargo.lock (202), on fuzz/Cargo.lock (111), and on the path-copy lockfile (zxcvbn 3.1.1, ssh-key 0.7.0-rc.11): no vulnerability, the same 1 allowed warning on Cargo.lock as before.
- Both lockfiles byte-identical after all runs.
- Bill of materials (`scripts/make-sbom.sh`, the tree before and after): 151 to 140 components. The 11 that left are exactly aho-corasick 1.1.5, bit-set 0.8.0, bit-vec 0.8.0, deranged 0.5.9, fancy-regex 0.18.0, lazy_static 1.5.1, num-conv 0.2.2, powerfmt 0.2.1, regex 1.13.1, time 0.3.55, time-core 0.1.9. None added; every other component byte-identical as JSON; the rest of the file identical. In the dependency graph only these change: zxcvbn has no dependency, and regex-automata depends on regex-syntax only (section 7).
- `scripts/check-vendor.sh`: PASS (Cargo.toml 195 packages, 182 from vendor/crates-io; fuzz 111, 101; 0 stubs; 14 cut copies). Its mutants, each in a second private copy restored by rsync (`diff -rq` identical at the end): N1, N2, N6 exit 101; N3, N4, N5, M1 to M4, X1 to X4, Y1, Y2, Z1, Z2, W1, W2 FAIL, exit 1, each with the message section 4 of the step 2 record names. P1: PASS (out of the script's scope, LD-254 (2)), and cargo no longer runs the file (section 2).
- `scripts/check-names.sh`: PASS (private copy 11,091 files).

On the shared tree after the apply: `cargo build --workspace --offline --locked` with an empty cargo home, exit 0, lockfiles unchanged; `scripts/check-vendor.sh` PASS (the counts above); `scripts/check-names.sh` PASS (11,379 files).

## 7. Notes for the lead

1. **App's regex engine is now built with only the features App names.** Before this step, `regex` (pulled in by zxcvbn) turned on, by Cargo's feature unification, regex-automata's literal prefilters (aho-corasick, memchr), full DFAs (`dfa-build`, `dfa-search`) and every Unicode table of regex-syntax (age, bool, gencat, script, segment). Now app-core's search (FEA-01.32), the placeholder replace (MOD-08.22) and app-autotype get exactly the root `Cargo.toml` features: regex-syntax `std`, `unicode-case`, `unicode-perl`; regex-automata `std`, `syntax`, `meta`, `nfa-pikevm`, `nfa-backtrack`, `hybrid`, `dfa-onepass`, `perf-inline`, `unicode-case`, `unicode-perl`, `unicode-word-boundary`. This is what LD-122 and LD-123 describe ("the engine is built without those tables"); until now the tables were in the build anyway. App's own check already refuses Unicode category and script classes (LD-123), and every test passes, the release timed tests of fea01 and mod08 among them (section 6). The compiled size App measures for a pattern (LD-113) can differ from before, as no full DFA or prefilter is built. No send-back: recorded so the Checker and Verify know why regex-automata's graph changed.
2. aho-corasick stays in both lockfiles and in `vendor/crates-io` although nothing compiles it (section 3); the regex-automata trim of step 4.3 can take it out.
3. No new finding.
4. One slip of the no-git rule: after the records were written, a check command carried a read-only `git status` with its output thrown away. The folder has no `.git`; nothing changed. The name guard after the records: PASS, 11,380 files.

## 8. Checker 1 (2026-10-30): passed

Setup: a private copy (`rsync -a --exclude /target --exclude /fuzz/target --exclude /app-shots`), target folders under `/tmp`, an empty cargo home (afterwards it held only `.global-cache`, `.package-cache`, `.package-cache-mutate` and `registry/CACHEDIR.TAG`), a throwaway `HOME` with `RUSTUP_HOME` the user's and `RUSTUP_AUTO_INSTALL=0`, `CARGO_NET_OFFLINE=true`, every cargo call `--offline --locked` but the one lockfile rebuild of the step 2 state. Mutants ran in a second copy, restored by `rsync -a --delete` and checked with `diff -rq` (0 differences) before each one and at the end. At the end the shared tree still matched the copy: both lockfiles, both `Cargo.toml` files, `.cargo/`, `deny.toml`, `scripts/`, `vendor/`, `crates/app-core` and `plan/architecture.md`.

- **Build and tests.** `cargo build --workspace`: exit 0. `cargo test --workspace --no-fail-fast`: exit 0, 2,439 passed, 0 failed, 62 ignored, 102 result lines. Per binary (ignored in brackets): app-autotype lib 3, int05 51, int05_match 38, int05_typing 14; app-cli main 15, bench_system 0 (1), bench_zeroing 0 (1), int10 116, memory_hygiene 1; app-core lib 25, app05 36 (2), auto_open 4, autotype_support 2, fea01 35 (2), fea02 20, fea03 16, fea04 30, fea05 46 (3), fea06 38, fea07 26, fea08 82, fea09 25, fuzz_seeds 0 (12), mod01 39, mod02 35, mod03 18, mod04 25, mod05 20, mod06 24, mod07 12, mod08 48, mod09 19, mod10 14, mod11 48 (4), mod12 29, mod13 11, no_plain_copies 1, round_trip 3, zxcvbn_copy 2; app-crypto lib 47 (1), cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7; app-ffi lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7; app-format lib 24, attacks 13, document_read 114 (5), fuzz_seeds 0 (1), header 78, keyfile 154 (5), keys 40, open 68, property 1 (1), redteam_s2 8 (1), testdata 4, version3 51, write_file 53, write_groups 45, write_meta 46, write_pool 53, write_values 39, write_version 33; app-hwkey lib 37, real_key 1 (1), watch 2; app-model lib 28; app-platform lib 31 (7), net_start 0; app-sshagent lib 22, agent 25, own_agent 38; the other result lines 0. This is step 2's list (step 2 record section 5) plus zxcvbn_copy 2.
- **Net.** `-p app-platform --features net`: lib 44 (7), net_start 1, doc-tests 0. `-p app-ffi --features net`: 297 passed, 6 ignored (lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7).
- **Release.** Timed tests: fea01 37, fea05 49, fea06 38, fea07 26, mod08 48, mod11 52, 0 failed. AT-B01 (`--release -p app-crypto`): 163 passed, 10 ignored, per binary as above.
- **Lint.** `cargo fmt --all -- --check`, the fuzz fmt, the three clippy steps of check.sh (`-D warnings`) and `cargo check --manifest-path fuzz/Cargo.toml --bins`: exit 0.
- **Advisories and policy, offline.** `cargo deny --offline --locked check` (workspace, and fuzz with deny.toml minus its net feature line): advisories, bans, licenses, sources ok; the warnings other than the yanked lookup are 2 and 16, as section 6. `cargo audit -n` against a copy of the local advisory database: Cargo.lock (202) no vulnerability and the 1 allowed warning (RUSTSEC-2026-0374); fuzz/Cargo.lock (111) none; the path-copy lockfile (ssh-key 0.7.0-rc.11, zxcvbn 3.1.1) none.
- **Lockfiles: removals only.** The step 2 state was rebuilt in a second copy: the 5 folders made again from their `.crate` (a list with every file's hash and the `.crate` checksum), and zxcvbn's 4 dependencies put back in its `Cargo.toml` (fancy-regex 0.18, lazy_static 1.3, regex 1, time 0.3). `cargo metadata --offline` added back exactly lazy_static 1.5.1, regex 1.13.1, fancy-regex 0.18.0, bit-set 0.8.0 and bit-vec 0.8.0 to Cargo.lock (207 entries, as step 2), and those 5 plus time 0.3.55, time-core 0.1.9, deranged 0.5.9, powerfmt 0.2.1 and num-conv 0.2.2 to fuzz/Cargo.lock (121, as step 2). From that state to the tree, the lockfiles lose only those entries and zxcvbn's dependency list; the only other change is the 4 dependency names that lose their version (bit-vec in bit-set 0.11.1, bit-set and bit-vec in proptest). No entry added, no path package added.
- **Cargo trees.** `cargo tree --workspace --all-features -e normal,build,dev` for aarch64-apple-darwin and x86_64-apple-darwin, root and fuzz: none of lazy_static, regex, fancy-regex, bit-set 0.8.0, bit-vec 0.8.0 and aho-corasick is in any of the 4 trees, and the fuzz trees name none of the 10 that left fuzz/Cargo.lock. In the root, time, time-core, deranged, powerfmt and num-conv come only through dev edges (rcgen and yasna, app-platform's tests): with `-e normal,build` they are in neither target's tree. `-i aho-corasick --target all`, every edge and feature: nothing to print, root and fuzz.
- **Copies.** `vendor/crates-io` holds 192 folders, exactly the registry entries of both lockfiles. For each one the `.crate` SHA-256 in the local cargo cache equals the Cargo.lock checksum and the `package` value. Every file on disk (7,940, the lists aside) is in its list with the right hash. Against its `.crate`, only the `Cargo.toml` of the 14 cut copies differs, and only ring's `aesni-x86_64.pl` is missing (step 1). The 14 cut copies keep `.cargo-checksum.upstream.json`, and every other file in their new lists has its upstream hash. No crypto copy changed. `vendor/ssh-key/src` differs from its `.crate` only in `lib.rs`, `private/ecdsa.rs` and `private/opaque.rs` (LD-209). `vendor/zxcvbn` is a path copy and has no checksum list (LD-136).
- **Bill of materials.** `scripts/make-sbom.sh` on the rebuilt step 2 state and on the tree: 151 to 140 components. Gone: aho-corasick 1.1.5, bit-set 0.8.0, bit-vec 0.8.0, deranged 0.5.9, fancy-regex 0.18.0, lazy_static 1.5.1, num-conv 0.2.2, powerfmt 0.2.1, regex 1.13.1, time 0.3.55, time-core 0.1.9. None added, every other component identical, the other top-level fields identical. In the graph only zxcvbn and regex-automata lost edges, besides the packages that left.
- **Code review** of `vendor/zxcvbn` against the published zxcvbn 3.1.1. `Cargo.toml`: lazy_static, time, regex and fancy-regex gone, `rust-version` 1.80, `build = false`, changes 7 to 10 listed. 15 `LazyLock` statics (adjacency_graphs 4, frequency_lists 1, scoring 6, matching 4); upstream's 6 pattern statics and 2 wasm year statics are gone. `utc_year`: the days-to-civil steps of the proleptic Gregorian calendar (a year from 1 March, so day 306 of it is 1 January), `i64` throughout, rounded down before 1970. `find_repeat`, `shortest_unit`, `split_date` and the recent-year loop do what the patterns' leftmost-first search did. `LICENSE` unchanged.
- **Independent comparison** (a program under `/tmp` only, not in the project). The new functions, taken word for word from the copy, against regex 1.13.1, fancy-regex 0.18.0 and time 0.3.55 built from their published archives: 3,000,000 random and built strings (small alphabets with line feed, carriage return, U+2028, U+0085, picture characters, Unicode white space, digits, and random Unicode scalars) through the repeat loop (i, j, token, base, count), `find_repeat` greedy and lazy (6,000,000 calls, with `shortest_unit` on each greedy match) and the recent-year search; `split_date` against the date pattern on 3,000,000 built tokens plus every Unicode scalar in three shapes (6,336,192 in all); the no-separator test against `^[0-9]{4,8}$` on 2,000,000 tokens; `utc_year` against the time crate's year at 1 January, 1 March, 28 and 29 February and 31 December of every year from -9998 to 9998 (each at the instant, 1 s and 1 ns before, 1 ns after, the day's last nanosecond and the next day) plus 5,000,000 random instants. 0 differences. Each of 4 faults planted in the copied functions gives over 100,000 differences, so the program sees a change.
- **Mutants of the new code** (second copy, `cargo test -p app-core --test zxcvbn_copy`): the Builder's M1 to M12 each fail it (M4 and M9 in ld136_8, the others in ld136_9). Five more: E1 (an empty number in a date), E2 (no 20dd years), E4 (backslash not a separator) and E5 (a 4-digit first number refused) fail. E3 (`doe / 36_525` in place of `doe / 36_524`) passes, and it gives the same year: it moves the year of the era back by one only on 7 days in 400 years, each the first days of a March-first year, where the day of the year then counts from 306 or more and adds the year back (0 differences in the comparison above, and day by day over 3 eras). So it is not a gap in the test.
- **The clock.** The dates in ld136_9 do not depend on the reference year: with it set to 2026, 2027, 2030, 2032, 2035, 2040, 2045, 2050, 2060, 2100 and 2200 (in a copy under `/tmp` only), all 36 cases give the same dates.
- **P1.** With `build = false`, a `build.rs` put in `vendor/zxcvbn` is not built or run (0 build-script lines, no file written; check-vendor PASS, as LD-254 (2) scopes it). With that line removed, cargo builds it and runs it.
- **check-vendor.sh**: PASS (195 packages, 182 from vendor/crates-io; fuzz 111, 101; 0 stubs; 14 cut copies). The 20 mutants of the step 2 record section 4: N1, N2 (a `file://` git source; offline, nothing fetched) and N6 exit 101; N3, N4, N5, M1 to M4, X1 to X4, Y1, Y2, Z1, Z2, W1 and W2 FAIL, exit 1, each with its message.
- **check-names.sh**: PASS (copy 11,092 files).

No finding. Notes for the lead:

1. Section 7 note 1: App does not depend on the Unicode tables being off. app-core `pattern.rs` (`folded_width`) makes a Unicode category or script class invalid "whatever tables another crate's features switch on", and app-autotype uses regex-syntax only for the case folding tables (`unicode-case` stays on). fea01 (T62) and mod08 test such classes; all pass.
2. LD-136's row names changes 1 to 4 as the only ones; the copy now lists 10 (5 under LD-140, 6 under LD-247 (5), 7 to 10 under LD-255 (1) and (3)).

## 9. Checker 2 (2026-10-30): passed

Scope: the crypto copies, as section 7 of spec/research/dependencies.md marks them (crypto, key or support: 73 rows). Step 3a changed no crypto copy: the zxcvbn copy and the 11 packages that left the bill of materials are all "no" in that column. So this review proves that every crypto copy is still the copy step 2 left, and that the step changed nothing in how a crypto copy is built on a Mac. Of the 73 rows, 69 are copies in `vendor/crates-io`; ssh-key 0.7.0-rc.11 is the path copy `vendor/ssh-key` (LD-209); des, fiat-crypto and rustls-platform-verifier left in steps 1 and 2.

Setup: a private copy (`rsync -a --exclude /target --exclude /fuzz/target --exclude /app-shots`), and three more copies made from it: one for mutants (restored by `rsync -a --delete` and checked with `diff -rq`, 0 differences, before each mutant and at the end), one with the upstream manifests, one with the step 2 state. Target folder under `/tmp`, an empty cargo home (at the end it held only `.global-cache`, `.package-cache`, `.package-cache-mutate` and `registry/CACHEDIR.TAG`), a throwaway `HOME` with `RUSTUP_HOME` the user's and `RUSTUP_AUTO_INSTALL=0`, `CARGO_NET_OFFLINE=true`, every cargo call `--offline`, and `--locked` except the lockfile rewrites of the two rebuilt copies. Each `.crate` came from `~/.cargo/registry/cache` and was unpacked under `/tmp`. Lists were read with python3's standard library. At the end the shared tree still matched the private copy: `vendor/`, both lockfiles, both `Cargo.toml` files, `.cargo/`, `deny.toml` and `scripts/check-vendor.sh`.

### Byte for byte (rule 3)

- All 192 `.crate` files: the SHA-256 equals the checksum in Cargo.lock or fuzz/Cargo.lock and the copy's `package` value, and for the 14 cut copies also the `package` value of the upstream list. 192 registry entries, 192 folders, none missing, none extra.
- `diff -rq` of each unpacked `.crate` against its copy, all 192: 286 lines. 206 are the two lists, only in the copy (192 + 14). 65 are `.gitignore` and `.gitattributes` files that cargo vendor never copies. 1 is ring's step 1 cut. 14 are `Cargo.toml`, in exactly the 14 copies of `cut_copies`. No other file differs, and no copy holds a file its `.crate` lacks, the lists aside.
- The 69 crypto copies: 64 are byte-for-byte their `.crate` (the lists and the never-copied git files aside). The other 5 are the cut copies of step 2, and each `Cargo.toml` only lost lines (`diff`; `Cargo.toml.orig` is the same as in the `.crate` in all 5):

| Copy | Lines removed | Lines added | What its Cargo.toml lost | Other differences |
|---|---|---|---|---|
| ring 0.17.14 | 7 | 0 | the table `[target.'cfg(all(all(target_arch = "aarch64", target_endian = "little"), target_os = "windows"))'.dependencies.windows-sys]` | `crypto/fipsmodule/aes/asm/aesni-x86_64.pl` only in the `.crate` (step 1, LD-247 (4)) |
| getrandom 0.2.17 | 5 | 0 | the table `[target.'cfg(target_os = "wasi")'.dependencies.wasi]`, and `"wasi/rustc-dep-of-std"` in the feature `rustc-dep-of-std` | none |
| getrandom 0.4.3 | 4 | 0 | the table `[target.'cfg(all(target_os = "uefi", getrandom_backend = "efi_rng"))'.dependencies.r-efi]` | none |
| curve25519-dalek 5.0.0 | 4 | 0 | the table `[target.'cfg(curve25519_dalek_backend = "fiat")'.dependencies.fiat-crypto]` | none |
| ssh-cipher 0.3.0 | 7 | 0 | the feature `tdes = ["dep:des"]`, `"des?/zeroize"` in the feature `zeroize`, and the optional `[dependencies.des]` | none |

  This is the table of step 2 (security/parity/E0-S7-step2.md section 20), line for line. No code file differs.
- Lists of the 69 crypto copies (2,225 files on disk): every file is in its list with the right hash, and no file is unlisted. The list of each of the 64 plain copies equals a list built from its `.crate` (every file but `.gitignore` and `.gitattributes`). For the 5 cut copies, the upstream list equals the list built from the `.crate`, and every entry of the new list but `Cargo.toml` and the upstream list has its upstream hash; the only upstream entry the new list lacks is ring's cut file. Entries, new and upstream: ring 391 and 391, getrandom 0.2.17 39 and 38, getrandom 0.4.3 49 and 48, curve25519-dalek 75 and 74, ssh-cipher 18 and 17. The same check over all 192 copies: 0 differences.
- `vendor/ssh-key` against its `.crate` (SHA-256 `f9a32fae177b74a22aa9c5b01bf7e68b33545be32d9e381e248058d2adc15ce3`): in `src/`, only `lib.rs` (the LD-209 header and the removed README include), `private/ecdsa.rs` (the one length check, change 1) and `private/opaque.rs` (the wipe on drop, change 3). `Cargo.toml`: a header comment, `publish = false`, and the README entry, the 10 test targets and the dev-dependencies removed. Left out: README, CHANGELOG, `tests/`, `Cargo.lock`, `Cargo.toml.orig`, `.cargo_vcs_info.json`. That is what LD-209 lists, and no more.

### The step changed nothing in how a crypto copy is built

The step 2 state, rebuilt as Checker 1 did (section 8): the 5 folders made again from their `.crate`, and fancy-regex 0.18, lazy_static 1.3, regex 1 and time 0.3 put back in zxcvbn's `Cargo.toml`. `cargo metadata --offline` added exactly those 5 packages to Cargo.lock (207 entries) and those 5 plus the time family to fuzz/Cargo.lock (121).

`cargo tree --offline --locked --workspace --all-features -e normal,build,dev,features --target <target> --prefix depth -f '{p} [{f}]'` on both states; each distinct package with its features:

| Workspace | Target | Step 2 state | Now | What differs |
|---|---|---|---|---|
| root | aarch64-apple-darwin | 214 | 208 | aho-corasick, bit-set 0.8.0, bit-vec 0.8.0, fancy-regex, lazy_static, regex gone; regex-automata loses features; time loses `default` |
| root | x86_64-apple-darwin | 215 | 209 | the same |
| fuzz | aarch64-apple-darwin | 117 | 106 | those 6 plus deranged, num-conv, powerfmt, time, time-core gone; regex-automata and regex-syntax lose features |
| fuzz | x86_64-apple-darwin | 119 | 108 | the same |

No crypto copy is in that list: each one is in the trees with the same features as before. Every one of the 69 is in at least one Mac tree (root 68 on aarch64 and 69 on x86_64, fuzz 61 and 62). Their features on a Mac, as step 2 recorded: ring `alloc, default, dev_urandom_fallback`; getrandom 0.2.17 none; getrandom 0.4.3 `std, sys_rng` (and none on its build edge); curve25519-dalek `digest, zeroize`; ssh-cipher `aes, chacha20poly1305, encoding, rand_core, zeroize`. None of the packages that left depends on a crypto copy, or is a dependency of one.

### The cut tables are never selected on a Mac

The upstream-manifest copy, as step 2's Checker 2 made it, now on the step 3a tree: the 5 cut crypto copies got back their upstream `Cargo.toml` and list (ring also its cut file), and the 14 packages the cut tables and the cut feature name came back, each unpacked whole from its `.crate` with a list of its files: des 0.9.0, fiat-crypto 0.3.0, r-efi 6.0.0, wasi 0.11.1, windows-sys 0.52.0, windows-targets 0.52.6 and the 8 windows_* 0.52.6 crates (under `/tmp` only; never in the project folder). `cargo metadata --offline` rewrote the lockfiles: Cargo.lock gained those 14 packages (105 lines) and fuzz/Cargo.lock gained des, fiat-crypto and r-efi (24 lines); no line removed.

The same `cargo tree` call, the copy's path replaced by one word, on the private copy and on the upstream-manifest copy:

| Workspace | Target | Lines | Cut against upstream manifests |
|---|---|---|---|
| root | aarch64-apple-darwin | 1,581 | byte-identical |
| root | x86_64-apple-darwin | 1,589 | byte-identical |
| fuzz | aarch64-apple-darwin | 670 | byte-identical |
| fuzz | x86_64-apple-darwin | 696 | byte-identical |

So with every feature of our crates, on both Mac targets, in both workspaces, the packages and their features are the same with or without the cuts. With `--target all`, the upstream-manifest copy names fiat-crypto, r-efi, wasi, windows-sys 0.52.0, windows-targets and the 8 windows_* crates (root), and fiat-crypto and r-efi (fuzz): the tables are real on other systems, and only the Mac cfg leaves them out. des is in no tree, because nothing turns on `tdes`.

Custom cfgs: outside `vendor/`, `curve25519_dalek_backend` and `getrandom_backend` are named only in the records, and `RUSTFLAGS` is set only in `scripts/repro-build.sh` (path maps and linker flags). `.cargo/config.toml` sets no flags.

### Mutants on the crypto copies (check-vendor.sh)

| Mutant | check-vendor |
|---|---|
| None | PASS, exit 0 |
| C1: ring `pregenerated/sha256-armv8-ios64.S`, one `nop` line added, its hash written into the new list | FAIL, exit 1, `ring-0.17.14: not upstream beyond its cut: pregenerated/sha256-armv8-ios64.S` |
| C2: getrandom 0.2.17 `src/lib.rs`, `pub const UNLISTED_MUTANT: u8 = 1;` added, its hash written into the new list | FAIL, exit 1, `getrandom-0.2.17: not upstream beyond its cut: src/lib.rs` |
| M1: curve25519-dalek `src/scalar.rs`, Scalar addition calls `UnpackedScalar::sub`, its hash written into the new list | FAIL, exit 1, `curve25519-dalek-5.0.0: not upstream beyond its cut: src/scalar.rs` |
| C4: a new `build.rs` in ssh-cipher, nothing else changed | FAIL, exit 1, `ssh-cipher-0.3.0: files not in its list: build.rs` |
| P2: a new `build.rs` in the plain copy sha2 0.11.1, listed with its hash | PASS, exit 0 |

P2 is a list rewritten with a new file: out of check-vendor's scope (LD-254 (2)), as step 2 noted. sha2's manifest has `build = false`, so cargo would not run the file, and the `.crate` diff above finds it. Not a send-back.

### Known answers on the copies (AT-B01)

- `cargo test --offline --locked --release --no-fail-fast -p app-crypto`: exit 0. 163 passed, 0 failed, 10 ignored: lib 47 (1 ignored), cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7.
- `cargo test --offline --locked --no-fail-fast -p app-platform --features net` (ring and getrandom 0.2.17): exit 0. lib 44 passed (7 ignored), net_start 1, doc-tests 0.

No finding. No file in the shared tree changed but these records. scripts/check.sh was not run (the lead runs it).

## 10. Verify (2026-10-30): signed

Verdict: **signed**. Every E0-S7 check that step 3a covers passed again in a private copy. The Verify agent did not build or check this step, and it changed no product file. No new finding (the next free number is F-137). The runs went past midnight into 2026-10-31.

Setup: a private copy, `rsync -a --exclude /target --exclude /fuzz/target --exclude /app-shots` (`/tmp/e0s7s3a-verify-copy`); a mutant copy (`/tmp/e0s7s3a-verify-mut`, restored by `rsync -a --delete` before each mutant; `diff -rq` then 0 lines, the dangling `macos/AppCore/Generated` link aside); and a copy that holds the step 2 state (`/tmp/e0s7s3a-verify-step2`, section 10.2). Target folders under `/tmp`, a new empty cargo home per run, a throwaway `HOME`, `RUSTUP_HOME` the user's, `RUSTUP_AUTO_INSTALL=0`, `CARGO_NET_OFFLINE=true`, `SSH_AUTH_SOCK` unset. Every cargo call was `--offline --locked`, except the lockfile rewrite of the step 2 copy and the comparison program of section 10.7 (both under `/tmp`). The published `.crate` files were read from `~/.cargo/registry/cache` and never unpacked into the tree.

No network: every cargo run went through `sandbox-exec` with `(allow default)`, `(deny network-outbound (remote ip))`, one allowance for `localhost:*`, and a deny on the resolver socket. Inside it, a socket to 192.0.2.1:443 gets "Operation not permitted", a name lookup fails, and 127.0.0.1 connects. xcodebuild ran outside it, because it refuses to start inside another sandbox; it resolved only the local package. The empty cargo home held only `.global-cache`, `.package-cache`, `.package-cache-mutate` and `registry/CACHEDIR.TAG` afterwards. Both lockfiles kept their SHA-256 through every run. At the end the shared tree matched the copy (`cmp` of both lockfiles, both `Cargo.toml` files, `.cargo/config.toml`, `deny.toml`, `scripts/check-vendor.sh`, `make-sbom.sh`, `build-core.sh`, `check-names.sh`, `plan/architecture.md`, app-core `tests/zxcvbn_copy.rs`, `tests/fea05.rs` and `src/health.rs`; `diff -rq vendor` 0 lines).

### 10.1 Build and tests, offline and locked, with an empty cargo home

- `cargo build --offline --locked --workspace --all-targets -v` (sandbox): exit 0, 1 m 20 s, 347 compile and build-script runs. No line names `registry/src` or the cargo cache. 179 package folders under `vendor/crates-io/` were compiled, and none of them is lazy_static, regex, fancy-regex, bit-set 0.8.0, bit-vec 0.8.0 or aho-corasick. The time family was compiled only for app-platform's test certificates (a dev edge, section 10.2).
- `cargo test --offline --locked --workspace --no-fail-fast` (sandbox): 102 result lines, 2,437 passed, 2 failed, 62 ignored, 3 m 16 s. The 2 failures are the sandbox, as in step 2: `fea06_29_offline_streams` (setuid `ps` is refused) and `t53_t57_ssh_signs_in_through_apps_socket` (macOS's `sshd-auth` starts its own sandbox). Each passes alone outside it. So 2,439 pass. Per test binary (ignored in brackets): app-autotype lib 3, int05 51, int05_match 38, int05_typing 14; app-cli main 15, bench_system 0 (1), bench_zeroing 0 (1), int10 116, memory_hygiene 1; app-core lib 25, app05 36 (2), auto_open 4, autotype_support 2, fea01 35 (2), fea02 20, fea03 16, fea04 30, fea05 46 (3), fea06 38, fea07 26, fea08 82, fea09 25, fuzz_seeds 0 (12), mod01 39, mod02 35, mod03 18, mod04 25, mod05 20, mod06 24, mod07 12, mod08 48, mod09 19, mod10 14, mod11 48 (4), mod12 29, mod13 11, no_plain_copies 1, round_trip 3, zxcvbn_copy 2; app-crypto lib 47 (1), cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7; app-ffi lib 166 (4), autotype 15, autotype_typing 4, clipboard 9, edit 21, generator 12, key_pages 2 (1), memory 1, messages 7, new_vault 12, option_a 8 (1), reports 3, session 11, ssh 19, vault_settings 7; app-format lib 24, attacks 13, document_read 114 (5), fuzz_seeds 0 (1), header 78, keyfile 154 (5), keys 40, open 68, property 1 (1), redteam_s2 8 (1), testdata 4, version3 51, write_file 53, write_groups 45, write_meta 46, write_pool 53, write_values 39, write_version 33; app-hwkey lib 37, real_key 1 (1), watch 2; app-model lib 28; app-platform lib 31 (7), net_start 0; app-sshagent lib 22, agent 25, own_agent 38; uniffi-bindgen-swift main 0; the other doc-tests 0. This is step 2's list plus zxcvbn_copy 2, the same as sections 6 and 8.
- `-p app-platform --features net` (sandbox): lib 44 passed (7 ignored), net_start 1, doc-tests 0. `-p app-ffi --features net` (sandbox): 297 passed, 6 ignored, in the 15 binaries of section 6.
- Release, timed tests (`--release -p app-core --test fea01 --test fea05 --test fea06 --test fea07 --test mod08 --test mod11`): fea01 37, fea05 49, fea06 38, fea07 26, mod08 48, mod11 52, 0 failed (fea06 run outside the sandbox for `fea06_29`).
- `cargo check --offline --locked --manifest-path fuzz/Cargo.toml --bins` (sandbox): exit 0.
- The strength cases did not change: app-core `tests/fea05.rs` was last written on 2026-10-28 and `src/health.rs` on 2026-10-29, both before step 3a, and fea05 gives 46 passed, 3 ignored (debug) and 49 (release), as before.

### 10.2 Both lockfiles against the step 2 state: removals only

The step 2 state was rebuilt in a third copy: the 5 folders made again from their `.crate` (every file but `.gitignore` and `.gitattributes`, with a list of each file's SHA-256 and the `.crate` checksum), and zxcvbn's 4 dependencies put back in its `Cargo.toml` as the published zxcvbn 3.1.1 manifest names them (fancy-regex 0.18, lazy_static 1.3, regex 1, time 0.3). `cargo metadata --offline` then added exactly lazy_static 1.5.1, regex 1.13.1, fancy-regex 0.18.0, bit-set 0.8.0 and bit-vec 0.8.0 to Cargo.lock, and those 5 plus time 0.3.55, time-core 0.1.9, deranged 0.5.9, powerfmt 0.2.1 and num-conv 0.2.2 to fuzz/Cargo.lock: 207 and 121 entries, the step 2 counts.

| Lockfile | Step 2 | Now | Lines removed | Lines added | Entries gone | Entries new |
|---|---|---|---|---|---|---|
| Cargo.lock | 207 | 202 | 53 | 3 | 5 | 0 |
| fuzz/Cargo.lock | 121 | 111 | 87 | 0 | 10 | 0 |

Every remaining entry keeps its version, its source and its checksum. zxcvbn lost its 4 dependency names in both files. The 3 added lines are dependency names that lose their version now that one version is left: `bit-vec` in bit-set 0.11.1, and `bit-set` and `bit-vec` in proptest (the records above say 4; see the notes). No entry and no path package was added.

`cargo tree --offline --locked --workspace --all-features -e normal,build,dev,features --prefix none -f '{p} [{f}]'`, the copy's path replaced by one word, step 2 state against now: the only packages that differ are the freed ones, regex-automata and regex-syntax (features only), and time (features only, root). No crypto copy differs. With `-e normal,build`, none of the 11 packages that left the bill of materials is in any of the 4 trees (root and fuzz, aarch64-apple-darwin and x86_64-apple-darwin). With dev edges, the root still has time, time-core, deranged, powerfmt and num-conv (rcgen and yasna, app-platform's test certificates), and the fuzz trees have none of them.

### 10.3 A source outside the tree fails check-vendor

Each mutant was made in the mutant copy and restored before the next one. Nothing is fetched: the `git` source of N2 names a folder that does not exist, and the run is offline.

| Mutant | Result |
|---|---|
| None | PASS, exit 0 (195 packages, 182 from vendor/crates-io; fuzz 111, 101; stubs 0; cut copies 14) |
| N1: a registry package not vendored (`cfg-if-1.0.5` moved out) | exit 101, `no matching package named cfg-if found`, `directory source … which is replacing registry crates-io` |
| N2: the root `[patch]` zxcvbn as a `git` source | exit 101, `failed to load source for dependency zxcvbn` |
| N3: the root `[patch]` zxcvbn at a copy under /tmp | FAIL, exit 1: `read from outside the tree: zxcvbn 3.1.1: path at /tmp/e0s7s3a-verify-outside/zxcvbn/Cargo.toml` |
| N3b: the same path written with `..` | FAIL, exit 1, the same message with the normalized path |
| N4: a copy that is a link out of the tree (`subtle-2.6.1`) | FAIL, exit 1: `symbolic links in the package folders: vendor/crates-io/subtle-2.6.1` |
| N5: vendor/zxcvbn names `regex` again, which is no longer vendored | exit 101, `no matching package named regex found`, required by zxcvbn |
| W1: a new `build.rs` in the plain copy byteorder 1.5.0 | FAIL, exit 1: `vendor/crates-io/byteorder-1.5.0: files not in its list: build.rs` |

P1 (LD-255 (1)): a `build.rs` put in `vendor/zxcvbn` that writes a file under /tmp. With `build = false`, `cargo build --offline --locked -p zxcvbn -v` exits 0 with no build-script line and no file written. With that one line removed, cargo builds the script and runs it (the file is written). Cargo.lock did not change. check-vendor passes it, as LD-254 (2) scopes the script.

### 10.4 The bill of materials keeps the same components and checksums

`scripts/make-sbom.sh` ran with an empty cargo home in both states. The step 2 state prints `151 components, 116 license texts, 12 crates without a license file`; the tree now prints `140 components, 106 license texts, 12 crates without a license file`.

- Gone: aho-corasick 1.1.5, bit-set 0.8.0, bit-vec 0.8.0, deranged 0.5.9, fancy-regex 0.18.0, lazy_static 1.5.1, num-conv 0.2.2, powerfmt 0.2.1, regex 1.13.1, time 0.3.55, time-core 0.1.9. None new. Each of the other 140 components is identical as JSON (name, version, license, checksum, products).
- 127 components carry a SHA-256, and each equals its Cargo.lock checksum. zxcvbn and ssh-key carry `pedigree` instead. The other top-level fields are identical.
- In the dependency graph, only zxcvbn (its 4 edges) and regex-automata (aho-corasick and memchr) lost edges.
- THIRD-PARTY-NOTICES.md: the crate table and the license texts of the step 2 file, less the 11 crates, are exactly the new file (153 to 142 table rows, 116 to 106 texts; the 10 texts that left were used only by those crates). No new text. `rust-std-COPYRIGHT.html` is byte-identical.

### 10.5 Crypto copies against upstream (the diff proof, rule 3)

Every copy in `vendor/crates-io` was compared with its published `.crate`, read from the archive in the local cargo cache:

- 192 folders, exactly the registry entries of both lockfiles. For each, the archive's SHA-256 equals the lockfile checksum and the copy's `package` value, and for the 14 cut copies also the upstream list's `package` value.
- Files that differ: 14, each the `Cargo.toml` of a copy named in `cut_copies`. Only in the copy: 206, the 192 lists and the 14 upstream lists. Only in the archive: 66, the 65 `.gitignore` and `.gitattributes` files cargo vendor never copies, and ring's `crypto/fipsmodule/aes/asm/aesni-x86_64.pl` (step 1, LD-247 (4)). **No code file differs in any copy, and no copy holds a file its archive lacks.**
- All 7,926 files on disk (the lists aside) are in their list with the listed SHA-256.
- The 5 cut crypto copies only lost manifest lines: ring 0.17.14 7 removed, getrandom 0.2.17 5, getrandom 0.4.3 4, curve25519-dalek 5.0.0 4, ssh-cipher 0.3.0 7, and 0 added in each, as in step 2 section 20 and section 9 above.
- `vendor/ssh-key/src` against ssh-key-0.7.0-rc.11.crate (SHA-256 `f9a32fae177b74a2…`): only `lib.rs`, `private/ecdsa.rs` and `private/opaque.rs` differ (LD-209).
- `vendor/zxcvbn/LICENSE` is byte-identical to the one in zxcvbn-3.1.1.crate.

### 10.6 AT-B01 known answers on the copies, in release

`cargo test --offline --locked --release --no-fail-fast -p app-crypto` (sandbox, empty cargo home): exit 0, **163 passed, 0 failed, 10 ignored**: lib 47 (1), cipher 21, cipher_large 0 (3), hash 6 (1), kdf 35 (3), mac 8 (1), random 7, secret 10 (1), ssh_wipe 1, stream 19, doc-tests 2 and 7. `ssh::tests::sign_ed25519_rfc8032_test_1`, `ssh::tests::sign_p256_rfc6979_sample` and F-134's `f_134_damaged_speed_record_is_measured_again` are among them.

### 10.7 Upstream zxcvbn against the new copy

No copy of `vendor/zxcvbn` from before this step is kept (the Builder's and Checkers' copies are deleted, and there is no snapshot). So Verify compared the new copy with the published zxcvbn 3.1.1, built under /tmp from its `.crate` with the real regex 1.13.1, fancy-regex 0.18.0, time 0.3.55, lazy_static 1.5.1 and itertools 0.14.0. That copy has one /tmp-only edit: `omnimatch` is public, as LD-136 change 5 makes it. Its manifest has no wasm or dev tables. Nothing of it is in the project.

One program, built against each, prints for every password each repeat (i, j, token, base token, count), recent-year (i, j, token, name, match) and date match (i, j, token, separator, year, month, day) that `omnimatch` finds, sorted. These fields do not depend on LD-136 changes 1 to 6 (guesses, order, the removed word). 300,000 generated passwords, each at most 100 characters (splitmix64, seed `0x0E073A007E21F003`), in 8 shapes: printable ASCII; a small alphabet with line feeds; units repeated with Unicode characters, carriage returns and line separators; dates with 33 separators (the Unicode white space kinds, zero-width characters, full-width and Arabic-Indic digits, letters); runs of digits with 18dd to 21dd years; random Unicode scalars; words with years and runs; real days in 4 orders, with and without separators. Result: 212,575 repeat, 65,264 recent-year and 182,079 date matches. Both outputs are 22,659,867 bytes with SHA-256 `33805a119ff4af4a635ee29b0deafdcf5e76c9cd3016deafbb4a24995a828f06`, and `cmp` finds them identical.

The program sees a change: each of 3 faults planted in a /tmp copy of the new copy gives differences. Only a space as white space in `split_date`: 17,778 passwords differ. A carriage return in place of the line feed in `find_repeat`: 31,553. Overlapping recent years: 1,047.

### 10.8 The name guard

- The copy: `scripts/check-names.sh --self-test` self-test PASS, and `names: PASS (11092 files scanned, 16 vault files name-only)`.
- `vendor/` alone: `names: PASS (8185 files scanned)`, which is every file in it (`find vendor -type f`: 8,185; step 2 had 8,332, less the 147 files of the 5 folders).
- The shared tree after these records: `names: PASS (11380 files scanned, 16 vault files name-only)`, exit 0.

### 10.9 The Mac app still builds

- `scripts/build-core.sh` (sandbox, empty cargo home, offline and locked): exit 0, 52 s. It made `target/app-core/AppFFI.xcframework`, `Swift/AppCore.swift`, `include/AppFFI.h` and `include/module.modulemap`.
- `xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/e0s7s3a-verify-dd build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: `** TEST BUILD SUCCEEDED **`, exit 0, 22 s, no code warning. The only resolved package is the local one, `AppCore: …/macos/AppCore @ local`. No test was run, and no window was shown.

### 10.10 check-vendor on the shared tree

`scripts/check-vendor.sh` (sandbox): PASS, exit 0 (195 packages, 182 from vendor/crates-io; fuzz 111, 101; stubs 0; cut copies 14).

### Notes, not findings

1. The records count 4 dependency names without a version (sections 3 and 8, dependencies.md section 12, the status line). The diff has 3 lines, and the records themselves name 3: `bit-vec` in bit-set 0.11.1, and `bit-set` and `bit-vec` in proptest. The tree is right; only the count in the text is off.
2. The copy before step 3a is kept nowhere, so Verify could not run it again. The Builder's two runs of old against new and Checker 1's function-level comparison stand. Section 10.7 adds upstream against new.
3. Still open, as recorded: the time family stays in Cargo.lock for rcgen and yasna (dev edge only); aho-corasick stays in both lockfiles until the regex-automata trim (step 4.3); LD-136's row in spec/decisions.md lists changes 1 to 4 only (Checker 1 note 2).

### Clean-up

Every process Verify started ended; no `sshd` was left. All `/tmp/e0s7s3a-verify-*` folders are deleted. `scripts/check.sh` was not run (the lead runs it). No git command was run.
