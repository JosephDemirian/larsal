# E13-S1 Parity sign-off, group SG (Generator and checks)

Rows: SG-01 to SG-07 in [plan/security.md](../../plan/security.md), "Generator and checks (SG)". Story: E13-S1. Cards: FEA-02 to FEA-07, INT-10.
Verify agent, 2026-10-29. Earlier proof used as a map: [SG-01 to SG-03](SG-01-SG-02-SG-03.md), [SC-06, SG-04, SF-16](SC-06-SG-04-SF-16.md), [breach](SG-05-SG-06-SN-01-SN-03.md), [SG-07](SG-07.md), [E5-S6](E5-S6-generator.md), [E5-S7](E5-S7-reports.md), [E12-S1](E12-S1-command-line.md).

| Row | Result |
|---|---|
| SG-01 | verified |
| SG-02 | verified |
| SG-03 | verified |
| SG-04 | verified (one level difference from the estimator, on purpose, D-05-1; see the row) |
| SG-05 | waits: the capture of a real check sends data to the outside service (rule 7, owner's yes) and needs the window (Mac QA, owner's go). Everything that runs on this Mac without leaving it passes. |
| SG-06 | verified |
| SG-07 | verified |

No finding: no row is weaker than the reference.

## How this was run

- Today's tree, read-only. Rust built with `CARGO_TARGET_DIR=/tmp/e13s1-target` (release for app-core, app-crypto and app-cli; debug for app-ffi). The command line checks used the release `app` from that build, copied to a /tmp work folder.
- Swift tests ran in a private copy (`rsync -a --exclude target --exclude app-shots` at 21:05 to a /tmp folder, its own cargo target and derived data). No product code was edited.
- The reference: its source (develop branch) read for each row; its command line tool (installed 2.7.11) run with a throwaway `HOME` under /tmp, never its real settings folder.
- Demo data only: three demo vaults made today by the reference tool's `import` from demo XML written in /tmp (password `demo-sg`; deleted at the end), and copies of `testdata/rich-v3`, `rich-v4`, `option-a-personal` and `big-10000`.
- Rule 10 and 11: no window, no screen capture, no general pasteboard; only processes I started; all /tmp folders deleted at the end.
- Other agents edited `crates/app-core/src/health.rs` (20:49) and `crates/app-cli/src/commands.rs` (20:55) during the run (F-066: a protected Title is masked in composed texts). My first fea05 and fea07 binaries and my first `app` were older than those edits, so I re-ran fea05, fea06 and fea07 (49, 38, 26 passed) and rebuilt `app` (21:13), then re-ran the `analyze` files (output byte-identical), the statistics on all six vaults (same result), the one-time codes (7 of 7 same) and the generator sets (100 per set, same result). The numbers below are from both runs.

Tests, all pass today:

| Command | Result |
|---|---|
| `cargo test --release -p app-core --test fea02 --test fea03 --test fea04 --test fea05 --test fea06 --test fea07` | 20, 16, 30, 49, 38 and 26 passed, 0 failed |
| `cargo test --release -p app-crypto --test mac --test random` | 8 passed (1 ignored) and 7 passed |
| `cargo test --release -p app-cli --test int10 -- int10_4_a int10_7_c int10_16_b int10_21_c int10_31_a int10_32_b int10_33_a int10_34_a int10_35_a` | 9 passed |
| `cargo test -p app-ffi --features net --lib reports::tests`, the same without `net`, `--lib generator`, and `--features net --test reports --test generator` | 17 passed with `net`, 17 without, 2, then 3 and 12 passed |
| Swift, private copy: `scripts/build-core.sh`, `xcodebuild build-for-testing`, then `test-without-building -only-testing:AppTests/ReportsTests -only-testing:AppTests/GeneratorSnapshotTests -only-testing:AppTests/ParityGeneratorTests` | `Test run with 22 tests in 3 suites passed after 41.247 seconds.` (snapshots offscreen; among them "Parity reports-reports-breach-check: the page starts at the consent text; nothing is sent until the press", "FEA-05.18: Skip in Reports hides an entry; Show Skipped Entries lists it again", "Parity generator-password: options that make nothing show the reason; Copy and Use are off (D-02-3)") |

## SG-01 Generates from the OS random source, without bias

**Reference.** One generator object wraps the crypto library's system random source. A pick below `n` draws 4 bytes and throws the draw away while it is above the largest multiple of `n` that fits, then takes the remainder: rejection sampling, so no modulo bias. Password characters, the every-group shuffle (Fisher-Yates) and passphrase words all use that pick.

**App.** `app_crypto::random::below` (crates/app-crypto/src/random.rs) draws `u32`s from `getrandom`'s `SysRng` (the OS source, no seed, no state) and rejects draws below `2^32 mod n`, then takes the remainder. app-core's generator draws only through it (generator/mod.rs, password.rs, passphrase.rs). The Swift layer has no random call of its own (search of macos/App for `randomElement`, `.random(`, `SystemRandomNumberGenerator`, `SecRandomCopyBytes`, `arc4random`: none). LD-220 (2) notes that the TLS library of the opt-in network client has its own randoms for TLS only; the generator never uses them.

**Checks today.**
- `fea02_06_os_source_without_bias`, `fea02_06_no_random_source_outside_app_crypto`, `fea02_07_uniform_picks`, `fea02_08_every_group_exact_distribution`, `fea03_06_uniform_picks_with_replacement` and app-crypto `random` (7) pass.
- Black-box, 100 passwords of 999 characters each (99,900 draws) from the release `app`:

```
app -L 999 -c abcdefg              symbols 7  draws 99900 chi2 6.5  (df 6)
app -L 999 -l --exclude-similar    symbols 25 draws 99900 chi2 21.9 (df 24)
app -c abcdefg, three more runs:   chi2 7.4, 7.9, 4.6 (df 6)
```

All below the 0.001 limits (22.46 for df 6, 51.18 for df 24). The reference gave 6.8, 7.1 and 1.0 on the same 7-character runs (one first run gave 23.6; three more runs were normal, so it was chance).

**Result: verified.**

## SG-02 Character classes, look-alike exclusion, one character from every class, extra and excluded characters

**Reference.** Groups: lower, upper, digits, six symbol groups (brackets, punctuation, quotes, dashes, math, signs), extended Latin (U+00A1 to U+00FF without U+00AD), and the extra characters as their own group. Look-alike exclusion removes `l`, `B G I O`, `0 1 6 8`, `|` and U+00F9. Excluded characters are removed from every group; empty groups drop out. Every group: one pick from each group, the rest from the whole pool, then a shuffle; refused when the length is below the number of groups. Command line: with neither `--exclude-similar` nor `--every-group` both are on.

**App.** app-core generator/password.rs (FEA-02). The command line follows FEA-02.21 (six symbol groups, the same flag rule). The screen follows D-02-2 (one `special` group, both options always applied); E5-S6 verified it through the screen.

**Check today: 300 passwords per option set from each tool** (`generate`; character set used, lengths, groups present):

```
(none)                          ref  53 chars len [32] | app  53 chars len [32] | same chars: True
-L 64 -l                        ref  25 chars len [64] | app  25 chars len [64] | same chars: True
-L 40 -U -n                     ref  28 chars len [40] | app  28 chars len [40] | same chars: True
-L 40 -s                        ref  31 chars len [40] | app  31 chars len [40] | same chars: True
-L 40 -lUns --exclude-similar   ref  84 chars len [40] | app  84 chars len [40] | same chars: True
-L 40 -ln -x aeiou0             ref  26 chars len [40] | app  26 chars len [40] | same chars: True
-L 30 -c abc123                 ref   6 chars len [30] | app   6 chars len [30] | same chars: True
-L 40 -e                        ref  93 chars | app  93 chars | only ref: U+00B7 | only app: U+00F9
-L 8 -lUns --every-group        both refuse, exit 1 (the reference: "Invalid password generator after applying all options"; App: "a character from every group needs a length of at least 9.")
-L 12 -lUns --every-group       ref  94 chars | app  94 chars | lower, upper, digit and a symbol in 300 of 300 for both
-L 10 -lUns --every-group       all six symbol groups present: ref 200 of 200, app 200 of 200
```

- `-e`: with neither flag, look-alike exclusion is on; the reference drops U+00F9 as its look-alike and App drops U+00B7 (D-02-1, on purpose; same count, 93).
- `-L 8 -lUns --every-group`: Sprint 3 recorded that App made a password here (one special group). Today the command line refuses like the reference (FEA-02.21 parity, done in E12-S1); the screen keeps D-02-2.
- Tests: fea02 (20) pass, among them `fea02_02_lookalike_exclusion`, `fea02_03_extra_characters`, `fea02_04_excluded_characters`, `fea02_21_command_line_options`; int10 `int10_34_a_generate_defaults_and_limit`, `int10_21_c_generated_password_and_a_bad_length`.

**Result: verified.**

## SG-03 Passphrases from a 7,776-word list, 7 words by default, custom lists deduplicated, strength shown

**Reference.** Default 7 words, separator a space, lower case, from its bundled list; a custom list is read into a set (duplicates dropped exactly as written; a word in two cases stays twice) and then each pick is lower-cased; a list under the recommended size gives a warning. The strength shown for a passphrase is log2(list size) × words, not the estimator.

**App.** app-core generator/passphrase.rs and wordlist.rs (FEA-03). The shipped list is the published EFF large list. A custom list is deduplicated after lower-casing (FEA-03.10). The strength shown is FEA-03's entropy (FEA-05.8, test `fea05_09_generator`).

**Checks today.**

```
shipped list: 7776 lines, 7776 unique words, dice numbers 11111..66666 in order
SHA-256 of the words, each followed by LF: 6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522 (equals the value in wordlist.rs and fea03_01)
reference list: 7772 words; 30 of App's words are not in it, 26 of its words are not in App's (D-03-1, on purpose)

100 passphrases per setting (reference `diceware`, App `passphrase`):
ref (default) word counts [7]  all lower | app (default) word counts [7]  all lower, all 100 from App's list
ref -W 3      word counts [3]  all lower | app -W 3      word counts [3]  all lower, all 100 from App's list
ref -W 12     word counts [12] all lower | app -W 12     word counts [12] all lower, all 100 from App's list

custom list "alpha, beta, beta, Alpha, 11111<TAB>gamma, (blank), '  delta  '":
both: words {alpha, beta, delta, gamma}; both warn that the list is under the recommended size
word shares over 3,000 picks: ref alpha 0.392, beta 0.206, delta 0.206, gamma 0.195
                              app alpha 0.260, beta 0.247, delta 0.239, gamma 0.254
```

The reference keeps `alpha` and `Alpha` as two list items, so `alpha` comes twice as often and its entropy counts 5 words where 4 exist; App's lower-case deduplication keeps every word equally likely. App goes further here.

- Tests: fea03 (16) pass, among them `fea03_01_builtin_list_facts`, `fea03_07_entropy_formula`, `fea03_10_unique_after_lower_casing`, `fea03_16_command_line_passphrase`; fea05 `fea05_09_generator`; int10 `int10_4_a_passphrase_and_its_alias`, `int10_35_a_passphrase_errors`.
- The screen (strength shown, Regenerate, Copy): E5-S6 Done; Swift generator suites re-run today, see the test table.

**Result: verified.**

## SG-04 Reports weak, reused and expired passwords; entries can be excluded

**Reference.** The Health Check scores each live entry: the estimator's bits; a reused password (not counting recycled entries and reference passwords) loses 15 per extra use and is capped at 74; an expired one gets 0; one expiring within 30 days is capped at 70 and loses 2 per day. Rows at Weak or below are listed; excluded entries are hidden unless "also show excluded entries" is on; the context menu excludes, expires or deletes. Statistics count groups, entries, expired, unique, reused, maximum reuse, short (under 8), weak (Health Check score, passwords under 25 characters), excluded and the average length, skipping the recycle bin. The flag is stored as the entry's quality-check element (or a legacy custom data item).

**App.** app-core health.rs and stats.rs (FEA-05, FEA-07), the screens in E5-S7 (app-ffi reports.rs, ReportsView). Differences on purpose: the estimator (D-05-1), days to expiry in local dates (D-05-4), reference passwords skipped (D-05-3), user inputs to the estimator (LD-44).

**Check today: `db-info` statistics of both tools, 10 rows, in UTC, UTC+14 and UTC−8.** The `health` demo vault has a strong password, a reused strong pair, a weak password, an excluded weak one, a short one, an expired one, one expiring 2026-11-20, one expiring 2027, a reference password, an empty one, a reused weak one in a sub-group and a recycled one.

```
vault                     ref values [groups entries expired unique reused maxreuse short weak excluded avg]
health.appvault           [2 12 1 9 2 2 4 8 1 19]  all 10 rows equal in the 3 time zones
breach.appvault           [3 9 0 6 2 2 4 7 1 12]   all 10 rows equal in the 3 time zones
rich-v3.appvault          [5 8 1 5 0 1 0 4 0 15]   all 10 rows equal in the 3 time zones
rich-v4.appvault          [5 8 1 5 0 1 0 4 1 15]   all 10 rows equal in the 3 time zones
option-a-personal.appvault[8 23 1 20 1 2 0 7 0 19] weak: ref 7, app 6, in the 3 time zones; the other 9 rows equal
big-10000.appvault        [1 10000 0 10000 0 1 0 10000 0 13] all 10 rows equal in the 3 time zones
```

The one difference, traced: the reference's weak count includes Figma (`Fy6@Tn1!Qp8#Hc4$`, demo password from the mockup), which its estimator rates 74.359 bits (Weak, below 75); App's rates it 77.439 (Good). Every other password the count looks at (under 25 characters) is on the same side of the Weak line in both tools (Wise and Hetzner Cloud move from Good to Excellent in App, which does not change the count). The password is 16 random characters from all four classes, about 105 bits of real entropy, so App's Good is the truer rating; this is the estimator difference D-05-1 allows (E4-S11 measured 5 of 500 passwords one level higher in App and 55 lower). App is not weaker here. Excluded entries: both count the excluded one in the statistics (FEA-07.10, as the reference) and show "excluded 1".

- Tests: fea05 (49) and fea07 (26) pass, among them `fea05_11_weak_predicate`, `fea05_12_skipped_entries`, `fea05_13_reuse`, `fea05_14_reuse_cap`, `fea05_17_expired`, `fea05_18_expiring`, `fea05_19_expiring_and_weak`, `fea05_25_exclude_action`, `fea05_26_expire_and_delete_actions`, `fea05_27_parity_sample`, `fea05_21_time_zone`; app-ffi `reports::tests` `fea_05_15_health_report_matches_the_sidebar`, `fea_05_26_expire_now_from_the_report`, `fea_07_statistics_and_the_frame_rows`; int10 `int10_31_a_db_info`.
- The screens (Health Check with Show Skipped Entries, Skip in reports, Expire, Delete; Statistics): E5-S7 Done, Verify signed 2026-10-28; Swift `ReportsTests` re-run today, see the test table.

**Result: verified.**

## SG-05 Online breach check only on the button, below a caution text; 5 hex characters of SHA-1 over HTTPS, minimal user agent; recycled and empty passwords skipped

**Reference.** The breach page shows a caution text (the service, hashing, the first five characters, the IP address and the number of passwords exposed) above "Perform Online Analysis". Only the press starts it. It adds every live entry's password that is not recycled and not empty (excluded entries are still sent), one request per distinct password, `GET https://api.pwnedpasswords.com/range/<first 5 hex of SHA-1>` with a `User-Agent` of its product name only (no version, no platform), and stops on the first error.

**App.** The consent notice in macos/App/ReportsView.swift (`MSG-BREACH-CONSENT`: the service, SHA-1, the first 5 characters, HTTPS, the number of passwords and the IP address, "Nothing is sent until you press the button") sits above the only start, `ACT-BREACH-RUN` "Check passwords online" (ReportsModel `startBreach`). app-core breach.rs builds `GET https://api.pwnedpasswords.com/range/<5 hex>` with `User-Agent: App` and `Add-Padding: true`, one request per distinct prefix; it skips recycled, empty, excluded and reference passwords (D-06-2 to D-06-5: App sends less). app-ffi sends through app-platform `net` (HTTPS only, E6-S7).

**Checks today.**
- app-core fea06 (38) pass, among them `fea06_01_nothing_before_the_press`, `fea06_02_requests`, `fea06_14_excluded_and_references`, `fea06_15_recycle_bin_and_history`.
- app-ffi `reports::tests` (fake transport, no network): `fea_06_01_nothing_is_sent_before_the_press` (opening every report makes no HTTPS client), `fea_06_02_requests_and_findings` (each request `RANGE_URL` + 5 characters, one per prefix, headers exactly `User-Agent: App` and `Add-Padding: true`), `fea_06_11_nothing_to_check_sends_nothing`, `fea_06_12_first_failure_stops_the_check`, `fea_06_17_lock_drops_the_check_and_late_answers`: all pass, with and without the `net` feature.

**What waits.** The row's proof is a network capture during a real check. That check sends hash prefixes to the outside service, which needs the owner's yes (AGENTS.md rule 7), and it is started from the window (Mac QA, owner's go; E5-S7 parked the same capture). Status left as it is.

**Result: waits (owner's go for the real capture).** Nothing found weaker than the reference.

## SG-06 Command line breach check offline against a hash file, or through an outside lookup tool that gets each full SHA-1 as a program argument; App never puts hashes on a command line

**Reference.** `analyze -H FILE` reads records of 40 hex characters, `:`, a count and line ends; every live (not recycled) entry whose password's SHA-1 matches is listed, empty and excluded passwords included, in file order; a parse error stops at the line. Its counts are a signed 32-bit integer. A second option runs an outside lookup program once per entry with `--hash <full SHA-1>` on its command line.

**App.** `app analyze -H FILE` (crates/app-cli/src/commands.rs `analyze`) calls app-core `breach::offline_check`. There is no outside-program option; `--hibp` is a hidden alias of `-H`.

**Check today: the same 12 demo hash files on the same demo vault** (Alpha and Beta `password`, Alpha's history `iloveyou`, Gamma `123456`, Delta empty, Eps `Tr0ub4dor&3`, Zeta `café`, Ex `hunter2` excluded from reports, Ref a field reference to Alpha, Work/Mail/Site `123456`, Recycle Bin/Old `letmein`):

| File | Reference | App |
|---|---|---|
| 01 mixed: CR LF and LF, lower-case hex, empty count, count 0 | Site, Gamma 37359195; Beta, Alpha 10434004; Delta 5; Zeta (no number); Ex 17; Ref 4; Eps (no number); exit 0 | the same entries, counts and order (`Leaked password: Work/Mail/Site (in the list 37359195 times)` ...); exit 0 |
| 02 recycle bin and history hashes only | nothing, exit 0 | nothing, exit 0 |
| 03 count 4294967297 | 1 | 4294967297 (FEA-06.17) |
| 04 count 2147483648 | leaked, no number | 2147483648 |
| 05 count 18446744073709551615 | leaked, no number | 18446744073709551615 |
| 06 `G` inside a hash | no error; Beta, Alpha 2 | `Could not read record 1 of the hash file.`, exit 1 (D-06-8) |
| 07 blank first line, 08 no final line end, 09 space before `:`, 12 41 hex characters | parse error, line 1, exit 1 | `Could not read record 1 of the hash file.`, exit 1 |
| 10 empty file | nothing, exit 0 | nothing, exit 0 |
| 11 count `0007` | Beta, Alpha 7 | Beta, Alpha 7 |

**The lookup tool.** A stand-in lookup script in /tmp that only writes its arguments to a log, given to the reference with a dummy list file:

```
reference: analyze --<lookup option> /tmp/.../fake-lookup.sh -H /tmp/.../list.<ext> breach.appvault
log:       --path /tmp/.../list.<ext> --hash 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
           ... 9 lines, one per live entry, among them 7c4a8d09ca3762af61e59520943dc26494f8941b (= SHA-1 of 123456)
App:       app analyze --<lookup option> ... -> "app analyze: unknown option --<lookup option>. Run app help analyze to see its options.", exit 1
nm -u on the release app: no posix_spawn, fork, vfork, execv, execve, execvp, system or popen import
```

So the reference shows every full hash to any process that can list arguments; App has no such path and cannot start a program. App goes further, as the row says.

- Tests: fea06 (38) pass (`offline_check` and the file reader); int10 `int10_7_c_quiet_analyze_prints_only_findings`, `int10_32_b_hash_file_option` pass; args.rs's unit test refuses the lookup option.

**Result: verified.**

## SG-07 One-time codes (HMAC-SHA1, SHA-256, SHA-512, Steam); App uses app-crypto's HMAC

**Reference.** The code is RFC 6238 with the UI toolkit's message authentication class over SHA-1, SHA-256 or SHA-512, the key decoded from Base32, dynamic truncation, then either decimal digits or the Steam alphabet `23456789BCDFGHJKMNPQRTVWXY` (5 characters in the legacy `S` form; a link with `encoder=steam` keeps its digit count, 6 by default, in both tools below). Settings come from an `otpauth` link, a key-query form or the two legacy fields (`30;6`, `30;S`, ...).

**App.** app-core totp.rs uses `app_crypto::mac::hmac_sha1`, `hmac_sha256` and `hmac_sha512` (lines 210 to 212); app-core's Cargo.toml has no HMAC or SHA crate.

**Checks today.**
- fea04 (30) pass, among them `fea04_11_rfc_6238_and_rfc_4226_vectors`, `fea04_13_steam_code`; app-crypto `mac` (8) pass.
- Side by side on a demo vault made by the reference tool (App's code read just before and just after the reference's, same window):

```
T1 (otpauth, SHA-1, 6 digits, 30 s):       reference 635432     | App 635432 / 635432         | same
T256 (otpauth, SHA-256, 8 digits, 60 s):   reference 81308982   | App 81308982 / 81308982     | same
T512 (otpauth, SHA-512, 10 digits):        reference 0044447498 | App 0044447498 / 0044447498 | same
Steam (otpauth, encoder=steam):            reference 4WVWB5     | App 4WVWB5 / 4WVWB5         | same
Legacy (two fields, 60;8):                 reference 49436741   | App 49436741 / 49436741     | same
LegacySteam (two fields, 30;S):            reference 4WVWB      | App 4WVWB / 4WVWB           | same
KeyQuery (key=, step 60, size 8, SHA-256): reference 11361642   | App 11361642 / 11361642     | same
```

- Independent: Python's `hmac` (SHA-1, the RFC 6238 seed, 30 s) gave `602802` and `app show -t` gave `602802` in the same window.

**Result: verified.**
