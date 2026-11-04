# FEA-05 Strength estimate and Health Check

Status: reviewed
Epics: E4-S11 (screens: E5-S5 editor meter, E5-S6 generator, E5-S7 reports, E5-S8 master password)
Parity rows: SC-06, SG-03, SG-04, SF-16 (weak master password warning and minimum quality, FEA-05.20)

## What it does

App estimates how hard a password is to guess, in bits, and turns the estimate into one of five levels. The estimate drives:
- the meter under password fields while the user types (entry editor, master password),
- the strength shown in the generator,
- the strength indicator in the entry list and the "weak" search (FEA-01),
- the Health Check report, which adds penalties for reused and expiring passwords and lists every entry whose password is not at least Good,
- the warning when a weak master password is set.

Everything here runs locally. Nothing is sent anywhere (the online breach check is FEA-06).

Other cards own: the exclusion flag in the file (FMT-11.29, legacy form FMT-14.19), expiry (MOD-09), the recycle bin (MOD-04), field references (MOD-08), passphrase entropy (FEA-03), the statistics report (FEA-07), the `is:weak` search syntax (FEA-01), the master password screens (APP-07, MOD-12), settings (APP-01).

Words used here:
- **E**: the estimate in bits, a real number of 0 or more.
- **Strength score**: floor(E), an integer.
- **Health score**: the strength score after the Health Check penalties (FEA-05.13, FEA-05.14). It can be negative.
- **Level**: Bad, Poor, Weak, Good, Excellent (FEA-05.4).
- **Live entry**: an entry that is not a history item.
- **Tree order**: visit the root group; visiting a group means first its entries in stored order, then each child group in stored order, visited the same way.
- "Excluded": the entry's flag that keeps it out of reports is set (FMT-11.29, including the legacy custom data form of FMT-14.19). On screen App calls this "Skip in reports" (`ACT-HC-EXCLUDE`, FEA-05.18).
- Message texts in this card are App's own wording, not the reference's. Placeholders in angle brackets stay placeholders.

## Inputs and outputs

| In | Notes |
|---|---|
| Password text | any length; empty allowed |
| Vault | for the Health Check: groups, live entries, recycle bin, exclusion flags, expiry, now |
| Now | local date and time, for expiry |

| Out | Notes |
|---|---|
| E | real, 2 decimals when shown |
| Level | one of five |
| Strength reasons | text lines (FEA-05.6) |
| Health Check rows | entry, group path, health score, level, reasons, details (FEA-05.15 to FEA-05.18) |

The strength estimate works on a password the user typed or one entry's password. The Health Check result holds no password (architecture: commands return views without secrets).

## Rules

FEA-05.1 **Estimator.** E comes from the zxcvbn estimate of the password. The reference gives it no user inputs. App passes the entry's title, user name and URL host as user inputs (decided: spec/decisions.md LD-44), so a password equal to one of them rates low; this only makes ratings stricter. The reference uses a C port of zxcvbn that returns bits directly; App uses the `zxcvbn` crate (plan/architecture.md), which returns a guess count and a match sequence. How App turns that into E is lead decision D-05-1 (FEA-05.19 is the parity sample both must meet).

FEA-05.2 **Long passwords.** Only the first 256 characters go to the estimator. For a longer password of length n, E = E256 × n / 256 (E256 plus E256 / 256 for every character after the 256th). The reference counts length in UTF-16 code units; App counts characters (D-05-2). Observed with 2.7.11: a 256-character text gave 109.118 bits and the same pattern at 300 characters gave 127.872 = 109.118 × 300 / 256. The `zxcvbn` crate reads only the first 100 characters (E4-S11 finding), so in App E256 is the estimate of those 100 (LD-135). Verify (E4-S11, after LD-140): such a password rated lower or the same in every measured case. Against the reference, 0 of 60 passwords of 101 to 300 characters rated higher and 7 lower; against the same code reading 256 characters, 357 of 361 rated lower and 4 the same.

FEA-05.3 **Empty password.** E = 0. The estimator is not called.

FEA-05.4 **Score and level.** Strength score = floor(E) for E ≥ 0. The level of any score (strength or health):

| Score | Level |
|---|---|
| ≤ 0 | Bad |
| 1 to 39 | Poor |
| 40 to 74 | Weak |
| 75 to 99 | Good |
| ≥ 100 | Excellent |

FEA-05.5 **Colors.** App takes colors from the mockup's design tokens (design/mockup.html): Bad `danger`, Poor `poor`, Weak `warn`, Good and Excellent `ok`. One mapping for every place (meter, list, report). For information, the reference uses: report icons Bad `#C43F31`, Poor `#E07F16`, Weak `#FFD30F`, Good and Excellent `#5EA10E` (dark theme `#C43F31`, `#DB9837`, `#F0C400`, `#608A22`); its meters and list column use red for Bad and Poor, orange for Weak, and green shades for Good and Excellent.

FEA-05.6 **Strength reasons.** From the strength score alone:

| Level | Reason line (our ID, App text) | Detail line |
|---|---|---|
| Bad or Poor | `MSG-HC-VERY-WEAK` "Very easy to guess" | `MSG-HC-ENTROPY` "Estimated strength: E bits", E with 2 decimals |
| Weak | `MSG-HC-WEAK` "Somewhat easy to guess" | same |
| Good or Excellent | none | none |

FEA-05.7 **Meter under a password field.** Shown under the entry editor's password field and the new master password field (not under the repeat field).
- Recomputed after each change of the text, off the screen thread, once typing pauses; a result for older text is dropped (LD-137: one estimate can take 200 ms).
- Empty text: bar 0, no tooltip.
- Otherwise: bar value = min(strength score, 100) on a scale of 0 to 100; color by level (FEA-05.5); tooltip `MSG-Q-LEVEL` "Rated <level>", where Bad is shown as Poor.
- Entry editor only: placeholders and references in the typed text are resolved for the entry being edited before estimating (MOD-08), so `{REF:P@I:…}` is rated by the password it points to. This is in the source; 2.7.11 rates the raw text (differs in installed version).

FEA-05.8 **Generator display.** For the password tab: `MSG-GEN-ENTROPY` "E bits of strength" (2 decimals), a bar of min(strength score, 200) on a scale of 0 to 200, the color by level, and `MSG-GEN-QUALITY` "Rated <level>" where Bad is shown as Poor. For the passphrase tab the same display uses FEA-03's entropy instead of the estimator. FEA-02 and FEA-03 own the generator itself.

FEA-05.9 **Entry list indicator.** A column with one icon per entry: only for entries with a non-empty password that are not excluded. The level comes from the strength score of the password with placeholders resolved (MOD-08); no reuse or expiry penalty. Tooltip: the strength reasons. Sort key: the strength score, or 0 for entries without the icon.

FEA-05.10 **Weak predicate.** An entry is "weak" when all of these hold: not excluded; its password (as stored) is not empty; it is not expired (MOD-09); and the strength level of its password with placeholders resolved is Bad, Poor or Weak. FEA-01 `is:weak` and the sidebar's "Weak passwords" view use this predicate (whether they also skip the recycle bin is FEA-01's rule).

FEA-05.11 **Health Check: which entries.** Go through the live entries in tree order. Skip:
- the recycle bin group, every group inside it, and every entry in them (MOD-04);
- entries whose password (as stored) is empty;
- App only: entries whose password contains a field reference (MOD-08 pattern) (D-05-3).

Excluded entries are evaluated; FEA-05.15 hides them by default. History items are never evaluated.

FEA-05.12 **Reuse count.** Before evaluating, count passwords over every live entry outside the recycle bin, except entries whose password contains a field reference. The key is the stored password text, compared exactly (case and spaces count). Excluded entries count; empty passwords are counted too but never evaluated. Reuse count of an entry = the number of counted entries with the same password, itself included. For each password keep the list of its entries in tree order, as "group path/title", where the group path is the group names from the root group (included) down to the entry's group, joined with `/`.

FEA-05.13 **Health score: strength and reuse.** For an evaluated entry:
1. Start with the strength score of its stored password (FEA-05.4) and its strength reasons (FEA-05.6).
2. If the reuse count c is 2 or more: subtract 15 × (c − 1); add reason `MSG-HC-REUSED` "Same password on c entries"; add one detail `MSG-HC-USED-IN` "• <path/title>" per entry using it, at most 20, then one detail `…` if there are more; then if the score is above 74, set it to 74.

FEA-05.14 **Health score: expiry.** Then:
- If the entry is expired (MOD-09): set the score to 0; add reason `MSG-HC-EXPIRED` "Past its expiry date" and detail `MSG-HC-EXPIRY-WAS` "Expiry date <expiry date and time> has passed".
- Else if the entry expires (flag on) and d ≤ 30, where d = calendar days from today to the expiry date: if the score is above 70, set it to 70; subtract 2 × (30 − d); add detail `MSG-HC-EXPIRES-ON` "Expiry date: <expiry date and time>"; add one reason: d ≤ 2 `MSG-HC-EXPIRES-NOW` "Expires in 2 days or less"; 3 ≤ d ≤ 10 `MSG-HC-EXPIRES-IN` "d days until it expires"; 11 ≤ d ≤ 30 `MSG-HC-EXPIRES-SOON` "Expires within 30 days".
- Dates and times are shown in the short local format of the system.
- d: the reference subtracts today's local date from the expiry's UTC date (confirmed by Verify in E4-S11 through the reference command line tool's weak count at UTC+14 and UTC−8). App uses the local date of both (D-05-4). d = 0 means the expiry is later today.

Reasons and details keep the order they were added: strength, reuse, expiry. On screen they are one per line.

FEA-05.15 **What the report lists.** An evaluated entry is a candidate when its health level is below Good (health score ≤ 74). A candidate is shown unless:
- it is excluded and the toggle `SET-HC-SHOW-EXCLUDED` "Show skipped entries" is off; the toggle is visible only when at least one evaluated entry is excluded;
- it is expired and the toggle `SET-HC-SHOW-EXPIRED` "List expired entries too" is off.

Both toggles start off each time the report opens and are not saved. Changing a toggle recomputes the report.

FEA-05.16 **Order.** Rows are sorted by health score, lowest first. Equal scores keep tree order (D-05-5; the reference leaves ties in an unspecified order). The user can sort by any column; the score column sorts as numbers.

FEA-05.17 **Row content.**

| Column | Content |
|---|---|
| Level | icon and color by health level; tooltip `MSG-HC-TIP-BAD` "Bad. Replace this password now.", `MSG-HC-TIP-POOR` "Poor. Replace this password soon.", `MSG-HC-TIP-WEAK` "Weak. A stronger password would be better." |
| Title | the entry title, then ` (Excluded)` if excluded, then ` (Expired)` if expired; for an excluded entry the tooltip `MSG-HC-TIP-EXCLUDED` "Reports skip this entry" |
| Path | the group path of FEA-05.12 (root group name included) |
| Score | the health score as an integer, may be negative |
| Reason | the reasons, one per line; tooltip: the details, one per line |

Nothing in a row is a secret. A hint under the table says that hovering a reason shows details and double-click opens the entry.

FEA-05.18 **Report states and actions.**
- The report is computed when it is opened and after each action below, in the background, with `MSG-HC-WAIT` "Checking your passwords…" until done. It is not kept up to date while the user edits elsewhere.
- No rows: `MSG-HC-ALL-HEALTHY` "No password needs attention right now."
- Double-click or `ACT-HC-EDIT` (one row selected): open the entry editor; after Save, recompute.
- `ACT-HC-EXPIRE` (one or more rows): expire now (MOD-09), recompute.
- `ACT-HC-DELETE` (one or more rows, also the Delete key): delete with the usual confirmation, to the recycle bin or for good per MOD-04, recompute.
- `ACT-HC-EXCLUDE` "Skip in reports" (one or more rows): a check item that is checked when any selected entry is excluded; choosing it sets every selected entry to the opposite of that check state; recompute. Each changed entry is one change (MOD-03 decides history).

FEA-05.19 **Parity sample for the estimator.** Values from the installed reference (`estimate`, 2.7.11). App must give the same level for every row not marked "may differ"; Verify runs App's estimator on this list (D-05-1). E4-S11, after LD-140: same level for all 20 rows.

| Password | Reference E | Level | Note |
|---|---|---|---|
| (empty) | 0.000 | Bad | FEA-05.3 |
| `password` | 1.000 | Poor | |
| `P@ssw0rd` | 3.000 | Poor | |
| `abc123` | 3.700 | Poor | |
| `letmein` | 4.000 | Poor | |
| `qwertyuiop` | 4.459 | Poor | |
| `hunter2` | 11.379 | Poor | |
| `Summer2024!` | 19.087 | Poor | |
| `demo-pass-1` | 38.320 | Poor | may differ (near 40) |
| `Zm4#Lp9` | 43.091 | Weak | |
| `Tr0ub4dor&3` | 46.711 | Weak | |
| `correcthorsebatterystaple` | 47.983 | Weak | |
| `x9!Lq#4vTz` | 58.492 | Weak | |
| `Vp5#nQ2wLk8` | 67.548 | Weak | |
| `Zm4#Lp9qW2xR` | 73.970 | Weak | may differ (near 75) |
| `Zm4#Lp9qW2xR7v` | 85.091 | Good | |
| `kT7#pQ2vZ9mW4xR8` | 100.263 | Excellent | may differ (near 100) |
| `4v8Nq2LmZ7rT1xKc9WbP` | 113.306 | Excellent | |
| `kT7#pQ2vZ9mW4xR8nB3yL6cF` | 148.733 | Excellent | |
| `kT7#pQ2vZ9mW4xR8` repeated to 300 characters | 127.872 | Excellent | FEA-05.2 |

FEA-05.20 **Master password gate.** When the user sets or changes the master password (APP-07, MOD-12), with a non-empty new password, using the level of its strength score:
1. If the level is below the minimum level `SET-MK-MIN-LEVEL` (APP-01 S-CFG-02 `security.min_master_quality`; 0 to 4 for Bad to Excellent; values outside are clamped; default 0; APP-01 owns it; the reference keeps it in its settings file with no control on screen): refuse with `MSG-MK-TOO-WEAK` "This password is weaker than App allows. Choose a stronger one." The key is not changed.
2. Else if the level is below Good: warn `MSG-MK-WEAK` "This password is easy to guess, so your vault is less safe. Use it anyway?" with the buttons `ACT-MK-USE-WEAK` "Use this password" and Cancel (default Cancel). Cancel returns to the screen with nothing changed.

## Edge cases and errors

| Case | Result |
|---|---|
| Password made only of spaces | not empty: estimated normally |
| Two entries with passwords `abc` and `ABC` | not reused (exact compare) |
| Entry reused with an excluded entry | counted as reused (c = 2); only the non-excluded one is shown by default |
| Entry reused with an entry in the recycle bin | not counted |
| Entry reused with a history item | not counted (history is never counted) |
| Entry whose password is `{REF:P@I:…}` pointing at entry X | reference: not in the reuse count, and evaluated on the raw reference text (usually high, so not listed). App: skipped (D-05-3). X is evaluated normally |
| More than 20 entries share a password | 20 path details (`MSG-HC-USED-IN`), then `…` |
| Score below 0 | shown as is (for example −25); level Bad |
| Expiry flag on, expiry later today | d = 0: score capped at 70, then −60; reason `MSG-HC-EXPIRES-NOW` |
| Expiry flag on, expiry in 31 days or more | no expiry penalty |
| Expiry flag off but an expiry time set | ignored |
| Entry moved into the recycle bin while the report is open | gone after the next recompute |
| Vault with no evaluated entries | `MSG-HC-ALL-HEALTHY` |
| Lock while the report is open | the report closes and its data is dropped |

**Lead decisions** (open; until ruled, the default rule of spec/decisions.md applies: the recommended option):

| ID | Question | Options | Recommended |
|---|---|---|---|
| D-05-1 | How App gets E from the `zxcvbn` crate | (a) E = log2 of the crate's guess count. The crate scores unmatched (brute force) text at 10 guesses per character, about 3.32 bits, while the reference scores it by the character classes used, about 6.5 bits per character for mixed text: a random 20-character password gets about 66 bits (Weak) instead of 113 (Excellent). The published crate does cap its guess count at the 64-bit maximum (Verify, E4-S11; App's patched copy uses f64, LD-136), so under (a) no password could pass 64 bits and nothing would ever be Good. (b) E = the sum over the crate's match sequence: for a brute force match, its length × log2(N), where N = 26 if it has a lowercase letter + 26 if an uppercase letter + 10 if a digit + 33 if any other printable ASCII character (space included) + 100 if any non-ASCII character (control characters add nothing; a brute force match with N below 2 counts 0, LD-135); for a repeat match, its base by these same rules plus log2 of the repeat count (a copy cut short counts as one more, LD-139); for every other match, log2 of that match's guess count. App chooses the matches itself: E is the smallest such sum over every way to cover the password with the crate's matches and single characters, with N from the classes of the whole password and no penalty per match (LD-140). (c) Map the crate's 0 to 4 score to fixed E values | (b), accepted when it meets FEA-05.19. The constants of (b) are ours; Verify tunes them only if a sample row fails |
| D-05-2 | Length unit for the 256 cap | (a) UTF-16 code units, as the reference; (b) characters | (b): only text outside the Basic Multilingual Plane differs |
| D-05-3 | Passwords that contain a field reference, in the Health Check | (a) evaluate the raw reference text, as the reference; (b) skip them | (b): the target entry is checked itself; same visible result in practice |
| D-05-4 | Days to expiry | (a) as the reference (local today against the UTC expiry date); (b) local dates for both | (b) |
| D-05-5 | Order of equal health scores | (a) unspecified, as the reference; (b) tree order | (b) |

## Security notes

- The estimate runs in the Rust core. The screen sends the typed password to the core to be rated and receives only E, the level and the reason ids; the core never logs the password or keeps it after the call (SR-07, Rust rule 3).
- The Health Check and the list indicator return no secrets to the screen layer: titles, paths, scores, levels and reasons only. Reasons never quote a password. Reuse is shown by entry path, not by value.
- Reuse is found by comparing the vault's own password values in place; no copy or map of passwords is built (LD-137).
- Excluded entries are hidden by default but are not secret from the user: showing them needs only the toggle.
- Titles, paths and group names are set as text (AT-E01).
- Parity rows: SC-06 (strength while typing, FEA-05.7), SG-03 (passphrase strength shown, FEA-05.8 with FEA-03), SG-04 (weak, reused and expired passwords reported, entries can be excluded, FEA-05.11 to FEA-05.18). SF-16 (warn on a weak master password below Good, optional minimum quality 0 to 4, off by default, FEA-05.20).

## Test cases

Where a case gives "E = …", the test replaces the estimator with a stub that returns that value for that password, so the case tests the Health Check math and not the estimator. "Now" is 2026-10-25 12:00 local time; the time zone is UTC unless stated.

| Case | Given | When | Then |
|---|---|---|---|
| 05-01 levels | strength scores −25, 0, 1, 39, 40, 74, 75, 99, 100, 250 | level | Bad, Bad, Poor, Poor, Weak, Weak, Good, Good, Excellent, Excellent. FEA-05.4 |
| 05-02 floor | E = 39.99; E = 74.5; E = 100.0 | strength score, level | 39 Poor; 74 Weak; 100 Excellent. FEA-05.4 |
| 05-03 empty | password empty | estimate | E 0, score 0, Bad; the estimator is not called (stub records no call). FEA-05.3 |
| 05-04 long text | stub gives E256 = 109.118 for the first 256 characters of `kT7#pQ2vZ9mW4xR8` repeated to 300 characters | estimate | E = 127.873 (109.118 × 300 / 256 = 127.8727; the reference printed 127.872 from its unrounded E256), score 127; the stub was called with exactly 256 characters. FEA-05.2 |
| 05-05 user inputs | entry title `alice`, username `alice`, no URL, password `alice2024` | estimate | the estimator is called with the password and the user inputs `alice` (title) and `alice` (user name); the reference passes none (LD-44, LD-135). FEA-05.1 |
| 05-06 reasons | E = 12.5; E = 58.492; E = 85.0 | strength reasons and details | "Very easy to guess" + "Estimated strength: 12.50 bits"; "Somewhat easy to guess" + "Estimated strength: 58.49 bits"; none. FEA-05.6 |
| 05-07 meter | editor password field: empty; `password` (E 1.0); `x9!Lq#4vTz` (E 58.492); a password with E 150 | meter | bar 0, no tooltip; bar 1, color `poor`, tooltip "Rated Poor"; bar 58, `warn`, "Rated Weak"; bar 100, `ok`, "Rated Excellent". E = 0 for a stubbed non-empty text gives tooltip "Rated Poor" (Bad shown as Poor) and color `danger`. FEA-05.5, 05.7 |
| 05-08 meter resolves references | entry X password `kT7#pQ2vZ9mW4xR8`; editing entry Y, typed `{REF:P@I:<X id>}` | meter | rated as `kT7#pQ2vZ9mW4xR8` (same E as typing it). FEA-05.7 |
| 05-09 generator | password tab, generated text with E 113.306; passphrase tab with FEA-03 entropy 77.55 | display | "113.31 bits of strength", bar 113 of 200, "Rated Excellent"; passphrase: "77.55 bits of strength", "Rated Good" (the estimator is not called). FEA-05.8 |
| 05-10 list indicator | A password `password`; B empty password; C excluded with `password`; D password `{REF:P@I:<A id>}` | list | A: Poor icon, sort key 1, tooltip "Very easy to guess" + detail; B: no icon, key 0; C: no icon, key 0; D: rated as `password` (Poor). FEA-05.9 |
| 05-11 weak predicate | A `password`; B excluded `password`; C `password`, expired 2026-10-01; D empty; E `4v8Nq2LmZ7rT1xKc9WbP` | `is:weak` | A only. FEA-05.10 |
| 05-12 skipped entries | groups Root > Work, Root > Recycle Bin (the bin) > Old; entries: Root/A empty password; Work/B `x` (E 2); Recycle Bin/C `x`; Old/D `x`; B has a history item with `y` | Health Check | only B is evaluated; B's reuse count is 1 (C and D are in the bin; history ignored). FEA-05.11, 05.12 |
| 05-13 reuse | groups Root > Work, then Root > Mail; Root/Work/GitHub and Root/Mail/Proton both `Tr0ub4dor&3` (E 46.711); Root/Bank (an entry directly in Root) `Tr0ub4dor&3`, excluded | Health Check, toggles off | reuse count 3 for each. GitHub: 46 − 30 = 16, Poor; reasons "Somewhat easy to guess", "Same password on 3 entries"; details "Estimated strength: 46.71 bits", "• Root/Bank", "• Root/Work/GitHub", "• Root/Mail/Proton" (tree order). Proton the same. Bank hidden (excluded); the show-excluded toggle is visible. FEA-05.12, 05.13, 05.15 |
| 05-14 reuse cap | two entries with the same password, E = 113.306 | Health Check | 113 − 15 = 98, then capped to 74: Weak, listed; reasons only "Same password on 2 entries" (no strength reason, E was Excellent). FEA-05.13, 05.15 |
| 05-15 case-sensitive reuse | A `Secret-1`, B `secret-1` | reuse counts | 1 and 1. FEA-05.12 |
| 05-16 more than 20 uses | 22 entries Root/E01 … Root/E22 with the same password | details of E01 | "Same password on 22 entries"; details: strength line, "• Root/E01" … "• Root/E20", then `…`. FEA-05.13 |
| 05-17 expired | password E = 113.306, expires, expiry 2026-10-20 12:00 | Health Check | score 0, Bad; reason "Past its expiry date"; detail "Expiry date <2026-10-20 12:00 in short local format> has passed"; hidden while show-expired is off, listed with ` (Expired)` when on. FEA-05.14, 05.15 |
| 05-18 expiring | E = 113.306, expires; expiry dates 2026-10-26, 2026-11-01, 2026-11-14, 2026-11-24, 2026-11-25 | Health Check | d = 1: 70 − 58 = 12, "Expires in 2 days or less"; d = 7: 70 − 46 = 24, "7 days until it expires"; d = 20: 70 − 20 = 50, "Expires within 30 days"; d = 30: 70, "Expires within 30 days"; d = 31: 113, not listed. Each listed one has detail "Expiry date: <date>". FEA-05.14 |
| 05-19 expiring and weak | E = 20.0, expires in 5 days, reused once (c = 2) | Health Check | 20 − 15 = 5 (no cap needed), then 5 − 50 = −45: Bad, score shown −45; reasons in order "Very easy to guess", "Same password on 2 entries", "5 days until it expires". FEA-05.13, 05.14, 05.17 |
| 05-20 expiry later today | E = 90, expires 2026-10-25 23:00 | Health Check | not expired, d = 0: 70 − 60 = 10, Poor, "Expires in 2 days or less". FEA-05.14 |
| 05-21 time zone | Mac time zone UTC+2, now 2026-10-25 23:30 local; E = 90, expires 2026-10-26 23:30 UTC (2026-10-27 01:30 local) | d | App: 2 (local dates), score 70 − 56 = 14, "Expires in 2 days or less". The reference by its rule: 1 (local today against the UTC date), score 12; rule confirmed by Verify (E4-S11). FEA-05.14 |
| 05-22 order | listed scores: Root/B 30, Root/A 30, Root/C −10, Root/D 74 (tree order A, B, C, D) | report order | C (−10), A (30), B (30), D (74). FEA-05.16 |
| 05-23 row content | Root/Work/Gamma, excluded and expired, E 10, toggles on | row | title `Gamma (Excluded) (Expired)`; path `Root/Work`; score `0`; tooltips set; level Bad. FEA-05.15, 05.17 |
| 05-24 healthy | every evaluated entry Good or better | report | `MSG-HC-ALL-HEALTHY` "No password needs attention right now.", no table. FEA-05.18 |
| 05-25 exclude action | two rows selected, one excluded | open the row menu | "Skip in reports" is checked; choosing it clears the flag on both; recompute. With neither excluded: unchecked, choosing sets both. FEA-05.18 |
| 05-26 expire and delete actions | row X selected; recycle bin on | expire now; then delete and confirm | X expired now, so it moves under the show-expired rule; then X moves to the recycle bin and leaves the report. FEA-05.18 |
| 05-27 parity sample | every row of FEA-05.19 | App's estimator (D-05-1) | same level as the table, except rows marked "may differ". FEA-05.19, 05.1 |
| 05-28 master password minimum | `SET-MK-MIN-LEVEL` = 3 (Good); new master password `Zm4#Lp9` (Weak) | set master password | refused with `MSG-MK-TOO-WEAK`; key unchanged. FEA-05.20 |
| 05-29 master password warning | minimum 0; new password `password` (Poor) | set master password | `MSG-MK-WEAK`; Cancel keeps the screen; "Use this password" (`ACT-MK-USE-WEAK`) goes on. With `4v8Nq2LmZ7rT1xKc9WbP` (Excellent): no warning. FEA-05.20 |
| 05-30 reference skipped | Root/X `abc` (E 3), Root/Y `{REF:P@I:<X id>}` | Health Check | App: X listed, reuse count 1; Y not evaluated (D-05-3). FEA-05.11 |
| 05-31 colors | levels Bad, Poor, Weak, Good, Excellent in the report | icon colors | `danger`, `poor`, `warn`, `ok`, `ok`. FEA-05.5 |

## How this was learned

- Read the reference's password health routines (bits to score, level thresholds, reasons, the 256-character cap, reuse and expiry penalties), the Health Check report and its screen definition (which entries, filters, toggles, order, columns, tooltips, actions), the reports dialog (recompute after edit), the entry list model (strength column, sort key, tooltip), the search's weak keyword, the password field and generator meters, the state color palette, the master password settings page (minimum quality and the weak warning), the statistics routine (which reuses the health evaluation), the command line `estimate` command and the bundled zxcvbn C port's header.
- Read the change history after 2.7.11 for these files: reference passwords are resolved for the meter and list since a 2026 change (not in 2.7.11).
- Ran the installed command line tool's `estimate` (2.7.11) on the passwords of FEA-05.19 and on long texts for FEA-05.2.
- Not run: the Health Check screen (the command line tool has no health report). Its behavior comes from reading the source.
- The `zxcvbn` crate was not run (no Rust toolchain installed yet). The statements about its guess count come from its public design. Verify ran and diffed it in E4-S11: it prices brute force at 10 guesses per character, saturates its guess count at the 64-bit maximum and reads only the first 100 characters, as stated.
