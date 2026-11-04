# FEA-07 Statistics

Status: reviewed
Epics: E4-S11, E5-S7
Parity rows: SG-04

## What it does

The Statistics tab of the Reports screen shows facts about the open vault: its name, file, dates, and counts of groups, entries, expired entries, reused, short and weak passwords, excluded entries, passkeys and one-time password entries, plus the average password length. Some rows carry a warning mark with an explanation. The numbers are computed in larsal-core. The command line tool prints the same numbers (INT-10).

## Inputs and outputs

Input: the unlocked vault, the clock (for expiry), the vault file's path and modification time (from larsal-core storage), and whether the vault has unsaved changes.

Output: one record of rows. Each row has a stable ID, a value, and an optional warning. No row ever holds a password or any other protected value.

Labels are Larsal's own wording; the rows are listed in Larsal's screen order (FEA-07.19).

| ID | Larsal label | Value type |
|---|---|---|
| `stat.entries` | Entries | whole number ≥ 0 |
| `stat.groups` | Groups | whole number ≥ 0 |
| `stat.unique_pw` | Different passwords | whole number ≥ 0 |
| `stat.reused_pw` | Repeated passwords | whole number ≥ 0 |
| `stat.max_reuse` | Most uses of one password | whole number ≥ 0 |
| `stat.weak_pw` | Rated below Good | whole number ≥ 0 |
| `stat.short_pw` | Under 8 characters | whole number ≥ 0 |
| `stat.expired` | Past expiry | whole number ≥ 0 |
| `stat.totp` | One-time code entries | whole number ≥ 0 |
| `stat.passkeys` | Passkey entries | whole number ≥ 0 |
| `stat.avg_len` | Length on average | whole number ≥ 0, shown as "1 character" or "N characters" |
| `stat.excluded` | Skipped in reports | whole number ≥ 0 |
| `info.name` | Name | text (vault name, FMT-10) |
| `info.description` | Description (not in mockup, FEA-07.15) | text (vault description, FMT-10) |
| `info.location` | File | text (full path) or empty |
| `info.created` | Created on | date and time, or empty |
| `info.last_saved` | Most recent save | date and time, or empty |
| `info.unsaved` | Changes not saved yet (not in mockup, FEA-07.15) | yes or no |

## Rules

FEA-07.1 **What counts.** Every group and entry counts unless it is in the recycle bin. The recycle bin group itself and every group and entry below it are left out (MOD-04). Further rules:
- The root group counts as a group.
- History items never count (MOD-03).
- Group search flags (FEA-01.20) and Auto-Type flags play no part.
- Entries excluded from reports count everywhere, except where FEA-07.11 says otherwise.

FEA-07.2 **Groups.** `stat.groups` is the number of counted groups, including the root. A new vault with only a root group shows 1.

FEA-07.3 **Entries.** `stat.entries` is the number of counted entries.

FEA-07.4 **Expired.** `stat.expired` is the number of counted entries that have expiry on and an expiry time before now (MOD-09). Entries with an empty password count too.

FEA-07.5 **Which passwords.** The password rows (FEA-07.6 to FEA-07.12) use counted entries whose password is not empty. The password is taken as stored, with no placeholder or reference resolution (MOD-08). Two passwords are the same only when their text is identical: case matters, and there is no Unicode normalization. So `{REF:P@I:…}` is a password of its own, 42 characters long, even when it points to another entry's password.

FEA-07.6 **Unique.** `stat.unique_pw` is the number of different passwords among those entries.

FEA-07.7 **Non-unique.** `stat.reused_pw` is the number of those entries minus `stat.unique_pw`. Three entries sharing one password add 1 to unique and 2 to non-unique.

FEA-07.8 **Maximum reuse.** `stat.max_reuse` is the largest number of those entries that share one password. It is 1 when every password is different, and 0 when no entry has a password.

FEA-07.9 **Short.** `stat.short_pw` is the number of those entries whose password is shorter than 8 length units (FEA-07.18).

FEA-07.10 **Weak.** `stat.weak_pw` is the number of those entries where both hold:
- the password is shorter than 25 length units (longer ones are never counted, to save time);
- the entry's Health Check score (FEA-05) rates Bad, Poor or Weak, which is a score below 75. That score includes FEA-05's reuse penalty and cap, and its expiry rules: an expired entry scores 0, and an entry expiring within 30 days is lowered.
Entries excluded from reports are still counted here. The reuse used by that score follows FEA-05, which leaves out entries whose password is a field reference. So FEA-07.5's raw-text rule and the score's reuse count can differ for reference passwords. This is not the same test as `is:weak` (FEA-01.17), which ignores reuse and expiry, skips excluded and expired entries, and resolves placeholders.

FEA-07.11 **Excluded.** `stat.excluded` is the number of counted entries that are excluded from reports (FMT-11.29) **and** have a non-empty password. An excluded entry with an empty password is not counted.

FEA-07.12 **Average length.** `stat.avg_len` is the sum of the lengths (FEA-07.18) of the FEA-07.5 passwords, divided by their number, rounded to the nearest whole number with halves rounded up (9.5 → 10). It is 0 when there are no passwords. It is shown as "1 character" for 1 and "N characters" otherwise, including "0 characters".

FEA-07.13 **Passkeys.** `stat.passkeys` is the number of counted entries that hold a passkey: any field whose name starts with the passkey prefix (INT-04, MOD-01). It counts entries, not keys.

FEA-07.14 **One-time passwords.** `stat.totp` is the number of counted entries that have one-time password settings, by the same test as `has:totp` (FEA-04, FEA-01.18). Installed version 2.7.11 has no rows for FEA-07.13 and FEA-07.14 (differs in installed version). The source has both.

FEA-07.15 **Information rows.**

| ID | Value |
|---|---|
| `info.name` | the vault name |
| `info.description` | the vault description |
| `info.location` | the full path of the vault file. Empty when the vault has never been saved |
| `info.created` | the creation time of the **root group**, not a metadata time |
| `info.last_saved` | the modification time of the vault file on disk, read when the tab opens. Empty when there is no file |
| `info.unsaved` | yes when the vault has changes not yet written to disk, otherwise no |

The mockup shows name, location, created and last saved. It does not show description or unsaved changes. Lead decision. Recommended: add both rows to the mockup's info card, because the reference shows them and an unsaved-changes warning matters when a save has failed (APP-05).

FEA-07.16 **Warnings.** A row gets a warning mark, with the explanation shown on hover or as a note, when its condition holds. The explanations are paraphrased; Larsal's own text goes to the screen strings.

| Row | Warning when | Explanation (meaning) |
|---|---|---|
| `info.unsaved` | yes | changes are not yet saved to disk |
| `stat.expired` | > 0 | the vault holds expired entries |
| `stat.reused_pw` | `stat.reused_pw` > `stat.unique_pw` ÷ 10, with whole-number division (remainder dropped) | more than about 10% of passwords are reused |
| `stat.max_reuse` | > 3 | some password is used more than three times |
| `stat.short_pw` | > 0 | at least 8 characters are recommended |
| `stat.weak_pw` | > 0 | use long random passwords rated good or excellent |
| `stat.excluded` | > 0 | excluded entries are not always a problem, but keep an eye on them |
| `stat.avg_len` | < 10 and at least one password exists | the average is under ten characters |

For the average, the reference also warns when there are no passwords at all (0 < 10). Larsal does not warn then (lead decision: a vault with no passwords has no short average). The mockup's sample warning conditions (any reuse, reuse above 1) are illustrations only: the conditions above apply.

FEA-07.17 **When it is computed.** The numbers are computed each time the Statistics tab is opened. They are not live: they do not change while the tab stays open. The work runs off the screen thread. While it runs, the tab shows a short progress note in place of the rows (architecture: slow work shows progress in place). Closing the tab or locking the vault cancels it and drops the partial results.

FEA-07.18 **Length unit.** Lengths for FEA-07.9, FEA-07.10 and FEA-07.12 count UTF-16 code units, as the reference does. A character outside the Basic Multilingual Plane, such as `🔑`, counts as 2. Lead decision. Recommended: UTF-16 units, so the same vault shows the same numbers in both apps and in both command line tools. The other option is to count Unicode characters (code points).

FEA-07.19 **Row order.** The reference puts the information rows first and then the counts, in its own order. Larsal lays out the rows as the mockup does:
- a grid of number tiles in the order entries, groups, unique, non-unique, maximum reuse, weak, short, expired, TOTP, passkeys, average, excluded;
- then an info card holding name, location, created and last saved, and the two rows of FEA-07.15 if the lead adds them.
The order is a layout matter. The values follow this card.

FEA-07.20 **Times shown.** `info.created` and `info.last_saved` are shown in the Mac's local time zone, in the mockup's long date format. The reference shows the file time in local time, but the root group's creation time in the zone it was stored in, which is UTC. So `2026-01-10T10:00:00Z` shows as 10:00 even in a UTC+1 zone (observed). Larsal converts both to local time. Lead decision.

FEA-07.21 **One computation.** The Statistics tab and the command line tool's database-info output (INT-10) use the same larsal-core function, so they always agree.

## Edge cases and errors

| Case | Behavior |
|---|---|
| Vault with only the root group | Groups 1. Every count 0. Average "0 characters". Maximum reuse 0. No warning except unsaved changes, if it applies (FEA-07.16) |
| No recycle bin in the vault | Nothing is left out by FEA-07.1 |
| A hostile vault names the root group as its recycle bin | Everything is recycled: groups 0, entries 0, every number 0. MOD-04 decides whether such a vault is repaired on open |
| Excluded entry with an empty password | Counted in entries and expired (if expired). Not counted in excluded (FEA-07.11) |
| Expired entry with a password of 25 or more units | Counted in expired. Never counted as weak (FEA-07.10) |
| Passwords that differ only in case (`Abc`, `abc`) | Two unique passwords (FEA-07.5) |
| Password `{REF:P@I:<id of A>}` while A's password is `samepass1` | Counted as its own 42-unit password: unique, not reused (FEA-07.5) |
| Entry with a history item whose password differs | Only the current password counts (FEA-07.1) |
| Vault never saved, or file deleted while open | Location and/or last saved empty. No error |
| Very large vault | Progress note while computing. The screen stays responsive (FEA-07.17) |

## Security notes

- The statistics command returns numbers and metadata text only (architecture, larsal-desktop Must). No password, hash or protected value reaches the screen, a log or an error (Rust rule 3, AT-E07, AT-C06).
- Finding unique passwords means comparing secret values. Larsal compares the vault's own values in place inside larsal-core; no set, map or digest of passwords is built (SR-07, LD-137).
- The weak count runs the strength estimate (FEA-05) on passwords. It must use the same in-memory path as Health Check, with no copies outside secret types.
- Computing on a worker must not keep the vault alive after lock: lock cancels the work (FEA-07.17, APP-02).
- Parity row SG-04 covers reporting weak, reused and expired passwords with exclusions. This card is its statistics half. FEA-05 is the Health Check half.

## Test cases

Clock 2026-10-25T12:00:00Z, Mac time zone UTC unless a row says otherwise. Strength scores below are the FEA-05 password-only scores, observed with the reference's estimate command.

Demo vault **V3** (password `demo`; root `Root`, created 2026-01-10T10:00:00Z):

| Entry | Group | Password | Other |
|---|---|---|---|
| Same 1, Same 2, Same 3 | Root | `samepass1` (9 units, score 17) | |
| Excluded weak | Root | `abc` (score 2) | excluded from reports |
| Excluded empty | Root | empty | excluded from reports |
| Emoji | Root | `🔑🔑🔑🔑` (8 units, score 29) | |
| Long reused 1, Long reused 2 | Root | `correct horse battery staple` (28 units) | |
| Expired long | Root | `Vb7#Qx2!Lm9$Rt4&Kp6@Wz3^Hy` (26 units) | expires 2026-01-01T00:00:00Z |
| Ref pw | Root | `{REF:P@I:31313131313131313131313131313131}` (42 units) | |
| With history | Root | `Zq8!fT3#nB6^wR9*` (16 units, score 97) | one history item with password `histpass` |
| Totp | Root | empty | field `otp` holding a valid TOTP link (FEA-04) |
| Passkey | Root | empty | one passkey field (INT-04) |
| Empty pw | Root/Sub | empty | |
| Trashed entry | Recycle Bin/Trashed | `samepass1` | in the recycle bin |

Demo vault **V6**: Strong A and Strong B, both with `Zq8!fT3#nB6^wR9*`; Soon with `Hk4@pX7!mQ2#vT9%` (score 89, expires 2026-11-04T12:00:00Z, 10 days ahead); Excl strong with `Wd5$rN8^jL3&cF6*` (score 102, excluded). All in root.

Demo vault **V7**: Nine with `abcdefghi`; Ten with `abcdefghij`. Both in root.

Demo vault **V4**: root group only.

| Case | Given | When | Then |
|---|---|---|---|
| T01 FEA-07.1, FEA-07.2, FEA-07.3 | V3 | open Statistics | groups 2 (Root, Sub; not Recycle Bin, not Trashed); entries 14 |
| T02 FEA-07.4 | V3 | open Statistics | expired 1 |
| T03 FEA-07.5, FEA-07.6, FEA-07.7 | V3 | open Statistics | unique 7, non-unique 3. `histpass` and the recycled `samepass1` do not count |
| T04 FEA-07.8 | V3 | open Statistics | maximum reuse 3 |
| T05 FEA-07.9, FEA-07.18 | V3 | open Statistics | short 1 (`abc`; the emoji password is 8 units, so not short) |
| T06 FEA-07.10 | V3 | open Statistics | weak 5: Same 1 to 3, Excluded weak, Emoji. The long passwords (28, 26, 42 units) are skipped, and `Zq8…` scores 97 |
| T07 FEA-07.11 | V3 | open Statistics | excluded 1 (Excluded empty is not counted) |
| T08 FEA-07.12, FEA-07.18 | V3 | open Statistics | average "18 characters" (27 + 3 + 8 + 56 + 26 + 42 + 16 = 178 units, ÷ 10 = 17.8, rounded to 18) |
| T09 FEA-07.13, FEA-07.14 | V3 | open Statistics | passkeys 1, TOTP 1. Installed 2.7.11 shows neither row |
| T10 FEA-07.16 | V3, saved | open Statistics | Warnings on expired, non-unique (3 > 7 ÷ 10 = 0), short, weak, excluded. None on maximum reuse (3 is not > 3), average (18) or unsaved |
| T11 FEA-07.10 | V6 | open Statistics | unique 3, non-unique 1, maximum reuse 2, short 0, weak 3 (Strong A and B through reuse, Soon through expiry), excluded 1, average "16 characters" |
| T12 FEA-07.12, FEA-07.16 | V7 | open Statistics | average "10 characters" (9.5 rounds up). No average warning. Weak 2 |
| T13 FEA-07.2, FEA-07.12, FEA-07.16 | V4, saved | open Statistics | groups 1, entries 0, every other number 0, average "0 characters", no warnings. The reference warns on the average here |
| T14 FEA-07.16 | Vault with 10 different passwords plus 1 entry repeating one of them | open Statistics | unique 10, non-unique 1. No non-unique warning (1 is not > 1) |
| T15 FEA-07.16 | Vault with 9 different passwords plus 1 repeat | open Statistics | unique 9, non-unique 1. Non-unique warning (1 > 0) |
| T16 FEA-07.8, FEA-07.16 | 4 entries share `samepass1` | open Statistics | maximum reuse 4, with warning |
| T17 FEA-07.1 | FEA-01 demo vault S1 (Archive has searching off) | open Statistics | groups 5 (Vault, Banking, Cards, Archive, Dev & Ops), entries 6, expired 1, unique 5, non-unique 1, maximum reuse 2, short 4, weak 6, excluded 0, average "8 characters", passkeys 0, TOTP 1. The Archive group and E5 count, because search flags do not matter |
| T18 FEA-07.5 | Entries with `Abc` and `abc` | open Statistics | unique 2, non-unique 0 |
| T19 FEA-07.15, FEA-07.20 | V3 saved at 2026-10-20T08:00:00Z to `/tmp/spec/v3.larsalvault`, zone Europe/Berlin (UTC+2 that day, UTC+1 in January) | open Statistics | `info.location` `/tmp/spec/v3.larsalvault`. `info.created` 10 January 2026, 11:00 (local). `info.last_saved` 20 October 2026, 10:00. `info.unsaved` no. The reference shows created as 10:00 |
| T20 FEA-07.15 | New vault, not yet saved | open Statistics | location empty, last saved empty, unsaved yes (with warning) |
| T21 FEA-07.17 | V3, Statistics open | change an entry's password in another window | Numbers do not change until the tab is opened again |
| T22 FEA-07.17 | Generated vault with 10,000 entries | open Statistics, then lock at once | Progress note shown; lock cancels; no numbers kept |
| T23 FEA-07.21 | V3 | run the command line tool's database-info (INT-10) | Same numbers as T01 to T09 |
| T24 FEA-07.1 | Hostile vault whose recycle bin id is the root group's id | open Statistics | counted as a vault with no recycle bin (LD-76, LD-135): every group and entry is counted |
| T25 FEA-07.19 | Any vault | open Statistics | Tiles in the FEA-07.19 order, then the info card |
| T26 FEA-07.5, FEA-07.10 | Command traffic of the Statistics tab recorded with V3 open | open Statistics | Only numbers and the four or six info texts cross. No password text |

## How this was learned

- Read in the reference source: the statistics routine (what is counted, the recycled test, password grouping, the short and long length constants, rounding, warning conditions), the Statistics tab of the reports screen (row list, row order, warning icons and their explanations, the "please wait" row, computing on first show), the reports dialog (tab order: Statistics first; reload each time the dialog opens), the password health routines (score bands, reuse penalty and cap, expiry penalties, reference passwords left out of reuse), the entry routines for expiry, exclusion, one-time password settings and passkey fields, the date formatting helper, and the command line database-info command.
- Compared with installed version 2.7.11 through the change history: 2.7.11 lacks the passkey and TOTP rows.
- Observed with the installed command line tool's database-info and estimate commands on demo vaults V3, V4, V6, V7 and FEA-01's S1, built in `/tmp/spec-fea01-07/` from generated XML documents with password `demo`. Seen this way: every count in T01 to T08 and T11 to T13 and T17; the UTF-16 length unit (the emoji password is not short, and the average is 18, not 17); excluded entries still counted as weak; excluded entries with an empty password not counted as excluded; history and recycle bin left out; rounding of 9.5 up to 10; the creation time shown in UTC while the file time is shown in local time.
- Mockup read: the Statistics tab's tile grid, labels and info card.
