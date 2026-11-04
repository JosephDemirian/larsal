# FEA-06 Breach check

Status: reviewed
Epics: E4-S11 (network client: E6-S7; screen: E5-S7; command line: E12-S1)
Parity rows: SG-05, SG-06 (offline check, no outside lookup program), SN-01, SN-03, SG-04

## What it does

The breach check tells the user which entry passwords appear in a public list of passwords from known data breaches. There are two modes:

- **Online** (desktop app). Only when the user starts it, Larsal hashes each password with SHA-1 and asks the public Have I Been Pwned "range" service for every hash that starts with the same 5 hex characters. The service never sees a password or a full hash. Larsal finds its own hash in the answer and reads how often it was seen.
- **Offline** (command line only). The user gives a downloaded file of breached password hashes. Larsal reads it once from start to end and reports the entries whose password hash is in it. Nothing goes over the network.

This card owns: what is sent, when, how answers and files are read, what is listed, errors, and the privacy rules. Other cards own: the HTTPS client and its TLS rules (larsal-platform `net.rs`, E6-S7, SN-03), the command syntax and exact output text of `larsal analyze` (INT-10), the exclusion flag (FMT-11.29, FEA-05.18 actions), the recycle bin (MOD-04), the report screen layout (mockup, E5-S7).

Words used here:
- **Hash**: the SHA-1 of the UTF-8 bytes of the password, as 40 uppercase hex characters.
- **Prefix**: the first 5 characters of the hash. **Suffix**: the other 35.
- **Count**: how many times the service or the file says the password was seen.
- **Checked entry**: an entry whose password is checked (FEA-06.2).
- **Tree order**: as in FEA-05 (a group's entries, then its child groups, from the root).

## Inputs and outputs

| In | Notes |
|---|---|
| Vault | live entries (no history), recycle bin, exclusion flags |
| User action | `ACT-BREACH-RUN` (online), or the command line with a file path (offline) |
| Service answer | HTTP response body, text; Larsal reads at most 1 MiB per answer (FEA-06.6) |
| Hash file | text file of any size, read as a stream |

| Out | Notes |
|---|---|
| Findings | list of (entry, count) |
| Online screen | progress, result table, or a message |
| Offline output | one line per finding, or a parse error |

## Rules

### Online

FEA-06.1 **Only on request.** Nothing is sent until the user presses `ACT-BREACH-RUN` ("Check passwords online") on the breach page of the reports, under the consent text `MSG-BREACH-CONSENT`. Paraphrase: the check sends information to the online Have I Been Pwned service; each password is hashed and only the first five characters of each hash are sent, over HTTPS; the vault cannot be rebuilt from this; but the service learns how many passwords are checked and the computer's IP address. Opening the reports, unlocking, saving or any timer never starts a check. The reference has no setting that turns the check on: the press is the consent, every time. Larsal does the same; if APP-01 has a global switch for network features that is off, the button is disabled and says why (D-06-1). This satisfies SN-01: no traffic until the user acts.

FEA-06.2 **Which passwords.** Go through the live entries in tree order. Skip entries in the recycle bin or in any group inside it (MOD-04), and entries whose stored password is empty. Also skip, in Larsal only:
- excluded entries (D-06-2; the reference sends them too and only hides them in the results);
- entries whose password contains a field reference (MOD-08 pattern) (D-06-3; the reference hashes the raw reference text).

The password is the stored text, not resolved. Equal passwords are checked once.

FEA-06.3 **Hash and prefix.** Hash as defined above (SHA-1 is allowed here because the service demands it: `larsal-crypto/hash.rs`). Prefix = first 5 characters, uppercase hex. Example: `password` has hash `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`, prefix `5BAA6`, suffix `1E4C9B93F3F0682250B6CF8331B7EE68FD8`.

FEA-06.4 **Request.** One HTTPS GET per distinct prefix (D-06-4; the reference sends one per distinct password, so two passwords with the same prefix give two identical requests):

`https://api.pwnedpasswords.com/range/` followed by the prefix.

Headers Larsal sets:

| Header | Value |
|---|---|
| `User-Agent` | the product name only, no version, no platform: `Larsal` (renamed with D1). The reference sends its own name, `4B 65 65 50 61 73 73 58 43` (stored encoded, name rule). The service requires a user agent |
| `Add-Padding` | `true` (D-06-5; the reference does not send it) |

No cookies, no `Referer`, no `Accept-Language`, no authentication, no body. Requests go out at most 6 at a time. The reference also lets its network library add its default headers (such as a language header): check with Verify by a network capture of the reference (that capture contacts the service, so it needs the owner's yes, AGENTS.md rule 7). Still open after E4-S11: waits for the owner's yes.

FEA-06.5 **Padding.** With `Add-Padding: true`, the service's public API documentation says it adds made-up suffix lines with a count of 0, so every answer has a similar size. Lines with count 0 are "not found" (FEA-06.6). Not observed: no network was used to write this card; check with Verify against a local test server, and against the service only with the owner's yes. E4-S11: larsal-core reads count-0 lines as not found (06-05); the test server check waits for the network client (E6-S7).

FEA-06.6 **Reading an answer.** An answer is accepted when the status is 200. Its body is text: lines `SUFFIX:COUNT`, separated by CR LF (Larsal also accepts LF alone). Larsal looks for the line whose suffix (the part before `:`) equals its own suffix, compared without case; count = the decimal number after `:`, with spaces trimmed. A count that is not a number gives 0. A count past the largest 64-bit value stops at it, as offline (FEA-06.17, LD-135). No such line gives 0. Count 0 means not found. Larsal reads at most 1 MiB of a body; a longer body is an error (D-06-6; the reference has no limit). The reference searches the whole body for the 35-character uppercase suffix and reads the number after it up to the next line feed; for the service's real answers this gives the same result.

FEA-06.7 **Progress.** The progress bar runs from 0 to the number of requests; each finished request adds one. `ACT-BREACH-RUN` is disabled while requests are running. If there is nothing to check (FEA-06.2 leaves no password), no request is made and the result is shown at once (FEA-06.10).

FEA-06.8 **Errors.** The first request that fails (no network, DNS, TLS or certificate error, timeout, a status other than 200, a body over the limit) cancels every outstanding request. Larsal then shows the results found so far, followed by a line in the error color: `MSG-BREACH-FAILED` "The online check stopped early: <reason>", where the reason is a plain-language text plus the HTTP status when there is one. The reference adds the network library's error text and the response body to the message; Larsal puts the body only in the debug log, never on screen (it is outside text). Timeouts: as set in `net.rs` (E6-S7); recommended 15 seconds to connect and 30 seconds per request.

FEA-06.9 **Results.** When every request is done (or after an error), list every checked entry (FEA-06.2) whose password was found (count > 0). In Larsal an excluded entry is never listed, even when a checked entry has the same password (D-06-2). The reference lists every live entry outside the recycle bin whose stored password was found:

| Column | Content |
|---|---|
| Title | entry title, then ` (Excluded)` when excluded (only reachable in the reference, see D-06-2) |
| Path | group path from the root group (included), joined with `/` |
| Exposure | text from the count, in the error color (table below); sorts by the count |

Order: count, highest first; equal counts in tree order (D-06-7; the reference leaves them unspecified).

The count bands below match the reference; the texts are Larsal's own.

| Count | ID | Larsal text |
|---|---|---|
| 1 | `MSG-BREACH-COUNT-1` | Seen once |
| 2 to 10 | `MSG-BREACH-COUNT-10` | Seen 2 to 10 times |
| 11 to 100 | `MSG-BREACH-COUNT-100` | Seen 11 to 100 times |
| 101 to 1,000 | `MSG-BREACH-COUNT-1K` | Seen 101 to 1,000 times |
| 1,001 to 10,000 | `MSG-BREACH-COUNT-10K` | Seen 1,001 to 10,000 times |
| 10,001 to 100,000 | `MSG-BREACH-COUNT-100K` | Seen 10,001 to 100,000 times |
| 100,001 to 1,000,000 | `MSG-BREACH-COUNT-1M` | Seen 100,001 to 1,000,000 times |
| more | `MSG-BREACH-COUNT-MORE` | Seen over 1,000,000 times |

The reference hides excluded entries unless the user turns on a toggle to show them, and shows that toggle only when a listed entry is excluded. In Larsal excluded entries are never checked (D-06-2), so Larsal has no such toggle.

FEA-06.10 **Nothing found.** No finding and no error: `MSG-BREACH-NONE` "None of your passwords turned up in known leaks."

FEA-06.11 **Row actions.** The same as the Health Check (FEA-05.18): edit (double-click, one row), expire now, delete (also the Delete key), skip in reports. After an action the table is rebuilt from the findings already known; no new request, except:
- After the user edits an entry from this table and saves: if the password changed (or the exclusion flag changed, in the reference), the old password is dropped from the findings and the new password is checked with one new request. Larsal keeps no full hash to compare, so the edit itself tells whether the password changed (LD-135). Larsal skips that request when the new password is empty or the entry is now excluded (the reference sends the hash prefix of an empty password in that case).

FEA-06.12 **Lock and close.** Closing the reports or locking the vault cancels every outstanding request and drops all findings, hashes and counts. Opening the breach page again starts from the consent text.

FEA-06.13 **What Larsal keeps in memory.** Per checked password only: the entry ids that use it, the prefix, the suffix (in a secret type) and the count. The suffix is wiped when its answer has been read. Larsal never keeps the password text as a key (the reference keys its findings by the password text).

### Offline (command line)

FEA-06.14 **The file.** A text file of records. Each record is: exactly 40 hex characters (either case), `:`, zero or more decimal digits, then a line end. A line end is CR, LF or CR LF; after a line end any further CR and LF characters are skipped, so blank lines between records are allowed; a blank line before the first record is a parse error at record 1 (LD-135; the reference command line tool also stops at line 1 for a leading LF, CR LF or CR: Verify, E4-S11). The last record must also end with a line end. An empty file has no records. This is the format of the service's downloadable password list (hash, count, CR LF).

FEA-06.15 **Parse errors.** Anything else stops the check: fewer than 40 characters before the end of the file, a missing `:`, any character other than a digit, CR or LF after `:` (also `+`, a space or a minus), or a record cut off by the end of the file. The result is the error `MSG-BREACH-FILE-PARSE` "Could not read record N of the hash file.", where N counts records from 1 (skipped blank lines do not count), and nothing else is output; the command exits with failure. The reference stops at the same records (observed with 2.7.11, including the missing final line end); its error text is its own.

FEA-06.16 **Hex.** The reference turns the 40 characters into bytes with a decoder that silently skips characters that are not hex (observed: a `Z` inside a hash gave no error and no match). Larsal treats a non-hex character as a parse error (D-06-8).

FEA-06.17 **Counts.** An empty count is 0. Larsal reads counts into 64 bits and stops at the largest 64-bit value. The reference's counter wraps at 2^32 (observed: `4294967297` printed as 1); a wrapped count of 0 or of 2^31 and above prints with no number (Verify, E4-S11: `2147483648` and `4294967296`).

FEA-06.18 **Which entries (offline).** Every live entry outside the recycle bin, including entries with an empty password and excluded entries: the reference does not skip them (observed: an empty password matched the hash `DA39A3EE5E6B4B0D3255BFEF95601890AFD80709`). Larsal does the same, for parity with the reference's command line (D-06-9). The password is the stored text.

FEA-06.19 **Search.** Hash every checked entry's password first. Then read the file once, as a stream, never all of it into memory. For each record whose hash matches one or more entries, add one finding per matching entry with the record's count. Findings come in file order. For entries sharing a hash, the reference lists them in reverse tree order (observed: "Beta" before "Alpha" when Alpha comes first in the tree); Larsal does the same.

FEA-06.20 **Output.** One line per finding with the entry's path (the group names below the root group, then the title, joined with `/`; an entry directly in the root group shows only its title) and the count: count > 0 says the password was leaked that many times (singular for 1); count 0 says it was leaked, without a number. Before the findings the tool prints a line saying the check will take a while. Exit status success, also with no findings. INT-10 owns the exact wording and the option names.

FEA-06.21 **Not in Larsal.** The reference's command line can hand each hash to an outside lookup program for a preprocessed file, one process per entry. Larsal does not run outside programs for this (D-06-10).

## Edge cases and errors

| Case | Result |
|---|---|
| Vault with no checked password | online: no request, `MSG-BREACH-NONE` at once |
| Two entries with the same password | one request; both listed with the same count |
| Two passwords with the same prefix | Larsal: one request, both suffixes looked up in the one answer |
| Password with non-ASCII characters (`café`) | hashed as UTF-8: `F424452A9673918C6F09B0CDD35B20BE8E6AE7D7` |
| Answer line count not a number | count 0, not found |
| Status 429, 500 or any other non-200 | error (FEA-06.8); results so far kept |
| Network down when the user presses the button | the first request fails: error line, no findings |
| Body larger than 1 MiB | error (Larsal only) |
| Lock during a check | everything cancelled and dropped |
| Entry edited from the results to an empty password | Larsal: no new request; the entry leaves the findings |
| Offline file without a final line end | parse error on the last record, no findings printed |
| Offline file with lowercase hex, CR LF or lone CR line ends | read normally |
| Offline record `HASH:` | count 0: "leaked" without a number |
| Offline record with a space before `:` or a `+` in the count | parse error |
| Offline file path missing or unreadable | error message with the path or the system's reason, exit failure (INT-10) |

**Lead decisions** (open; until ruled, the default rule of spec/decisions.md applies: the recommended option):

| ID | Question | Options | Recommended |
|---|---|---|---|
| D-06-1 | Opt-in | (a) the button press is the consent each time, as the reference; (b) also a setting that must be on first | (a), plus respect a global network switch if APP-01 has one |
| D-06-2 | Excluded entries, online | (a) send them and hide them in the results unless a toggle is on, as the reference; (b) never send them | (b): less leaves the Mac, and the mockup says excluded entries are skipped |
| D-06-3 | Passwords that contain a field reference | (a) hash the raw text, as the reference; (b) skip them | (b): the target entry is checked itself |
| D-06-4 | Requests per prefix | (a) one per distinct password, as the reference; (b) one per distinct prefix | (b): the service learns less about how many passwords share a prefix |
| D-06-5 | Padding header | (a) none, as the reference; (b) `Add-Padding: true` | (b): answer sizes then tell an observer less about the prefix |
| D-06-6 | Answer size limit | (a) none, as the reference; (b) 1 MiB | (b): every read is bounded (Rust rule 5) |
| D-06-7 | Order of equal counts | (a) unspecified; (b) tree order | (b) |
| D-06-8 | Non-hex character in a hash file | (a) skip it silently, as the reference; (b) parse error | (b) |
| D-06-9 | Offline: empty and excluded passwords | (a) checked, as the reference; (b) skipped like online | (a): the command line is compared with the reference black-box (E12-S1) |
| D-06-10 | Outside lookup program | (a) support it; (b) leave it out | (b) |

## Security notes

- Privacy model (k-anonymity): only a 5-character prefix of each hash leaves the Mac. Never send a full hash, a suffix or a password, and never send any request before the user's press (SG-05, SN-01). AT check: a network capture during a check shows only `GET /range/XXXXX` requests to the service host; a capture of first start and of opening the reports shows none (E5-S7 check, SN-01).
- The service still learns the IP address, the time, and the number of prefixes. The consent text says so (FEA-06.1). One request per prefix (D-06-4) and padding (D-06-5) reduce what it learns.
- An unsalted SHA-1 of a password is as good as the password for weak passwords. Hashes and suffixes live in secret types, are wiped after use and never go to logs, error text or the screen layer (SR-07, Rust rules 3 and 9).
- TLS with certificate checks, no plain HTTP fallback, no redirects to other hosts (SN-03, `net.rs`). The user agent carries no version or platform.
- The answer is outside data: parse it with a size limit (D-06-6), never as HTML, never show its body on screen (AT-E01).
- The offline file can be tens of gigabytes: stream it, never load it; a hostile file must not crash or hang the tool (fuzz the record parser with the `cargo fuzz` targets, AT-A10).
- Results list titles and paths only, never the password or its hash.
- Lock cancels requests and drops all data (FEA-06.12).

## Test cases

Hashes (SHA-1 of UTF-8, computed with python3): `password` `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`; `123456` `7C4A8D09CA3762AF61E59520943DC26494F8941B`; empty text `DA39A3EE5E6B4B0D3255BFEF95601890AFD80709`; `café` `F424452A9673918C6F09B0CDD35B20BE8E6AE7D7`; `Tr0ub4dor&3` `874572E7A5AE6A49466A6AC578B98ADBA78C6AA6`. Online cases use a local test server in place of the service (no real network); the server records each request.

Demo vault V: Root/Alpha `password`; Root/Beta `password`; Root/Gamma `123456`; Root/Delta empty; Root/Eps `Tr0ub4dor&3`; Root/Zeta `café` (tree order as listed).

| Case | Given | When | Then |
|---|---|---|---|
| 06-01 nothing before the press | V; the test server | open the reports, open the breach page, wait 10 seconds | the server received no request. FEA-06.1 |
| 06-02 requests | V | press `ACT-BREACH-RUN` | exactly 4 requests: `GET /range/5BAA6`, `/range/7C4A8`, `/range/87457`, `/range/F4244`, each with `User-Agent: Larsal` and `Add-Padding: true`, no cookie, no `Accept-Language`; none for Delta. FEA-06.2, 06.3, 06.4 |
| 06-03 shared prefix | entries with passwords `demo-415` (hash `1E5F193CF5FFC3EDA845A505F2A28E76A1490111`) and `demo-733` (hash `1E5F17AEB095DB8B7AD022CBBE5DA2385D263637`) | press the button | one request, `/range/1E5F1`; both suffixes looked up in its answer. The reference sends two. FEA-06.4 |
| 06-04 answer parsing | answer for `5BAA6`: `0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:10434004\r\n` | read | count 10434004 for `password`. FEA-06.6 |
| 06-05 not found, padding | answer for `7C4A8` holding only other suffixes and the line `D09CA3762AF61E59520943DC26494F8941B:0` | read | count 0: Gamma not listed. FEA-06.5, 06.6 |
| 06-06 case and LF | answer `1e4c9b93f3f0682250b6cf8331b7ee68fd8:7\n` | read | count 7. FEA-06.6 |
| 06-07 bad count | answer `1E4C9B93F3F0682250B6CF8331B7EE68FD8:x\r\n` | read | count 0, not listed. FEA-06.6 |
| 06-08 results | counts: `password` 10434004, `Tr0ub4dor&3` 1, `café` 0, `123456` 37359195 | all done | rows in order: Gamma (37359195, "Seen over 1,000,000 times"), Alpha (10434004, "Seen over 1,000,000 times"), Beta (10434004, "Seen over 1,000,000 times"), Eps (1, "Seen once"); path `Root` for each; Zeta not listed. FEA-06.9 |
| 06-09 count texts | counts 1, 2, 10, 11, 100, 101, 1000, 1001, 10000, 10001, 100000, 100001, 1000000, 1000001 | text | Seen once; Seen 2 to 10 times (2 and 10); Seen 11 to 100 times (11, 100); Seen 101 to 1,000 times (101, 1000); Seen 1,001 to 10,000 times (1001, 10000); Seen 10,001 to 100,000 times (10001, 100000); Seen 100,001 to 1,000,000 times (100001, 1000000); Seen over 1,000,000 times (1000001). FEA-06.9 |
| 06-10 nothing found | V where every answer lacks our suffixes | all done | `MSG-BREACH-NONE` ("None of your passwords turned up in known leaks."). FEA-06.10 |
| 06-11 empty vault | vault with only Delta | press the button | no request; `MSG-BREACH-NONE` at once. FEA-06.7, 06.10 |
| 06-12 error | the server answers `/range/5BAA6` with status 500 and keeps `/range/87457` waiting | press the button | outstanding requests cancelled; findings so far shown, then `MSG-BREACH-FAILED` with "status 500"; the body text is not on screen. FEA-06.8 |
| 06-13 body limit | answer of 2 MiB | read | error (FEA-06.8), Larsal only. FEA-06.6 |
| 06-14 excluded and references | V plus Root/Ex `hunter2` excluded and Root/Ref `{REF:P@I:<Alpha id>}` | press the button | no request for the prefixes of `hunter2` or of the reference text. FEA-06.2 |
| 06-15 recycle bin and history | V plus an entry `letmein` in the recycle bin and a history item of Alpha with `iloveyou` | press the button | no request for either prefix. FEA-06.2 |
| 06-16 edit from results | results of 06-08; edit Alpha's password to `4v8Nq2LmZ7rT1xKc9WbP` and save | after save | Alpha leaves the findings unless the new answer finds it; exactly one new request, for the new password's prefix. With the new password empty: no request, Alpha leaves the findings. FEA-06.11 |
| 06-17 lock | a check running (server delays answers) | lock the vault | requests cancelled; after unlock the breach page shows the consent text and no results. FEA-06.12 |
| 06-18 memory | a check finished | inspect the core's breach state | holds entry ids, prefixes and counts; no password text, no full hash (debug-build test hook). FEA-06.13 |
| 06-19 offline basic | V; file `7C4A8D09CA3762AF61E59520943DC26494F8941B:37359195\n5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8:10434004\r\nDA39A3EE5E6B4B0D3255BFEF95601890AFD80709:5\nF424452A9673918C6F09B0CDD35B20BE8E6AE7D7:0\n` | `larsal analyze` with the file | findings in this order: Gamma 37359195; Beta 10434004; Alpha 10434004; Delta 5; Zeta (leaked, no number); exit success. Observed with 2.7.11 in the same order. FEA-06.14, 06.17, 06.18, 06.19, 06.20 |
| 06-20 offline missing final line end | file `7C4A8D09CA3762AF61E59520943DC26494F8941B:37359195\n5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:10` | analyze | `MSG-BREACH-FILE-PARSE` with N = 2; no findings printed; exit failure. Observed. FEA-06.14, 06.15 |
| 06-21 offline blank lines and plus | file `<123456 hash>:37359195\n\n\n<password hash>:+10\n` | analyze | `MSG-BREACH-FILE-PARSE` with N = 2 (blank lines skipped and not counted). Observed. FEA-06.15 |
| 06-22 offline no colon / space | `<123456 hash>37359195\n`; `<123456 hash> :1\n` | analyze | `MSG-BREACH-FILE-PARSE` with N = 1, both. Observed. FEA-06.15 |
| 06-23 offline empty count | `<123456 hash>:\n` | analyze | Gamma leaked, no number. Observed. FEA-06.17, 06.20 |
| 06-24 offline line ends | `<123456 hash>:12\r<password hash>:3\r\n` | analyze | Gamma 12; Beta 3; Alpha 3. Observed. FEA-06.14 |
| 06-25 offline empty file | empty file | analyze | no findings; exit success. Observed. FEA-06.14 |
| 06-26 offline non-hex | `<first 39 characters of the 123456 hash>Z:9\n` | analyze | Larsal: `MSG-BREACH-FILE-PARSE` with N = 1. The reference: no error, no match (observed). FEA-06.16 |
| 06-27 offline big count | `<password hash>:4294967297\n` | analyze | Larsal: Alpha and Beta 4294967297. The reference prints 1 (observed). FEA-06.17 |
| 06-28 offline path text | entry Root/Work/Mail/Site with `123456`; file `<123456 hash>:3\n` | analyze | path shown `Work/Mail/Site` (root name left out). FEA-06.20 |
| 06-29 offline streams | a 5 GB demo file of random records, with the `123456` record last | analyze | finds Gamma; the tool's memory stays under 100 MB during the run. FEA-06.19 |
| 06-30 no outside program | Larsal's `analyze` help; a run of 06-19 under a process monitor | read the help; run | no option to hand hashes to another program; the run starts no child process. FEA-06.21 |

## How this was learned

- Read the reference's online breach downloader (hashing, URL, user agent, answer search, error handling), its network manager, the breach report and its screen definition (consent text, button, progress, table, toggle, actions, refresh after edit), the reports dialog, the offline breach routine (record parser, matching) and the command line `analyze` command (output, outside-program option), and the build switch that removes network code.
- Ran the installed command line tool's `analyze` (2.7.11) with nine crafted demo hash files against a demo vault in `/tmp/spec-fea04-06/` (demo password `demo`): cases 06-19 to 06-27.
- Never contacted the service. The padding header's effect (FEA-06.5) is from the service's public API documentation, not observed. The headers the reference's network library adds by default are not observed: check with Verify with a network capture (still open after E4-S11: needs the owner's yes).
