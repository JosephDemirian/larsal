# FEA-03 Passphrases and the word list

Status: reviewed
Epics: E4-S9, E5-S6; license and attribution E14-S2
Parity rows: SG-01, SG-03, SC-06

## What it does

The Passphrase tab of the generator screen (FEA-02) picks words at random from a word list and joins them with a separator. Options: word count, separator, word case, and which word list: the built-in one or a list the user added from a file. The strength shown is word count × log2(number of words in the list).

Everything FEA-02 says about the screen applies here too: live regeneration (FEA-02.14), the editable output (FEA-02.16), entry points and Apply (FEA-02.17), saving settings (FEA-02.18), Copy (FEA-02.20) and secret handling (FEA-02.23). The command line has its own passphrase command (FEA-03.16; INT-10 owns the syntax). Code: `app-core` `generator/passphrase.rs` and `generator/wordlist.rs`.

## Inputs and outputs

In: the options below and a loaded word list. Out: a passphrase as a `SecretString`, plus the entropy number (FEA-03.7). Errors: `EmptyWordList` (FEA-03.13), `RandomFailed` (FEA-02.6 applies to every pick here), word list file errors (FEA-03.11).

### Options and defaults

App-wide settings, not in the vault, saved with the password settings (FEA-02.18).

| Setting (our ID) | Default | Values |
|---|---|---|
| `generator.passphrase.words` | 7 | screen 1 to 100; core and command line D-03-5 |
| `generator.passphrase.separator` | one space (U+0020) | any text, also empty (limit D-03-5) |
| `generator.passphrase.case` | lower | lower, upper, title, mixed (the reference stores 0 to 3 in this order) |
| `generator.passphrase.word_list` | `builtin` | `builtin`, or the full path of a user list (FEA-03.14) |

### App's built-in word list (D-03-1)

| Fact | Value |
|---|---|
| Source | The EFF Large Wordlist for Passphrases, published by the Electronic Frontier Foundation in 2016 (https://www.eff.org/dice), unmodified |
| Words | 7,776 = 6^5, so five dice rolls pick one word; log2(7,776) = 12.925 bits per word |
| Published file | one line per word: a five-digit dice code (digits 1 to 6), a tab, the word; codes 11111 to 66666 in order (checked by Verify in Sprint 3 on the file App ships: 7,776 lines, each five dice digits, a tab and the word, codes 11111 to 66666 in order, LF line ends; the SHA-256 of the words, each followed by one LF, equals the check value below) |
| First and last | `abacus` (11111), `zoom` (66666) |
| Characters | lower-case a to z only, except 4 words with a hyphen: `drop-down`, `felt-tip`, `t-shirt`, `yo-yo` |
| Word lengths | 3 to 9 characters: 82 of 3, 467 of 4, 928 of 5, 1,372 of 6, 1,591 of 7, 1,779 of 8, 1,557 of 9 |
| Check value | SHA-256 of the 7,776 words in order, each followed by one LF, dice codes removed: `6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522` (computed from the reference's first, unmodified copy of the list; confirmed 2026-10-26: EFF's published file at https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt gives the same value, 7,776 words) |
| Where it lives | compiled into the binary in `generator/wordlist.rs`, with the license reasons in the file header and the attribution as the constant `ATTRIBUTION` (architecture) |
| License | CC BY 4.0: EFF's copyright page (https://www.eff.org/copyright) puts its original material under the Creative Commons Attribution 4.0 International License (observed 2026-10-26, read again 2026-10-31 in E14-S2); when the list was published, EFF's site terms gave CC BY 3.0 US. App uses EFF's list unmodified. CC BY 4.0 asks for the creator, the source, a note that the work is unmodified, the license and its no-warranty notice, and the FSF lists it as compatible with every version of the GNU GPL (https://www.gnu.org/licenses/license-list.html), so the list is compiled into App under GPL-3.0-or-later (LD-262 (3)) |
| Attribution App shows | the one text `app_core::generator::wordlist::ATTRIBUTION`, word for word in `macos/App/Resources/Credits.rtf` (the About window), `app --license` (INT-10 F05) and the "Built-in word list" section of `THIRD-PARTY-NOTICES.md` (scripts/make-sbom.sh reads it from the source): "Word list: EFF Large Wordlist for Passphrases, by the Electronic Frontier Foundation, https://www.eff.org/dice, unmodified, used under the Creative Commons Attribution 4.0 International license (CC BY 4.0, https://creativecommons.org/licenses/by/4.0/), which provides it as is, with no warranty." Credits.rtf holds the same words; the test `e14_2_the_license_and_word_list_notices_are_shown` keeps it and `app --license` equal to the constant |

### The reference's shipped word list (for comparison only)

The reference ships one list: EFF's large list, changed by its maintainers in three steps: 3 offensive words removed (2021); 24 words, many of them brand and product names, replaced by 27 others (2022); the 4 hyphenated words removed (2025). Result: 7,772 words, lower-case a to z only, 3 to 10 letters (one word of 10), one per line, no dice codes. The installed version 2.7.11 ships the same 7,772-word file. The reference ships no license or attribution text for it: its copyright file has no entry for the list; its command line help names the default "EFF English"; its user guide links to EFF's word list page. App does not copy this list (clean room, and it is not 7,776 words).

## Rules

FEA-03.1 The built-in list is the one in "App's built-in word list": 7,776 words, matching every fact in that table, compiled in, with its attribution (`ATTRIBUTION`, the one text) shown in About, in `app --license` and in the third-party notices. Its license is CC BY 4.0, used unmodified (LD-262 (3)).

FEA-03.2 With the built-in list, each word adds log2(7,776) = 12.925 bits in App; in the reference, with 7,772 words, log2(7,772) = 12.924. The shown totals differ only at some word counts: 6 words show 77.55 in App and 77.54 in the reference; 8 words 103.40 and 103.39.

FEA-03.3 Word count: default 7. Reference screen: a slider 1 to 40 (tick every 8) and a number field 1 to 100, kept in step. The core treats any count below 1 as 1. Reference command line: default 7; any whole number of 1 or more (observed: 1,000 works); 0, negative numbers and non-numbers give an "invalid word count" error and status 1. App limits: D-03-5.

FEA-03.4 Separator: default one space. Any text is allowed, also empty and several characters long; it is not trimmed. It goes between words only, never before the first or after the last. The command line always uses one space.

FEA-03.5 Word case, applied to each picked word:

| Case | Result |
|---|---|
| lower (default) | the whole word in lower case |
| upper | the whole word in upper case |
| title | first character in upper case; the rest as in the list (reference). App: the rest in lower case (D-03-2). Same result for the built-in list, which is all lower case |
| mixed | exactly one word, at a uniformly random position, in upper case; every other word in lower case |

Case mapping is full Unicode mapping (so `ß` in upper case becomes `SS`, in both the reference and Rust's standard mapping). "First character" is the first Unicode scalar value. The command line always uses lower.

FEA-03.6 Picking. Each word is drawn independently and uniformly from the list's unique entries with `below(N)` (FEA-02.6), with replacement, so a word may repeat inside one passphrase (with 7 words from 7,776 this happens in about 0.27 % of passphrases). For mixed case, App first draws the upper-case position with `below(word count)`, then the words. The reference draws that position on every call, whatever the case setting, and uses it only for mixed; the difference matters only for scripted tests.

FEA-03.7 Entropy shown = word count × log2(N), N = the number of unique entries in the loaded list (after FEA-03.10); 0 when the list is empty. It is not adjusted for case, separator or the mixed position. Shown with 2 decimals, with the same quality word, bar and character count as FEA-02.15 (bands below 40 Poor, below 75 Weak, below 100 Good, else Excellent). Built-in list: 3 words 38.77 Poor; 5 words 64.62 Weak; 6 words 77.55 Good; 7 words 90.47 Good; 8 words 103.40 Excellent. Text the user types over the output: D-03-7.

FEA-03.8 Reading a word list file. (1) Decode the bytes as UTF-8; a leading byte order mark is honoured (UTF-8, or UTF-16 in either byte order; observed for UTF-8 and UTF-16 big-endian). (2) Split into lines at LF; CRLF also ends a line. (3) Trim each line's leading and trailing white space (Unicode white space: observed for tab, U+00A0 and U+2003). (4) If the trimmed line is one or more ASCII digits, optionally followed by groups of a hyphen and more digits, then ASCII white space (space, tab and the other ASCII white-space controls; not U+00A0 or other Unicode spaces), then one run of characters that are not ASCII white space (for example `11111 abacus`, `11111` + tab + `abacus`, `1-2-3-4-5 abacus`), keep only that run. Any other line is kept whole: `11111 two words` stays as it is, `2nd` stays, `11111` alone stays, `123 456` becomes `456`. (5) Every non-empty line is an entry. (6) Entries are made unique (FEA-03.10). App keeps the entries in order of first appearance (the reference's order is arbitrary; only scripted tests depend on order).

FEA-03.9 Signed lists. If the first line starts with `-----BEGIN PGP SIGNED MESSAGE-----`, the loader skips lines up to and including the first line that is empty after trimming (the armor headers), stops at the first line that starts with `-----BEGIN PGP SIGNATURE-----`, and removes a leading `- ` (dash, space) from any line before step (3) of FEA-03.8. The signature is not checked. These marker strings are fixed by the OpenPGP clear-signed text format (RFC 4880, section 7).

FEA-03.10 Making entries unique. Reference: exact, case-sensitive comparison, so `Alpha` and `alpha` are two entries; after lower-casing both give `alpha`, which then comes up twice as often while the entropy counts both (observed: 25 of 60 picks were `alpha` from a 6-entry list holding both). App: D-03-2 (unique after lower-casing).

FEA-03.11 Bad text in a file. Reference: invalid UTF-8 bytes become U+FFFD (observed: a Latin-1 `é` became U+FFFD inside the word); a carriage return not followed by LF is dropped (observed: a file with only CR line ends gave one entry, all words run together); no size limit. App: D-03-3.

FEA-03.12 Minimum recommended size: 1,296 unique entries (6^4, the size of a four-dice list). Below it the screen shows a warning under the options (`MSG-PP-LIST-SMALL`: the selected list has fewer words than recommended) and the command line prints that warning on standard error; generation still works and the command line exits with status 0 (observed: 1,295 entries warn, 1,296 do not). The entropy number already shows the smaller size.

FEA-03.13 Empty or unreadable list. Reference: the passphrase is empty, Copy and Apply are disabled (output empty), the small-list warning shows, Regenerate stays enabled; the command line prints an empty line, a "could not load" warning and the small-list warning, and exits with status 0 (observed). App: D-03-4.

FEA-03.14 Managing word lists on the screen.

| Part | Behavior |
|---|---|
| Picker | built-in list first (the reference labels built-in lists as system lists), then the files in the user word list folder, by file name. App folder: `~/Library/Application Support/App/wordlists/` (the reference uses a `wordlists` folder next to its settings file) |
| Add (`ACT-PP-LIST-ADD`) | a file chooser offering `.txt`, `.asc` and `.wordlist` files, or all files. The chosen file is copied into the folder under its own file name and becomes the selected list. The folder is created if missing. If a user list of that file name exists: confirm `MSG-PP-LIST-OVERWRITE` (Overwrite or Cancel, Cancel is the default); Cancel leaves the old file. A failed copy or delete shows `MSG-PP-LIST-ADD-FAILED` or `MSG-PP-LIST-DELETE-FAILED` with the system's reason. App checks the file (FEA-03.8, D-03-3) before copying |
| Remove (`ACT-PP-LIST-REMOVE`) | enabled only for user lists. Confirm `MSG-PP-LIST-REMOVE` naming the list (Remove or Cancel, Cancel is the default); Remove deletes the file. The reference drops the list from the picker even when the delete failed (after showing the error). App then selects the built-in list |
| Selection | saved as `builtin` or as the user file's full path. A saved list that is no longer there (deleted outside the app) falls back to the built-in list |
| Reading | the reference reads the selected file again on every option change, so edits to the file show at once. App reads it when it is selected and when the generator opens |

FEA-03.15 The tab in use is saved as `generator.kind` and restored when the generator opens (FEA-02.18). Apply and Copy work the same on both tabs.

FEA-03.16 Command line passphrase command (the reference names it `diceware`; INT-10 owns App's name, syntax and help). Options: word count (default 7) and a word list file path (default the built-in list). Always lower case and one space. Errors per FEA-03.3 and D-03-4; the small-list warning per FEA-03.12. Ignores the saved settings.

FEA-03.17 The passphrase is a secret, handled as FEA-02.23 says. The word list itself is not secret.

## Edge cases and errors

| Case | Expected |
|---|---|
| Word list with one entry | every passphrase repeats that word; 0.00 bits; small-list warning |
| Same word twice in one passphrase | allowed (FEA-03.6) |
| Separator empty | words run together; the entropy number is unchanged (it does not see that word borders vanish) |
| Custom list with an entry containing a space (`echo echo`) | that whole entry is one "word" |
| A user list file deleted while selected | App: next generation fails with `MSG-PP-LIST-UNREADABLE`, Copy and Apply disabled (D-03-4) |
| Line `- word` in a list that is not signed | kept as `- word` (the dash rule applies only to signed lists) |
| Signed list without the signature line | read to the end of the file |
| User list with upper-case words and case lower | words are lower-cased (and in App made unique first, D-03-2) |

Not on Mac: nothing. Only the user word list folder differs per platform (the reference keeps it next to its settings file on every platform).

## Lead decisions

| ID | Question | Options | Recommendation |
|---|---|---|---|
| D-03-1 | Which built-in list | (a) EFF's large list unmodified, 7,776 words; (b) EFF's large list with our own replacements for offensive words, brand names and hyphenated words, still 7,776 words (a changed CC BY work: the change must be noted); (c) the reference's 7,772-word list: not allowed (clean room, and not 7,776) | (a): matches the architecture and SG-03, verifiable by the check value, dice codes stay exact. Getting the file from eff.org needs the owner's yes (AGENTS rule 7), or the lead supplies it; Verify then checks it against the table. License: CC BY 4.0, with the attribution `ATTRIBUTION` (LD-262 (3), E14-S2). |
| D-03-2 | Case and uniqueness | (a) as the reference: unique by exact text; title keeps the rest of the word; (b) title = first character upper, rest lower; entries made unique after lower-casing, so N counts distinct outputs | (b): no word comes up more often than others, and the entropy number is never too high |
| D-03-3 | Reading user files | Reference: bad bytes become U+FFFD, lone CR dropped, no limits, no check on Add | Refuse a file that is not valid UTF-8 (after a byte order mark) with `MSG-PP-LIST-NOT-UTF8`; treat lone CR as a line end; refuse files over 4 MiB, with over 500,000 unique entries, or with an entry over 256 characters, with `MSG-PP-LIST-TOO-BIG`; run these checks on Add, before copying, and on every load. Add a fuzz target for the reader (it is a parser of user files, Rust rule 10). |
| D-03-4 | Empty or unreadable list | Reference: empty output on screen; empty line and status 0 on the command line | Screen: show `MSG-PP-LIST-EMPTY` or `MSG-PP-LIST-UNREADABLE`, Copy and Apply disabled. Command line: the same message, status 1. |
| D-03-5 | Limits (Rust rule 5, AT-E03) | Reference: screen 1 to 100 words; command line no upper limit; separator up to 32,767 characters (text field default) | Screen 1 to 100; core and command line 1 to 1,000, else `MSG-PP-COUNT`; separator at most 64 characters |
| D-03-6 | Mockup gaps | The mockup has a word count slider 3 to 12, case chips lower, UPPER and Title, and no list picker | Keep a number field 1 to 100 (the slider may stay 3 to 12); add a fourth case chip for mixed; add the list picker with Add and Remove. Needs the owner's look approval (AT-K05). |
| D-03-7 | Strength after the user types over a passphrase | (a) as the reference: the word formula stays; (b) once the user edits the output, show FEA-05's estimate of the text, as on the password tab | (b): the formula describes generated phrases only |

## Security notes

- SG-01, AT-B04: every word pick and the mixed position use `app-crypto::random` `below(n)`, without bias (FEA-02.6). Never a seeded or time-based generator.
- SG-03: the built-in list has 7,776 words (12.925 bits per word); 7 words give 90.47 bits. The reference's list has 7,772.
- The entropy number must reflect the list really in use: N counts unique entries after FEA-03.10 and D-03-2, never 7,776 for a user list. A list with duplicates or few words must not show a higher number than it delivers; the small-list warning (FEA-03.12) tells the user.
- A user word list is untrusted input (another app with the user's rights can replace a file in the folder): bounded reading, no crash, no hang (D-03-3; AT-A10 style fuzzing). A replaced list shows its real size in the entropy number and the warning.
- "Signed" lists are not verified (FEA-03.9); the signature gives no protection. App must not present it as checked.
- The passphrase is a secret (FEA-03.17): AT-C02, AT-C06, AT-D01 to AT-D03 apply as in FEA-02.

## Test cases

List A is a demo file of 6 lines, in this order: `alpha`, `bravo`, `charlie`, `delta`, `echo`, `foxtrot`. "Scripted source" and α = 10^-6 as in FEA-02.

| Case | Given | When | Then |
|---|---|---|---|
| FEA-03.1 facts | the built-in list | load | 7,776 entries; first `abacus`, last `zoom`; the 4 hyphenated words present; every other entry only a to z; length counts as in the table; SHA-256 of the entries joined with LF plus a final LF = `6d557f06…3bc522` (full value in the table) |
| FEA-03.1 attribution | App built (App.app and `app`) | read `Credits.rtf` (the About window's text, offscreen, AGENTS.md rule 10), run `app --license`, read `THIRD-PARTY-NOTICES.md` in App.app/Contents/Resources | each holds `app_core::generator::wordlist::ATTRIBUTION` word for word (CC BY 4.0, unmodified); the first two by test `e14_2_the_license_and_word_list_notices_are_shown` |
| FEA-03.2 display | built-in list, 6 words | open the passphrase tab | 77.55 bits, Good (the reference shows 77.54) |
| FEA-03.3 defaults | fresh settings | open the passphrase tab | 7 lower-case words from the built-in list, one space between; 90.47 bits, Good |
| FEA-03.3 command line errors | `app diceware -W 0`; `-W abc`; `-W -1` | run each | one error line, status 1 |
| FEA-03.3 command line large | `app diceware -W 1000` | run | 1,000 words |
| FEA-03.4 separator | list A, 4 words, separator `-` | generate | exactly 3 `-`, none at the start or end |
| FEA-03.4 empty separator | list A, 3 words, separator empty, case lower, scripted [0, 1, 1] | generate | `alphabravobravo` |
| FEA-03.4 long separator | list A, 2 words, separator ` + `, scripted [2, 3] | generate | `charlie + delta` |
| FEA-03.5 title | list A, 3 words, separator `-`, case title, scripted [5, 0, 5] | generate | `Foxtrot-Alpha-Foxtrot`; bounds [6, 6, 6] |
| FEA-03.5 mixed | list A, 3 words, separator `-`, case mixed, scripted [1, 2, 3, 4] | generate | `charlie-DELTA-echo`; bounds [3, 6, 6, 6] |
| FEA-03.5 upper | list A, 2 words, case upper, scripted [0, 1] | generate | `ALPHA BRAVO` |
| FEA-03.5 full mapping | list with lines `ßig`, `zeta`; case upper; scripted [0] | generate 1 word | `SSIG` |
| FEA-03.5 title rest | list with the one line `aPPle`; case title | generate 1 word | App `Apple` (D-03-2); reference `APPle` |
| FEA-03.6 uniform (statistical) | list A, 1 word | 600,000 passphrases | chi-square over the 6 words below 35.89 (5 degrees of freedom) |
| FEA-03.6 repeats (statistical) | built-in list, 7 words | 100,000 passphrases | passphrases with a repeated word: 270 ± 80 (probability 0.002698) |
| FEA-03.6 mixed position (statistical) | list A, 4 words, case mixed | 400,000 passphrases | each has exactly one all-upper word; that word at each position 100,000 ± 1,340 times |
| FEA-03.7 formula | list A, 3 words | generate | 7.75 bits, Poor |
| FEA-03.7 bands | built-in list; 3, 5, 7, 8 words | generate each | 38.77 Poor; 64.62 Weak; 90.47 Good; 103.40 Excellent |
| FEA-03.7 not adjusted | built-in list, 7 words, case mixed, separator `#` | generate | 90.47 bits |
| FEA-03.7 empty | empty list | open the tab | 0.00 bits |
| FEA-03.8 parse | file lines: `11111` tab `alpha`; `11112 bravo`; `1-1-1-2-1   charlie`; `  delta  `; empty line; `echo echo`; `Alpha`; `alpha` | load, 1 word, case lower | App: 5 entries `alpha bravo charlie delta`, `echo echo`; 2.32 bits. Reference: 6 entries (`Alpha` separate), 2.58 bits, and `alpha` picked about 2 times in 6 (observed 25 of 60) |
| FEA-03.8 non-dice lines | lines `11111 two words`, `2nd`, `11111`, `123 456` | load | entries `11111 two words`, `2nd`, `11111`, `456` |
| FEA-03.8 white space | lines `alpha`; U+2003 `bravo` U+00A0; tab `charlie` tab | load | entries `alpha`, `bravo`, `charlie` |
| FEA-03.8 byte order marks | UTF-8 BOM + `alpha` LF `bravo` LF; the same text as UTF-16 big-endian with BOM | load each | entries `alpha`, `bravo` both times |
| FEA-03.8 order | list A | scripted [3], 1 word | `delta` (file order kept) |
| FEA-03.9 signed | lines: `-----BEGIN PGP SIGNED MESSAGE-----`, `Hash: SHA256`, empty, `11111 one`, `- two`, `- -three`, `four`, `-----BEGIN PGP SIGNATURE-----`, `sigword` | load | entries `one`, `two`, `-three`, `four` (observed in the reference); `Hash: SHA256` and `sigword` absent |
| FEA-03.9 unsigned dash | lines `- two`, `alpha` (no signed header) | load | entries `- two`, `alpha` |
| FEA-03.10 unique | lines `Apple`, `apple`, `APPLE`, `pear` | load | App: 2 entries; 1 word shows 1.00 bit. Reference: 4 entries, 2.00 bits |
| FEA-03.11 bad UTF-8 | bytes `caf` E9 LF `bravo` LF | add the file | App refuses it with `MSG-PP-LIST-NOT-UTF8`, nothing copied (D-03-3). Reference: entries `caf` + U+FFFD and `bravo` |
| FEA-03.11 lone CR | bytes `alpha` CR `bravo` CR `charlie` CR | load | App: 3 entries. Reference: 1 entry `alphabravocharlie` |
| FEA-03.11 too big | a 5 MiB file; a file with one 300-character line | add each | refused with `MSG-PP-LIST-TOO-BIG` |
| FEA-03.12 threshold | files of 1,295 and 1,296 lines `w1` to `w1295` / `w1296` | load each, generate | warning for 1,295 only; both generate 7 words |
| FEA-03.12 command line | `app diceware -w` the 1,295-line file | run | warning on standard error, 7 words on standard output, status 0 |
| FEA-03.13 missing file | `app diceware -w /tmp/spec-demo/none.txt` | run | App: error line, status 1 (D-03-4). Reference: empty line, two warnings, status 0 |
| FEA-03.13 screen | user list selected, then its file emptied outside App | reopen the generator | `MSG-PP-LIST-EMPTY`, output empty, Copy and Apply disabled |
| FEA-03.14 add | demo file `demo-words.txt`, 1,300 lines | Add | copied to `~/Library/Application Support/App/wordlists/demo-words.txt`, selected, no warning; built-in list still first in the picker |
| FEA-03.14 overwrite | `demo-words.txt` already added | Add another file named `demo-words.txt`, choose Cancel | old file unchanged; Overwrite instead replaces it |
| FEA-03.14 remove | built-in selected | look at Remove | disabled |
| FEA-03.14 remove user list | `demo-words.txt` selected | Remove, confirm | file deleted; built-in list selected |
| FEA-03.14 saved list gone | saved selection is `demo-words.txt`; file deleted outside App | open the generator | built-in list selected |
| FEA-03.15 restore tab | passphrase tab, 9 words, Apply from a popup | open the toolbar generator | passphrase tab, 9 words |
| FEA-03.16 command line default | `app diceware` | run 100 times | each line 7 lower-case built-in words with single spaces |
| FEA-03.16 command line list | `app diceware -w` list A `-W 1` | run 60 times | each line one of the 6 words |
| FEA-03.17 secret | debug build | generate a passphrase, close, dump memory | the passphrase is not found (AT-C02) |
| D-03-5 limits | core | 1,001 words; separator of 65 characters | refused with `MSG-PP-COUNT`; separator refused |
| D-03-7 edit | passphrase tab | type `demo` over the output | strength line shows FEA-05's estimate of `demo`, not the word formula |
| FEA-03 AT-B04 | source tree | search for random sources outside `app-crypto` | the passphrase code calls only `app-crypto::random` |

## How this was learned

- Read the reference's passphrase generator core: defaults, word count floor, case conversion, the pick loop and the mixed-case position, the entropy formula, the minimum list size, and the word list reader (line trimming, dice-code stripping, signed-list handling, uniqueness).
- Read the generator screen and its layout file: word count slider and field ranges, separator field, case choices, the word list picker with add and remove, its confirm and error messages, the small-list warning, and the strength line on this tab.
- Read the settings defaults table, the resource paths for built-in and user word lists, the command line passphrase command, the reference unit tests (word case, duplicate entries) and the screen test that expects 77.54 bits for 6 words.
- Read the shipped word list, its history of four changes (2017 copy, 2021, 2022, 2025), the copyright file, the command line help and the user guide page. Counted words, lengths and hyphenated words, and hashed the first, unmodified 2017 copy.
- Compared the installed version 2.7.11 with the source: same reader and generator; its app bundle ships the same 7,772-word file (same SHA-256).
- Ran the installed command line tool in `/tmp/spec-fea02-fea03` on demo lists: dice-code lines, a duplicate differing only in case, an entry with a space, a signed list, a missing file, lists of 1,295 and 1,296 words, CR-only, CRLF, UTF-8 and UTF-16 byte order marks, Latin-1 bytes, Unicode white space, and word count errors.
- Computed entropies, the repeat probability and statistical bars with python3.
- 2026-10-31 (E14-S2): the License and Attribution rows were read from App's own files (`generator/wordlist.rs` `ATTRIBUTION`, scripts/make-sbom.sh, crates/app-cli/tests/license.rs) and security/parity/E14-S2-license.md. The reference was not opened for them.
