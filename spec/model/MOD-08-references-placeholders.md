# MOD-08 References and placeholders

Status: reviewed; MOD-08.32 written and reviewed 2026-10-31 (LD-279 (2), LD-281 (6)); LD-284 written and reviewed
Epics: E4-S6; E11-S3 (MOD-08.32, the scope sentence of MOD-08.27)
Parity rows: SD-08, SC-04, SG-04, SI-06, SI-09, SI-10, SR-07, SR-10, SR-11

## What it does

A text value in an entry can hold placeholders: words in braces, such as `{USERNAME}`, that Larsal replaces with live values when it uses the text. A field reference is a placeholder that fetches a field of another entry, such as `{REF:P@I:<id>}`. Resolution never changes the stored value. Only the copy, the screen, the browser fill, Auto-Type and the command line see the result.

This card owns:
- how placeholders are found in a text, escaped, classified and resolved,
- every placeholder the reference knows, with its exact result,
- the field reference syntax, the entry search behind it, and the case rules,
- the depth limit, what happens with loops, and the extra bounds Larsal adds,
- where the reference resolves and where it does not,
- what happens to references when their target entry is deleted for good,
- the "contains a placeholder" test used by the browser bridge,
- opening an entry's URL: command URLs, vault links and other URLs (MOD-08.31),
- the search scope of a reference in an entry inside a share group (MOD-08.32).

Auto-Type key names and Auto-Type-only commands (`{ENTER}`, `{TAB}`, `{DELAY n}`, `{PICKCHARS}`, `{CLEARFIELD}`, `{MODE=...}`, and others) belong to INT-05. MOD-10 creates references when it clones. Standard field names (`Title`, `UserName`, `Password`, `URL`, `Notes`) are FMT-11.16 facts. Entry ids are 16 bytes (FMT-12); "hex id" below means those 16 bytes as 32 hex digits, in stored byte order, without dashes.

## Inputs and outputs

In: a text, the entry it belongs to (its context), the vault that entry lives in, the clock and the time zone, the vault file path.
Out: the resolved text. Resolution never fails. Anything it cannot resolve stays as written, or becomes empty where a rule says so.

Limits: depth budget 10 (MOD-08.18). Larsal adds a work bound of 10,000 span steps and 1,048,576 characters of output per top-level call (MOD-08.20, lead decision D-08-3).

## Rules

### Finding placeholders

MOD-08.1 **Spans.** The resolver scans the text from left to right for spans. A span is a `{`, then one or more items, then the matching `}`. An item is one character that is not a brace, or a nested span. A nested span must itself be a valid span (not empty, balanced). When no valid span starts at a `{`, that `{` is plain text and the scan moves on by one character. Spans do not overlap. The text between spans is copied unchanged. So `{}` is never a span, and `{TITLE` and `TITLE}` stay literal. In `{a{b}` the span is `{b}`. `{{}}` holds no span.

MOD-08.2 **Escape.** When the whole text being resolved starts with `\{` and ends with `\}`, the result is that text with the leading `\{` turned into `{` and the trailing `\}` turned into `}`. Nothing inside is resolved. This applies to every text the resolver handles, including a field value reached through another placeholder. A `\{` anywhere else gets no special meaning: `a\{TITLE\}b` stays `a\{TITLE\}b`, backslashes included.

MOD-08.3 **Classification.** Each span is classified by the first test that matches:

| Order | Test on the span text | Kind |
|---|---|---|
| 1 | starts with `{S:` (exact case) | custom field (MOD-08.7) |
| 2 | starts with `{REF:` (exact case) | reference (MOD-08.13) |
| 3 | starts with `{T-CONV:` (any case) | conversion (MOD-08.21) |
| 4 | starts with `{T-REPLACE-RX:` (any case) | regex replace (MOD-08.22) |
| 5 | the whole span, upper-cased, is in the table of MOD-08.4 | that placeholder |
| 6 | anything else | unknown (MOD-08.5) |

So `{title}`, `{Title}` and `{TITLE}` are the same, while `{s:Name}` and `{ref:...}` are unknown and stay literal.

MOD-08.4 **Fixed placeholders.** Any case.

| Placeholder | Result | Resolved again |
|---|---|---|
| `{TITLE}` `{USERNAME}` `{PASSWORD}` `{NOTES}` `{URL}` | the entry's raw standard field | yes (MOD-08.6) |
| `{UUID}` | the entry's hex id, lowercase | no |
| `{TOTP}` | the entry's current one-time code (FEA-04) | no (MOD-08.12) |
| `{TIMEOTP}` | same as `{TOTP}` (source only; the installed version leaves it literal) | no |
| `{URL:RMVSCM}` `{URL:WITHOUTSCHEME}` `{URL:SCM}` `{URL:SCHEME}` `{URL:HOST}` `{URL:PORT}` `{URL:PATH}` `{URL:QUERY}` `{URL:FRAGMENT}` `{URL:USERINFO}` `{URL:USERNAME}` `{URL:PASSWORD}` | a part of the entry's URL (MOD-08.9) | no |
| `{DT_SIMPLE}` `{DT_YEAR}` `{DT_MONTH}` `{DT_DAY}` `{DT_HOUR}` `{DT_MINUTE}` `{DT_SECOND}` and the same seven with `DT_UTC_` | date and time (MOD-08.10) | yes |
| `{DB_DIR}` | the vault file's folder (MOD-08.11) | no |

MOD-08.5 **Unknown spans.** The result is `{`, then the inner text (the span minus its outer braces) resolved, then `}`. So `{FOO}` stays `{FOO}`, `{ {TITLE} }` gives `{ Probe }` and `{{TITLE}}` gives `{Probe}`. The source branch differs: it looks inside the braces for a known placeholder and resolves `{{TITLE}}` to `Probe`, with side effects (see D-08-1). Larsal follows the installed version (lead decision D-08-1).

### Entry values

MOD-08.6 **Standard fields.** `{TITLE}`, `{USERNAME}`, `{PASSWORD}`, `{NOTES}` and `{URL}` take the entry's raw value and resolve it again, in the same entry. That is how chains work: a title `{USERNAME}` whose username is `{S:Login}` gives the value of `Login`.

MOD-08.7 **Custom fields: `{S:name}`.** The name is everything between `{S:` and the final `}`. It must equal a field name exactly, case included. Standard fields count too: `{S:UserName}` gives the username, `{S:username}` gives nothing. A missing name gives the empty string. A found value is resolved again in the same entry.

MOD-08.8 **`{UUID}`.** The 32 lowercase hex digits of the entry's id, for example `0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f`.

MOD-08.9 **URL parts.** The entry's `URL` field is resolved first. If the result is empty, every URL part is empty, `{URL:PORT}` included. Otherwise it is parsed tolerantly. Observed values (reference command line tool, `show`):

| URL (after resolving) | SCM | HOST | PORT | PATH | QUERY | FRAGMENT | USERINFO | USERNAME | PASSWORD | RMVSCM |
|---|---|---|---|---|---|---|---|---|---|---|
| `https://u:pw@example.com:8443/p/a.php?q=1&r=2#frag` | https | example.com | 8443 | /p/a.php | q=1&r=2 | frag | u:pw | u | pw | `//u:pw@example.com:8443/p/a.php?q=1&r=2#frag` |
| `https://Example.COM/A%20B/c?x=%41&y=1#F%20g` | https | example.com | -1 | /A B/c | x=A&y=1 | F g | | | | `//example.com/A B/c?x=A&y=1#F g` |
| `https://example.com` | https | example.com | -1 | | | | | | | `//example.com` |
| `http://example.com:80/` | http | example.com | 80 | / | | | | | | `//example.com:80/` |
| `example.com` | | | -1 | example.com | | | | | | `example.com` |
| `https://[::1]:8080/x` | https | ::1 | 8080 | /x | | | | | | `//[::1]:8080/x` |
| `https://bücher.example/` | https | xn--bcher-kva.example | -1 | / | | | | | | `//xn--bcher-kva.example/` |
| `ftp://user@host.example:21/file.txt` | ftp | host.example | 21 | /file.txt | | | user | user | | `//user@host.example:21/file.txt` |
| `https://user%40mail:p%3Ass@host.example/` | https | host.example | -1 | / | | | user@mail:p%3Ass | user@mail | p:ss | `//user%40mail:p%3Ass@host.example/` |
| `https://example.com:/x` | https | example.com | -1 | /x | | | | | | `//example.com/x` |
| `mailto:a@b.example` | mailto | | -1 | a@b.example | | | | | | `a@b.example` |
| `HTTPS://EXAMPLE.COM/Path` | https | example.com | -1 | /Path | | | | | | `//example.com/Path` |
| `https://exa mple.com/a b` (invalid host) | https | | -1 | /a b | | | | | | (empty) |
| `cmd://open -a Safari https://x.example` | cmd | | -1 | //x.example | | | | | | (empty) |

The patterns: scheme and host are lower-cased, and IPv6 hosts are given without brackets. Host form for non-ASCII names, observed in the reference: a host whose top-level domain is on its URL library's allow list is given in Unicode, the others in ASCII (punycode). Observed Unicode: `.com`, `.org`, `.net`, `.de`, so `https://bücher.com/` gives `bücher.com`, and RMVSCM keeps the Unicode host; even the input `https://xn--bcher-kva.de/` gives `bücher.de`. Observed punycode: `.fr` and `.example`. Larsal always gives the ASCII (punycode) form, in HOST and in RMVSCM, whatever the input form (lead decision LD-58, D-08-11 (b)). So `https://bücher.com/` gives `xn--bcher-kva.com` in Larsal. Path, query, fragment, username and password are percent-decoded. User info keeps `%3A`, because a colon is its delimiter. Text with no scheme is all path. A port that is absent or empty gives `-1` (lead decision D-08-6). An invalid URL gives an empty RMVSCM and empty parts wherever no part could be parsed.

MOD-08.10 **Date and time.** The values come from the clock when the placeholder is resolved. `DT_` uses the Mac's local time zone and `DT_UTC_` uses UTC. Formats: SIMPLE = `yyyyMMddHHmmss` (14 digits), YEAR = 4 digits, MONTH, DAY, HOUR (00 to 23), MINUTE and SECOND = 2 digits each, zero-padded. Each placeholder reads the clock on its own. Example, observed at 2026-10-24T22:46:28Z on a Mac at UTC+2: `{DT_SIMPLE}` = `20261025004628`, `{DT_UTC_SIMPLE}` = `20261024224628`.

MOD-08.11 **`{DB_DIR}`.** The absolute path of the folder that holds the vault file, with no trailing slash. The reference command line tool showed `/private/tmp/spec-mod08-10` for a vault opened as `/tmp/spec-mod08-10/m08.larsalvault`: the path with links resolved. For a vault that was never saved, Larsal gives the empty string (lead decision D-08-8).

MOD-08.12 **`{TOTP}` and `{TIMEOTP}`.** The code for the current time, as FEA-04 computes it. An entry with no one-time password gives the empty string. For invalid settings the reference inserts a short error text that names the problem (for example, an invalid key). Larsal gives the empty string (lead decision D-08-7). Auto-Type computes the code for the moment of typing (INT-05). `{TIMEOTP}` exists in the source only; the installed version leaves it literal.

### Field references

MOD-08.13 **Syntax.** `{REF:` W `@` S `:` text `}`.
- W, the wanted field, is one of `T U P A N I`. S, the field searched, is one of `T U P A N I O`. Both codes are case-insensitive. The `REF:` itself must be upper case (MOD-08.3).
- The text is one or more items, each either one character that is not a brace, or a `{...}` group with no `}` inside. So `{REF:T@I:{UUID}}` is valid.

| Code | As W (field returned) | As S (field searched) |
|---|---|---|
| T | Title | Title |
| U | UserName | UserName |
| P | Password | Password |
| A | URL | URL |
| N | Notes | Notes |
| I | the hex id, lowercase | the id |
| O | (not allowed) | any field, standard or custom |

A `{REF:` span that does not fit this syntax stays exactly as written. Examples: wanted code `X` or `O`, empty text, or the lowercase `{ref:`. Larsal reads the syntax from the start of the span. The reference searches for the pattern anywhere in the span (lead decision D-08-1).

MOD-08.14 **Search text is resolved first.** Before the search runs, the text is resolved as a placeholder in the referring entry. So `{REF:T@I:{UUID}}` points at the entry itself, and `{REF:T@I:{S:Target}}` uses the id stored in the field `Target`.

MOD-08.15 **Which entry is found.** The search visits groups in pre-order from the root: first a group's own entries in stored order, then each child group in stored order, recursively. It covers the recycle bin and its contents, and the referring entry itself. It never covers history items. The first entry that matches wins. When the referring entry is at or below a share group, the search covers only what that share sends, in the same order (MOD-08.32).
- T, U, P, A, N: the raw field value (not resolved) must equal the text exactly, case-sensitively. Leading and trailing spaces count.
- O: the raw value of any one of the entry's fields, standard or custom, must equal the text exactly.
- I: every character of the text that is not a hex digit is dropped (dashes, spaces, braces). What is left must decode to exactly 16 bytes equal to the entry's id. Hex digits are case-insensitive. `0A0A` (2 bytes) matches nothing. Digits pair up from the right. With an odd count, the leftmost digit alone makes the first byte. So 31 digits also make 16 bytes: `a` followed by `0a` 15 times finds the entry whose id is `0a` 16 times (observed). 33 digits make 17 bytes and match nothing.

MOD-08.16 **Result.** The found entry's raw value of the wanted field (for I, its lowercase hex id) is resolved again in the context of the found entry, not the referring one. A search with no match gives the empty string. A reference inside a text whose entry is not in a vault stays as written.

MOD-08.17 **Standard fields only.** No wanted code returns a custom field. To reach one, the target entry holds `{S:name}` in one of its standard fields, and the reference asks for that field.

### Depth, loops and bounds

MOD-08.18 **Depth budget.** Resolution uses three kinds of step. A string step resolves every span in a text. A span step resolves one span. A reference step resolves one reference. Every step first takes 1 from the budget it was given. If the result is below 0, the step returns its input text unchanged and logs a warning that names the entry id but no value.
- A top-level call is a string step with budget 10.
- A string step gives its reduced budget to each span step it runs.
- A span step gives its reduced budget to every string step it starts: for a field value, a custom field value, the inner text of an unknown span, the URL before parsing, the date text, or the output of a conversion or a regex replace.
- A reference span step hands its budget plus 1 to the reference step, so the span step itself costs nothing. The reference step resolves the found value with a string step at its own reduced budget.
- A span step can be given a whole text instead of one span (the search text of a reference, MOD-08.19). When the text does not start with `{` and end with `}`, the span step runs a string step on it at its reduced budget. When it does, the whole text is classified as one span by MOD-08.3, even when it holds several spans. So the search text `{S:A}{S:B}` asks for a custom field named `A}{S:B` and finds nothing, while `Al{S:B}` resolves fully (observed).

Results this gives, observed in the installed version (the `{TITLE}` row and the brace rows with the title `Probe` were computed with the same steps; the brace rows were observed with another title):

| Case | Result |
|---|---|
| Password `{PASSWORD}`, resolve `{PASSWORD}` | `{PASSWORD}` |
| Title `{TITLE}` | `{TITLE}` |
| Title `{USERNAME}!`, username `{TITLE}?`, resolve the title | `{TITLE}?!?!?!` |
| Two entries whose titles reference each other: B = `{REF:T@I:<C>}`, C = `{REF:T@I:<B>}`; resolve B's title | `{REF:T@I:<B>}` (B's id in lowercase hex) |
| Custom `Loop1` = `{S:Loop2}`, `Loop2` = `{S:Loop1}`; resolve `{S:Loop1}` | `{S:Loop2}` |
| `{{{{{TITLE}}}}}` (5 levels) | `{{{{Probe}}}}` |
| `{{{{{{TITLE}}}}}}` (6 levels) | unchanged |

MOD-08.19 **Fresh budgets: a crash in the reference.** The reference resolves three things with a brand-new budget of 10 instead of the current one: the search text of a reference, the three parts of a regex replace, and the text part of a conversion. A loop that passes through one of them never ends, and the process crashes. Observed with the command line tool, exit by SIGSEGV, for a username `{T-CONV:/{USERNAME}/upper/}`, a username `{T-REPLACE-RX:/{USERNAME}/a/b/}` and a title `{REF:T@T:{TITLE}}`. Larsal gives these parts the current reduced budget, never a fresh one (lead decision D-08-2). The reference step resolves its search text with a span step at the reference step's reduced budget. A conversion or regex span step resolves its parts with string steps at the span step's reduced budget. Every loop then ends like the loops of MOD-08.18. Larsal gives a username `{T-CONV:/{USERNAME}/upper/}` the result `{USERNAME}`, a username `{T-REPLACE-RX:/{USERNAME}/a/b/}` the result `{USERNAME}`, and a title `{REF:T@T:{TITLE}}` the empty string. For values that do not loop, the results are the same as the reference's, unless a chain is deeper than the budget.

MOD-08.20 **Work bound (Larsal only).** The depth budget alone allows exponential growth. A field holding `{USERNAME}` 16 times, inside an entry whose username is that same field, made the reference write 167,772,161 bytes in 2.4 s. At 32 copies it would need gigabytes. Larsal counts span steps and output characters for each top-level call. Above 10,000 span steps or 1,048,576 characters, Larsal stops and returns the raw input unchanged, and logs a warning with no values (lead decision D-08-3). Normal values never come near this: the 4-copy case needs 1,364 span steps and 40,960 characters, and Larsal resolves it exactly like the reference. Third bound (LD-111): at most 16,777,216 characters of total work per call (copies made by conversions included); past it, the raw input comes back.

### Conversions and regex replace

MOD-08.21 **`{T-CONV:<sep><text><sep><type><sep>...}`.** The body is the span after `{T-CONV:`, including the final `}`. The separator is the body's first character, and it may be any character. The body is split on the separator, and empty parts are kept. Fewer than 4 parts, or a line feed anywhere in the span, makes the result empty. Part 2 is the text, which is resolved first. Part 3, lower-cased, is the type. Anything after part 3 is ignored. Types, tested in this order:

| Type | Result |
|---|---|
| `base64` | Base64 of the text's UTF-8 bytes, standard alphabet, with `=` padding (`abc` → `YWJj`, `ä` → `w6Q=`) |
| `hex` | lowercase hex of the UTF-8 bytes (`abc` → `616263`, `ä` → `c3a4`) |
| `uri` | percent-encoding of the UTF-8 bytes, every byte except `A-Z a-z 0-9 - . _ ~`, uppercase hex digits (`a b&c` → `a%20b%26c`, `äö €` → `%C3%A4%C3%B6%20%E2%82%AC`) |
| `uri-dec` | percent-decoding, then UTF-8 decoding with U+FFFD for bad bytes. `+` stays `+`. A `%` with fewer than 2 characters after it stays literal (`%41%2` → `A%2`). For `%` followed by 2 characters that are not hex, see D-08-10. |
| starts with `u` | full Unicode upper case (`straße` → `STRASSE`). So `upper`, `u` and `uri-x` all upper-case. |
| starts with `l` | full Unicode lower case (`İ` → `i̇`) |
| anything else | empty |

The conversion's result is resolved again (budget per MOD-08.18).

MOD-08.22 **`{T-REPLACE-RX:<sep><text><sep><pattern><sep><replacement><sep>...}`.** The body is split as in MOD-08.21, but 5 parts are needed. Text and replacement are each resolved first; the pattern is used as written, never resolved (LD-114). Bounds (LD-113): a pattern of at most 1,024 characters and a compiled size of at most 256 KiB, else invalid; a text of at most 65,536 characters, else the raw text comes back. Every non-overlapping match of the pattern in the text is replaced, from left to right. Empty matches count: text `abc` with an empty pattern and replacement `x` gives `xaxbxcx`. The reference's pattern dialect is Perl-compatible: lookahead, lookbehind, inline flags such as `(?i)`, and lazy quantifiers. Larsal (LD-110) uses a linear-time engine: inline flags and lazy quantifiers work; lookahead, lookbehind, backreferences and Unicode category or script classes such as `\p{L}` make the pattern invalid (empty result; LD-123). `\d` and `\w` match ASCII only. In the replacement, `$n` and `\n` (n a number) insert capture group n. Two digits are read when that group exists, otherwise one digit, so `$10` with one group gives group 1 followed by `0`. A group that does not exist is written as a backslash and its digits (`$2` with one group gives `\2`; `$0` gives `\0`). An invalid pattern makes the result empty. The result is resolved again. Larsal's regex engine and its step limit: lead decision D-08-9.

### Display

MOD-08.23 **Password mask for display.** Before the URL is resolved for display, the reference turns every `{PASSWORD}` (any case) in the raw URL into `******`. Display here means the list's URL column, the URL text in the preview, and the confirm prompt for a command URL. The link the user clicks uses the unmasked resolution. No other path to the password is masked: `{S:...}`, `{REF:P@...}` and a conversion of `{PASSWORD}` all show in clear. Larsal masks every value that comes from a protected field when it resolves for display (lead decision D-08-4). The masked form is used only in these three places. Search, copy, fill, Auto-Type and every other place in MOD-08.25 use the unmasked resolution. The reference's list column resolves the already resolved display text once more; only a URL in the escape form (MOD-08.2) shows a difference there. Larsal resolves once.

MOD-08.24 **Reference marker.** A standard field "holds a reference" when the reference pattern of MOD-08.13 appears anywhere in its raw value. For this test any case of `ref:` counts. In the entry list, each column whose field holds a reference shows a short marker meaning "reference" before the resolved value. An entry with any standard field holding a reference is drawn in a dimmer text colour, moved toward the background (lighter on a light background, darker on a dark one). This replaces the entry's own text colour. The Notes column shows the raw first line of the notes and still gets the marker.

### Where resolution happens

MOD-08.25 **Places.** "Yes" means the text is fully resolved in the entry's context before use.

| Place | Resolved | Notes and owner |
|---|---|---|
| Copy title, username, password, URL, notes, a custom field | yes | APP-03 clipboard rules |
| Copy password and one-time code | yes | the resolved password followed by the current code |
| Double-click copy of username, password or URL in the list | yes | APP-01 setting |
| List columns Title, UserName, Password, URL; sort keys of UserName and Password | yes | URL masked (MOD-08.23); Notes column raw |
| Preview pane: title, username, password, notes, URL, custom fields | yes | protected custom fields stay hidden until shown (SC-04) |
| Open URL and the command-URL confirm | yes | confirm text masked (MOD-08.23); the open action: MOD-08.31 |
| Editor: password strength meter, URL validity colour | yes | the edit fields themselves show raw values |
| Health Check strength | yes | FEA-05. Reuse detection, breach check (FEA-06) and statistics (FEA-07) use raw passwords. |
| Website icon download | yes | MOD-06 |
| Auto-open entries: URL (the vault path, often built with `{DB_DIR}`), UserName (the key file path), Password | yes | SR-10; the auto-open owner card (APP-06) |
| Browser bridge: login, password, title, group name, id, extra string fields, entry list | yes | INT-01. Main URL for matching: resolved only when it holds a reference. Additional URLs: always resolved (INT-03). |
| Auto-Type sequences, window titles, title and URL matching | yes | INT-05 |
| Search on title, username, password, URL | yes | FEA-01; other fields raw |
| Delete prompts that name an entry | yes | title only |
| Command line `show` | yes | INT-10; protected fields print as hidden unless asked for; without `-s`, parts that resolve from a protected value are masked and print as `(hidden)` (D-08-4, LD-172) |
| Command line `clip`, `ls`, `search` output | no | raw |
| Exports, merge | no | FEA-09, MOD-11 |
| Shared-group export | no | every field keeps its text as written, so no value from outside the share enters a container (INT-08.13, LD-279 (1)); the reference replaces a reference whose target lies outside the shared group by its resolved value |

MOD-08.26 **One resolution form.** The reference has a second, "single" entry point. It is used for search, Auto-Type title and URL matching, delete prompts, Auto-Type list copies and `{PICKCHARS}`. In the installed version it fails on a value that begins with `{` and ends with `}` but holds several spans: the title `{USERNAME} and {NOTES}` is not resolved for search (observed: `search title:zed` found nothing; the source fixes this). Larsal uses the full resolution of this card everywhere. The one exception is the search text of a reference, which Larsal resolves as one span, as the reference does (MOD-08.18, MOD-08.19).

### References and deletion

MOD-08.27 **Permanent delete of a referenced entry.** This applies only to deleting selected entries for good, not to moving into the recycle bin. Emptying the recycle bin and deleting a group for good run no check, so references to the entries they remove dangle (MOD-04.6). Before entry X is deleted for good, the reference finds every entry in the vault, the recycle bin included (history items excluded, entries deleted in the same action excluded) whose standard field both holds a reference (MOD-08.24) and contains X's hex id anywhere, in any case. References that find X by title or another search field are not found. Larsal also leaves out every referencing entry whose search scope (MOD-08.32) does not hold X, such as an entry inside a share group that refers to X outside it: that entry is not counted and not overwritten, because its reference already finds nothing, and Overwrite would only copy X's value into the share, which the next export sends to every member (decided: spec/decisions.md LD-284 (2), F-142). Its field keeps its raw text. The reference has no such scope and counts every entry found. If any are left after leaving out the entries deleted in the same action and the entries whose scope does not hold X, the user gets a prompt (message `MSG-08-1`: the entry's resolved title and the number of referencing entries) with three choices. When every referencing entry is in the same delete or has a scope that does not hold X, Larsal asks nothing and deletes X (lead decision LD-59, LD-284 (2)). The reference leaves the entries of the same delete out only after it has decided to ask, so it then asks with a count of 0. The choices:

| Choice | Effect |
|---|---|
| Overwrite (default) | In every such field, the whole field is replaced by X's raw value of the same field name, then X is deleted. The referencing entries get no history item, but their modification and access times move to now (MOD-03). |
| Skip | X is not deleted. The rest of the selection goes on. |
| Delete | X is deleted, and the references stay. They now resolve to empty. |

The overwrite copies the same field name, not the wanted field. A Notes field holding `{REF:P@I:<X>}` receives X's notes, not X's password. A reference to an entry in the recycle bin keeps working.

MOD-08.28 **Browser save guard.** In the source (not the installed version), the browser bridge refuses to create or update an entry when the login or password it received "contains a placeholder". The reply carries the bridge error code 34 (INT-01). The source counts as a placeholder: any span, with a trailing `\}` read as `}`, that is a known placeholder at any brace depth up to 10 (custom field, reference, conversion, regex, or the table of MOD-08.4), or that contains the reference pattern anywhere. Unknown words such as `{abc}` are allowed. Larsal's test (lead decision D-08-5): resolve the value in a blank entry of the target vault. If the result differs from the value, or the reference pattern appears in it, the value is refused.

### Context

MOD-08.29 **Context needed.** Resolution always runs for one entry. Entry fields come from that entry. References need the entry to be in a vault. `{DB_DIR}` needs the vault's file path. A reference resolves in the found entry's context (MOD-08.16). A history item is not in a vault for this rule (the reference gives it no group), so when Larsal resolves one of its fields (the history view), references stay as written. Outside a vault, `{DB_DIR}` gives the empty string, as for an unsaved vault (D-08-8). The reference would read a missing vault there.

MOD-08.30 **Reference format Larsal writes.** When Larsal builds a reference (MOD-10), it writes `{REF:` code `@I:` 32 uppercase hex digits `}`, with code U for the username and P for the password, as the reference does.

### Opening an entry URL

MOD-08.31 **Opening an entry URL.** The user opens an entry's URL with the open-URL action, a click on the URL in the preview, or a double-click on the URL cell (APP-01.22). The `URL` field is resolved in full (MOD-08.25). The kind is chosen from the resolved text, by how it starts (exact case): (Decided: spec/decisions.md LD-59, LD-70, LD-71.)

- **Command URL** (starts with `cmd://`). The command is the resolved text after `cmd://`.
  - The reference runs the command without a question when the entry's field `_EXEC_CMD` holds exactly `1`. Larsal never trusts that field, because anyone who can change the vault (a sync, a shared group, an import) can set it: Larsal asks every time unless the user ticked "Remember my choice" with Yes on this Mac for this vault, entry id and exact command text (decided: spec/decisions.md LD-70). `_EXEC_CMD` is read and written unchanged as a normal field (FMT-14.22). `cmd://` with nothing after it asks nothing and runs nothing.
  - The question (`MSG-08-2`: "Run this command?" with the command below it; buttons Yes and No, default No; LD-232 (6)) shows the URL resolved for display (MOD-08.23), without `cmd://`, as plain text. When longer than 400 characters it shows the first 400 followed by ` […]`. The reference masks only a literal `{PASSWORD}` there; Larsal masks every protected value (D-08-4), and a protected URL field shows as `******` whole (LD-232 (2)).
  - The question has a "Remember my choice" box. The reference then stores `_EXEC_CMD` = `1` for Yes and `0` for No in the entry. Larsal stores a ticked Yes only in its own settings on this Mac (S-STATE list in APP-01), keyed by the vault file, the entry id and a SHA-256 of the command text, so a changed command asks again; a ticked No stores nothing. Larsal shows the box only when the URL is not protected (its own flag or the vault's, LD-207) and resolving it changes nothing, so the stored text is the exact command; every other command asks every time, with no box (F-071; LD-70, LD-238 (4), LD-238 (5)). Larsal does not change `_EXEC_CMD`. MOD-01.10 still applies to a field set by another app.
  - Yes runs the command as the question showed it: the URL is resolved again on the question's clock, so dates and codes run as shown; when the command no longer reads as shown (a sync changed it meanwhile), nothing runs or is kept and Larsal asks again (F-128; LD-238 (1), LD-242 (3)). A change only past the 400 characters shown still runs (accepted, LD-242 (2)). The text is split into words at spaces; double quotes group words, and three double quotes in a row stand for one literal quote mark. The first word is the program, the rest are its arguments. The program is started directly and detached, never through a shell, so `$HOME`, `;` and `|` are passed on as plain text. An empty word list runs nothing. A program that does not start shows nothing (LD-242 (3)).
  - After the program starts, setting `window.minimize_on_open_url` (S-ENTRY-07) minimizes the window, or hides it.
- **Vault link** (starts with the 7 bytes `6b 64 62 78 3a 2f 2f`, stored encoded (name rule); below written as `<vault-link>`). Larsal opens another vault with the auto-open logic (SR-10, APP-06). The path is the text after the prefix. A `file://` URL is turned into a local path, and a relative path is taken from the folder of the current vault. The key file path is the entry's resolved `UserName`, with the same path rules (empty means no key file), and the password is the entry's resolved `Password`. The vault opens in front, with these credentials. A key file path that holds a protected value is used but never kept or named (APP-06.24, LD-238 (5)). When no regular file exists at the path, Larsal shows `MSG-08-3` "Larsal cannot find the vault <path>." and opens nothing; when the path holds a protected value it shows "Larsal cannot find that vault." with no path (LD-238 (3), LD-232 (6)). S-ENTRY-07 does not apply.
- **Any other URL.** The text is read as typed input: text without a scheme gets `http://`, so `example.com` opens `http://example.com`. An empty result does nothing. The reference hands every scheme to the system opener. Larsal goes further (AT-E02, lead decision LD-59): only `http`, `https` and `mailto` go to the system opener. Every other scheme, including `javascript:`, `file:`, `data:` and schemes that start other programs, shows `MSG-08-4` ("Larsal does not open this kind of link") and opens nothing. The check uses the resolved text. After a URL opens, S-ENTRY-07 applies.
  - Larsal also refuses with `MSG-08-4`, and opens nothing, an `http`, `https` or `mailto` URL that holds a protected value, since opening hands the text to another app (rule 4; stricter than the reference, which opens it; LD-232 (2)). It holds one when the URL field is protected (its own flag or the vault's, LD-207), or when its display resolution (MOD-08.23) put in the mask or read a protected or never-shown field: a `{REF:…}` search that compares such a field on any entry it looks at, whether its guess is right or wrong (with the vault's default protection every `{REF:…@P:…}` and `{REF:…@O:…}` search does), and a display `{S:…}` of a one-time password or passkey field (F-129, F-130, LD-245 (1)). The check asks the resolver whether it masked, never compares texts (F-129). A reference by id (`{REF:U@I:…}`) reads no value and opens as before.

### Scope in a share group

MOD-08.32 **A reference inside a share group finds only what that share sends** (decided: spec/decisions.md LD-279 (2), LD-284 (1), F-142; SI-09). A share group is a group that carries the share item (INT-08.1), the same test as "shared" in MOD-02.18: in any mode, Inactive included, approved or not (INT-08.31), and also when the item cannot be read (INT-08.4). The share group of an entry is the nearest share group at or above it: the entry's own group first, then each group up to the root. When the referring entry (the context of the reference step, MOD-08.16) has a share group, the search of MOD-08.15 covers only the entries that this vault's share item for that group would put in its container (INT-08.12 steps 3 and 4), with the same pre-order and the same match rules, started at the share group instead of the root:
- Keep group structure on: the share group's subtree. The vault's recycle bin and everything in it are left out of that subtree when they lie under the share group, as the share's export leaves them out (INT-08.35, LD-281 (4)).
- Keep group structure off, or a share item that cannot be read (INT-08.4): the share group's own entries only, in stored order. No group below the share group is searched.

Keep group structure is read as INT-08.3 reads `KeepGroups`: on only for the exact text `True`, so a missing `KeepGroups` means off. The scope is the same for every entry whose share group it is, so an entry in a group below a keep-off share group also searches only the share group's own entries: not its own group, not itself. The mode (Inactive, Import, Export, Synchronize) and approval (INT-08.31) do not change the scope; it is what the item would send if it exported now. A search that finds no match there gives the empty string (MOD-08.16); it never goes on into the rest of the vault.
- Every use. The scope holds wherever Larsal resolves a reference: every "yes" place of MOD-08.25, among them copy, the list and the preview, the browser bridge's fill and URL matching (INT-01, INT-02, INT-03), Auto-Type (INT-05), search (FEA-01), Open URL (MOD-08.31) and the command line tool's `show` (INT-10). Exports write the raw text (MOD-08.25), and a shared-group export resolves nothing (INT-08.13); an export that resolves a reference keeps to this scope too.
- The share's own references. A reference whose target lies inside the scope resolves as before (INT-08 T20's Alias).
- A group inside a share group, with no share item of its own, has that share group as its share group, so its entries search the share group's scope. With Keep group structure on, that is the whole share group, and the share group's other entries find its entries. With it off, or with a share item that cannot be read, its entries search only the share group's own entries, so they find neither themselves nor the other entries of their group, and no entry whose share group is that one finds them: the share sends none of them.
- A share group inside another share group: the innermost share group wins. An entry under the inner share group searches only the inner one's scope; an entry of the outer share group that is not under the inner one searches the outer one's scope, which holds the inner one's entries only with Keep group structure on for the outer one. Why: the members of the inner share hold only the inner group, while the outer share's container holds the inner group's entries too (with Keep group structure on) (INT-08.12 step 4, the edge case "two share groups in one vault"), so the innermost scope is the one that gives each set of members only what they were sent.
- Chains. Each reference step uses the scope of its own referring entry (MOD-08.16). An entry found inside a scope has a scope that lies inside it (the same share group, or, with Keep group structure on, one inside it), so a chain that starts inside a share group never leaves the scope it started in. An entry outside every share group that finds an entry inside one gets that entry's value resolved in the narrower scope.
- An entry with no share group searches the whole vault, share groups included (MOD-08.15). The scope follows the entry's place and its share item at the time of resolution: an entry moved out of a share group, or whose share group lost its share item, searches the whole vault from then on, and a change of Keep group structure changes the scope at once.

## Edge cases and errors

- An unbalanced brace anywhere (`{TITLE`, `TITLE}`, `}{`) is plain text (MOD-08.1).
- `{S:}` asks for a field with an empty name, so the result is empty. `{S:{TITLE}}` looks for a field named `{TITLE}`, so the result is empty.
- `{REF:T@T:Alpha }`, with a trailing space, finds nothing, so the result is empty (MOD-08.15).
- `{REF:T@I: <id> }` with spaces finds the entry, because non-hex characters are dropped (MOD-08.15).
- Two entries titled `Dup`, one in the root and one in a subgroup: `{REF:U@T:Dup}` returns the root one, because the root's entries come first (MOD-08.15).
- `{REF:T@O:cval}` written in entry Probe, which itself has a field `cval`, returns Probe, because the search includes the referring entry and Probe comes first.
- A conversion missing its last separator (`{T-CONV:/abc/upper}`) gives the empty string (MOD-08.21).
- `{T-REPLACE-RX:/abc/(/X/}` has an invalid pattern, so the result is empty (MOD-08.22).
- The text `x{T-CONV:/abc/junk/}y` gives `xy`: an invalid conversion leaves nothing behind.
- Values with line breaks resolve normally. A literal line feed inside a conversion or regex span makes that span empty. A carriage return alone does not (observed by Verify in Sprint 3, V-08-4: with a carriage return written by Larsal's saver, since the reference's XML import turns a lone carriage return into a line feed, the reference command line tool's `show` gave `xA`, carriage return, `By` for `x{T-CONV:/a`, carriage return, `b/upper/}y`, and the regex span replaced normally; Larsal gave the same results).
- A huge field (more than 1,048,576 characters) is returned raw by Larsal even when it holds no placeholder. The result is the same text, so nothing is lost (MOD-08.20).
- Permanent delete of X and Y together, where only Y references X: the reference still shows the MOD-08.27 prompt, naming 0 references. Larsal does not ask, because no referencing entry is left (MOD-04.6, lead decision LD-59).
- A command URL whose resolved text is `cmd://` and nothing more: no question, nothing runs (MOD-08.31).
- A vault link to a missing file: `MSG-08-3`, nothing opens (MOD-08.31).
- A share member plants `{REF:P@U:<a user name>}` in the share group: in every importing vault it finds only entries that the share sends, so it gives the empty string unless the share itself sends such an entry (MOD-08.32, 08-63, 08-70).
- The vault's root group carries the share item: with Keep group structure on, the scope is the whole vault less the recycle bin and its contents (MOD-08.32, 08-69); off, the root's own entries only. An entry in that recycle bin finds no entry of the bin, itself included.
- Keep group structure off: an entry in a group below the share group finds, by reference, only the share group's own entries, never itself or another entry of its own group (MOD-08.32, 08-71).
- Permanent delete of an entry outside a share group that only entries inside it refer to: Larsal asks nothing, deletes it, and those references keep their raw text (MOD-08.27, 08-73).
- The user moves a planted entry out of the share group, or clears the share item (INT-08.21): from then on it searches the whole vault, like any entry the user made there (MOD-08.32).
- The reference logs "maximum depth reached" with the entry id at every exhaustion. Larsal logs one warning per top-level call, with the id and no values (Rust rule 9).

## Security notes

- **Hostile vault data must never hang or crash Larsal** (AT-A08, AT-G03). The reference crashes on three loop forms (MOD-08.19) and can be made to allocate gigabytes (MOD-08.20). Larsal bounds depth, steps and output. Run the E4-S6 fuzz target on the resolver with random vaults of up to 20 entries and fields up to 4 KB. Pass: every call returns within 50 ms, below the bounds, and never panics.
- **Regex from a vault is untrusted.** A crafted `{T-REPLACE-RX}` pattern can backtrack catastrophically. Larsal's engine needs a step limit or must run in linear time, and a limit hit makes the result empty (D-08-9).
- **References can exfiltrate.** A reference planted in a field that a site or a window receives sends another entry's password there. The installed version lets the browser bridge save a login such as `{REF:P@T:Bank}`. On the next fill, that site then receives the Bank password. Larsal refuses such saves (MOD-08.28, D-08-5; SI-10). A shared-group import is a second way in: a share member writes the reference into the container, and every importing vault takes it as written (INT-08.13, INT-08.16). Larsal lets a reference inside a share group find only the entries that the share sends to every member (MOD-08.32, LD-279 (2), LD-284 (1), F-142; SI-09), so the planted text can never read the member's own entries outside the share, nor a private entry in a group below a share whose Keep group structure is off. The delete prompt's Overwrite never copies a value from outside the share into it (MOD-08.27, LD-284 (2)).
- **Display leaks.** Only a literal `{PASSWORD}` is masked in displayed URLs. Larsal masks every protected value it resolves for display (D-08-4; SC-04). Open URL never hands a protected value to another app: such a URL is refused with `MSG-08-4`, and a protected `cmd://` shows masked (MOD-08.31; LD-232 (2), LD-245 (1); SR-11).
- **Dangerous links.** Placeholders can build a scheme (`{S:a}:alert(1)` with `a` = `javascript`). Larsal checks the scheme of the resolved URL, not the raw one, before opening, and opens only `http`, `https` and `mailto` (MOD-08.31, AT-E02).
- **Resolved text is shown as plain text, never as markup** (AT-E01).
- A resolved secret is a secret: it lives in `SecretString` and is wiped after use. The resolver's scratch buffers are wiped too (SR-07, AT-C02). Logs never hold a resolved or raw value (AT-C06).
- **Command URLs run programs** (SR-11). They always ask unless the user said Yes with "Remember my choice" on this Mac for this exact command (LD-70; the vault's own `_EXEC_CMD` = `1` is ignored), the default answer is No, the question shows the masked text, and the program starts without a shell, so the text cannot chain commands (MOD-08.31). A hostile vault can still store `_EXEC_CMD` = `1`; the user's open action is then the only gate, as in the reference.

## Test cases

Vault R8 (built in `/tmp/spec-mod08-10`, password `demo`). Entries in search order:

| # | Group | Title | Id (16 times the byte) | Fields |
|---|---|---|---|---|
| 1 | Root | Probe | 0f | UserName `probe-user`, Password `{PASSWORD}`, URL `https://u:pw@example.com:8443/p/a.php?q=1&r=2#frag`, Custom1 `cval`, plus each test field below |
| 2 | Root | Alpha | 0a | UserName `alice`, Password `pw-A`, URL `https://alpha.example`, Notes `note-A`, Custom1 `cval`, Mixed `x{TITLE}y{USERNAME}z` |
| 3 | Root | `{REF:T@I:0c…0c}` (B) | 0b | UserName `bob` |
| 4 | Root | `{REF:T@I:0b…0b}` (C) | 0c | UserName `carol` |
| 5 | Root | NoPort | 77 | UserName `{URL:PORT}\|{URL:HOST}\|{URL:SCM}`, URL `example.org/x` |
| 6 | Root | Nested | 88 | UserName `{REF:U@I:0a…0a}-{S:Extra}`, Extra `{TITLE}` |
| 7 | Root | Dup | 11 | UserName `root` |
| 8 | Root/Sub | Dup | 22 | UserName `sub` |
| 9 | Root/Recycle Bin | Binned | 44 | UserName `binned-user` |

"Resolve V in Probe" means: a field of Probe holds V, and the field is shown resolved (copy, preview, `show -a`). Every Then value was observed with the installed command line tool unless the row says Larsal.

| Case | Given | When | Then |
|---|---|---|---|
| 08-01 spans | `{TITLE`, `TITLE}`, `{}`, `{{FOO}}` in Probe | resolve each | `{TITLE`, `TITLE}`, `{}`, `{{FOO}}` (MOD-08.1, MOD-08.5) |
| 08-02 escape whole | `\{TITLE\}` in Probe | resolve | `{TITLE}` (MOD-08.2) |
| 08-03 escape inside | `a\{TITLE\}b` in Probe | resolve | `a\{TITLE\}b` (MOD-08.2) |
| 08-04 case of names | `{TITLE}`, `{title}`, `{Title}`, `{url:host}`, `{URL:SCHEME}`, `{url:withoutscheme}` in Probe | resolve | `Probe`, `Probe`, `Probe`, `example.com`, `https`, `//u:pw@example.com:8443/p/a.php?q=1&r=2#frag` (MOD-08.3, MOD-08.4; the two aliases from the source) |
| 08-05 case of S and REF | `{s:Custom1}`, `{ref:u@i:0a…0a}`, `{REF:u@i:0a…0a}` in Probe | resolve | `{s:Custom1}`, `{ref:u@i:0a…0a}` (both literal), `alice` (MOD-08.3, MOD-08.13) |
| 08-06 unknown | `{FOO}`, `{ {TITLE} }`, `{{TITLE}}`, `{{S:Custom1}}`, `{{REF:U@I:0a…0a}}` in Probe | resolve | `{FOO}`, `{ Probe }`, `{Probe}`, `{cval}`, `{alice}` (MOD-08.5; Larsal per D-08-1) |
| 08-07 field chain | Nested (6) | resolve its UserName | `alice-Nested` (MOD-08.6, MOD-08.16) |
| 08-08 S rules | `{S:Custom1}`, `{S:custom1}`, `{S:Missing}`, `{S:UserName}`, `{S:P01}` with P01 = `{TITLE}`, in Probe | resolve | `cval`, empty, empty, `probe-user`, `Probe` (MOD-08.7) |
| 08-09 UUID | `{UUID}` in Probe | resolve | `0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f` (MOD-08.8) |
| 08-10 URL parts | Probe's URL | resolve `{URL:RMVSCM}`, `{URL:SCM}`, `{URL:HOST}`, `{URL:PORT}`, `{URL:PATH}`, `{URL:QUERY}`, `{URL:FRAGMENT}`, `{URL:USERINFO}`, `{URL:USERNAME}`, `{URL:PASSWORD}` | `//u:pw@example.com:8443/p/a.php?q=1&r=2#frag`, `https`, `example.com`, `8443`, `/p/a.php`, `q=1&r=2`, `frag`, `u:pw`, `u`, `pw` (MOD-08.9) |
| 08-11 URL table | one entry per URL row of MOD-08.9, UserName = the ten URL placeholders joined by `\|` | resolve UserName | exactly that row (MOD-08.9) |
| 08-12 URL no port, empty URL | NoPort (5); an entry with an empty URL and UserName `{URL:PORT}` | resolve UserName | `-1\|\|`; empty (MOD-08.9, D-08-6) |
| 08-13 date and time | clock 2026-10-24T22:46:28Z, local zone UTC+2 | resolve `{DT_SIMPLE}`, `{DT_UTC_SIMPLE}`, `{DT_YEAR}-{DT_MONTH}-{DT_DAY} {DT_HOUR}:{DT_MINUTE}:{DT_SECOND}` | `20261025004628`, `20261024224628`, `2026-10-25 00:46:28` (MOD-08.10) |
| 08-14 DB_DIR | R8 opened as `/tmp/spec-mod08-10/m08.larsalvault`; a Larsal vault never saved | resolve `{DB_DIR}` | `/private/tmp/spec-mod08-10`; Larsal: empty (MOD-08.11, D-08-8) |
| 08-15 TOTP | Probe has no one-time password | resolve `{TOTP}`, `{TIMEOTP}` | empty, `{TIMEOTP}` (installed version); Larsal: empty, empty (MOD-08.12) |
| 08-16 TOTP invalid | an entry whose one-time settings have an invalid key | resolve `{TOTP}` | reference: a short error text; Larsal: empty (MOD-08.12, D-08-7) |
| 08-17 REF codes | in Probe: `{REF:U@I:<0a upper>}`, `{REF:U@I:<0a lower>}`, `{REF:T@U:alice}`, `{REF:I@T:Alpha}`, `{REF:N@T:Alpha}`, `{REF:A@T:Alpha}`, `{REF:T@A:https://alpha.example}`, `{REF:T@N:note-A}`, `{REF:T@P:pw-A}` | resolve | `alice`, `alice`, `Alpha`, `0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a`, `note-A`, `https://alpha.example`, `Alpha`, `Alpha`, `Alpha` (MOD-08.13) |
| 08-18 bad REF | `{REF:X@T:Alpha}`, `{REF:O@T:Alpha}` in Probe | resolve | both unchanged (MOD-08.13) |
| 08-19 search text resolved | `{REF:T@I:{UUID}}`; `{REF:T@I:{S:Target}}` with Target = `0a0a…0a` | resolve in Probe | `Probe`; `Alpha` (MOD-08.14) |
| 08-20 search order | R8 | resolve `{REF:U@T:Dup}`, `{REF:U@T:Binned}` | `root`, `binned-user` (MOD-08.15) |
| 08-21 O and self | in Probe: `{REF:T@O:cval}`, `{REF:T@O:alice}` | resolve | `Probe`, `Alpha` (MOD-08.15) |
| 08-22 exact match | in Probe: `{REF:T@T:alpha}`, `{REF:T@U:ALICE}`, `{REF:T@T:Alpha }`, `{REF:P@T:Nonexistent}` | resolve | empty, empty, empty, empty (MOD-08.15, MOD-08.16) |
| 08-23 id forms | in Probe: `{REF:T@I:0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a}`, `{REF:T@I: <0a hex> }`, `{REF:U@I:0A0A}`, `{REF:T@I:a` + `0a` × 15 `}` (31 digits), `{REF:T@I:` `0a` × 16 + `0}` (33 digits) | resolve | `Alpha`, `Alpha`, empty, `Alpha`, empty (MOD-08.15; the last two observed in review) |
| 08-24 two refs | `{REF:U@I:<0a>} and {REF:P@I:<0a>}` in Probe | resolve | `alice and pw-A` (MOD-08.16) |
| 08-25 custom field via redirect | an entry T2 with Notes `{S:Pin}` and Pin `1234`; another entry holds `{REF:N@T:T2}` | resolve | `1234` (MOD-08.17) |
| 08-26 depth table | each row of the MOD-08.18 table | resolve | the row's result (MOD-08.18) |
| 08-27 loops through fresh budgets | an entry with UserName `{T-CONV:/{USERNAME}/upper/}`; another with UserName `{T-REPLACE-RX:/{USERNAME}/a/b/}`; another titled `{REF:T@T:{TITLE}}` | resolve that field | reference: process killed by SIGSEGV (observed). Larsal: returns within 50 ms, no crash; the values are, in order, `{USERNAME}`, `{USERNAME}` and empty (MOD-08.19, D-08-2) |
| 08-28 work bound | an entry whose UserName is `{USERNAME}` 4 times; another whose UserName is `{USERNAME}` 8 times | resolve UserName | 4 copies: 40,960 characters, the same as the reference (observed). 8 copies: reference 2,621,440 characters; Larsal returns the raw 80-character value (MOD-08.20, D-08-3) |
| 08-29 conversions | in Probe: `{T-CONV:/{USERNAME}/upper/}`, `{t-conv:/AbC/l/}`, `{T-CONV:/abc/base64/}`, `{T-CONV:/abc/hex/}`, `{T-CONV:/a b&c/uri/}`, `{T-CONV:/a%20b/uri-dec/}`, `{T-CONV:\|a/b\|upper\|}`, `{T-CONV:/abc/uri-x/}`, `{T-CONV:/straße/upper/}` | resolve | `PROBE-USER`, `abc`, `YWJj`, `616263`, `a%20b%26c`, `a b`, `A/B`, `ABC`, `STRASSE` (MOD-08.21) |
| 08-30 conversion errors | `x{T-CONV:/abc/junk/}y`, `{T-CONV:/abc/upper}`, `{T-CONV:/a/b/upper/}`, a conversion span with a line feed inside | resolve | `xy`, empty, empty, empty (MOD-08.21) |
| 08-31 conversion edge | `{T-CONV:/abc/upper/extra/}`, `{T-CONV:/%41%2/uri-dec/}`, `{T-CONV:/a+b/uri-dec/}`, `{T-CONV:/ä/hex/}` | resolve | `ABC`, `A%2`, `a+b`, `c3a4` (MOD-08.21) |
| 08-32 regex | `{T-REPLACE-RX:/abc123/\d+/X/}`, `{T-REPLACE-RX:/2024-10-25/(\d+)-(\d+)-(\d+)/$3.$2.$1/}`, `{T-REPLACE-RX:/aaa/a/b/}`, `{T-REPLACE-RX:/abc/(?i)B/x/}`, `{T-REPLACE-RX:/abc/(?<=a)b/X/}`, `{T-REPLACE-RX:/abc//x/}` | resolve | `abcX`, `25.10.2024`, `bbb`, `axc`, `aXc`, `xaxbxcx` (MOD-08.22) |
| 08-33 regex groups | `{T-REPLACE-RX:/abc/(b)/[$1$1]/}`, `.../(b)/[$0]/}`, `.../(b)/[$2]/}`, `.../b/[\1]/}`, `.../(b)/$10/}` (text `abc`) | resolve | `a[bb]c`, `a[\0]c`, `a[\2]c`, `a[\1]c`, `ab0c` (MOD-08.22) |
| 08-34 regex errors | `x{T-REPLACE-RX:/abc/(/X/}y`, `{T-REPLACE-RX:/abc/b/x}` | resolve | `xy`, empty (MOD-08.22) |
| 08-35 display mask | entry with UserName `al`, Password `pw1`, URL `https://h.example/?u={USERNAME}&p={PASSWORD}`; a second entry with URL `https://h.example/?p={S:Pin}`, where Pin is protected and holds `9876` | show the list URL column, and open the URL | reference: shows `https://h.example/?u=al&p=******` and opens `https://h.example/?u=al&p=pw1`; for the second entry it shows `https://h.example/?p=9876`. Larsal: the second shows `https://h.example/?p=******` (MOD-08.23, D-08-4); Larsal opens neither: each open shows `MSG-08-4` (MOD-08.31, LD-232 (2)) |
| 08-36 marker | Alpha, Probe, and an entry with UserName `{REF:U@I:<0a>}` | show the list | only the third entry: the reference marker and then `alice` in UserName, row in the lighter colour (MOD-08.24) |
| 08-37 places | Probe with UserName `{S:Custom1}` | copy username; preview; command line `show -a UserName`; command line `clip -a UserName`; export | `cval`, `cval`, `cval`, raw `{S:Custom1}`, raw (MOD-08.25) |
| 08-38 single form | entry titled `{USERNAME} and {NOTES}`, UserName `zed`, Notes `qq` | search `title:zed` | installed version: no result (observed). Larsal: found, because the title resolves to `zed and qq` (MOD-08.26) |
| 08-39 delete overwrite | entries X (id 0a…, UserName `alice`, Notes `nx`) and Y (UserName `{REF:U@I:<0a>}`, Notes `{REF:P@I:<0a>}`) | delete X for good, choose Overwrite | Y.UserName = `alice`, Y.Notes = `nx`; Y has no new history item; X is gone (MOD-08.27) |
| 08-40 delete skip and delete | same X and Y | delete X for good, choose Skip; then again, choose Delete | X stays; then X is gone and Y.UserName resolves to empty (MOD-08.27) |
| 08-41 not by title | entries X (title `Alpha`) and Y (Password `{REF:P@T:Alpha}`) | delete X for good | no prompt; X is deleted (MOD-08.27) |
| 08-42 recycle | X and Y as in 08-39 | move X to the recycle bin | no prompt; Y.UserName still resolves to `alice` (MOD-08.27) |
| 08-43 browser guard | association done; the bridge asks to save login `{REF:P@T:Bank}`, then `{abc}`, then `\{TITLE\}`, then `user{DT_YEAR}` | save | refused with code 34; saved; refused; refused (MOD-08.28, D-08-5) |
| 08-44 context | an entry not yet added to any vault, holding `{REF:U@I:<0a>}`, `{TITLE}` and `{DB_DIR}`; a history item of Probe holding `{REF:U@I:<0a>}` | resolve | `{REF:U@I:<0a>}` unchanged; `{TITLE}` gives its title; `{DB_DIR}` empty; the history item's reference unchanged (MOD-08.29) |
| 08-45 written format | clone Alpha with the references option (MOD-10) | read the clone's UserName raw | `{REF:U@I:0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A}` (MOD-08.30) |
| 08-46 search text as one span | in Probe, with SA = `Al`, SB = `pha`, SC = `Alpha`: `{REF:U@T:{S:SA}{S:SB}}`, `{REF:U@T:Al{S:SB}}`, `{REF:U@T:{S:SC}}`, `{REF:U@I:{UUID}x{TITLE}}` | resolve | empty, `alice`, `alice`, empty (MOD-08.18, MOD-08.19, MOD-08.26; observed in review) |
| 08-47 delete scope | X and Y as in 08-39, X in the recycle bin | empty the recycle bin; then again with X in a group that is deleted for good | no prompt either time; X is gone and Y.UserName resolves to empty (MOD-08.27) |
| 08-49 host form (LD-58) | URLs `https://bücher.com/`, `https://bücher.de/`, `https://xn--bcher-kva.de/`, `https://bücher.fr/` | resolve `{URL:HOST}` and `{URL:RMVSCM}` | reference (observed): `bücher.com`, `bücher.de`, `bücher.de`, `xn--bcher-kva.fr`, RMVSCM with the same host form. Larsal: `xn--bcher-kva.com`, `xn--bcher-kva.de`, `xn--bcher-kva.de`, `xn--bcher-kva.fr`, RMVSCM `//xn--bcher-kva.com/` and so on (MOD-08.9) |
| 08-50 command URL asks | URL `cmd:///usr/bin/touch /tmp/m08-run`, no `_EXEC_CMD` | open the URL; answer No | question `MSG-08-2` with the text `/usr/bin/touch /tmp/m08-run`, default No; nothing runs; no `_EXEC_CMD` field (MOD-08.31) |
| 08-51 remembered Yes | same entry | open, tick "Remember my choice", answer Yes; open again; then change the command text by one character and open | the file `/tmp/m08-run` exists; no `_EXEC_CMD` field is written; the second open runs with no question; the changed command asks again (MOD-08.31, LD-70) |
| 08-52 remembered No still asks | `_EXEC_CMD` = `0`; also a URL `cmd://` alone | open each | the first shows the question; the second shows nothing and runs nothing (MOD-08.31) |
| 08-52b vault flag ignored (LD-70) | A demo vault made elsewhere with `URL` = `cmd:///usr/bin/touch /tmp/m08-flag` and `_EXEC_CMD` = `1`, opened for the first time on this Mac | open the URL; answer No | the question is shown; `/tmp/m08-flag` does not exist; `_EXEC_CMD` still `1` after save |
| 08-53 question text | Password `pw1`, a protected custom field Pin `9876`; URL `cmd://echo {PASSWORD} {S:Pin} ` followed by 500 `x` | open the URL | the question shows `echo ****** ****** xxx…`, cut after 400 characters and ending in ` […]`. Reference: `echo ****** 9876 xxx…` (MOD-08.31, MOD-08.23, D-08-4) |
| 08-54 no shell | URL `cmd:///usr/bin/touch "/tmp/m08 a" /tmp/m08-$HOME;x` | open, answer Yes | two files exist, named exactly `/tmp/m08 a` and `/tmp/m08-$HOME;x`; no other command ran (MOD-08.31) |
| 08-55 vault link | in `/tmp/m08v/`: vault A, vault B (password `demo`, key file `b.larsalkey`); an entry in A with URL `<vault-link>b.larsalvault`, UserName `b.larsalkey`, Password `demo`; a second entry with URL `<vault-link>missing.larsalvault` | open each URL | B opens unlocked in front; the second shows `MSG-08-3` and opens nothing (MOD-08.31, SR-10) |
| 08-56 other URLs | URLs `example.com`, `https://example.com`, `mailto:a@b.example`, `javascript:alert(1)`, `file:///etc/hosts`, `data:text/html,x`, `ssh://host.example`, and `{S:a}:alert(1)` with a = `javascript` | open each | reference (from source): all go to the system opener, the first as `http://example.com`. Larsal: the first three open (`http://example.com`, `https://example.com`, the mail link); each of the others shows `MSG-08-4` and nothing opens (MOD-08.31, AT-E02) |
| 08-57 minimize after open | S-ENTRY-07 on | open `https://example.com`; run a command URL (Yes); open a vault link | the window minimizes after the first two, not after the vault link (MOD-08.31) |
| 08-58 same delete, no question | X and Y as in 08-39 | select X and Y, delete both for good | Larsal: no prompt, both are gone. Reference (from source): the prompt names 0 references (MOD-08.27, LD-59) |
| 08-48 masked form only for display | entry with UserName `al`, Password `pw1`, URL `https://h.example/?p={PASSWORD}` | copy the URL; search `url:pw1` | copied `https://h.example/?p=pw1`; the entry is found (MOD-08.23; the search observed in review) |
| 08-59 command changed meanwhile | URL `cmd:///usr/bin/touch /tmp/m08-a` | open; while `MSG-08-2` shows, a sync changes the URL to `cmd:///usr/bin/touch /tmp/m08-b`; answer Yes | neither file exists; `MSG-08-2` shows again with `/usr/bin/touch /tmp/m08-b` (MOD-08.31, F-128, LD-242 (3)) |
| 08-60 protected value refused | the vault keeps its default protection; entry Target with Password `demo-s`; another entry with a protected custom field PIN `4711` and a one-time password field; URLs `https://example.com/?t={REF:T@P:demo-s}`, `https://example.com/?t={REF:T@P:nope}`, `https://example.com/?t={REF:T@O:4711}`, `https://example.com/?c={S:otp}` (on the entry with the one-time password), `https://example.com` in a URL field marked protected, and `https://example.com/?u={REF:U@I:<Target's id>}` | open each | the first five show `MSG-08-4` and nothing opens, whatever the guess; the last opens (MOD-08.31, F-130, LD-232 (2), LD-245 (1)) |
| 08-61 Remember box | URL `cmd:///usr/bin/touch /tmp/m08-{TITLE}`; a second entry with URL `cmd:///usr/bin/touch /tmp/m08-c` in a URL field marked protected; a third with `cmd:///usr/bin/touch /tmp/m08-d` | open each | the first two ask with no "Remember my choice" box (resolving changes the first; the second is protected and shows `******`); the third shows the box (MOD-08.31, F-071, LD-238 (5)) |
| 08-62 program missing | URL `cmd:///tmp/m08-no-such-program` | open, answer Yes | no message; nothing runs (MOD-08.31, LD-242 (3)) |
| 08-63 planted reference finds nothing (F-142) | Member A's vault is INT-08's V: Team(20) carries an approved Synchronize share item (path `team.larsalvault`, share password `demo-share-1`, Keep group structure on) and holds Mail(0A) (user `ann`, password `pw-1`), Bank(0B) (password `pw-b`) and Sub(21) with Wiki(0C) (password `pw-w`). A adds to Team the entry Team wiki(44) with password `{REF:P@U:ann@example.com}` and URL `https://evil.example/login`, and saves, which exports. Member B's vault S is V plus a group Home(30), outside Team, with the entry Gmail(0F): user `ann@example.com`, password `gmail-secret-demo` | B's shared-group import of A's container (INT-08.16); then resolve Team wiki's password by copy, the preview, the command line tool's `show -a Password`, the browser bridge's fill reply for `https://evil.example/login`, and Auto-Type of `{USERNAME}{TAB}{PASSWORD}` on Team wiki; search `pw:gmail-secret-demo` | Larsal: Team wiki is in B's Team with its password as written; every resolution gives the empty string, never `gmail-secret-demo`; the fill reply and the typed text hold no `gmail-secret-demo`; the search lists Gmail and not Team wiki (MOD-08.32, MOD-08.15) |
| 08-64 the share's own references | S after 08-63; Team also holds Alias(0D) with password `{REF:P@I:0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B}` (INT-08 T20), Team wiki 2(45) with password `{REF:P@U:ann}` and Team wiki 3(46) with password `{REF:P@T:Wiki}` | resolve each password | Larsal: `pw-b`, `pw-1`, `pw-w` (MOD-08.32: Wiki is in Sub, inside Team) |
| 08-65 a group inside the share group | S after 08-63; Sub (no share item) holds Sub ref(47) with password `{REF:P@T:Mail}` and Notes `{REF:P@U:ann@example.com}` | resolve both | Larsal: `pw-1`; empty (MOD-08.32) |
| 08-66 a share group inside a share group | S after 08-65, and Sub now carries its own approved share item (Import, path `x.larsalvault`, password `p`); Sub ref(47) also gets UserName `{REF:P@T:Wiki}` | resolve Sub ref's password and UserName, and Team wiki 3's password (08-64) | Larsal: empty (Mail is outside Sub: the innermost share group wins); `pw-w`; `pw-w` (the outer share group covers the inner one) (MOD-08.32) |
| 08-67 chains | S after 08-64; Team holds Chain(48) with password `{REF:P@T:Team wiki}`; Home holds Outside(31) with password `{REF:P@T:Mail}` and UserName `{REF:P@T:Team wiki}` | resolve Chain's password, Outside's password and Outside's UserName | Larsal: empty (Chain finds Team wiki, whose reference searches Team only); `pw-1` (an entry outside every share group searches the whole vault); empty (Team wiki's value is resolved in Team wiki's scope) (MOD-08.32, MOD-08.16) |
| 08-68 any share item counts | S after 08-63 | set Team's share item to Inactive; then replace it with an item whose value is not base64 (INT-08.4); then with an Import item that arrived by merge and was never approved (INT-08.31); each time resolve Team wiki's password | Larsal: empty every time (MOD-08.32) |
| 08-69 root share and the recycle bin | a demo vault whose root group carries an approved Export share item with Keep group structure on; root holds Planted(44) with password `{REF:P@U:ann@example.com}`; Gmail(0F) (user `ann@example.com`, password `gmail-secret-demo`) is in the recycle bin | resolve Planted's password; restore Gmail to root and resolve again | Larsal: empty; then `gmail-secret-demo`, because Gmail is now in the shared part of the vault (MOD-08.32, INT-08.35) |
| 08-70 keep off sends only the share group's own entries (LD-284 (1)) | S after 08-64, with Team's share item in S set to Keep group structure off (still an approved Synchronize item); Sub(21) also holds Private(49) with user `pat` and password `private-demo`; Team holds Team note(4A) with password `{REF:P@U:pat}` and URL `https://evil.example/login` | resolve Team note's password by copy, the preview, the command line tool's `show -a Password` and the browser bridge's fill reply for `https://evil.example/login`; resolve the passwords of Team wiki 3 and Alias (08-64); then replace Team's item with an Inactive one with keep off and resolve the same; then with an Inactive one with keep on | Larsal: Team note gives the empty string every time, never `private-demo`, and the fill reply holds no `private-demo`; Team wiki 3: empty (Wiki is in Sub, which a keep-off container does not hold); Alias: `pw-b` (Bank is one of Team's own entries); the same with the Inactive keep-off item (the mode does not change the scope); with the Inactive keep-on item: Team note `private-demo` and Team wiki 3 `pw-w`, because Sub is now in what Team sends (MOD-08.32) |
| 08-71 an entry below a keep-off share group (LD-284 (1)) | S as in 08-70's first step (Team's item Synchronize, keep off); Sub holds Sub ref(47) as in 08-65 (password `{REF:P@T:Mail}`, Notes `{REF:P@U:ann@example.com}`) and Sib(4B) with password `{REF:P@T:Wiki}` and UserName `{REF:T@I:{UUID}}` | resolve Sub ref's password and Notes, and Sib's password and UserName | Larsal: `pw-1` (Mail is one of Team's own entries); empty; empty (Wiki is in Sib's own group, below Team); empty (Sib itself is not in the scope) (MOD-08.32) |
| 08-72 a share item that cannot be read (LD-284 (1)) | S after 08-64 (Team's item keep on) | replace Team's item with a value that is not base64; then with the base64 of `<?xml version="1.0"?><X><KeepGroups>True</KeepGroups></X>` (wrong root element, INT-08.4); each time resolve the passwords of Team wiki 3, Alias and Team wiki | Larsal, both times: empty (the item cannot be read, so the scope is Team's own entries only, and Wiki is in Sub); `pw-b`; empty (MOD-08.32) |
| 08-73 delete with a reference from inside a share (LD-284 (2)) | S after 08-63 (Team's item keep on); Team holds Y(4C) with password `{REF:P@I:0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F}` (Gmail's id; Gmail(0F) is in Home, outside Team). A second copy of that vault also holds, in Home, Z(32) with password `{REF:P@I:0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F}` | in the first copy, delete Gmail for good; in the second, delete Gmail for good and choose Overwrite; then save the second copy, which exports Team | Larsal: first copy: Y is not counted, so the count is 0 and Larsal asks nothing (LD-59); Gmail is gone; Y's password keeps its raw text `{REF:P@I:0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F}` and resolves to empty; Y's modification time does not change. Second copy: `MSG-08-1` counts 1 (Z only); after Overwrite, Z's password is `gmail-secret-demo` and Y's password keeps its raw text; the Team container holds no `gmail-secret-demo` (MOD-08.27, INT-08.13) |

## How this was learned

- Read in the reference source: the placeholder module (type table, URL and date helpers, display mask, span pattern, reference pattern, "contains placeholder"), the entry's resolve routines (string, span, reference, conversion, regex), the entry search behind references, the id formatter, the clone routine that builds references, the delete-with-references prompt, the browser bridge's save handler, the entry list model, the preview pane, the copy and open-URL actions (command URL question, remembered choice, command split, vault links, the system opener), Auto-Type's sequence parser (only to mark the INT-05 border), the command line `show` and `clip` commands, and the tests for entries and placeholders.
- Compared the source with the installed version's tag in the reference history: the unknown-span handling, `{TIMEOTP}`, the single-form fix and the browser save guard are newer than 2.7.11. All other rules here are the same in both.
- Ran the installed command line tool on demo vaults made from hand-written XML (`import`, password `demo`) in `/tmp/spec-mod08-10/`. Probed 90 field values in R8 (`show -a`), 15 URL shapes, 35 conversion and regex forms, the loop forms, the 4-, 8- and 16-copy growth cases, and `search`. A small model of the resolve steps reproduced every observed value. It was used to compute the depth table. Review round: the same tool on new demo vaults in `/tmp/spec-mod0809-rv/` (password `demo`) confirmed the id digit counts, the search-text forms of 08-46, the URL search of 08-48, `uri-dec` with bad escapes, `$0` in a regex replacement, and the Unicode hosts of V-08-2. These come from the source only (GUI, browser, clone, open URL), not from runs: rows 08-16, 08-50 to 08-58 (the reference parts), 08-25, 08-35, 08-36, 08-39 to 08-45, 08-47, the copy part of 08-48, and the copy, preview, `clip` and export parts of 08-37.
- MOD-08.32 and rows 08-63 to 08-69 (2026-10-31) are Larsal's own rule, written from the lead's ruling LD-279 (2), the case in security/findings.md F-142 and the INT-08 card; its Keep group structure scope, the MOD-08.27 sentence on scope and rows 08-70 to 08-73 (2026-10-31) come from the lead's ruling LD-284; nothing of the reference was read or run for them. The reference has no such scope: its search covers the whole vault (MOD-08.15).

### Lead decisions

| ID | Question | Options | Recommendation |
|---|---|---|---|
| D-08-1 | Unknown spans holding a placeholder, such as `{{TITLE}}` | (a) installed: keep the outer braces, resolve inside (`{Probe}`); read the reference syntax from the span start. (b) source: strip braces until a known name is found (`Probe`). Side effects: `{{S:Custom1}}` → empty, `{{REF:…}}` → value without braces, and `{REF:X@T:{REF:U@I:…}}` resolves the inner reference. | (a): consistent, and no mangled names. check with Verify against a build of the source. |
| D-08-2 | Fresh budget for search text, regex parts and conversion text | (a) fresh 10, as the reference does, which crashes on loops; (b) the current reduced budget | (b) |
| D-08-3 | Extra work bound | (a) none; (b) 10,000 span steps and 1,048,576 output characters per call, raw input returned when exceeded | (b) |
| D-08-4 | Masking in display | (a) only a literal `{PASSWORD}`; (b) every value from a protected field (password, protected custom field, references to them) shows as `******` in display resolution | (b) |
| D-08-5 | Browser save test | (a) the source's detector; (b) refuse when resolving in a blank entry changes the value, or the reference pattern appears | (b): simpler, and it refuses every form the source refuses |
| D-08-6 | `{URL:PORT}` with no port | (a) `-1`, as observed; (b) empty; (c) the scheme's default port | (a), for parity |
| D-08-7 | `{TOTP}` with invalid settings | (a) error text; (b) empty | (b) |
| D-08-8 | `{DB_DIR}` for an unsaved vault | (a) the process folder, as the source does; (b) empty | (b) |
| D-08-9 | Regex engine and URL parser (no approved crate yet) | regex: (a) a linear-time engine (no lookaround, so the reference's own lookahead examples fail and become empty); (b) a backtracking engine with a step limit (limit hit = empty). URL: a WHATWG parser plus the decoding of MOD-08.9, or a small parser of our own for the parts only | regex (b) with a 1,000,000-step limit and ASCII `\d` and `\w`; URL: a parser checked against the MOD-08.9 table. Both need AT-J03 review. |
| D-08-10 | `%` followed by 2 non-hex characters in `uri-dec` | (a) the reference makes one garbage byte (`%zz%C3%28` → two U+FFFD then `(`); (b) keep `%zz` as text | (b) |
| D-08-11 | Host form for non-ASCII names (MOD-08.9) | (a) mirror the URL library's allow list, as the reference does; (b) always ASCII (punycode); (c) always Unicode | Decided: (b), spec/decisions.md LD-58 |

D-08-1 to D-08-10 are not listed in spec/decisions.md, so its default rule applies: each takes the recommendation above. D-08-11 is LD-58. Opening URLs, dangerous schemes and the same-delete prompt are LD-59.

### Check with Verify

- V-08-1: the source-only behaviors (`{TIMEOTP}`, unknown-span unwrapping, the single-form fix, the browser guard), on a build of the source.
- V-08-2 (closed: observed again by Verify in Sprint 3, `https://bücher.com/` gave `bücher.com` in the reference command line tool and `xn--bcher-kva.com` in Larsal, LD-58): hosts with non-ASCII top-level domains that the reference may show in Unicode form instead of punycode. Observed in review (command line tool, `show`): `{URL:HOST}` of `https://bücher.com/`, `.org`, `.net` and `.de` gives `bücher.com` and so on in Unicode, and RMVSCM keeps the Unicode host; `https://xn--bcher-kva.de/` also gives `bücher.de`; `.fr` and `.example` give punycode. MOD-08.9 now records this, and Larsal gives punycode always (LD-58).
- V-08-3: `{DB_DIR}` in the GUI for a vault opened through a symbolic link.
- V-08-4 (closed, observed by Verify in Sprint 3: it does not empty the span; see Edge cases): a carriage return without a line feed inside a conversion span.

### Not on Mac

- The Linux secret-service integration resolves placeholders in the values it hands out.
- The Linux portable build opens URLs through the desktop opener. On Mac, the system opens them.
