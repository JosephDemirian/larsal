# FEA-01 Search language and rules

Status: reviewed
Epics: E4-S8, E5-S4
Parity rows: SC-08 (clear the search after idle, FEA-01.27). Related: SD-05 (recycle bin kept out of results), SR-01 and SR-02 (a lock ends the search), SG-04 (`is:weak`, `is:expired`)

## What it does

The user types a query in the search box. App splits it into terms, and lists every entry in scope that satisfies all the terms. A term can name a field (`user:alex`), exclude (`-github`), use wildcards (`git*b`), a regular expression (`*user:^a\d+$`) or an exact match (`+title:Gmail`). Without a field name, a term looks in title, username, URL, tags and notes. Passwords and custom fields are searched only when the user names them.

The same language drives the sidebar's built-in views (Expired, Weak Passwords, TOTP entries, All Entries), clicks on tags, saved searches stored in the vault, and the expired-entries list after unlock. The command line tool's `search` command uses this language too, but its scope rules belong to INT-10. Auto-Type's entry picker also uses it (INT-05).

## Inputs and outputs

| Input | Type | Notes |
|---|---|---|
| Query text | text, at most 1,024 characters in App (FEA-01.32) | From the search box, a built-in view or a saved search |
| Exact tag terms (App) | list of tag texts | From a tag click in the sidebar (FEA-01.35) |
| Base group | group id | The root group. With the limit option on and a group selected, the selected group (FEA-01.23) |
| Case-sensitive option | bool, default off | FEA-01.24 |
| Clock and time zone | now, local zone | Only for `is:expired` (FEA-01.16) |

Output: an ordered list of entry ids (tree order, FEA-01.22), plus, in App, a flag saying that a regular expression was invalid (FEA-01.31). The search never returns field values to the screen. The screen asks for list views of the ids, which carry no secrets (architecture, app-desktop Must).

Our setting IDs (APP-01 holds the inventory; if APP-01 names them differently, APP-01 wins):

| ID | Default | Kept across restarts | Meaning |
|---|---|---|---|
| `search.limit_to_group` | off | yes | Search only the selected group and its subgroups |
| `search.case_sensitive` | off | no (session only, all open vaults) | Plain and wildcard terms match case exactly |
| `search.enter_to_search` | off | yes | Run the search only when Return is pressed |
| `search.clear_when_idle` | off | yes | Clear the search text after the box has been out of focus for a while |
| `search.clear_after_minutes` | 5 | yes | Range 1 to 1,440 |

## Rules

### Parsing the query

FEA-01.1 **Terms.** Terms are separated by the space character U+0020 only. Several spaces in a row, and spaces at the start or end, produce no terms. Tabs, line feeds and no-break spaces are ordinary characters inside a term.

FEA-01.2 **Term shape.** Each term is `[modifiers][field:]value`.
- Modifiers: one or more of `-`, `!`, `*`, `+`, in any order and any number, at the very start of the term. `-` or `!` means exclude (FEA-01.11). `*` means the value is a regular expression (FEA-01.8). `+` means exact match (FEA-01.9).
- Field: a run of ASCII letters, digits and `_` (it may be empty), followed by `:`. Only the first colon counts: in `url:build.example:22` the field is `url` and the value is `build.example:22`.
- Modifiers count only before the field. In `t:-git` the value is the literal text `-git`.
- A term with no colon has no field. `*hub` is the regular expression `hub` with no field. `t:*hub` is the wildcard value `*hub` in the title.

FEA-01.3 **Quoted values.** When the value starts with `"`, App looks for a closing `"` that is followed by a space or the end of the query. Inside the quotes, `\"` stands for `"`. A backslash followed by any other character keeps both characters (`"a\b"` is the 3-character text `a\b`). A quoted value may hold spaces. When no such closing quote exists, the value is the plain text up to the next space, and the quote character is part of it. So `"PIN` searches for the 4 characters `"PIN`. For `"abc"def ghi`, the closing quote is followed by `d`, so the terms are `"abc"def` and `ghi`.

FEA-01.4 **Empty values.** A term whose value is empty is dropped. Examples: `title:`, `x:`, `""`, `-`, `*`, `+`, `**`. A query with no terms left matches every entry in scope. This is how All Entries works (its query is `*`).

FEA-01.5 **Field names.** Field names ignore case. A field name selects the first name in this list that **starts with** it: `attachment`, `attribute`, `notes`, `pw`, `password`, `title`, `username`, `url`, `group`, `tag`, `is`, `has`, `uuid`. The full table of what that gives:

| Typed field | Means |
|---|---|
| `a`, `at`, `att`, `atta` … `attachment` | attachment names |
| `attr`, `attri` … `attribute` | custom field names and values |
| `n` … `notes` | notes |
| `p`, `pw`, `pa`, `pas` … `password` | password |
| `t`, `ti` … `title` | title |
| `ta`, `tag` | tags |
| `u`, `us`, `use`, `user` … `username` | username |
| `ur`, `url` | URL |
| `uu`, `uui`, `uuid` | entry id |
| `g` … `group` | group |
| `i`, `is` | entry state (FEA-01.16, FEA-01.17) |
| `h`, `ha`, `has` | entry feature (FEA-01.18) |
| `_name` | the value of the field named `name` (FEA-01.6) |
| empty, or anything else (`tags`, `user1`, `e`, `foo`, `https`, `12`) | not a field: the term searches the default fields (FEA-01.13) for the value after the colon |

So `foo:github` searches the default fields for `github`, `https://github.com` searches them for `//github.com`, and `12:30` searches them for `30`. `tags:` is not an alias, even though the reference's help popup lists it: `tags:safe` searches the default fields for `safe`. App keeps this, so a saved search means the same in both apps (lead decision: the other option is to accept `tags` as an alias).

FEA-01.6 **Field by name.** A field part that starts with `_` names one field of the entry: the text after the `_`, matched against field names exactly, with case. `_otp:JBSWY` looks in the field `otp`. `_UserName:alex` looks in the standard username field, using its stored text (no placeholder resolution, FEA-01.19). The standard field names are `Title`, `UserName`, `Password`, `URL`, `Notes` (FMT-11). A field name with a space, a hyphen or a non-ASCII letter cannot be named this way. `_Security:blue` looks for a field named `Security`, not `Security answer`. Use `attribute:` for those. When the entry has no field with that name, the term does not match. `_:x` names the empty field name and never matches.

### Matching a value

FEA-01.7 **Plain values (no `*` modifier).** Every character is literal, except three wildcards:

| Wildcard | Matches |
|---|---|
| `*` | any run of characters, also an empty one, but not a line feed |
| `?` | exactly one character (one Unicode code point, so `🔑` is one), but not a line feed |
| `\|` | splits the value into alternatives. The value matches when any alternative matches |

So `.`, `(`, `[`, `\` and `$` are plain characters. Without `+`, a value matches when it occurs anywhere in the field text (substring). `t:gmail|bank` matches `Gmail` and `Big Bank`. A value made of `|` alone has an empty alternative, so it matches every field, empty ones too. A value of `?` alone matches any field that holds at least one character other than a line feed.

FEA-01.8 **Regular expressions (`*` modifier).** The value is a regular expression, matched anywhere in the field text unless it anchors itself. Wildcards (FEA-01.7) do not apply. An invalid expression never matches. App uses the linear-time engine of LD-110 with the bounds of LD-113, LD-120 and LD-123: look-around, backreferences and Unicode category or script classes such as `\p{L}` are invalid. So the term fails, and an excluded invalid term (`-*t:[`) holds for every entry. The reference shows no message (it only writes a warning to its debug log). App adds a notice (FEA-01.31). Dialect: see FEA-01.32 and the lead decision there.

FEA-01.9 **Exact match (`+` modifier).** The whole field text must match the whole value, alternatives included: `+t:Gmail|Big` matches the title `Gmail`, but not `Big Bank`. A field text with one extra line feed at its very end also matches (notes `hello` + LF matches `+n:hello`). This is the end-anchor rule of the reference's regex library. `+` combines with `*`: `+*t:G.*` is a regular expression that must match the whole title. In the source, `+` also makes the term case-sensitive. The installed version 2.7.11 does not do that: there `+t:github` matches `GitHub` (differs in installed version). App follows the source.

FEA-01.10 **Case.** By default, matching ignores case. It uses Unicode simple case folding per character, with no normalization: `éclair` matches `Éclair`, `STRAßE` matches `Straße`, `STRASSE` does not match `Straße`, and a precomposed `é` does not match `e` followed by a combining accent. Case is matched exactly when `search.case_sensitive` is on, or when the term has `+` (FEA-01.9). A regular expression may switch case itself with inline flags such as `(?i)`.

FEA-01.11 **Exclusion.** With `-` or `!`, a term holds exactly when its match fails. `-github`, `!github` and `--github` are the same.

FEA-01.12 **Combining.** An entry is a result when every term holds (logical AND). Terms cannot be joined with OR. Use `|` inside one value instead (`user:"name1|name2"`). Term order never changes the result.

### What each field looks at

FEA-01.13 **Field sources.**

| Field | Looks at | Placeholders resolved (FEA-01.19) |
|---|---|---|
| none (default) | title, username, URL, tags (FEA-01.14), notes. The term holds when any of them matches | title, username, URL: yes. Notes, tags: no |
| `title`, `username`, `url` | that standard field | yes |
| `password` | the password | yes |
| `notes` | the notes | no |
| `attribute` | the name and the value of every custom field, protected values included. Not the five standard fields, and not the passkey fields (INT-04) | no |
| `attachment` | every attachment name of the entry (MOD-05) | n/a |
| `_name` | the value of that one field (FEA-01.6) | no |
| `group` | FEA-01.15 | n/a |
| `tag` | each tag, whole-tag match (FEA-01.14) | no |
| `uuid` | the entry id as 32 lowercase hex digits, in the byte order stored in the file (FMT-12) | n/a |
| `is`, `has` | FEA-01.16 to FEA-01.18 | n/a |

Field protection flags (MOD-12) do not change what is searched. History items are never searched (FEA-01.20).

FEA-01.14 **Tags match whole.** A value must match a complete tag, never part of one, in every mode: `tag:wor` does not match the tag `work`, but `tag:wor*` and `tag:work` do (case ignored). The default fields apply the same rule to tags. So the plain term `dev` matches an entry tagged `dev` through its tags, but not one tagged `devops`, unless another default field contains `dev`. With a `*` regular expression, the expression too must cover the whole tag. Tags themselves are defined in MOD-07.

FEA-01.15 **Group.** When the value (the text after unquoting, before any wildcard work) contains `/`, it is matched against the path of the entry's own group: `/` + the names of all groups from the root down to that group, joined with `/`. In demo vault S1 the path of `Visa Card` is `/Vault/Banking/Cards`. Otherwise it is matched against the name of the entry's own group only, not its parent groups. `g:Bank` matches entries directly in `Banking`, not those in `Banking/Cards`.

FEA-01.16 **`is:expired`.** The value ignores case and must start with `expired`. If the value, split on `-` with empty pieces dropped, has a second piece, that piece is read as a whole number N (base 10). Text that is not a number reads as 0. Otherwise N is 0. The term matches an entry that has expiry on (MOD-09), whose expiry time is before now + N calendar days in the local time zone, and that is not in the recycle bin. Recycled entries never match, whatever the group search flags say. So `is:expired` means "expired now", and `is:expired-7` means "expired or expiring within 7 days". `is:expiredxyz` reads as N = 0. N counts calendar days in the local zone, so across a daylight-saving change one of those days is 23 or 25 hours long. The modifiers `*` and `+` have no effect on `is` and `has` terms. Only exclusion works.

FEA-01.17 **`is:weak`.** The value must equal `weak`, case ignored. The term matches an entry when all of these hold: it is not excluded from reports (FMT-11.29), its stored password is not empty, it is not expired (expiry on and expiry time before now), and the strength of its password, after placeholder resolution, rates Bad, Poor or Weak on the FEA-05 password-only scale (a score below 75). The reuse and expiry penalties of the Health Check score are not used here (compare FEA-07.10). Any other value after `is:` (`is:foo`) never matches.

FEA-01.18 **`has:totp`.** The value must equal `totp`, case ignored. The term matches an entry that has one-time password settings (FEA-04). Any other value after `has:` never matches.

FEA-01.19 **Placeholders.** Title, username, password and URL are matched after full, unmasked placeholder and reference resolution (MOD-08), with its depth limit. So a username `{REF:U@I:…}` is searched as the username it points to. Notes, tags, custom fields, attachment names and group names are matched as stored. Dynamic placeholders (date and time, the current one-time code) resolve when the search runs.

### Scope, order and options

FEA-01.20 **Which entries are searched.** App searches the base group and every group below it. A group's own entries are searched only when the group's resolved search flag is on. The flag is a tri-state (FMT-11.9): on, off, or inherit from the parent. Inherit at the root means on (MOD-02). A group set to on is searched even below a group set to off. A group set to off hides only the entries whose groups resolve to off. History items are never results. The command line tool ignores these flags (INT-10).

FEA-01.21 **Recycle bin.** The reference creates its recycle bin with searching off (MOD-04), so recycled entries do not appear. A vault from another writer can have a recycle bin with searching on (inherit). The reference then lists recycled entries in results, except for `is:expired`. App never lists entries that are in the recycle bin (the recycle bin group and everything below it), whatever any group flag says: the bin's own flag, or the flag of a group inside the bin set to on (decided: spec/decisions.md LD-57). This overrides FEA-01.20 for the bin. It matches the mockup, where search covers every entry except the bin's.

FEA-01.22 **Result order.** The core returns results in tree order: the base group's entries in their stored order, then each child group in stored order, depth first (pre-order). The reference's screen re-sorts results by group name (collation-aware, digits compared as numbers), with ties left in tree order. App's screen applies the list's current sort, as the mockup does (default: last modified, newest first). Lead decision. The other option is to sort by group name as the reference does. The mockup has no group column.

FEA-01.23 **Limit to the selected group.** With `search.limit_to_group` on and a group view showing, the base group is that group. The search flags of FEA-01.20 still apply, including flags inherited from groups above the base. When the user selects another group while a search is active:
- option on: the search runs again in the new group;
- option off: the search ends, the box is cleared and the group's entries show.
In App, when the current view is not a group (All Entries, a tag, a built-in view), the base is the root group. The limit option also applies to tag clicks and saved searches. It never applies to the expired-entries list after unlock (FEA-01.28).

FEA-01.24 **Case-sensitive option.** `search.case_sensitive` changes only plain and wildcard terms, and `*` terms without their own inline flag. It is a toggle in the search menu. It applies at once to every open vault, re-runs the active search, and resets to off when App restarts.

FEA-01.25 **When the search runs.**
- With `search.enter_to_search` off, the search runs as the user types. The reference waits until 500 ms pass with no typing. App runs at once on each change, as the mockup does, because the 50 ms target (FEA-01.34) allows it (lead decision; the other option is the 500 ms wait). Return in the box then opens the selected entry for editing, as the reference does (APP-08 owns the key).
- With `search.enter_to_search` on, typing does not search. Return runs the search.
- Built-in views, tag clicks and saved searches run at once, whatever the option says.
- Text that is empty, or spaces only, ends the search and shows the normal list. The reference treats spaces-only text as a query with no terms and lists every entry. App follows the mockup, which trims (lead decision).

FEA-01.26 **Live results.** Any change to the vault while a search is active runs the same query again. The selected entry stays selected when it is still a result. Otherwise the first result is selected. Switching between open vaults restores each vault's own search text. The case and limit options are global.

FEA-01.27 **Ending a search.** The search ends and the box is cleared when the user:
- presses Escape in the search box or the list;
- clicks the clear button;
- selects a group with `search.limit_to_group` off (FEA-01.23).
It also ends when the vault locks (APP-02). Lock clears the text, so a query is never shown after unlock. With `search.clear_when_idle` on, the text is cleared `search.clear_after_minutes` minutes after the search box loses focus:
- focus coming back stops that timer;
- while it runs, a change of selected entry or of view starts the full time again.

FEA-01.28 **Built-in queries.** These views are queries in this language. App's views must give exactly these results:

| ID | View | Query |
|---|---|---|
| `builtin.all` | All Entries | `*` |
| `builtin.expired` | Expired | `is:expired` |
| `builtin.weak` | Weak Passwords | `is:weak` |
| `builtin.totp` | TOTP entries (in the reference's sidebar; App shows it if the mockup gains it) | `has:totp` |
| `builtin.tag` | a click on tag T | App: one exact tag term (FEA-01.35). Reference: `tag:"T'"`, where T' is T with each `"` written as `\"` |
| several tags selected | | App: one exact tag term per tag, all required. Reference: their tag queries joined with one space |
| `builtin.unlock_expired` | after unlock, when MOD-09's setting is on, with N = its day offset | `is:expired-N`. The base is always the root group. When it has no results, nothing is shown and no search stays active. The banner says "expired entries" for N = 0 and "expiring within N days" otherwise (MOD-09, SR-08) |

FEA-01.29 **Saved searches.** The user can save the current query under a name. Saved searches are stored in the vault, in one vault custom-data item holding a JSON object that maps each name to its query (FMT-14 gives the key and the layout). So they travel with the file and are shared with the reference.
- Save: shown when the search box holds text. The user picks an existing name, which overwrites that query, or types a new one. An empty name saves nothing. Saving changes the vault (it is saved per APP-05).
- List: shown after the built-in views, ordered by name in code-unit order, so with case (`Zeta` before `alpha`).
- Run: a click puts the query in the box and runs it at once (FEA-01.25).
- Remove: a context-menu action removes that name, without a confirm step.
- Reading: an item that is not a JSON object reads as no saved searches. The next save replaces it with an object that holds only the new search. App ignores members whose value is not text. The reference turns numbers and booleans into text, and other values into an empty query (source, re-read by Verify in Sprint 3: the stored text is read as a JSON document turned into a map, so anything that is not an object gives no searches, and each value becomes text through the toolkit's general conversion, which turns numbers and booleans into text and lists, objects and null into the empty text).
- Whether App's sidebar shows saved searches: lead decision. Recommended: yes, a Searches section under the tags, because vaults shared with the reference carry them. Either way, App keeps the item on save (SD-06).

FEA-01.30 **Result header.** While a search is active, the list title says it is showing search results and shows the result count (mockup: "Search results" and the count). For a built-in view, the view's own title is shown instead. With no results, the mockup's empty state names the default fields: titles, usernames, URLs, notes and tags. That text must stay true to FEA-01.13.

FEA-01.31 **Invalid expression notice (App).** When any `*` term is invalid, or exceeds the FEA-01.32 limits, the results are exactly as FEA-01.8 says. In addition, the search box shows a small notice that the regular expression is invalid. The notice never repeats any field value. Lead decision (the reference shows nothing).

FEA-01.32 **Limits and dialect (App).** The reference has no limits here. The numbers below are App's own (lead decision).
- Query text: at most 1,024 characters. The box stops accepting input at the limit. The core refuses a longer query, for example from a hostile saved search, with a QueryTooLong error. The current results stay unchanged, and the screen shows a short notice.
- Regular expressions run on an engine whose time grows linearly with the text length (no backtracking blow-up).
- Compiled size and work: the bounds of LD-113, LD-116, LD-120, LD-122 and LD-123 (at most 256 KiB compiled, scaled down for long texts, one folding budget per query, one slow-engine budget per run). Nesting: at most 100 levels. A pattern over a limit counts as invalid.
- Wildcard values compile under the same limits.
- Placeholder resolution keeps MOD-08's bounds.
- Lead decision on the engine (LD-110, LD-122, LD-123): the linear-time engine crates `regex-syntax` and `regex-automata`. Look-around, back-references and Unicode category or script classes are invalid. `\d`, `\w` (and their negations) match ASCII only, as in the reference.
- The other option is a backtracking engine closer to the reference's Perl-style dialect. It would need a step limit and carries hang risk.
- The parser accepts every text without panicking (fuzz target `search_query`).

FEA-01.33 **What leaves the core.** The search returns entry ids only. It never sends a field value, a resolved placeholder or a match position to the screen. Matching protected values (passwords, protected custom fields, one-time password secrets) happens inside app-core on secret types. Any temporary resolved copy is wiped right after it is compared (Rust rule 3).

FEA-01.34 **Speed.** A query of up to 5 terms over 10,000 entries returns in under 50 ms on this Mac (E4-S8). The query is parsed and compiled once per run, not once per entry.

FEA-01.35 **Exact tag terms (App).** A tag click in the sidebar builds no query text. The sidebar hands the core one exact tag term per selected tag (decided: spec/decisions.md LD-66). An exact tag term holds when one of the entry's tags equals T exactly: code unit by code unit, case included, with no wildcards, no alternatives and no escaping. Several terms must all hold. Scope follows FEA-01.20 to FEA-01.23. The search box shows `tag:"T"` for each term as display text only. Typing in the box replaces the terms with a normal text query. Saving while exact tag terms are active saves the display text as a normal query (FEA-01.29). The reference builds text instead (FEA-01.28), so there case is ignored, `*`, `?` and `|` inside a tag act as wildcards, and a tag that ends in `\` or holds `\"` gives a different search.

## Edge cases and errors

| Case | Behavior |
|---|---|
| Query is only modifiers or empty values (`-`, `*`, `title:`) | No terms. Every entry in scope is listed (FEA-01.4) |
| Unknown field (`foo:x`) | Not an error. Searches the default fields for `x` (FEA-01.5) |
| Text with a colon that is not meant as a field (`12:30`, a URL) | The part before the colon is taken as a field name. If it is not a known field, the default fields are searched for the rest (FEA-01.5) |
| Unterminated quote | The quote is a literal character (FEA-01.3) |
| Invalid regular expression | That term fails. If excluded, it holds. App shows the notice (FEA-01.8, FEA-01.31) |
| Group name with spaces typed without quotes (`g:Dev & Ops`) | Becomes 3 terms (`g:Dev`, `&`, `Ops`). The user must quote it (`g:"Dev & Ops"`) |
| Wildcard across lines in notes (`n:account*recovery` over `Work account` LF `recovery …`) | No match: `*` and `?` do not cross a line feed |
| Carriage return in a value | `*` and `?` match it (the reference's regex library treats only a line feed as a line end, as far as could be seen). Observed by Verify in Sprint 3 with a carriage return written by App's saver: the reference command line tool's `search` and App both find the user name `a`, carriage return, `b` with `u:a?b`, `u:a*b`, `+u:a?b`, `+u:a*b` and the regular expressions `a.b` and `^a.b$` |
| Base group has searching off (`Archive` with the limit on) | No results |
| Root group named as the recycle bin by a hostile vault | App acts as if there is no bin (LD-76), so entries are searched normally |
| Query over 1,024 characters | QueryTooLong. Results unchanged (FEA-01.32) |
| Saved-search item is not valid JSON | No saved searches are listed. Nothing crashes (FEA-01.29) |
| `is:expired-99999999999` (too large for a whole number) | Reads as 0 (not a number in range) |
| Entry whose username is `{PASSWORD}` | The default search matches the password text through the username (FEA-01.19). See Security notes |

## Security notes

- Default search never looks at the password or custom fields directly. But resolved placeholders can pull secret text into searched fields, for example a username of `{PASSWORD}` or `{S:secret field}`. Then typing the secret finds the entry. This is reference behavior, and App keeps it for parity. It reveals nothing new to the person holding the unlocked vault.
- `pw:`, `_Password:`, `attribute:` and `_name:` match protected values, including one-time password secrets. The match runs only in app-core, on secret types. No value, match position or resolved text goes to the screen or a log (FEA-01.33, SR-07, AT-C06, AT-E07).
- The query text can itself hold a secret the user typed (`pw:hunter2`). App never logs query text. It clears the text on lock (FEA-01.27, SR-01, SR-02) and keeps it only in the screen and the session. A saved search is stored only inside the encrypted vault.
- Hostile vaults can carry saved searches (AT-A08). They are bounded: length cap, a linear-time regex engine, size and nesting limits, and MOD-08's resolution bounds (FEA-01.32). A saved search never runs on its own. It runs only when the user clicks it.
- The optional clear-after-idle timer (FEA-01.27) is parity row SC-08 (option, off; 5 minutes; APP-01 S-TIME-05, S-TIME-06).
- Recycled entries stay out of results (FEA-01.21, SD-05), so a deleted secret does not resurface in a search.
- Attack AT-E01 applies to everything a result row shows. The query echo in the empty-state text is plain text, never markup.

## Test cases

Demo vault **S1** (password `demo`). Root group `Vault`, id 01×16. Ids are written as the repeated byte: "11×16" is 16 bytes of 0x11, so the uuid text is `1111…11`. Clock: 2026-10-25T12:00:00Z, Mac time zone UTC. Options at their defaults unless a row says otherwise.

| Entry | Group path (search flag) | Title | Username | Password | URL | Notes | Tags | Other |
|---|---|---|---|---|---|---|---|---|
| E1 11×16 | /Vault (inherit) | GitHub | alex@example.com | Tr0ub4dor&3 | https://github.com/login | `Work account` LF `recovery codes in safe` | work, dev | |
| E2 12×16 | /Vault | Gmail | alex.personal | hunter2 | https://mail.google.com | | personal | |
| E3 13×16 | /Vault/Banking (inherit) | Big Bank | alex99 | hunter2 | https://bigbank.example | PIN is not here | | custom `Account No` = `12345678`; custom `Security answer` = `blue whale` (protected); attachment `statement.pdf` |
| E4 14×16 | /Vault/Banking/Cards (inherit) | Visa Card | | 4111-1111 | | expires soon | finance | expires 2026-01-01T00:00:00Z |
| E5 15×16 | /Vault/Archive (**off**) | Old GitHub | alex | oldpass | https://github.com | | work | |
| E6 16×16 | /Vault/Recycle Bin (recycle bin, off) | Deleted GitHub | alex | | https://github.com/old | | | |
| E7 17×16 | /Vault/Dev & Ops (inherit) | Build server | `{REF:U@I:11111111111111111111111111111111}` | s3rver! | ssh://build.example:22 | Uses key | dev, ops | custom `otp` (protected) = `otpauth://totp/demo?secret=JBSWY3DPEHPK3PXP` |

Strength scores (FEA-05 password-only): Tr0ub4dor&3 46, hunter2 low, oldpass low, s3rver! 15. All rate below 75.

| Case | Given | When | Then |
|---|---|---|---|
| T01 FEA-01.13, FEA-01.20, FEA-01.21 | S1 | query `github` | E1 only. E5 (Archive is off) and E6 (bin) are left out. The command line tool, which ignores group search flags, lists E1 and E5, never the bin's E6 (INT-10, D-INT10-11) |
| T02 FEA-01.10 | S1 | `GITHUB` | E1 |
| T03 FEA-01.1, FEA-01.12 | S1 | `git hub` | E1 (both terms are substrings of `GitHub`) |
| T04 FEA-01.4, FEA-01.28 | S1 | `*` (All Entries) | E1, E2, E3, E4, E7 |
| T05 FEA-01.4 | S1 | `-`, then `title:`, then `x:` | E1, E2, E3, E4, E7 each time |
| T06 FEA-01.25 | S1, search showing | box set to empty, then to 3 spaces | Search ends both times. Normal list shown |
| T07 FEA-01.13 | S1 | `hunter2` | No results (password not a default field) |
| T08 FEA-01.5, FEA-01.13 | S1 | `pw:hunter2`; `p:hunter`; `pass:hunter`; `password:hunter` | E2, E3 each time |
| T09 FEA-01.19 | S1 | `u:alex` | E1, E2, E3, E7 (E7 through its reference to E1's username) |
| T10 FEA-01.6, FEA-01.19 | S1 | `_UserName:alex` | E1, E2, E3 (E7's stored text `{REF:…}` does not contain `alex`) |
| T11 FEA-01.6 | S1 | `_username:alex`; `_Security:blue`; `_:x` | No results each time |
| T12 FEA-01.6, FEA-01.13 | S1 | `_otp:JBSWY`; `_Password:hunter` | E7; then E2, E3 |
| T13 FEA-01.9 | S1 | `+u:alex99`; `+u:alex` | E3; then no results (E5, E6 out of scope) |
| T14 FEA-01.9, FEA-01.10 | S1 | `+t:github`; `+t:GitHub` | No results; then E1. Installed 2.7.11 gives E1 for both (differs in installed version) |
| T15 FEA-01.9 | S1 | `+t:Gmail\|Big`; `+t:"Big Bank\|Gmail"` | E2; then E2, E3 |
| T16 FEA-01.14 | S1 | `tag:work`; `tag:wor`; `tag:wor*`; `tag:WORK` | E1; none; E1; E1 |
| T17 FEA-01.14, FEA-01.13 | S1 | `dev`; `de` | E1, E7 (tag `dev`); then E1 only (`codes` in notes). E7's tag `dev` is not matched by `de` |
| T18 FEA-01.13 | S1 | `attr:blue`; `attr:Account`; `attr:pdf`; `attr:otpauth` | E3; E3; none; E7 |
| T19 FEA-01.5, FEA-01.13 | S1 | `attach:statement`; `a:pdf`; `at:pdf`; `att:pdf` | E3 each time |
| T20 FEA-01.15 | S1 | `g:Cards`; `g:Bank`; `g:/Banking`; `g:/Vault/Banking/Cards`; `g:Vault`; `g:Banking/Cards` | E4; E3; E3, E4; E4; E1, E2; E4 |
| T21 FEA-01.16 | S1 | `is:expired`; `i:EXPIRED` | E4 each time |
| T22 FEA-01.13 | S1 | `uuid:1414`; `uuid:` | E4; then E1, E2, E3, E4, E7 |
| T23 FEA-01.11 | S1 | `-github`; `!github`; `--github`; `-!github` | E2, E3, E4, E7 each time |
| T24 FEA-01.8, FEA-01.31 | S1 | `*t:^Git`; `*t:[`; `-*t:[` | E1; then no results and the invalid notice; then E1, E2, E3, E4, E7 and the invalid notice |
| T25 FEA-01.8 | S1 | `*u:^\w+$` | E3 (`alex99`). E1, E2 and E7 hold `@` or `.` |
| T26 FEA-01.5 | S1 | `foo:github`; `e:github`; `:github`; `https://github.com` | E1 each time |
| T27 FEA-01.5 | S1 | `tags:safe`; `tag:safe` | E1 (default search finds `safe` in notes); then no results |
| T28 FEA-01.5 | S1 | `TITLE:git`; `Url:bigbank`; `user:alex.p`; `us:alex.p` | E1; E3; E2; E2 |
| T29 FEA-01.7 | S1 | `t:G?tHub`; `t:Git*b`; `t:G?Hub` | E1; E1; none |
| T30 FEA-01.7 | S1 | `url:github.com`; `url:github?com`; `t:gmail\|bank` | E1; E1; E2, E3 |
| T31 FEA-01.7 | S1 | `\|`; `?` | E1, E2, E3, E4, E7 each time |
| T32 FEA-01.2 | S1 | `*hub`; `t:*hub`; `t:-git`; `url:build.example:22` | E1; E1; none; E7 |
| T33 FEA-01.3 | S1 | `"PIN is"`; `"PIN`; `"git" "hub"` | E3; none; E1 |
| T34 FEA-01.3, FEA-01.1 | S1 | `g:Dev & Ops`; `g:"Dev & Ops"` | None; then E7 |
| T35 FEA-01.7 | S1 | `n:account*recovery`; `n:"codes in"` | None (no crossing a line feed); then E1 |
| T36 FEA-01.18 | S1 | `has:totp`; `h:TOTP`; `!has:totp`; `has:foo` | E7; E7; E1, E2, E3, E4; none |
| T37 FEA-01.17, FEA-01.28 | S1 | `is:weak` (Weak Passwords view) | E1, E2, E3, E7 (E4 expired; E5, E6 out of scope) |
| T38 FEA-01.11, FEA-01.9 | S1 | `+-t:Gmail` | E1, E3, E4, E7 |
| T39 FEA-01.20 | S1 plus group `/Vault/Archive/Keep` (search **on**) holding E8 `Keep me` | `keep` | E8 (on below off is searched). E5 is still left out |
| T40 FEA-01.21 | S1, but the bin's flag is inherit | `github`; `-is:expired` | App: E1; then E1, E2, E3, E7. The reference: E1, E6; then E1, E2, E3, E6, E7 |
| T41 FEA-01.23 | S1, `search.limit_to_group` on, group `Banking` selected | `*` | E3, E4 |
| T42 FEA-01.23, FEA-01.20 | S1, limit on, `Archive` selected | `github` | No results (Archive is off) |
| T43 FEA-01.23 | S1, query `*` active, limit off | user selects group `Cards` | Search ends, box empty, list shows E4 |
| T44 FEA-01.23 | S1, query `*` active, limit on, `Banking` selected | user selects `Cards` | Search runs again: E4 |
| T45 FEA-01.22 | S1 | core search `alex` | Ids in order E1, E2, E3, E7. The reference's screen shows E3 (Banking), E7 (Dev & Ops), E1, E2 (Vault). App's screen: the list sort |
| T46 FEA-01.24 | S1, `search.case_sensitive` on | `gmail`; `Gmail`; then App restarts and `gmail` is run | None (the URL holds `mail.google`, not `gmail`); E2; E2 (option back to off) |
| T47 FEA-01.26 | S1, query `pw:hunter` showing E2, E3, with E2 selected | E2's password is changed to `x` | Results: E3, and E3 is selected |
| T48 FEA-01.27 | S1, query `github` active | vault locks, then unlocks | Search box empty, normal list |
| T49 FEA-01.27 | `search.clear_when_idle` on, 5 minutes; query typed | focus leaves the box at 12:00:00 | Box cleared at 12:05:00. If focus returns at 12:03:00, nothing is cleared |
| T50 FEA-01.25 | `search.enter_to_search` on | user types `gmail` | No search until Return. After Return: E2 |
| T51 FEA-01.25, FEA-01.28, FEA-01.35 | `search.enter_to_search` on | user clicks tag `work` | Runs at once: the exact tag term `work` gives E1; the box shows `tag:"work"` |
| T52 FEA-01.28, FEA-01.35 | Vault with tag `say "hi"` on entry Q | click on that tag | Exact tag term `say "hi"`. Result: Q (the reference builds `tag:"say \"hi\""`, also Q) |
| T53 FEA-01.28, FEA-01.35 | S1 | tags `work` and `dev` both selected | Two exact tag terms, both required. Result: E1 |
| T54 FEA-01.28 | S1, MOD-09 show-expired-on-unlock on, offset 0, limit option on with `Dev & Ops` last selected | unlock | Query `is:expired-0` over the whole vault: E4 (in `Cards`, outside the selected group), under the expired-entries title |
| T55 FEA-01.28 | Same, but no expired entries | unlock | No search active, normal list |
| T56 FEA-01.29 | S1 | save query `tag:work` as `Work stuff` | Vault custom-data item (FMT-14) holds the JSON object {"Work stuff": "tag:work"}. Sidebar lists `Work stuff` after the built-in views |
| T57 FEA-01.29 | Saved `Zeta` and `alpha` | sidebar | Order: `Zeta`, `alpha` |
| T58 FEA-01.29 | Saved `Work stuff` | save `tag:dev` under `Work stuff`; then save with an empty name; then remove `Work stuff` | Value becomes `tag:dev`; nothing changes; the object becomes {} |
| T59 FEA-01.29 | Saved-search item holds `[1,2]` | open vault, then save `x` as `A` | No saved searches listed. After the save the item holds {"A": "x"} |
| T60 FEA-01.32 | Saved search whose query is 2,000 characters | click it | QueryTooLong notice. Results unchanged. No hang |
| T61 FEA-01.32 | S1 | `*t:(a+)+$`, with E1's title set to 40 × `a` + `!` | Returns in under 50 ms with no results |
| T62 FEA-01.32 | S1 | `*t:(?=Git)G` (look-ahead) | App: invalid notice, no results. The reference: E1 (accepted difference) |
| T63 FEA-01.33 | S1 | `pw:hunter2`, while the screen's command traffic is recorded | Only ids of E2 and E3 cross. No password text |
| T64 FEA-01.34 | Generated vault: 10,000 entries | `user:alex -tag:work *n:\d{4} is:weak g:/Vault` | Under 50 ms |

Demo vault **S2** (all entries in root `Root`, flags inherit; clock 2026-10-25T12:00:00Z, zone UTC):

| Entry | Fields |
|---|---|
| F1 | title `Éclair Café`, username `chef` |
| F2 | title `trail` + LF, notes `hello` + LF |
| F3 | title `Ref test`, username `{PASSWORD}`, password `zebra42` |
| F4 | title `Straße` |
| F5 | title `Soon`, expires 2026-10-30T12:00:00Z |
| F6 | title `Later`, expires 2026-11-30T12:00:00Z |
| F7 | title `Notes ref`, notes `{TITLE}` |
| F8 | id AB×16, title `Hexy` |
| F9 | title `Emoji 🔑 key` |
| F10 | title `c++ notes`, notes `-5 degrees` |

| Case | Given | When | Then |
|---|---|---|---|
| T65 FEA-01.10 | S2 | `éclair`; `ÉCLAIR`; `CAFÉ` | F1 each time |
| T66 FEA-01.10 | S2 | `straße`; `STRAßE`; `STRASSE` | F4; F4; none |
| T67 FEA-01.9 | S2 | `+t:trail`; `+n:hello`; `+n:"hello"` | F2 each time |
| T68 FEA-01.19 | S2 | `zebra42`; `u:zebra` | F3 each time (username resolves to the password) |
| T69 FEA-01.19 | S2 | `n:TITLE`; `n:Notes` | F7; none (notes are not resolved) |
| T70 FEA-01.16 | S2 | `is:expired`; `is:expired-5`; `is:expired-6` | None; none (12:00 on the 30th is not before 12:00 on the 30th); F5 |
| T71 FEA-01.16 | S2 | `is:expired-36`; `is:expired-37`; `is:EXPIRED-6`; `is:expiredxyz`; `is:expired-abc` | F5; F5, F6; F5; none; none |
| T72 FEA-01.13, FEA-01.9 | S2 | `uuid:abab`; `uuid:ABAB`; `+uuid:` + 32 × `AB` | F8; F8; none (exact is case-sensitive, ids are lowercase). Installed 2.7.11 gives F8 (differs in installed version) |
| T73 FEA-01.7 | S2 | `t:Emoji???key`; `t:Emoji??key`; `🔑` | F9; none; F9 |
| T74 FEA-01.2, FEA-01.3 | S2 | `c++`; `-5`; `"-5"` | F10; every entry except F10; F10 |
| T75 FEA-01.1 | S1 | `t:GitHub` + TAB + `Gmail` | No results (tab is part of the value) |
| T76 FEA-01.30 | S1 | `pw:hunter2`; then `<b>zzz</b>`; then the Expired view | List title for search results with count 2; then the empty state naming titles, usernames, URLs, notes and tags, with the query shown as plain text (AT-E01); then the title Expired with count 1 |
| T77 FEA-01.35 | Vault: entry R with tag `a\`, entry S with tag `a`, entry U with tag `a\"b` | click `a\`; then click `a\"b` | R only; then U only (the reference's text search differs for both) |
| T78 FEA-01.35 | Vault: entry G1 with tag `Work`, entry G2 with tag `work`, entry G3 with tag `x*`, entry G4 with tag `xyz` | click `work`; then click `x*` | G2 only (the reference: G1 and G2); then G3 only (the reference: G3 and G4) |
| T79 FEA-01.21 | S1, plus group B2 inside the recycle bin with its own search flag on, holding entry E12 titled `github bin` | `github` | App: E1 only. The reference: E1 and E12 (LD-57) |

## How this was learned

- Read in the reference source: the entry search engine and its term parser, the toolkit-level helper that turns a term into a regular expression (escaping, wildcards, exact anchors, case flag), and the group routines for tree order, search-flag inheritance, recycled state and the group path. Also read the main vault screen's search flow (base group, limit option, banner text, live refresh, ending a search, the expired-on-unlock search, saved-search save and delete), the search box widget (pause timer, Enter option, clear-after-idle timer, Escape, the search menu), the search help popup, the sidebar model for built-in views, saved searches and tags, the entry list's search-mode sort, the metadata routines for saved searches, the password health routines used by `is:weak`, the placeholder resolver, the Auto-Type picker and command line callers, and the Linux secret-service caller. Read the reference unit tests for the search engine.
- Compared the source with installed version 2.7.11 by reading the change history of those files. Two differences: in 2.7.11, `+` does not force case-sensitive matching (FEA-01.9), and the statistics additions of FEA-07 are missing.
- Observed with the installed command line tool (2.7.11), whose search ignores group search flags, on demo vaults built in `/tmp/spec-fea01-07/` from generated XML documents and imported with password `demo`. Seen this way: every S1 and S2 query above (results without the flag filter), tag whole-match, `tags:` not an alias, unknown and empty fields, modifier placement, quoting and unterminated quotes, wildcard and line-feed behavior, `?` as one code point, the trailing-line-feed exact match, Unicode case folding, placeholder resolution in username but not notes, `is:expired-N` boundaries, `is:weak` excluding expired and excluded entries, `has:totp`, invalid expressions (a warning on the error stream, no results), and `uuid:`.
- Not observed, from source only: group-flag filtering, the limit option and all screen behavior (the reference window was not launched).
- Mockup read: search box, search tips, list title and count, empty-state text, and that search covers all entries except the recycle bin's and follows the list sort.

### Not on Mac

- Linux secret-service lookups use this search engine with these settings: protected fields skipped, group flags ignored, and each attribute compared as an exact, case-sensitive literal. An empty attribute set there matches nothing. App has no secret-service bridge.
