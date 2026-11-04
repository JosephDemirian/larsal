# INT-05 Auto-Type sequences, placeholders and window matching

Status: reviewed (LD-176, LD-177)
Epics: E8-S1 (sequence language, placeholders, limits: INT-05.1 to INT-05.18; fuzz target; AT-G03), E8-S2 (candidates, window matching, global Auto-Type, picker, shortcut, remembered choice, typing from App's window, the editor page and the settings page: INT-05.19 to INT-05.36; AT-G01), E8-S3 (typing on macOS, focus checks, the Accessibility permission: INT-05.37 to INT-05.47; AT-G02). Card written in E1-S6.
Parity rows: SI-06, SI-14, SD-05, SD-08 (the AT-G03 part), SR-16 (the picker closes on lock), SI-12 (start with a search term only)

## What it does

Auto-Type types an entry's sign-in into another app as if the user typed it on the keyboard. What it types is a **sequence**: a short text such as `{USERNAME}{TAB}{PASSWORD}{ENTER}` that mixes plain characters, key names (`{TAB}`), commands (`{DELAY 500}`) and placeholders (`{USERNAME}`, resolved by MOD-08).

There are two ways to start it:
- **Global Auto-Type.** The user presses App's global shortcut while another app is in front. App reads the title of the window in front, finds the entries whose window rules, title or URL fit it, and either types the one match or shows a small picker over the other app. The picker also searches every unlocked vault.
- **From App's window.** The user picks an entry and chooses Type Login (⇧⌘V), Auto-Type Username Only or Auto-Type Password Only (APP-08). App asks first (by default), hides itself, and types into the app that was in front before.

On macOS, typing into another app needs the Accessibility permission. App posts keyboard events for every key; plain text goes as Unicode key events, never through the clipboard. Before every key, App checks that the same app and the same window are still in front; if not, it stops at once.

This card owns: the sequence language and its limits; which entries are candidates; window matching; the global flow and the picker; the global shortcut; the remembered choice; typing from App's window; the Auto-Type page of the entry editor and the Auto-Type page of settings; typing on macOS and the permission flow.

Neighbor cards: MOD-08 (placeholders and references inside sequences, window rules, titles and URLs), MOD-01.18 (the entry's Auto-Type block), MOD-02.14 to MOD-02.16 (the group switch and the sequence inheritance), MOD-04 and LD-57 (the recycle bin), MOD-09 (expired entries), FEA-01 (the picker's search), FEA-04 (one-time codes), FEA-08.59 (version 1 Auto-Type lines), FMT-11.24 (the Auto-Type block in the file), APP-01 (S-AT-01 to S-AT-10), APP-02.14 (lock again after Auto-Type), APP-03 (the picker's copy actions), APP-06 (the unlock panel, M06-40), APP-08 (menu items and shortcuts), APP-10 (secure input, screen-capture protection), INT-01 (the browser bridge's "start Auto-Type" request).

Public facts a Builder needs: Apple's macOS virtual key codes (Carbon `HIToolbox/Events.h`, `kVK_*`; values in INT-05.6 were read from the macOS 26.6 SDK on this Mac), Quartz Event Services (keyboard events, Unicode strings, event sources, flags), the Accessibility API (trust check, focused window, window title), Carbon hot keys, and the Text Input Sources keyboard layout data.

## Inputs and outputs

**In.** The chosen entry or the candidates of every unlocked vault; their fields, Auto-Type blocks (MOD-01.18) and groups (MOD-02); the settings S-AT-01 to S-AT-10 (APP-01); the app and window in front, with its title; the current keyboard layout; the clock (for `{TOTP}` and the remembered choice); the Accessibility permission state.

**Out.** Keyboard events posted to macOS; the picker panel; the pick-characters dialog; the messages of this card; copies to the clipboard from the picker (APP-03).

**Settings** (APP-01, General › Auto-Type): S-AT-01 match by title (on), S-AT-02 match by URL (on), S-AT-03 always ask (on), S-AT-04 don't ask from the main window (off), S-AT-05 skip expired (off), S-AT-06 lock again (off), S-AT-07 global shortcut (App: ⌃⌥V, D-INT05-10), S-AT-08 remember the choice (15 s), S-AT-09 start delay (500 ms), S-AT-10 key pause (25 ms).

**Limits** (the reference's unless marked App):

| Limit | Value | Rule |
|---|---|---|
| Repeat count of a key token | 0 to 100 | INT-05.6 |
| `{DELAY n}` | 0 to 10,000 ms | INT-05.7 |
| `{DELAY=n}` and the key pause S-AT-10 | 0 to 500 ms | INT-05.7 |
| Start delay S-AT-09 | 100 to 10,000 ms | INT-05.7 |
| Remembered choice S-AT-08 | 0 to 60 s | INT-05.31 |
| Keys typed in one run (App) | 10,000 | INT-05.16 |
| Sum of `{DELAY n}` in one run (App) | 60,000 ms | INT-05.16 |
| Field length for `{PICKCHARS}` (App) | 256 characters | INT-05.10 |
| Waiting for the target app to come to front (App) | 2 s | INT-05.38 |
| Waiting for the user to let go of modifier keys (App) | 2 s | INT-05.38 |
| Token text shown in a message | first 40 characters | INT-05.18 |

### Messages

Our own words. `‹…›` is filled in at run time.

| ID | Where | Rule | Text |
|---|---|---|---|
| MI05-10 | alert title, with one reason below | INT-05.15 | Auto-Type stopped |
| MI05-11 | reason | INT-05.2 | A { or } has no partner. |
| MI05-12 | reason | INT-05.6, INT-05.17 | ‹token› repeats more than 100 times. |
| MI05-13 | reason | INT-05.7 | ‹token› waits longer than 10 seconds. |
| MI05-14 | reason | INT-05.7 | ‹token› pauses more than 500 ms between keys. |
| MI05-15 | reason | INT-05.7 | ‹token› needs a number. |
| MI05-16 | reason | INT-05.9 | The one-time code settings of this entry are not valid. |
| MI05-17 | reason | INT-05.10 | ‹token› names a field this entry doesn't have. |
| MI05-18 | reason | INT-05.10 | ‹token›: the field has more than 256 characters to pick from. |
| MI05-19 | reason | INT-05.13 | ‹token› is not a placeholder App knows. |
| MI05-20 | reason | INT-05.13 | ‹token› is not a conversion App can use. |
| MI05-21 | reason | INT-05.16 | The sequence has more than 10,000 keys, waits and pauses. |
| MI05-22 | reason | INT-05.16 | The waits in the sequence add up to more than 60 seconds. |
| MI05-23 | reason | INT-05.42 | ‹character› can't be typed with ‹modifiers› on this keyboard layout. |
| MI05-24 | reason | INT-05.3 | ‹modifiers› at the end of the sequence have no key to go with. |
| MI05-25 | reason | INT-05.3, R05-2 (LD-177) | ‹sequence› has braces nested more than 32 deep. |
| MI05-26 | reason | R05-4 (LD-177) | ‹key› is App's own Auto-Type shortcut. |
| MI05-27 | reason | R05-7 (LD-177) | ‹placeholder› refers to itself or grows too large. |
| MI05-30 | alert | INT-05.44 | Title: App needs Accessibility access. Text: To type into other apps, turn on App in Privacy & Security › Accessibility, then try again. Buttons: Open Privacy & Security (default), Cancel |
| MI05-31 | settings notice, on (frame) | INT-05.35 | **Accessibility access is on.** macOS lets App type into other apps. Open Privacy & Security |
| MI05-32 | settings notice, off | INT-05.35 | **Accessibility access is off.** App can't type into other apps until you turn it on. Open Privacy & Security |
| MI05-33 | shortcut field error | INT-05.30 | Another app already uses this shortcut. |
| MI05-34 | shortcut field error | INT-05.30 | A shortcut needs ⌘ or ⌃. |
| MI05-35 | shortcut field error | INT-05.30 | App already uses this shortcut for ‹menu item›. |
| MI05-36 | shortcut field error | INT-05.30 | macOS didn't accept this shortcut. Choose another one. |
| MI05-40 | picker header (frame) | INT-05.26 | Type into “‹window title›”; when the title is empty: Type into ‹app name› |
| MI05-41 | picker search placeholder (frame) | INT-05.26 | Search all entries… |
| MI05-42 | picker, right side of the highlighted row (frame) | INT-05.26 | Type login ⏎ |
| MI05-43 | picker hint line (frame) | INT-05.26 | ↑↓ to choose · ⏎ types username, password and code · ⇧⏎ types the password only |
| MI05-44 | picker row menu | INT-05.29 | Type Username (⌘1), Type Password (⌘2), Type One-Time Code (⌘3), Type URL (⌘4), Type with Key Codes (⌘5), separator, Copy Username (⇧⌘1), Copy Password (⇧⌘2), Copy One-Time Code (⇧⌘3), Copy URL (⇧⌘4) |
| MI05-45 | picker, empty list | INT-05.27 | No entries match. Type to search all entries. |
| MI05-50 | question before typing from App's window | INT-05.33 | Type “‹entry title›” into ‹app name›? Buttons: Type (default), Cancel |
| MI05-51 | editor switch description | INT-05.34 | With a shortcut (frame): Types the sign-in into the window in front when you press ‹shortcut›. Without one: Choose a shortcut in Settings › Auto-Type to type this sign-in into other apps. |
| MI05-52 | editor save question | INT-05.34 | The Auto-Type sequence has an error: ‹reason›. For a window row: The Auto-Type sequence for “‹window text, first 40›” has an error: ‹reason›. Buttons: Fix It (default), Save Anyway |
| MI05-60 | pick-characters dialog | INT-05.36 | Title: Pick Characters. Text: Each button stands for one character of the field, by its position. ⌘S types the ones you picked. Check box: Add a Tab after each character. Buttons: Type (default), Cancel |

## Rules

### Sequence language (E8-S1)

INT-05.1 **Where a sequence comes from.** Global Auto-Type types the sequence of the picker row or the single match (INT-05.23). Type Login from App's window types the entry's effective sequence (MOD-02.16). The fixed actions type fixed sequences: Auto-Type Username Only `{USERNAME}`, Auto-Type Password Only `{PASSWORD}`, the picker's ⇧⏎ `{PASSWORD}`, and the picker menu items `{USERNAME}`, `{PASSWORD}`, `{TOTP}`, `{URL}`. The built-in default `{USERNAME}{TAB}{PASSWORD}{ENTER}` and its two shorter forms (`{PASSWORD}{ENTER}` when the username is empty, `{USERNAME}{ENTER}` when the password is empty) come from MOD-02.15 and MOD-02.16. A version 1 import fills sequences and window rules from notes lines (FEA-08.59).

INT-05.2 **Literal braces and the brace count.** Before anything else, every `{{}` in the sequence becomes a literal `{` and every `{}}` a literal `}`. Then the number of `{` must equal the number of `}` in what is left; otherwise the sequence fails with MI05-11. This is only a count: `}{` passes it (INT-05.3 types both as characters).

INT-05.3 **Tokens.** The sequence is read from left to right as tokens. A token is an optional run of modifier characters followed by either a brace token or one character.
- Modifier characters: `+` Shift, `^` Control, `%` Option, `#` Command. A modifier repeated in one run counts once. On macOS `^` is the Control key and `#` the Command key, as in the reference.
- A brace token is `{`, then one or more items, then the matching `}`. An item is one character that is not a brace, or a nested brace group that is itself balanced and not empty. So `{T-CONV:/{USERNAME}/upper/}` is one token.
- A `{` that does not start a brace token (as in `{}`) is a character token, and so is a `}` with no `{` before it.
- A run of modifier characters at the very end, with nothing after it, fails with MI05-24 (App, D-INT05-13; the reference types the last of them as a character).

INT-05.4 **Character tokens.** A character outside braces is typed as that character (INT-05.40). Every character counts as itself, `~` and `@` included (no character outside braces means Enter). With modifiers in front, the token is a key combination (INT-05.42).

INT-05.5 **Brace token names.** The text between the outer braces is the token's content. Names are compared ignoring case (`{tab}`, `{Tab}` and `{TAB}` are the same). When the content is a name, then one or more spaces, then digits, the digits are the token's count. Only key names and `DELAY` use a count; `CLEARFIELD`, `TOTP`, `TIMEOTP`, `PICKCHARS` and `MODE=` ignore it; a placeholder keeps the digits as part of its text and is resolved as written (INT-05.13), so `{USERNAME 2}` is unknown while `{S:Field 2}` names the field `Field 2`. The content is tested in this order: a key name with or without count (INT-05.6); `DELAY` with a count, or `DELAY=` (INT-05.7); `CLEARFIELD` (INT-05.8); `TOTP` or `TIMEOTP` (INT-05.9); `PICKCHARS`, alone or followed by `:` (INT-05.10); `MODE=` (INT-05.11); an ignored command (INT-05.12); anything else is a placeholder (INT-05.13).

INT-05.6 **Key names.** A key token presses one key, count times (count 1 when none is given, 0 types nothing). A count above 100 fails with MI05-12. Modifiers in front apply to every press (`+{TAB}` is Shift+Tab). App's macOS keys (D-INT05-13 for the rows where App differs from the reference on Mac):

| Names | Key App presses (virtual key code) | The reference on Mac |
|---|---|---|
| `TAB` | Tab (0x30) | same |
| `ENTER` | Return (0x24) | same |
| `SPACE` | Space (0x31) | same |
| `UP`, `DOWN`, `LEFT`, `RIGHT` | arrows (0x7E, 0x7D, 0x7B, 0x7C) | same |
| `HOME`, `END`, `PGUP`, `PGDOWN`, `PGDN` | Home (0x73), End (0x77), Page Up (0x74), Page Down (0x79) | same |
| `BACKSPACE`, `BS`, `BKSP` | Delete (0x33) | same |
| `DELETE`, `DEL` | Forward Delete (0x75) | same |
| `ESC` | Escape (0x35) | same |
| `HELP` | Help (0x72) | same |
| `CAPSLOCK` | Caps Lock (0x39) | same |
| `WIN`, `LWIN` | Command (0x37) | same |
| `RWIN` | right Command (0x36) | left Command |
| `F1` to `F16` | 0x7A, 0x78, 0x63, 0x76, 0x60, 0x61, 0x62, 0x64, 0x65, 0x6D, 0x67, 0x6F, 0x69, 0x6B, 0x71, 0x6A | same |
| `NUMPAD0` to `NUMPAD9` | keypad 0 to 9 (0x52 to 0x59, 0x5B, 0x5C) | the digit keys of the main row |
| `ADD`, `SUBTRACT`, `MULTIPLY`, `DIVIDE` | keypad + (0x45), − (0x4E), × (0x43), ÷ (0x4B) | `ADD` and `MULTIPLY` press nothing; `SUBTRACT` and `DIVIDE` press the main-row keys at the US positions of - and / |
| `INSERT`, `INS`, `BREAK`, `NUMLOCK`, `PTRSC`, `SCROLLLOCK`, `APPS` | nothing (no such key on a Mac); accepted without error | same |
| `LEFTBRACE`, `RIGHTBRACE`, `LEFTPAREN`, `RIGHTPAREN` | the characters `{`, `}`, `(`, `)` as text (INT-05.40) | nothing; so `{{}` and `{}}` type nothing on Mac (found by reading the macOS key table) |
| `(`, `)`, `[`, `]`, `+`, `%`, `^`, `~`, `#` | that character as text | same |

So `{+ 3}` types `+++`, and `{(}` types `(`.

INT-05.7 **Waits and the key pause.**
- `{DELAY n}` waits n milliseconds at that point. n above 10,000 fails with MI05-13.
- `{DELAY=n}` sets the pause after each later key to n milliseconds. Spaces between `=` and n and after n are allowed: `{DELAY= 50}` sets 50 ms (App; the reference reads ` 50` there as a count and sets 0). A space before `=` makes the token no command: `{DELAY = 5}` is an unknown placeholder (INT-05.13), as in the reference. n above 500 fails with MI05-14.
- Without digits (`{DELAY}`, `{DELAY=abc}`) the token fails with MI05-15 (App, D-INT05-13; the reference waits 1 ms, or sets the pause to 0).
- Every run starts with the pause S-AT-10, used clamped to 0 to 500 ms, and waits the start delay S-AT-09, used clamped to 100 to 10,000 ms, before the first key (INT-05.38). App's settings control for S-AT-10 offers 0 to 500 (D-INT05-14).

INT-05.8 **`{CLEARFIELD}`.** Presses ⌘A (Command with the key that types `a` on the current layout, INT-05.42), then Delete (0x33), each followed by the key pause. A count is ignored. (App, D-INT05-6; the reference sends Control with ←, Control-Shift with →, then Delete.)

INT-05.9 **`{TOTP}` and `{TIMEOTP}`.** Types the entry's current one-time code (FEA-04), computed at the moment typing reaches the token, so waits and pauses before it are counted exactly (App, D-INT05-8). An entry with no one-time password types nothing. An entry whose one-time settings are not valid fails the whole sequence with MI05-16 before any key is typed (FEA-04; this is stricter than MOD-08.12 on purpose: a sign-in typed without its code and then submitted is worse than none).

INT-05.10 **`{PICKCHARS}`.** Lets the user pick single characters of a field, for sites that ask for "characters 2, 5 and 7 of your password".
- `{PICKCHARS}` picks from Password. `{PICKCHARS:Name}` picks from the field Name; the name is everything after the first `:`, exact, case included, as MOD-08.7, standard field names included. So `{PICKCHARS:Pin:C=2}` looks for a field named `Pin:C=2` (as in the reference; an option list is not part of App's language).
- A field the entry does not have fails with MI05-17. A field whose resolved value (MOD-08, unmasked) is empty types nothing and shows no dialog. A resolved value longer than 256 characters fails with MI05-18 (App, D-INT05-7).
- Before typing starts, App shows the pick dialog (INT-05.36) once for each such token, in sequence order. The chosen characters are typed in the order picked; with "Add a Tab after each character" on, a Tab follows every character except the last.
- Cancel in the dialog stops the whole Auto-Type: nothing is typed (App, D-INT05-9; the reference types the rest of the sequence without those characters).

INT-05.11 **`{MODE=…}`.** `{MODE=VIRTUAL}` switches the following text to key-code typing (INT-05.41); `{MODE=NORMAL}`, or any other text after `MODE=`, switches back to Unicode typing (INT-05.40). The text ends with `VIRTUAL` in any case for the first form.

INT-05.12 **Ignored commands.** `{BEEP …}`, `{VKEY …}` and `{VKEY-EX …}`, `{APPACTIVATE …}` and comments `{C:…}` are accepted and type nothing (the reference does the same; D-INT05-11). The name is matched at the start of the content, ignoring case.

INT-05.13 **Placeholders.** Any other brace token is resolved with MOD-08, as one span, in the entry's context, unmasked (MOD-08.23 masks only for display).
- If the result equals the token text exactly, the token is unknown and the sequence fails with MI05-19. So `{FOO}`, `{USERNAME 2}` (MOD-08 knows no `USERNAME 2`), the lowercase `{s:Name}` and `{ref:…}` (MOD-08.3) fail. A custom field that does not exist, `{S:Missing}`, resolves to empty and types nothing without error (MOD-08.7).
- A custom field whose name ends in a space and digits works: `{S:Field 2}` types the field `Field 2`.
- Conversions are checked before they are resolved: `{T-CONV:…}` needs at least 4 parts, no line feed and a known type (MOD-08.21), and `{T-REPLACE-RX:…}` needs at least 5 parts and a pattern App can use (MOD-08.22, LD-110, LD-113, LD-123); otherwise the sequence fails with MI05-20, as in the reference (MOD-08 alone would give an empty result).
- Field references, URL parts, dates, `{DB_DIR}` and `{UUID}` work as MOD-08 says.

INT-05.14 **Typing resolved text.** The characters of a resolved value are typed one by one (INT-05.40): a line feed presses Return; a carriage return followed by a line feed presses Return once; a lone carriage return presses Return; a tab character presses Tab; every other control character (U+0000 to U+001F, U+007F) is dropped (App, D-INT05-13). Modifiers in front of a placeholder are ignored: `+{USERNAME}` types the username as written.

INT-05.15 **Check first, then type.** A run reads the whole sequence, resolves every placeholder, shows every pick dialog and checks every limit before the first key goes out (the one-time code, INT-05.9, is the only value computed later). Any failure stops the run with MI05-10 and its reason, and nothing is typed. The editor's check (INT-05.34) uses the same reader against the entry being edited, without dialogs and without typing; it checks that pick fields exist but does not test their length.

INT-05.16 **Bounds of one run** (App, D-INT05-7, AT-G03). One run types at most 10,000 actions (keys, waits and pauses; LD-186): every press counts, repeats, resolved characters and the two presses of `{CLEARFIELD}` included. Above that, MI05-21. The `{DELAY n}` waits of one run add up to at most 60,000 ms; above that, MI05-22. Reading a sequence takes time in proportion to its length; placeholder resolution keeps the bounds of MOD-08.18 to MOD-08.20; patterns keep the linear-time engine of LD-110.

INT-05.17 **Counts are plain numbers.** A count is decimal digits only. A count above a token's limit fails with that token's message, also when it has too many digits to read as a number (App, D-INT05-7; the reference reads such a count as 0, so `{TAB 99999999999}` types nothing and `{DELAY 5000000000}` passes its check).

INT-05.18 **What a message may show.** A reason names the token as written in the sequence, cut to its first 40 characters, or a modifier run, or one character from the sequence text (MI05-23). It never shows a resolved value, a window title or a field value.

### Candidates and window matching (E8-S2)

INT-05.19 **Candidates.** An entry may be offered or typed only when all of these hold: it is a live entry (never a history item) of an unlocked vault; its own Auto-Type flag is on (MOD-01.18); its group's effective Auto-Type switch is On (MOD-02.14); it is not in the recycle bin, whatever any flag says (LD-57, SD-05); it is not expired when S-AT-05 is on (MOD-09.16); its effective sequence (MOD-02.16) is not empty (App, D-INT05-13: a group set On below a group set Off with no sequence of its own gets an empty sequence by MOD-02.15; the reference offers such an entry and then types nothing). The same rule enables the three menu items of INT-05.33.

INT-05.20 **Window rules.** Each window association of an entry holds a window text and a sequence (MOD-01.18, FMT-11.24). The window text is resolved first (MOD-08, entry context). Then:
- A window text that is empty as stored is an **empty-window rule** (INT-05.23).
- A resolved text of at least 4 characters that starts with `//` and ends with `//` is a **pattern**: the text between them is a regular expression, matched anywhere in the title, ignoring case. App uses its linear-time engine with the bounds of MOD-08.22 (LD-110, LD-113); a pattern that is invalid there (lookahead, lookbehind, back-references, LD-123) matches nothing and shows no error. `////` is an empty pattern and matches every title (as in the reference).
- Any other resolved text is a **wildcard**: `*` matches any run of characters, none included; every other character matches itself, `?`, `|` and `.` included; the whole title must match; case is ignored (Unicode simple case folding).

INT-05.21 **Title match** (S-AT-01, on). The entry's title, resolved (MOD-08), is not empty and occurs in the window title, ignoring case.

INT-05.22 **URL match** (S-AT-02, on). The entry's URL, resolved, is not empty and occurs in the window title, ignoring case; or the URL's host (MOD-08.9 `{URL:HOST}`) is not empty and occurs in the window title, ignoring case. A URL without a scheme has no host (MOD-08.9), so only the first test applies to it.

INT-05.22a **Matching bounds** (LD-195). A window title over 8,192 bytes is not matched. An entry text or row sequence over 65,536 bytes never matches. Row titles and user names are cut to 1,024 characters. A title pattern is at most 1,020 characters. A matching run that hits its work meter is marked limited, and then the picker always opens instead of typing directly.

INT-05.23 **Sequences of a matching entry.** For a window title, App collects an entry's sequences in this order: each window rule, in stored order, whose window matches: its sequence, or the entry's effective sequence when the rule's sequence is empty; then the effective sequence for a title match; then the effective sequence for a URL match. Only when at least one of these matched, App adds the sequence of every empty-window rule, in stored order, using the effective sequence for an empty one (App, D-INT05-13; the reference adds an empty sequence). Repeated sequences are dropped, keeping the first. Each remaining sequence makes one row (entry, sequence). An entry with no row does not match.

INT-05.24 **No title, no matching.** When the window in front has an empty title (INT-05.37), App does no matching and opens the picker (INT-05.25 step 7).

### Global Auto-Type (E8-S2)

INT-05.25 **Global flow.** It starts when the global shortcut is pressed (INT-05.30) or when the browser bridge asks for it with an optional search text (SI-12, INT-01). In order:
1. If App is the active app, nothing happens: Auto-Type never types into App.
2. If App is typing, a shortcut press stops the typing (INT-05.39) and nothing else happens; a bridge request is ignored. If the picker, a pick dialog or an unlock panel for Auto-Type is open, nothing happens.
3. App captures the target: the active app, its focused window and that window's title (INT-05.37).
4. Without the Accessibility permission, App follows INT-05.44 and stops.
5. With no vault open, App plays the system alert sound and stops. When the vault shown in App's window is locked, App opens the unlock panel (APP-06, M06-40). Cancel stops; after unlocking, the flow goes on with every unlocked vault.
6. App collects the candidates (INT-05.19) of every unlocked vault and the matching rows (INT-05.20 to INT-05.24).
7. App opens the picker (INT-05.26) when S-AT-03 is on, when the number of rows is not exactly 1, when the title is empty, or when a search text was given (App; the reference types a single match and drops the search text). Otherwise it types the single row (INT-05.38).

INT-05.26 **The picker panel** (frame `menubar-auto-type-picker`). A floating panel that does not make App the active app: the target app stays active while the panel takes the keyboard (D-INT05-3). It shows on the screen that holds the target window, centered near its top, above other windows, with screen-capture protection (APP-10.3). From top to bottom:
- A keyboard icon and the header MI05-40. Under it, in small grey text, the target app's name (App, D-INT05-16).
- The search field with MI05-41, which has the keyboard focus. A search text from the browser bridge is filled in.
- One row per (entry, sequence): the entry's icon, its title in bold and a small line with its username. Title and username are resolved for display (MOD-08.23: values from protected fields are masked). When an entry has more than one row, the small line adds ` · ‹sequence›`; when more than one vault is unlocked, it adds ` · ‹vault name›` (D-INT05-16). Expired entries are drawn struck through with the expired badge (MOD-09.14). The highlighted row shows MI05-42 on its right.
- The hint line MI05-43.
Rows are sorted by title, ignoring case, in the user's language order, then by username, then by sequence. When the list is empty, MI05-45 shows instead.

INT-05.27 **What the list holds.** With an empty search field: the matching rows; when there are none (no match, or an empty title), every candidate of every unlocked vault. With text in the field: the entries that the search language finds (FEA-01) in every unlocked vault, kept only when they are candidates; the list updates as the user types (App, D-INT05-3: the reference filters only the matches unless a "search all" box is ticked; the frame has no such box and its placeholder says "Search all entries"). A found entry that has matching rows shows those rows; any other found candidate gets one row for its effective sequence and one for each other distinct, non-empty sequence of its window rules, as the reference's search mode does.

INT-05.28 **Which row is highlighted.** When the remembered choice (INT-05.31) is in the list, its row: the row with the same vault, entry and sequence, else the first row of the same entry. Otherwise the first row. The same rule runs after every change of the search text.

INT-05.29 **Picker keys and actions.**
- ↑ and ↓ move the highlight by one; Page Up and Page Down by five; the highlight stops at the first and last row.
- Return, or a double-click on a row, types that row's sequence.
- ⇧Return types `{PASSWORD}` of the highlighted entry (App, from the frame's hint line; the reference has no such key).
- ⌘1, ⌘2, ⌘3 and ⌘4 type `{USERNAME}`, `{PASSWORD}`, `{TOTP}` and `{URL}` of the highlighted entry; ⌘5 types the row's sequence with key codes (INT-05.41).
- ⇧⌘1 to ⇧⌘4 copy the username, password, one-time code or URL (APP-03, `copy.autotype_*`), then close the picker without typing.
- The same actions are in the row's right-click menu (MI05-44). An item is disabled when its field is empty or the entry has no valid one-time code.
- Escape clears the search text; when it is already empty, Escape closes the picker without typing.
- The picker also closes without typing when the target app quits or another app becomes active, and when any vault locks (SR-16).
Every type action closes the picker first, then types (INT-05.38). When the picker closes without typing and App was made active for the unlock panel (INT-05.25 step 5), App asks macOS to bring the target app back to the front.

INT-05.30 **The global shortcut** (S-AT-07).
- Default ⌃⌥V (App, D-INT05-10; the reference has none). App registers it when it starts and again whenever the setting changes; it is removed at quit and when the user clears it. It works while App's window is hidden, while App lives only in the menu bar, and while every vault is locked.
- App uses the system's hot key service, which needs no permission and sees no other keys (it is not an event tap; no Input Monitoring).
- A valid shortcut is one key plus at least ⌘ or ⌃; ⌥ and ⇧ may be added. macOS 15 and later refuse hot keys whose only modifiers are ⌥ or ⌥⇧, so App refuses them itself, with MI05-34. A shortcut equal to one of App's own menu shortcuts (APP-08) is refused with MI05-35.
- When macOS refuses to register it, the field turns red with MI05-33 (already taken by another app) or MI05-36 (any other refusal); the value is still stored on OK and tried again at the next start (APP-01 S-AT-07, APP-01.3).
- Stored as the key's virtual key code plus the modifiers; shown with the character that key types on the current layout.
- Recording (the settings row's Change button): the next key with its modifiers becomes the shortcut; Escape cancels the recording; Delete clears the shortcut to none (D-INT05-16).

INT-05.31 **Remember the previous choice** (S-AT-08, the "type again" rule). When the user types a row from the picker (any type action of INT-05.29), App remembers the vault, the entry and the sequence typed, for S-AT-08 seconds (0 to 60, default 15). Each new choice from the picker starts the time again; 0 remembers nothing. While the choice is remembered, every picker highlights it (INT-05.28), so pressing the shortcut and then Return types the same sign-in again, for sites that ask for the username and the password on two pages. The rule never blocks, delays or skips typing. Typing a single match without the picker, and the actions of INT-05.33, remember nothing. A remembered choice is dropped when its vault locks. When the time ends, the wait of INT-05.32 ends too. (The locked settings frame labels this row "Do not type the same login again within", which says the opposite: D-INT05-12.)

INT-05.32 **Lock again after Auto-Type** (S-AT-06, off; APP-02.14). A vault unlocked through the unlock panel of INT-05.25 step 5 is locked again at the first of: the typing ends (finished or stopped), the picker closes without typing, the run fails before typing (INT-05.15), or the remembered-choice time ends.

### Auto-Type from App's window (E8-S2)

INT-05.33 **Type Login and the two field actions** (APP-08: Type Login ⇧⌘V, Auto-Type Username Only, Auto-Type Password Only; enabled for one selected entry that is a candidate, INT-05.19, and for the two field actions only when that field is not empty).
1. Without the Accessibility permission: INT-05.44, stop.
2. When S-AT-03 is on and S-AT-04 is off (both defaults), App asks MI05-50 with the entry's title (resolved for display) and the name of the app that was active before App. Cancel stops.
3. App hides itself (as ⌘H), so macOS brings the previous app to the front. After the start delay (S-AT-09), App captures the target (INT-05.37). If App is still the active app, or no app is, the run stops with the system alert sound.
4. App types (INT-05.38 to INT-05.43). App stays hidden afterwards.

### Screens (E8-S2)

INT-05.34 **The editor's Auto-Type page** (frame `editor-editor-auto-type`).
- A switch "Let Auto-Type use this entry" (LD-167; the frame's text "Auto-Type for this entry" is replaced) with the description MI05-51; it sets the entry's Auto-Type flag (MOD-01.18). While it is off, every other control on the page is disabled and keeps its value.
- **Sequence:** two choices. "Use the group's sequence" shows below it, in monospace, the sequence the entry types while it inherits (MOD-02.16 steps 3 and 4). "Custom sequence" holds a monospace text field and the hint "Placeholders: {USERNAME} {PASSWORD} {TOTP} {TAB} {ENTER} {DELAY 500}". Choosing Custom fills the field with the shown sequence when it is empty. Saving with Custom stores the field's text as the entry's default sequence; an empty custom text is stored empty, which means inherit (as MOD-02.6 for groups).
- **Windows:** the lead "Auto-Type also offers this entry in windows whose title matches." and a table with the columns "Window title" and "Sequence", one row per window rule in stored order. An empty sequence cell shows "Entry sequence" in grey. Each row has a trash button "Remove". "Add window" adds a row at the end and puts the focus in its title cell. While editing a title cell, App offers the titles of the windows of other apps (INT-05.37; only with the Accessibility permission). Rows whose two cells are both empty are dropped at save (as the reference).
- **Checks:** a custom sequence and each row's sequence are checked as the user types (INT-05.15); an error shows in red under the field or the row. At save, the first error asks MI05-52: Fix It shows the page with the field; Save Anyway saves as typed.
- In a history view every control is read only.

INT-05.35 **The Auto-Type page of settings** (frame `settings-settings-auto-type`), top to bottom:
- The Accessibility notice: MI05-31 when App has the permission, MI05-32 when it has not; the button opens Privacy & Security › Accessibility. App checks again whenever the page shows and when App becomes active.
- Shortcut: the row "Type the login for the window in front" with the shortcut in a key cap and the button Change (S-AT-07, INT-05.30).
- Matching: "Match by window title" (S-AT-01), "Match by website address in the title" (S-AT-02), "Always ask which entry to type" (S-AT-03), "Skip expired entries" (S-AT-05), "Lock again after typing" (S-AT-06).
- Timing: "Wait before typing" (S-AT-09, ms stepper, 100 to 10,000, step 100), "Pause between keys" (S-AT-10, ms stepper, 0 to 500, step 5), and the remembered-choice row (S-AT-08, s stepper, 0 to 60, step 1), labelled "Preselect the previous choice for" (APP-01's wording, D-INT05-12).
- S-AT-04 has no row in the frame (D-INT05-14).

INT-05.36 **The pick dialog.** A small App dialog (MI05-60) in front of the target app. One numbered button per character of the field (1 to n, ten per row; fifteen per row from 60 characters, twenty from 100); the characters themselves are never shown. Clicking a button, or Space on a focused button, adds that character to a masked field that shows one dot per pick. "Add a Tab after each character" is on when the dialog opens (as in the reference). The arrow keys move between the buttons; Delete removes the last pick; ⌘S or Type accepts; Cancel or Escape cancels (INT-05.10). The masked field is a password-kind field (APP-10.9), so secure input is on while the dialog has focus. The dialog closes as Cancel when any vault locks.

### Typing on macOS (E8-S3)

INT-05.37 **The target.** At capture App records: the process of the active app (never App itself), its focused window as an Accessibility element (macOS has no public call that gives a window number for it; INT-05.39 compares elements with the system's equality test, V-INT05-8), the window's title read through the Accessibility API (empty when the app has no focused window or gives no title), and the app's display name. App needs no Screen Recording permission for this (D-INT05-1). The window list offered in the editor (INT-05.34) comes from the same API.

INT-05.38 **Before the first key.**
1. If the target app is not the active app (after the picker, the unlock panel or the pick dialog), App asks macOS to make it active and waits until it is, at most 2 seconds; otherwise the run stops with the system alert sound.
2. App waits the start delay (S-AT-09). A run from App's window waited it already in INT-05.33 step 3 and does not wait again (as the reference: one start delay per run).
3. App waits until no modifier key (⇧, ⌃, ⌥, ⌘, Caps Lock aside) is physically held, at most 2 more seconds; if one is still held, the run stops with the system alert sound and types nothing (App: the user may still hold the shortcut's keys).
4. App makes sure its own secure input is off (APP-10.12).

INT-05.39 **The focus check, and stopping.** Before every key event App checks that the active app is still the target process and that its focused window is still the target window. If not, typing stops at once: no further key goes out, App plays the system alert sound and opens no window (AT-G02; D-INT05-2: the reference compares only the process, so another window of the same app still receives keys). Typing also stops at once when any vault locks (APP-02, which covers sleep, screen lock and user switch), when App quits, when the target app quits, and when the global shortcut is pressed again. Keys already typed are not undone. A stop never leaves a key held down: every key App pressed gets its key-up.

INT-05.40 **Text characters.** In normal mode each character is one Unicode scalar value sent as a key-down and a key-up event that carry it as their Unicode string (both UTF-16 units of a character outside the Basic Multilingual Plane go together in one event; App, the reference sends the two halves as two events), with key code 0 and no modifier flags. After each pair App waits the key pause. Text is never put on the clipboard (D-INT05-4). The entry's obfuscation value (MOD-01.18) is kept unchanged and does not change how App types.

INT-05.41 **Key-code typing** (`{MODE=VIRTUAL}`, picker ⌘5). For each character App looks in the current keyboard layout for a key that types exactly that character with one press, with no modifier, with ⇧, with ⌥ or with ⌥⇧ (dead keys do not count). Found: App presses that key with those modifiers. Not found: the character is typed as in INT-05.40. App reads the layout once per run: the current keyboard input source's layout, else the current ASCII-capable layout (D-INT05-5; the reference's key-code mode on Mac drops lower-case letters, types upper-case letters as lower case and `"` as `'`, found by reading its macOS key table).

INT-05.42 **Named keys and key combinations.** A named key (INT-05.6) is pressed by its virtual key code, with the token's modifier flags. A modifier with a character (`^a`, `#v`, `+%x`) presses the key that types the lower-case form of the character on the current layout without ⇧ or ⌥, with the token's modifier flags. When no key on the layout types it, the run fails with MI05-23 before any key is typed. (The reference uses fixed US key positions; on a French layout its `#a` presses the key that types `q`, which is ⌘Q, Quit. D-INT05-5.)

INT-05.43 **Event details.** Every event comes from a private event source, so the physical keyboard's modifier state never mixes in, and carries its modifier flags explicitly; key-down then key-up; posted to the login session's event tap (`kCGSessionEventTap`, Apple's Quartz Event Services), not to one process (LD-231 (1), LD-234 (2)). (MacPass uses a private source for the same reason; the reference uses none.)

INT-05.44 **The Accessibility permission.** App checks it at the start of every Auto-Type, global or from the window, and on the settings page. When it is missing, App asks macOS to show its own permission request (at most once per App run) and shows MI05-30; Open Privacy & Security opens the Accessibility pane; nothing is typed. Because App checks every time, no restart is needed after the user grants it (V-INT05-5). App asks for no other permission for Auto-Type: no Screen Recording (D-INT05-1), no Input Monitoring (INT-05.30).

INT-05.45 **Secrets stay in Rust.** Resolved field values, one-time codes and picked characters exist only in Rust secret types (AGENTS.md rule 4, Rust rule 3) and are wiped when the run ends. The Swift screen layer receives only the picker's display rows (INT-05.26) and sends back the user's choice (vault, entry, row or action), the pick dialog receives only the field's length and sends back positions, and the keyboard events that carry secret characters are made and posted on the Rust side (D-INT05-15). The keyboard layout (INT-05.41, INT-05.42) reaches Rust as one whole table (character to key and modifiers), so Swift never looks up a single character. The remembered choice (INT-05.31) holds ids only. The remembered choice (INT-05.28) holds entry ids and the sequence text, which holds placeholders and never values (LD-195).

INT-05.46 **One run at a time.** While a run is checking, waiting or typing, another Auto-Type request is ignored, except the global shortcut, which stops it (INT-05.39).

INT-05.47 **Logging.** A failure or a stop writes one debug log line, never a window title, a field value, a sequence text or a picked position (LD-67, LD-88, Rust rule 9). A stop names its reason code and the keys typed: `Auto-Type stopped: ‹code› after ‹n› keys` (`not-in-front`, `keys-held`, `window-changed`, `stopped`, `no-event-source`). A failure names only its MI05 id: `Auto-Type failed: ‹MI05 id›`; app-autotype's errors carry no token position, and the reason text is not logged because it may hold the token (LD-231 (5)).

## Edge cases and errors

- **Several vaults, same entry title:** the rows differ by their small line (INT-05.26).
- **An entry matches by both title and URL:** one row (INT-05.23 drops the repeat).
- **A window rule's text is a placeholder that resolves to empty** (`{S:Missing}`): it is a wildcard for the empty title; titles are never empty during matching (INT-05.24), so it never matches. Only a text empty as stored is an empty-window rule.
- **A pattern like `//(?<=x)Bank//`:** invalid in App's engine, matches nothing, no message; the reference's engine accepts it (LD-123).
- **The title changes between the shortcut and the picker** (a page loads): matching used the captured title; typing checks the window, not its title, so typing goes on.
- **The user clicks into another field of the same window during typing:** same window, typing goes on into the new field; the focus check is per window (D-INT05-2). Clicking another window or app stops it.
- **The target app shows a sheet or a new window during typing** (a sign-in page opening a second-factor window): the focused window changes and typing stops. A sequence that crosses two windows does not work; the user starts Auto-Type again in the new window (the remembered choice helps, INT-05.31).
- **A secure input field in the target** (a password field in a browser, a terminal with secure keyboard entry): App types as usual; check with Verify that the events arrive (V-INT05-1).
- **Another app holds secure input in the background:** check with Verify that the global shortcut still fires (V-INT05-2).
- **Shortcut pressed while App's own window is in front:** nothing (INT-05.25 step 1); use Type Login there.
- **The entry is edited or deleted while the picker is open:** the row keeps what it showed; choosing a row of a deleted entry types nothing and closes the picker.
- **`{PICKCHARS}` in a sequence used with S-AT-03 off:** the pick dialog still shows; it is the user's confirmation for those characters.
- **The keyboard layout changes during a run:** App keeps the layout it read at the start (INT-05.41).
- **A sequence typed into a remote desktop or virtual machine window:** apps that read key codes instead of the Unicode string see key code 0 (the `a` key) for every character in normal mode; key-code mode (⌘5 or `{MODE=VIRTUAL}`) is the answer, as in the reference.
- **No title and no candidates at all** (every vault empty): the picker shows MI05-45.
- **A version 1 import with an `Auto-Type-Window` line but no sequence:** the window rule has an empty sequence and types the entry sequence (FEA-08.59, INT-05.23).
- **Duplicate or empty window rules in the file:** kept as read (FMT-11.24); rows with both parts empty are dropped only when the user saves the entry in the editor.

## Not on Mac

The reference also has: X11 typing with its own key symbol lookup; Wayland and desktop-portal typing, with options to keep the remote desktop session open, to type through the portal's clipboard, and a portal session token (APP-01 S-NOMAC-01 to -06); a shortcut set up through the desktop instead of a key field; Windows typing with its own virtual-key mapping and a "Home" based clear-field. None of these exist in App.

## Lead decisions

Decided: spec/decisions.md LD-176, all sixteen as recommended. D-INT05-12, D-INT05-14 and D-INT05-16 change texts of the locked mockup; those changes wait for the owner's OK before E8 (AT-K05).

| ID | Question | Options | Recommended, with evidence |
|---|---|---|---|
| D-INT05-1 | Where the window title comes from (INT-05.37) | (a) the window list with window names, which needs Screen Recording, as the reference and MacPass do; (b) the focused window's title through the Accessibility API, which typing needs anyway | (b). Apple's own engineer confirmed that window names in the window list are gated by Screen Recording since macOS 10.15 (Apple Developer Forums thread 126860); the reference asks for both permissions for global Auto-Type and MacPass's own check needs both. The focused window's title is part of the Accessibility API, so (b) needs one permission instead of two, gives the window that really has the focus instead of the top window in the list (the reference skips a "StatusIndicator" window the system injects while audio is recorded, a known trap of the list), and avoids the recurring Screen Recording reminders of newer macOS. SI-14's text ("and the Screen Recording permission") then changes to Accessibility only. Check with Verify V-INT05-4 |
| D-INT05-2 | What "the same window" means for the focus check (INT-05.39) | (a) the same process, as the reference; (b) the same process and the same focused window; (c) check once before typing, as MacPass | (b). AT-G02 says typing stops on a focus change; with (a) a browser with two windows keeps receiving the password in the other window. (c) misses changes during typing. The window identity costs one look-up per key. Extra stops (lock, quit, target quit, the shortcut pressed again) give the user a way out without an event tap |
| D-INT05-3 | The picker (INT-05.26 to INT-05.29) | (a) an App dialog that makes App active, with Group, Title, Username and Sequence columns and a "search all" box, as the reference; (b) a floating panel that does not activate App, laid out as the frame, where typed text always searches all entries | (b). The frame draws (b): no columns, no box, "Search all entries…". MacPass shows its candidates in a non-activating floating panel; with it the target app stays active, so typing needs no re-activation and the focus check starts from the real target. Rows keep the reference's one row per (entry, sequence). Check with Verify V-INT05-6 |
| D-INT05-4 | How text is sent (INT-05.40) | (a) Unicode key events with key code 0, as the reference and MacPass; (b) paste through the clipboard; (c) key codes only | (a). It types any character on any layout. (b) exposes the value to every clipboard reader and would write the owner's clipboard in tests (AGENTS.md rule 10); MacPass pastes only for its optional obfuscation. (c) cannot type characters missing from the layout; it stays available as key-code mode (D-INT05-5). The entry's obfuscation value stays unused, as in the reference |
| D-INT05-5 | Key codes for key combinations and key-code mode (INT-05.41, INT-05.42) | (a) fixed US key positions, as the reference; (b) look the character up in the current keyboard layout | (b). With (a) the reference's `#a` on a French layout presses ⌘Q (the US `a` position types `q` there), and its key-code mode drops every lower-case letter (found by reading its macOS key table). Lookup in the current layout is what the macOS keyboard layout data exists for and is what keyboard tools do |
| D-INT05-6 | `{CLEARFIELD}` on Mac (INT-05.8) | (a) Control with ←, Control-Shift with →, Delete, as the reference; (b) ⌘A, then Delete | (b). macOS uses ⌃← and ⌃→ to move between Spaces by default (Mission Control shortcuts), so (a) can switch the desktop in the middle of a sign-in; on other systems the reference's intent is "select the whole field, then delete", which ⌘A then Delete is on a Mac |
| D-INT05-7 | Bounds (INT-05.10, INT-05.16, INT-05.17) | (a) the reference's per-token limits only; (b) also: counts that are too long fail, at most 10,000 actions (keys, waits and pauses; LD-186) and 60 s of waits per run, at most 256 characters to pick from | (b). AT-G03 asks that hostile sequences stay bounded and nothing hangs. The reference's limits stop one token, not their sum: 10,000 `{TAB 100}` tokens type a million keys, and its number reader turns an overflowing count into 0 so the check passes. A normal sign-in is under 100 keys; 10,000 actions (keys, waits and pauses; LD-186) at the default pause take over 4 minutes; a pick dialog for a megabyte field would never draw |
| D-INT05-8 | When `{TOTP}` is computed (INT-05.9) | (a) before typing, at an estimated typing time, as the reference; (b) when typing reaches the token | (b). The estimate ignores the time real events take and the pick dialog; computing at the moment of typing is exact and as simple. FEA-04 already says "at the moment of typing" |
| D-INT05-9 | Cancel in the pick dialog (INT-05.10) | (a) type the rest without the characters, as the reference; (b) stop the whole run | (b). A sequence such as `{USERNAME}{TAB}{PICKCHARS}{ENTER}` would otherwise submit a sign-in with no characters, which can count as a failed attempt and lock the account |
| D-INT05-10 | Default shortcut and valid shortcuts (INT-05.30) | (a) none by default, as the reference; (b) ⌃⌥V, as both locked frames draw it | (b). The settings frame and the editor text both show ⌃⌥V; it holds ⌃, so it stays valid under the macOS 15 rule that refuses hot keys with only ⌥ or ⌥⇧ (Apple Developer Forums thread 763878; Eternal Storms blog, 2024-09-23). The hot key service needs no permission (the KeyboardShortcuts package README: "Does this package cause any permission dialogs? No"; it still uses Carbon for this). Check with Verify V-INT05-7 that ⌃⌥V registers on a fresh account |
| D-INT05-11 | `{VKEY}` and keys with no Mac key (INT-05.6, INT-05.12) | (a) accept and type nothing, as the reference; (b) map Windows virtual-key numbers to Mac keys | (a). The numbers are Windows key numbers; a sequence written with them for a Windows machine rarely means the same keys on a Mac, and every key worth typing has a name in INT-05.6. MacPass also does not support it (its parser logs "not supported") |
| D-INT05-12 | The "type the same login again" row (INT-05.31; LD-167) | (a) keep the frame's label "Do not type the same login again within"; (b) label it "Preselect the previous choice for" (APP-01 S-AT-08) with the reference's real rule | (b). The reference's rule (its settings label reads "remember the last typed entry for") only highlights the last choice in the next picker within that time; it never blocks typing again. The frame's label says the opposite and would make users expect a block that does not exist. The mockup text needs the owner's approval (AT-K05) |
| D-INT05-13 | Small differences from the reference | (1) an empty-window rule with an empty sequence types the entry sequence (the reference types nothing); (2) entries whose effective sequence is empty are not candidates; (3) CR LF types one Return and other control characters are dropped (the reference types CR as a character, then Return); (4) modifiers at the end fail (MI05-24); (5) `{DELAY}` without a number fails (MI05-15); (6) the keypad rows, `RWIN` and the four brace and parenthesis names of INT-05.6 | Take all six: each turns a silent "types nothing" or a surprise into either the obvious keys or a clear message at save time; none changes a sequence that works in the reference, except (6), where the reference's keys type nothing or a main-row key on a Mac |
| D-INT05-14 | Settings frame against APP-01 | (1) the frame draws "Always ask" off and "Skip expired" on; APP-01 has on and off; (2) S-AT-04 has no row; (3) S-AT-10 shows 0 to 1,000 in the reference but acts as at most 500; (4) the reference's picker size and sort keys (S-STATE-14 to -16) have no use in App's picker | (1) Keep APP-01's defaults: "Always ask" on is the user's confirm against a lookalike window (AT-G01, SI-06), and APP-01 lists turning it off as weakening; the frame is read as a sample state, so the mockup should draw the defaults. (2) Add a row "Don't ask when I start from App's window" under "Always ask which entry to type", dependent on it (APP-01.5), with the owner's approval. (3) App's control offers 0 to 500. (4) Leave the three state keys unread and unwritten |
| D-INT05-15 | Where secret characters are turned into key events (INT-05.45) | (a) in Swift; (b) on the Rust side, with the macOS calls behind `unsafe` in `app-platform`'s `macos/` files or through a macOS bindings crate | (b). AGENTS.md rule 4 forbids giving resolved secrets to the screen layer. The layout lookup table, the hot key, the picker and the permission screens hold no secrets and stay in Swift. The crate that reaches Quartz events and the Accessibility API is chosen at E8-S3 with an AT-J03 review (the approved table has `objc2` and `objc2-app-kit` only) |
| D-INT05-16 | Mockup gaps | (1) MI05-51's text when no shortcut is set; (2) the Accessibility-off notice MI05-32; (3) the app name under the picker header; (4) the picker's small-line additions for several sequences or vaults, the empty list MI05-45 and the row menu MI05-44; (5) the pick dialog MI05-60; (6) the question MI05-50; (7) the shortcut recorder's states and the errors MI05-33 to MI05-36; (8) the label of D-INT05-12 and the row of D-INT05-14 (2) | Add all to the locked mockup with the owner's approval (AT-K05). (3) is a security aid against lookalike titles (AT-G01): a web page sets its own window title but cannot change the browser's app name; the app name comes from the app's own bundle, so a lookalike app would have to be installed and named to match |

Check with Verify:

| ID | What to check |
|---|---|
| V-INT05-1 | Keyboard events App posts reach a text field of the test target while that target has turned on secure input itself (the target helper of the test cases calls the system's secure input switch) |
| V-INT05-2 | The global shortcut fires while another process (a second test helper) holds secure input |
| V-INT05-3 | Events posted to the hidden test target process alone (without making it active) arrive in its text field. The test process needs the Accessibility permission to post events; granting it in Privacy & Security is the owner's step. If not, the real-typing cases (T96, T97, T100, T101, T104) wait for the owner's go (AGENTS.md rule 10) and run in one Mac QA session |
| V-INT05-4 | The focused window's title through the Accessibility API equals the title users see, for the test target (always) and, with the owner's go only, for Safari, Chrome, Firefox and Terminal |
| V-INT05-5 | After the permission is granted in Privacy & Security, App's next check returns "granted" without a restart |
| V-INT05-6 | The non-activating picker panel takes typed search text while the test target stays the active app, and after the panel closes the target's text field still has the keyboard focus |
| V-INT05-7 | On this Mac (macOS 26.6): registering ⌥F19 and ⌥⇧F19 is refused, ⌃⌥V and ⌃⌥⌘F19 are accepted (registration only, no key pressed, unregistered at once) |
| V-INT05-8 | For the test target: two reads of its focused window give Accessibility elements that the system's equality test calls equal, and a second window of the same process gives one it calls different |

## Security notes

- **Typing into the wrong window (AT-G01, SI-06).** Any app can give its window a title that looks like a bank's sign-in page. App's defenses: "Always ask" on by default, so global Auto-Type types only after the user picks a row in the picker; the picker names the target window and the target app (D-INT05-16 (3)); a question naming the target app before typing from App's window; never typing into App itself; and typing only into the captured app and window (INT-05.39). With "Always ask" off and one match, App types without a confirm: APP-01 lists that setting as weakening.
- **Focus changes during typing (AT-G02).** Checked before every key; App stops at once and never retries into another window. Keys already typed stay; a half-typed password in a wrong window is possible only for keys already handed to macOS before the change (normally one; a few more with a key pause of 0). The check is per window, not per field: a click into another field of the same window, such as a browser's address bar, receives the rest of the keys, and an address bar may send what it gets to a search service as suggestions. Users stop it by pressing the shortcut again or locking (INT-05.39).
- **Hostile sequences (AT-G03, SD-08).** A sequence comes from the vault, which a sync, a shared group or an import can change. Every count, wait and pause is bounded; one run types at most 10,000 actions (keys, waits and pauses; LD-186) and waits at most 60 s; resolution keeps MOD-08's bounds; patterns use the linear-time engine; the reader has a fuzz target. Nothing is typed until the whole run is checked (INT-05.15). A sequence can still type any keys the user's account can type (for example `#q`), which is why "Always ask" is on by default.
- **The recycle bin (SD-05, LD-57).** Bin entries are never candidates and never typed, whatever any flag says.
- **Secure input and key loggers.** Typed keys travel as keyboard events: any process the user allowed to monitor input (Input Monitoring) can read them, unless the target field holds secure input. Auto-Type is safe from clipboard readers but not from key loggers; copy-and-paste has the opposite exposure. App turns its own secure input off before typing (APP-10.12) and on in the pick dialog (APP-10.9).
- **The delay limits.** The start delay is at least 100 ms so the shortcut's keys are released (and App waits for modifiers, INT-05.38); the per-key pause is at most 500 ms and a single wait at most 10 s, so a run cannot keep typing for minutes while the user looks elsewhere.
- **Secrets (SR-07, AGENTS.md rule 4).** Values exist only in Rust secret types and are wiped after each run; the Swift layer never receives them; messages and logs never carry values or window titles (INT-05.18, INT-05.47); the remembered choice holds ids only and goes when its vault locks.
- **The Accessibility permission** lets App control other apps. App uses it only to read the focused window and its title and to post keyboard events while a run is active; it asks for no Screen Recording and no Input Monitoring. The global shortcut is a system hot key and receives no other keys. The permission belongs to App's signed program; APP-11's hardened runtime and library validation keep other code from running inside App to borrow it.
- **Lock (SR-16).** A lock closes the picker and the pick dialog, stops typing and drops the remembered choice; a vault unlocked for Auto-Type can lock again right after (S-AT-06).
- **What must never happen:** typing into App itself; typing into a window other than the captured one; typing a bin entry or an entry with Auto-Type off; any key going out before the whole run passed its checks; a resolved value in a log, a message or the Swift layer; App writing to the clipboard to type.

## Test cases

Setup. No test types into the owner's apps. Most cases run on a recording backend: a fake keyboard that records each event (key code, flags, Unicode string, time), a fake "front app and window" provider (process, window identity, title, app name, the window list for the editor) the test changes at will, a fake permission state, a fake hot key service, a fake keyboard layout table (US and French AZERTY), and a fake clock. Real-typing cases use `AutoTypeTarget`, a small helper app built only for tests: it has one window with one text field, sets its window title from its launch arguments, logs every key event it receives (key code, flags, characters) to `/tmp/spec-int05/target-<n>.log`, and can turn on secure input (V-INT05-1). It is launched hidden and never made the active app; App's test build posts to its process (V-INT05-3), and its front-app provider reports the helper as the active app and the helper's window as the focused one, so the focus check (INT-05.39) runs against the helper; it is stopped by the PID that started it. Panels and dialogs (picker, question, pick dialog, unlock panel, settings and editor pages) are driven through their view models or rendered offscreen; no case shows a window on the owner's screen or makes App the active app (AGENTS.md rule 10). Clipboard cases use a private named test pasteboard, never the general pasteboard (AGENTS.md rule 10). The test settings set S-AT-07 to none, except the shortcut cases, which use the fake hot key service; only T107 touches the real service, with registration alone.

Demo vault V (`autotype-demo.appvault`, password `demo-at-vault`), made by our tools. Root R: switch Inherit, no sequence.
- Group Web (Inherit): E1 "GitHub": username `alex-dev`, password `demo-gh-pass-1`, URL `https://github.com/login`, one-time secret `JBSWY3DPEHPK3PXP` (30 s, 6 digits), custom sequence `{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}`, window rules A1 `*GitHub*` with an empty sequence and A2 `Sign in to GitHub · GitHub — Safari` with `{USERNAME}{TAB}{PASSWORD}{ENTER}`. E2 "GitHub (work bot)": `morgan-labs-ci`, `demo-gh-pass-2`, URL `https://github.com`, window rule `*GitHub*` with an empty sequence. E3 "Demo Mail": `demo@mail.example`, `demo-pass-1`, URL `https://mail.example.com`. E4 "Pin only": username empty, password `4321`. E11 "GitHub": username `old-user`, password `demo-old-gh`, entry Auto-Type flag off.
- Group Bank (Inherit, sequence `{USERNAME}{ENTER}{DELAY 200}{PASSWORD}{ENTER}`): E5 "Bank login": `demo-bank`, `demo-bank-pass`, window rules `//BANK1//` → `b1{ENTER}`, `//^BANK2$//` → `b2`, `//^BANK3-([ab]\d){2}$//` → `b3`, `//(?<=x)BANK//` → `bad`. E6 "Fields": custom fields `Pin` = `1234` (protected), `Site` = `Portal`, `Field 2` = `two`; window rules: empty window → `{S:Pin}`, `//^{S:Site}$//` → `{S:Site}`, `*Notes app*` → empty.
- Group Off (switch Off): E7 "Hidden": window rule `*GitHub*`.
- Group Off2 (switch Off, no sequence) holding group Quiet (switch On, no sequence) holding E10 "Quiet": title `Quiet`.
- E8 "Old Portal" in R: password `demo-old`, expires 2020-01-01.
- Recycle bin: group S (switch On) holding E9 "Binned": window rule `*GitHub*`.

Second vault W (`autotype-second.appvault`, password `demo-at-second`): one entry "GitHub W": username `second-user`, password `demo-second-pass`, window rule `*GitHub*`.

Parser entry P (for T01 to T41): username `Username`, password `Password@1`, URL `https://example.com`, custom field `attr1` = `value1`, in R of V. S-AT-09 500, S-AT-10 25 unless a case says otherwise. "Text x" means one Unicode key event pair for x (INT-05.40); "key K" a key press by code.

| Case | Given | When | Then |
|---|---|---|---|
| T01 INT-05.3, INT-05.13 | P | Run `{USERNAME}{TAB}{PASSWORD}{ENTER}` | Text `Username`, key 0x30, text `Password@1`, key 0x24; 500 ms before the first event, 25 ms after each |
| T02 INT-05.2 | P | Run `{{}x{}}` | Text `{`, `x`, `}` |
| T03 INT-05.2 | P | Run `{TAB}}` | MI05-10 with MI05-11; no event |
| T04 INT-05.3 | P | Run `}{` and then `{}` | Text `}`, `{`; then text `{`, `}` |
| T05 INT-05.3, INT-05.6 | P, US layout | Run `+{TAB}^a#v%{F4}` | Key 0x30 with Shift; key 0x00 with Control; key 0x09 with Command; key 0x76 with Option |
| T06 INT-05.3 | P | Run `abc+` | MI05-24 naming `+`; no event (the reference types `abc+`) |
| T07 INT-05.6 | P | Run `{TAB 3}{SPACE 0}{LEFT 100}` | 3 × key 0x30, nothing, 100 × key 0x7B |
| T08 INT-05.6 | P | Run `{LEFT 101}` | MI05-12 naming `{LEFT 101}`; no event |
| T09 INT-05.17 | P | Run `{TAB 99999999999}` and `{DELAY 5000000000}` | MI05-12, then MI05-13; no event (the reference: nothing typed, no error) |
| T10 INT-05.5, INT-05.6 | P | Run `{tab}{Enter}{PGDN}{pgdown}{Bksp}` | Keys 0x30, 0x24, 0x79, 0x79, 0x33 |
| T11 INT-05.6 | P | Run `{NUMPAD5}{ADD}{SUBTRACT}{MULTIPLY}{DIVIDE}{RWIN}` | Keys 0x57, 0x45, 0x4E, 0x43, 0x4B, 0x36 |
| T12 INT-05.6 | P | Run `{INSERT}{INS}{BREAK}{NUMLOCK}{PTRSC}{SCROLLLOCK}{APPS}` | No event, no error |
| T13 INT-05.6 | P | Run `{LEFTBRACE}{RIGHTBRACE}{LEFTPAREN}{RIGHTPAREN}{(}{)}{[}{]}{+}{%}{^}{~}{#}` | Text `{}()()[]+%^~#`, one pair per character |
| T14 INT-05.4, INT-05.6 | P | Run `{+ 3}~@` | Text `+`, `+`, `+`, `~`, `@`; no key 0x24 |
| T15 INT-05.7 | P | Run `{DELAY 500}`, then `{DELAY 10000}`, then `{DELAY 10001}` | A 500 ms wait; a 10,000 ms wait (fake clock); MI05-13 |
| T16 INT-05.7 | P | Run `{DELAY=50}a{DELAY= 0 }b`, then `{DELAY= 40}c`, then `{DELAY=501}`, then `{DELAY = 5}` | 50 ms after `a`, 0 ms after `b`; 40 ms after `c` (the reference: 0); then MI05-14; then MI05-19 |
| T17 INT-05.7 | P | Run `{DELAY}`, then `{DELAY=abc}` | MI05-15 twice |
| T18 INT-05.7 | Stored S-AT-10 = 900, S-AT-09 = 50 | Run `ab` | 100 ms before `a`; 500 ms after each key |
| T19 INT-05.8, INT-05.42 | P, US layout | Run `{CLEARFIELD 3}` | Key 0x00 with Command, then key 0x33; once |
| T20 INT-05.9 | E1, fake clock at 2026-10-28T10:00:29.800Z; S-AT-09 500 | Run `{TOTP}` | The code for the 30-second step that starts at 10:00:30 (computed when the key is reached, after the 500 ms start delay), not the 10:00:00 step |
| T21 INT-05.9 | P; then P with one-time secret `!!` | Run `x{TOTP}` | Text `x` only; then MI05-16 and no event at all |
| T22 INT-05.10, INT-05.36 | E1 | Run `{PICKCHARS}`; pick buttons 1 and 3 with "Add a Tab after each character" on; Type | Dialog shows 14 buttons numbered 1 to 14 and no characters; events: text `d`, key 0x30, text `m` |
| T23 INT-05.10 | E6 | Run `{PICKCHARS:Nope}`, then `{PICKCHARS:Pin}`, then `{PICKCHARS:Pin:C=2}` | MI05-17 naming `{PICKCHARS:Nope}`; then a dialog with 4 buttons; then MI05-17 (no field `Pin:C=2`) |
| T24 INT-05.10 | E1 | Run `{USERNAME}{TAB}{PICKCHARS}{ENTER}`; Cancel | No event at all (the reference types `alex-dev`, Tab, Return) |
| T25 INT-05.10 | Entry with a 257-character password | Run `{PICKCHARS}` | MI05-18; no dialog |
| T26 INT-05.11, INT-05.41 | P, US layout | Run `{MODE=VIRTUAL}aB{MODE=NORMAL}c` | Key 0x00, key 0x0B with Shift, text `c` |
| T27 INT-05.12 | P | Run `{BEEP 3 3}{VKEY 0x01}{VKEY-EX 0x01}{APPACTIVATE Notes}{C:note}x` | Text `x` only |
| T28 INT-05.13 | P | Run `{S:attr1}`, `{S:ATTR1}`, `{s:attr1}` | Text `value1`; nothing and no error; MI05-19 |
| T29 INT-05.13 | P | Run `{FOO}`, then `{USERNAME 2}` | MI05-19, twice |
| T30 INT-05.13 | E6 | Run `{S:Field 2}` | Text `two` |
| T31 INT-05.13 | P; E3's id as 32 hex digits | Run `{REF:U@I:<id>}`, then `{ref:U@I:<id>}` | Text `demo@mail.example`; then MI05-19 |
| T32 INT-05.13 | P | Run `{T-CONV:;{USERNAME};hex;}`, `{T-CONV:/{USERNAME}/nope/}`, `{T-CONV:}`, `{T-REPLACE-RX:/{USERNAME}/name/NAME/}`, `{T-REPLACE-RX:/{USERNAME}/a/}`, `{T-REPLACE-RX:/x/(?<=a)b/c/}` | Text `557365726e616d65`; MI05-20; MI05-20; text `UserNAME`; MI05-20; MI05-20 |
| T33 INT-05.14 | P with notes `l1` CR LF `l2` LF `l3` CR `x` TAB `y` U+0007 `z` | Run `{NOTES}` | Text `l1`, key 0x24, text `l2`, key 0x24, text `l3`, key 0x24, text `x`, key 0x30, text `y`, text `z` |
| T34 INT-05.14 | P | Run `+{USERNAME}` | Text `Username`, no flags |
| T35 INT-05.40 | P with username `é😀` | Run `{USERNAME}` | Two pairs: U+00E9; U+1F600 as one event holding its two UTF-16 units; key code 0, flags 0 |
| T36 INT-05.16 | P | Run `{TAB 100}` written 101 times; then `{DELAY 10000}` written 7 times | MI05-21; MI05-22; no event |
| T37 INT-05.16, AT-G03 | P with field `Grow` = `{USERNAME}` × 16 and username `{S:Grow}` | Run `{S:Grow}` | Returns within 1 s: MOD-08.20 gives the raw token back, so MI05-19; no event |
| T38 INT-05.18 | E6 with `Pin` protected | Run `{PICKCHARS:Nope}` and an invalid-code entry with `{TOTP}` | Messages hold `{PICKCHARS:Nope}` and MI05-16; neither holds `1234`, a secret or a window title |
| T39 INT-05.15 | P | Editor check of `{USERNAME}{PICKCHARS}` | Passes; no dialog shown, no event |
| T40 INT-05.2, INT-05.3 | Fuzz target for the reader (E8-S1) | Run 10 minutes | No panic; no input takes over 100 ms; every output is either an error or a list within INT-05.16 |
| T41 INT-05.5 | P | Run `{Delay 5}{clearfield}{totp}{PickChars}` with an empty password | 5 ms wait; ⌘A and Delete; nothing for the code; no dialog (empty field) |
| T42 INT-05.19 | V unlocked; front window title `GitHub` | Global Auto-Type, S-AT-03 on | Picker rows for E1 and E2; none for E11 (flag off), E7 (group Off), E9 (bin) |
| T43 INT-05.20 | V; titles `lorem BANK1 ipsum`, then `lorem bank1 ipsum` | Global, S-AT-03 off | Both times E5 types `b1` then key 0x24 (one row, typed directly) |
| T44 INT-05.20 | V; titles `BANK2`, `xBANK2` | Collect rows | `BANK2`: E5 with `b2`; `xBANK2`: no E5 row |
| T45 INT-05.20 | V; title `BANK3-A1B2` | Collect rows | E5 with `b3` (case ignored inside the pattern) |
| T46 INT-05.20, LD-123 | V; title `xBANK` | Collect rows | No E5 row; no message (lookbehind invalid in App) |
| T47 INT-05.20 | V; titles `Portal`, `Portal 2` | Collect rows | `Portal`: E6 with `{S:Site}`, then E6 with `{S:Pin}` (empty-window rule); `Portal 2`: no E6 row |
| T48 INT-05.20, INT-05.23 | V; title `My notes APP` | Collect rows | E6 with `{USERNAME}{ENTER}{DELAY 200}{PASSWORD}{ENTER}`, then E6 with `{S:Pin}`; title `Notes`: no E6 row |
| T49 INT-05.20 | Entry with rules `a?c`, `a.c`, `a+b` | Titles `a?c`, `abc`, `a.c`, `a+b`, `aab` | Rows for `a?c`, `a.c` and `a+b` only |
| T50 INT-05.20 | Entry with rule `////` | Title `anything at all` | The entry matches |
| T51 INT-05.21 | V; title `Demo Mail – Inbox`; S-AT-01 on, then off | Collect rows | E3 (title match); then no E3 row (its host `mail.example.com` is not in the title) |
| T52 INT-05.22 | V; titles `Inbox – mail.example.com`, `https://mail.example.com - Inbox` | Collect rows | E3, one row each time |
| T53 INT-05.23 | V; title `Sign in to GitHub · GitHub — Safari` | Collect rows | E1 twice: custom sequence (A1), then `{USERNAME}{TAB}{PASSWORD}{ENTER}` (A2); the title match adds nothing new; E2 once (its window rule) |
| T54 INT-05.23 | V; title `Unrelated` | Collect rows | No E6 row (its empty-window rule alone does not match) |
| T55 INT-05.19 | V; title `Quiet`; E10 selected in App's window | Collect rows; read the Entry menu | No E10 row; Type Login disabled for E10 |
| T56 INT-05.19, MOD-09.14 | V; title `Old Portal`; S-AT-05 off, then on | Global, S-AT-03 on | E8 row struck through with the badge; then no E8 row |
| T57 INT-05.24, INT-05.27 | V; empty title, app name `Notes` | Global | Picker header `Type into Notes`; rows for every candidate of V |
| T58 INT-05.25 | S-AT-03 off; title `Inbox – mail.example.com` | Global | No picker; E3's effective sequence typed |
| T59 INT-05.25 | S-AT-03 off; title `GitHub` | Global | Picker (several rows) |
| T60 INT-05.25, INT-05.37 | App's own window is the active app | Shortcut pressed | Nothing: no picker, no event |
| T61 INT-05.25 | No vault open | Shortcut pressed | System alert sound only |
| T62 INT-05.25, APP-06 | V open and locked, shown; second vault W unlocked | Shortcut pressed with title `GitHub`; unlock V in the panel | The panel shows M06-40; after unlock, the picker lists rows from V and W; with Cancel instead: nothing |
| T63 INT-05.26 | V; title `Sign in to GitHub · GitHub — Safari`, app `Safari`; S-AT-03 on | Global; render the picker offscreen | Header, the app name line, search placeholder, three rows: `GitHub`/`alex-dev` twice (the first highlighted with `Type login ⏎`; the small line adds each row's sequence) and `GitHub (work bot)`/`morgan-labs-ci`, then the hint line; layout as the frame `menubar-auto-type-picker` apart from D-INT05-16 (3) and (4) |
| T64 INT-05.27 | Picker open for title `GitHub` | Type `mail` | One row: E3 |
| T65 INT-05.28, INT-05.29 | Picker open for title `GitHub`, nothing remembered | Press Return | The first row (sorted by title: `GitHub` before `GitHub (work bot)`) is typed |
| T66 INT-05.29, APP-03 | Picker open, E1 highlighted | ⇧Return; again ⌘3; again ⇧⌘2 | `demo-gh-pass-1` typed; the code typed; private test pasteboard holds `demo-gh-pass-1`, picker closed, no event |
| T67 INT-05.29 | Picker open, search `mail` | Escape, Escape | Search empty, then picker closed; no event |
| T68 INT-05.29, SR-16 | Picker open | Lock V | Picker closed; no event |
| T69 INT-05.29 | Picker open | The fake provider makes another app active | Picker closed; no event |
| T70 INT-05.31 | Picker for title `GitHub`; fake clock t0 | Choose E2; at t0+10 s press the shortcut again, then Escape; at t0+16 s press it again | Second picker: E2 highlighted; third picker: first row highlighted |
| T71 INT-05.31 | S-AT-08 = 0 | Same as T70 at t0+1 s | First row highlighted |
| T72 INT-05.31 | S-AT-03 off, one match (title `Inbox – mail.example.com`) | Global, then S-AT-03 on and a picker within 5 s | Nothing remembered: first row highlighted |
| T73 INT-05.31 | E2 remembered | Lock V, unlock V, picker within the time | First row highlighted |
| T74 INT-05.32, APP-02.14 | S-AT-06 on; V locked | Shortcut, unlock in the panel, pick E3, typing ends | V locked after the last key; with the picker closed by Escape instead: V locked at once |
| T75 INT-05.30 | Fake hot key service; fresh settings | Start App | ⌃⌥V registered once |
| T76 INT-05.30 | Settings page, recorder | Record ⌥V; ⇧⌥V; ⌘L; ⌃⌥V | MI05-34; MI05-34; MI05-35 naming the lock item; accepted |
| T77 INT-05.30, APP-01.3 | Fake service refuses with "already taken" | Record ⌃⌥K, OK; restart App | Field red with MI05-33; value stored; registration tried again at start |
| T78 INT-05.30 | Recorder active | Escape; then Delete | Recording cancelled, old value kept; then the shortcut is none and unregistered |
| T79 INT-05.33 | S-AT-03 on, S-AT-04 off; previous app `Notes`; E3 selected | Type Login; Cancel | MI05-50 `Type “Demo Mail” into Notes?`; nothing else |
| T80 INT-05.33, INT-05.37 | Same, answer Type | Type Login | App hidden; after 500 ms the target is captured; E3's sequence typed |
| T81 INT-05.33 | S-AT-04 on | Auto-Type Password Only on E3 | No question; `demo-pass-1` typed |
| T82 INT-05.33, INT-05.37 | After hiding, App is still active (fake) | Type Login | Stops with the alert sound; no event |
| T83 INT-05.34 | E1 in the editor | Render the Auto-Type page offscreen | Texts as the frame `editor-editor-auto-type`, except the switch label "Let Auto-Type use this entry" (LD-167) and MI05-51 with the test shortcut |
| T84 INT-05.34 | E3 in the editor | Choose Custom, type `{TAB 101}`, Save; Fix It; then Save, Save Anyway | MI05-52 with MI05-12; page shown with the field; then saved with `{TAB 101}` |
| T85 INT-05.34 | E3 in the editor; the fake window list holds `Inbox – Demo Mail` and `Notes` | Add window, leave both cells empty, Save; add a row, edit its title cell, then type `*Mail*` with an empty sequence | First row dropped; the title cell offers the two fake titles; the row shows "Entry sequence" |
| T86 INT-05.34, MOD-02.6 | E1 in the editor | Clear the custom field, Save | Default sequence stored empty; the page then shows "Use the group's sequence" chosen, with `{USERNAME}{TAB}{PASSWORD}{ENTER}` |
| T87 INT-05.35, D-INT05-14 | Fresh settings | Render the settings page offscreen | "Always ask" on, "Skip expired" off, steppers 500 ms, 25 ms, 15 s; S-AT-10 refuses 501; remembered-choice row label per D-INT05-12 |
| T88 INT-05.35, INT-05.44 | Fake permission off, then on | Show the settings page; send the page a simulated "App became active" notice after the change | MI05-32; then MI05-31 |
| T89 INT-05.36, APP-10.9 | E1, `{PICKCHARS}` | Open the dialog's view model in the test build | Its masked field carries the password-kind mark (APP-10.9). The real secure-input state (on while the dialog has focus, off after it closes) needs a focused window: it is checked in the Mac QA session, with the owner's go (AGENTS.md rule 10) |
| T90 INT-05.39, AT-G02 | Recording backend; sequence `abcdef` | The fake provider changes the active app after the third key | Events for `a`, `b`, `c` only; alert sound; no window opened |
| T91 INT-05.39, INT-05.37 | Same | The fake provider changes only the focused window of the same app after the third key | Events for `a`, `b`, `c` only (the reference would go on) |
| T92 INT-05.39 | Same | Lock V after the second key; separately, press the shortcut after the second key | Two keys, then stop, each time; every key-down has its key-up |
| T93 INT-05.38 | Fake modifier state: ⌃ held | Start a run; release ⌃ after 1 s; separately hold it 3 s | Typing starts after the release; separately: stop with the alert sound, no event |
| T94 INT-05.44 | Fake permission off | Global Auto-Type twice in one App run | The system request is asked for once; MI05-30 both times; no event |
| T95 INT-05.46 | A run typing | Type Login on another entry | Ignored; the first run goes on |
| T96 INT-05.40 | `AutoTypeTarget` with title `Target A`; real backend | Run `aZ1é😀` into it | Its field holds `aZ1é😀`; log: key code 0, no flags for each |
| T97 INT-05.41 | `AutoTypeTarget`, US layout | Run `{MODE=VIRTUAL}aZ1é` | Log: 0x00; 0x06 with Shift; 0x12; `é` as a Unicode event (a dead key on US); field holds `aZ1é` |
| T98 INT-05.42 | Fake French AZERTY layout table | Run `#a` | Key 0x0C with Command (the AZERTY `a` key), not 0x00 |
| T99 INT-05.42 | US layout | Run `^ü` | MI05-23; no event |
| T100 INT-05.6 | `AutoTypeTarget` | Run `{TAB}{ENTER}{F5}{NUMPAD5}{DELETE}{BACKSPACE}` | Log codes 0x30, 0x24, 0x60, 0x57, 0x75, 0x33 |
| T101 INT-05.8 | `AutoTypeTarget` field holding `old` | Run `{CLEARFIELD}new` | Field holds `new` |
| T102 INT-05.43 | Recording backend | Run `a` and `#v` | Every event is made from a private event source; flags set explicitly: 0 for `a`, Command for `#v`; key-down before key-up |
| T103 INT-05.39 | Recording backend; sequence `abcdef` | The fake provider reports that the target process quit after the second key | Events for `a`, `b` only; alert sound |
| T104 V-INT05-1 | `AutoTypeTarget` with secure input on | Run `abc` | Field holds `abc` (or the case documents that macOS drops them) |
| T105 INT-05.45 | Test build; E1 global run | List every value crossing the bindings during the run (bindings call log) | No field value, code or picked character crosses into Swift; picker rows only, protected usernames masked |
| T106 INT-05.47 | After T90 | Read the debug log | One stop line with a reason code and the keys typed (`Auto-Type stopped: ‹code› after ‹n› keys`); no window title, no value, no sequence text |
| T107 INT-05.30, V-INT05-7 | Real hot key service on this Mac | Register ⌥F19, ⌥⇧F19, ⌃⌥⌘F19 and ⌃⌥V, each unregistered at once; press nothing | First two refused, last two accepted (documented as observed) |
| T108 INT-05.1, MOD-02.16 | E4 selected in App's window; S-AT-04 on | Type Login | Text `4321`, key 0x24 (the short form for an empty username) |
| T109 INT-05.25, INT-05.26, SI-12 | S-AT-03 off; title `Inbox – mail.example.com` (one match) | Bridge request "start Auto-Type" with search `mail` | Picker opens (no direct typing) with `mail` in the search field and one row: E3 |
| T110 INT-05.38 | Recording backend; the fake provider never makes the target active again after the picker | Choose a row | After 2 s (fake clock): the alert sound; no event |
| T111 INT-05.37 | Recording backend; the fake provider reports the active app `Notes` (process id 4242, display name `Notes`) with focused window element W1 titled `Inbox – Demo Mail`; then the same app with no focused window | Global Auto-Type, each time; then the provider reports App's own process as the active app and the shortcut is pressed | First capture: process 4242, element W1, title `Inbox – Demo Mail`, name `Notes`; second: process 4242, no element, empty title, name `Notes`; App active: nothing captured, no picker, no event (App is never the target); no Screen Recording permission is asked at any point |
| T112 INT-05.47 failure | Recording backend; an entry whose sequence is `{USERNAME` (MI05-11) | Global Auto-Type; read the debug log | One line `Auto-Type failed: MI05-11`; no token, no token position, no reason text, no value (LD-231 (5)) |

## How this was learned

- Read in the reference source (development branch): the Auto-Type controller (the key name table, the start and wait limits, the global flow with its never-type-into-itself check, the permission checks at first global use, the window-state save and restore, the match collection over every unlocked vault, the rule for when the selection dialog shows, the remembered match and its timer, the entry-level and sequence entry points, the typing loop with its active-window check and retries, and the sequence parser: brace escapes, the brace count, the token pattern with modifiers, nested groups and counts, the repeat, wait and pause limits, clear-field, one-time code timing, pick-characters, conversions, mode switches, ignored commands and the placeholder fall-back); the action classes; the macOS platform part (window list and titles, the injected status-indicator window, the Unicode event with key code 0, key events with flags, clear-field); the Windows and X11 clear-field parts for comparison; the macOS utilities (hot key registration and its modifier swap, the key code and modifier tables, the Accessibility prompt, the screen-recording check, the front, own and last-active process routines, secure input); the entry's sequence and window matching routines (pattern, wildcard, title and URL tests, empty-window rules); the group's sequence walk and switch resolution; the wildcard-to-pattern helper and its escaping; the association list; the selection dialog, its list model and view (filter, sort, closest-match highlight, key handling, the action menu and its shortcuts); the pick-characters dialog and its screen definition; the window title list box; the vault tab's global flow, unlock intent and relock; the vault view's entry-level actions and confirm; the entry editor's Auto-Type page, its screen definition and its save-time checks; the settings page, its screen definition and the settings defaults table; the Auto-Type unit tests (only to learn behaviour; the cases above use our own data).
- Not run: Auto-Type in the reference app was not started (brief; AGENTS.md rule 10), nothing was typed on this Mac, and no window of the owner's apps was read. Behaviours marked "found by reading" (the brace and keypad keys that type nothing, the key-code mode's dropped letters, the US key positions for combinations, the Control-arrow clear-field, counts that overflow to 0, an empty-window rule with an empty sequence) come from the source and its key tables. Read the macOS virtual key codes from the SDK header on this Mac (Xcode, macOS 26.6 SDK, `HIToolbox/Events.h`).
- Proven standard (AGENTS.md rule 9), read 2026-10-28:
  - MacPass (https://github.com/MacPass/MacPass): wiki page "Autotype" (https://github.com/MacPass/MacPass/wiki/Autotype): uses the front app's window title; window associations match exactly or by regular expression; title, URL, host and tag matching as options; one match types at once, several show a chooser; an "always show candidate selection" option. Source files `MPAutotypeDaemon.m` (hot key through the DDHotKey library, which uses Carbon hot keys; the chooser is a non-activating floating panel; the target is activated before typing; focus is checked once before typing), `MPAutotypeEnvironment.m` (window title from the window list, with a log line blaming missing Screen Recording on macOS 10.15 when no names come back), `MPAutotypeDoctor.m` (checks Accessibility and Screen Recording, opens the Privacy panes), `MPKeyTyper.m` (Unicode key events with key code 0 from a private event source; which event tap it posts to is not cited here, since this note and LD-231 (1) read it differently and it was not settled; App's tap comes from Apple's Quartz Event Services, INT-05.43, LD-234 (2)), `MPAutotypePaste.m` and `MPAutotypeParser.m` (pasting through the clipboard only for the obfuscation option; `{VKEY}` not supported).
  - KeeWeb wiki "Auto-Type" (https://github.com/keeweb/keeweb/wiki/Auto-Type): asks for Accessibility and Input Monitoring on macOS; `^` is Command on Mac and `^^` Control; supports `{DELAY X}`, `{CLEARFIELD}`, `{VKEY X}` and counts such as `{a 3}`.
  - Strongbox: its knowledge base (https://strongbox.reamaze.com/kb) and App Store page describe filling through the system's Password AutoFill; no keystroke Auto-Type was found for its Mac app.
  - Apple Developer Forums thread 126860 ("window name not available in macOS 10.15", https://developer.apple.com/forums/thread/126860): window names in the window list are gated by Screen Recording.
  - Apple Developer Forums thread 763878 (https://developer.apple.com/forums/thread/763878) and Eternal Storms Software, "Keyboard Shortcuts using Option and/or Shift Modifiers Only No Longer Allowed on macOS Sequoia" (https://blog.eternalstorms.at/2024/09/23/keyboard-shortcuts-using-option-and-or-shift-modifiers-only-no-longer-allowed-on-macos-sequoia/): hot keys with only ⌥ or ⌥⇧ are refused from macOS 15; reports differ on a partial change in 15.2 (V-INT05-7).
  - KeyboardShortcuts package README (https://github.com/sindresorhus/KeyboardShortcuts): global shortcuts through Carbon, no permission dialogs, sandbox-compatible.
  - Apple's sandbox design guide, quoted in Apple Developer Forums thread 28605 (https://developer.apple.com/forums/thread/28605): posting keyboard events to other apps is not allowed from a sandboxed app; App has no sandbox (plan/architecture.md).
- Checked against: the locked frames `editor-editor-auto-type`, `settings-settings-auto-type` and `menubar-auto-type-picker` (design/option-a/manifest.json and mockup.js), LD-57, LD-100, LD-167, APP-01 S-AT-01 to S-AT-10, APP-02.14, APP-03, APP-06 M06-40, APP-08, APP-10, MOD-01.18, MOD-02.14 to MOD-02.16, MOD-08, MOD-09.14, FEA-04, FEA-08.59, FMT-11.24, plan/security.md SI-06 and SI-14, plan/attacks-and-checks.md AT-G01 to AT-G03.

## Review 2026-10-28

Second Spec review. Checked against the reference source (the Auto-Type controller and its sequence reader, the action classes, the macOS typing part, the macOS key code and modifier tables, the entry's sequence and window matching routines, the wildcard helper and its escaping, the selection dialog with its list model and view, the pick-characters dialog and its screen definition, the vault tab's global flow and relock, the entry editor's save-time checks, the settings defaults table), MOD-08, MOD-01.18, MOD-02.14 to MOD-02.16, FEA-08.59, APP-01 S-AT-01 to S-AT-10, APP-08, APP-10, plan/security.md (SI-06, SI-12, SI-14, SD-05, SD-08, SR-16), plan/attacks-and-checks.md (AT-G01 to AT-G03), LD-167, LD-176, the frames `editor-editor-auto-type`, `settings-settings-auto-type` and `menubar-auto-type-picker` (manifest texts and mockup.js), and every virtual key code of INT-05.6 and the test cases against `HIToolbox/Events.h` of the macOS 26.6 SDK (all match). Confirmed as "same": the brace escapes and the brace count, the token shape with modifiers, nested groups and counts, the key name table and what each name presses on a Mac, the 100 / 500 ms / 10 s limits and the 100 ms to 10 s start delay, count overflow to 0, the order of the command tests, the ignored commands, the placeholder fall-back, `^` as Control and `#` as Command, the window rule kinds (pattern from 4 characters, `////` matches all, wildcard with only `*` special, whole title, case ignored), the title and URL tests, the empty-window rule order, the remembered choice and its timer, the relock points, the picker's keys and its action menu.

Fixes made (27): the Lead decisions intro says LD-176; INT-05.10 takes the pick field's name as everything after the first `:`, as the reference does (the card said a second `:` ends it), T23 follows; INT-05.7 says what spaces `{DELAY=n}` allows and marks `{DELAY= 50}` as App, and T16 no longer uses `{DELAY = 0}`, which the card's own rules make an unknown placeholder; INT-05.5 and INT-05.13 explain that a placeholder keeps its digits (`{S:Field 2}` works, `{USERNAME 2}` does not) instead of "a count is never allowed"; INT-05.13 adds the line feed test of MOD-08.21; INT-05.25 step 7 (a search text forces the picker) and INT-05.29 (⇧Return) are marked App; INT-05.27 says what a found entry with matching rows shows; MI05-34 no longer blames macOS for App's own rule, and the new MI05-36 covers other refusals (INT-05.30, D-INT05-16 (7)); MI05-60 is reworded, as it followed the reference's dialog text clause by clause; INT-05.36 gives the Tab check box's default (on, as the reference); INT-05.37 drops the window number, which only a private macOS call gives, and compares Accessibility elements (new V-INT05-8); INT-05.38 waits the start delay once for a run from App's window (INT-05.33 already waited it); INT-05.40 marks the one-event surrogate pair as App; INT-05.45 says the layout reaches Rust as one table, so Swift never looks up a secret character; D-INT05-16 (3) no longer claims an app cannot choose its own name; the security notes add keys already handed to macOS, the per-window (not per-field) gap such as a browser's address bar, and who can borrow the Accessibility permission (APP-11); the test setup makes the hidden helper the provider's active app so the focus check runs against it, drives every panel through view models or offscreen, and V-INT05-3 says granting the test process's permission is the owner's step; T70 closes the second picker (INT-05.25 step 2 would ignore the third press), T85 covers the window-title offer, T88 uses a simulated activation, T89 no longer needs a focused window (AGENTS.md rule 10), T107 adds ⌃⌥V as V-INT05-7 says; new T108 (INT-05.1 short form), T109 (bridge search text) and T110 (target never comes back).

Findings, each with a proposed ruling (the default rule of spec/decisions.md applies until the lead rules):

| ID | Finding | Proposed ruling |
|---|---|---|
| R05-1 | D-INT05-13 (2) says no change breaks a sequence that works in the reference, but INT-05.19 does: an entry whose effective sequence is empty (E10's case) with a window rule that has its own sequence is matched and typed by the reference; App drops the entry. INT-05.19 also disables Auto-Type Username Only and Password Only for such an entry, though they type fixed sequences. | Keep the intent (never a row that types nothing) without dropping the entry: an entry with an empty effective sequence stays a candidate; INT-05.23 and INT-05.27 never make a row whose sequence is empty; Type Login needs a non-empty effective sequence; the two field actions need only their field. Test: E10 gets a window rule `*Quiet*` → `{PASSWORD}`; title `Quiet` gives one E10 row with `{PASSWORD}`; Type Login stays disabled for E10, Auto-Type Password Only is enabled. |
| R05-2 | AT-G03: the reader has no bound on brace nesting. A vault (sync, shared group, import) can hold `{a` 50,000 times followed by `}` 50,000 times: the count passes, and a recursive reader can run out of stack and crash App. (The reference leaves this to its pattern engine's limits; not run.) | A brace token nests at most 32 levels (MOD-08 resolves only 10 deep anyway); deeper fails the run with a new reason MI05-25 "‹token› has braces nested more than 32 deep."; the reader keeps its own stack (no recursion on the call stack). Tests: the 50,000-level sequence fails within 100 ms; 32 levels read; the fuzz target (T40) gets deep-nesting seeds. |
| R05-3 | Control characters written in the sequence text itself are not covered: INT-05.14 handles only resolved values, and INT-05.40 would send a line feed or a NUL as a Unicode event. The reference skips a line feed in the sequence (its reader's "any character" does not take one) and sends tab, carriage return and other control characters as Unicode events. | In sequence text, line feed and carriage return are dropped (as the reference does for line feed, so a sequence that works there types the same), a tab character presses Tab, every other control character is dropped. Test: a sequence `a` LF `b` TAB `c` CR U+0000 `d` gives text `a`, `b`, key 0x30, text `c`, `d`. |
| R05-4 | A sequence can type App's own global shortcut (`^%v` with the default). macOS may hand a posted key that matches a hot key to the hot key's owner; then App sees its shortcut, stops its own run (INT-05.39), and the target never gets the key. Not checked: that needs keys posted to the whole session, which waits for the owner's go (AGENTS.md rule 10). The ruling below is safe either way. | The check of INT-05.15 fails such a sequence before typing with a new reason MI05-26 "‹token› is App's own Auto-Type shortcut."; the editor shows it while typing. Test: S-AT-07 ⌃⌥V on the fake hot key service; run `x^%v`; MI05-26, no event. |
| R05-5 | INT-05.22 tests the host in MOD-08.9's form, which App always gives in ASCII (punycode). Browsers and title extensions show internationalized names in Unicode, so an entry `https://bücher.example/` never matches a title holding `bücher.example`. | The host test tries the ASCII form and its Unicode form (the IDNA decoding), each ignoring case. Test: URL `https://bücher.example/`, title `Shop – bücher.example`: one row. |
| R05-6 | MI05-43 (frame) says "⏎ types username, password and code" for every row, but Return types the row's sequence, which often has no code (E2, E3) or no username (E4). The hint promises keys that may not come. | Hint line "↑↓ to choose · ⏎ types the login · ⇧⏎ types the password only", added to D-INT05-16 for the owner's OK with the other mockup texts (AT-K05). |
| R05-7 | A loop or a work bound (MOD-08.18, MOD-08.20) gives the raw text back, so INT-05.13 reports `{S:Grow}` (T37) or a self-referring `{USERNAME}` as "not a placeholder App knows" (MI05-19), which points the user at the wrong problem. | MOD-08's resolver tells its caller when a depth or work bound was hit; Auto-Type then uses a new reason MI05-27 "‹token› refers to itself or grows too large." T37 expects MI05-27. MOD-08 itself is unchanged for every other caller. |
| R05-8 | Other files still disagree with LD-176: APP-01 S-AT-07 says default none (D-INT05-10: ⌃⌥V) and S-AT-10 says 0–1,000 ms (D-INT05-14 (3): the control offers 0–500); plan/security.md SI-14 still names the Screen Recording permission (D-INT05-1: Accessibility only). | The lead has those rows updated by their owners in the same pass as LD-176's mockup changes; this card already holds the ruled values. |
