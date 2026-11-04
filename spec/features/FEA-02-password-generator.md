# FEA-02 Password generator

Status: reviewed
Epics: E4-S9, E5-S6
Parity rows: SG-01, SG-02, SC-01, SC-02, SC-06, SI-01

## What it does

Makes random passwords from character groups the user picks: letters, digits, six groups of ASCII symbols, extended ASCII, plus the user's own extra characters, minus characters the user excludes. Options: exclude look-alike characters, and take at least one character from every group. Every pick comes from the operating system's random source, without bias.

One generator core (`app-core` `generator/password.rs`) serves every caller:

- the toolbar generator (a screen of its own, works with no vault open),
- the generator popup on every password field: entry editor, master key fields (APP-07), shared-group password (INT-08),
- the browser bridge "generate password" request (INT-01 owns the message),
- the optional password for each new entry (FEA-02.19),
- the command line tool (`app generate`, and the generate option of add and edit; INT-10 owns the command syntax).

The same screen has a Passphrase tab: FEA-03. The strength number comes from FEA-05. Copying follows APP-03. APP-01 lists the settings below.

## Inputs and outputs

In: the options below. Out: a password of exactly `length` characters, held as a `SecretString`, or one of two errors: `InvalidOptions(reason)` (FEA-02.5) or `RandomFailed` (FEA-02.6).

A "character" is one Unicode scalar value (FEA-02.22).

### Options

| Option | Type and limits | Meaning |
|---|---|---|
| length | integer; screen 1 to 999; core and command line see D-02-4 | number of characters |
| classes | set of the classes in the table below | groups to draw from |
| extra | text, may be empty (limit D-02-4) | one more group made of these characters |
| excluded | text, may be empty (limit D-02-4) | characters removed from every group |
| exclude look-alike | on or off | FEA-02.2 |
| every group | on or off | FEA-02.8 |

### Character classes

Order matters: groups are built and pooled in this order (FEA-02.1). Code points are Unicode.

| Class (our ID) | Characters, in order | Count | Removed by look-alike exclusion | Count then |
|---|---|---|---|---|
| `lower` | a to z (U+0061 to U+007A) | 26 | l | 25 |
| `upper` | A to Z (U+0041 to U+005A) | 26 | B G I O | 22 |
| `digits` | 0 to 9 (U+0030 to U+0039) | 10 | 0 1 6 8 | 6 |
| `brackets` | U+0028 U+0029 U+005B U+005D U+007B U+007D, that is ( ) [ ] { } | 6 | none | 6 |
| `punctuation` | U+002C U+002E U+003A U+003B, that is , . : ; | 4 | none | 4 |
| `quotes` | U+0022 U+0027 (double quote, apostrophe) | 2 | none | 2 |
| `dashes` | U+002D U+002F U+005C U+005F U+007C (hyphen, slash, backslash, underscore, vertical bar) | 5 | U+007C | 4 |
| `math` | U+0021 U+002A U+002B U+003C U+003D U+003E U+003F, that is ! * + < = > ? | 7 | none | 7 |
| `signs` | U+0023 U+0024 U+0025 U+0026 U+0040 U+005E U+0060 U+007E (number sign, dollar, percent, ampersand, at, caret, grave accent, tilde) | 8 | none | 8 |
| `extended` | U+00A1 to U+00AC, then U+00AE to U+00FF | 94 | one character, see FEA-02.2 | 93 |
| `special` (App only, D-02-2) | the six symbol classes above as one group, in the order brackets, punctuation, quotes, dashes, math, signs | 32 | U+007C | 31 |

The six symbol classes together are exactly the 32 printable ASCII characters that are not letters, digits or space. `extended` leaves out U+0080 to U+009F (control characters), U+00A0 (no-break space) and U+00AD (soft hyphen). Upper, lower, digits and the six symbol classes together are all 94 printable ASCII characters except space.

### Settings and defaults

App-wide settings, not stored in the vault. Saved per FEA-02.18. The reference keeps the same values in its own settings file.

| Setting (our ID) | Screen default | Notes |
|---|---|---|
| `generator.kind` | password | password or passphrase tab (FEA-03) |
| `generator.password.length` | 20 | |
| `generator.password.upper` | on | |
| `generator.password.lower` | on | |
| `generator.password.digits` | on | |
| `generator.password.special` | on | simple view chip (FEA-02.12) |
| `generator.password.extended` | off | |
| `generator.password.advanced` | off | which view is shown |
| `generator.password.brackets`, `.punctuation`, `.quotes`, `.dashes`, `.math`, `.signs` | off each | advanced view chips |
| `generator.password.extra` | empty | advanced view only |
| `generator.password.excluded` | empty | advanced view only |
| `generator.password.exclude_lookalike` | on | reference: applies only in advanced view (FEA-02.12) |
| `generator.password.every_group` | on | reference: applies only in advanced view |

Built-in fallback options (the command line defaults, and the fallback in FEA-02.19): length 32; classes lower, upper, digits; exclude look-alike on; every group on; extra and excluded empty.

What the defaults produce:

| Caller | Effective options | Pool |
|---|---|---|
| Reference screen, first start | 20 characters; simple view, so look-alike and every group are off | 94 characters (all printable ASCII except space), uniform |
| Reference command line, no options | 32 characters; built-in fallback | 53 characters (25 + 22 + 6), at least one from each of the 3 groups |
| App screen, first start (D-02-2 option b) | 20 characters; lower, upper, digits, `special`; look-alike on; every group on | 84 characters (25 + 22 + 6 + 31), at least one from each of the 4 groups |

## Rules

FEA-02.1 Groups are built in the order of the class table: lower, upper, digits, brackets, punctuation, quotes, dashes, math, signs, extended (App: `special` sits where the six symbol classes sit), then the extra group last. Inside a group, characters keep the table order. Only selected classes make groups.

FEA-02.2 Exclude look-alike, when on, removes exactly: `l` from lower; `B G I O` from upper; `0 1 6 8` from digits; U+007C from dashes (and from `special`); and one character from extended. Nothing else is removed: `o`, `S`, `5`, `Z`, `2` stay, and the extra group is never filtered by this option. In extended, the reference removes U+00F9 (small u with grave), while its screen hint promises a small dot sign; App removes U+00B7 (middle dot) instead (D-02-1).

FEA-02.3 Extra characters form one group: each distinct character of the extra text once, in order of first appearance (so `aab` gives the group `a b`, equally likely). This group is added even when all its characters are already in selected classes. A character that is both in a selected class and in the extra text is then in the pool twice, so it is picked twice as often (parity: observed in the reference; App keeps it, because the extra group also counts for every group). The extra group is used even when no class is selected.

FEA-02.4 Excluded characters are removed from every group, including the extra group: every occurrence of every character in the excluded text. Excluded wins over extra. A group left empty is dropped and does not count as a group (FEA-02.5, FEA-02.8). Repeats in the excluded text change nothing.

FEA-02.5 A password can be made only when all of these hold; App checks them in this order and returns the first failure as `InvalidOptions(reason)`: (1) `length` is inside the limits (FEA-02.10); (2) at least one non-empty group remains after FEA-02.2 to FEA-02.4 (this also covers "no class and no extra characters"); (3) with every group on, `length` is at least the number of non-empty groups. When a check fails nothing is generated. The reference has the same three conditions (plus "length 1 or more"); its screen then disables Regenerate and keeps showing the last value (D-02-3); its command line prints an error and exits with status 1 (FEA-02.21).

FEA-02.6 Every random index in [0, n) comes from `app-crypto::random` `below(n)`: each index exactly equally likely (rejection sampling, no modulo bias), operating system source only (AT-B04). The reference does the same: it draws 32-bit values from the system source, keeps a value v only if v < (2^32 − 1) − ((2^32 − 1) mod n), and returns v mod n. If the random source fails, generation returns `RandomFailed`: nothing is shown, copied or applied, and no partial password is kept.

FEA-02.7 The pool is every character of every group, joined in group order, duplicates kept (FEA-02.3). With every group off, each of the `length` characters is `pool[below(pool size)]`, drawn independently.

FEA-02.8 With every group on, with G non-empty groups: (1) for each group in order, one character `group[below(group size)]`; (2) then `length − G` characters `pool[below(pool size)]`; (3) then shuffle: for i from `length − 1` down to 1, j = `below(i + 1)`, swap the characters at i and j. Draws happen in exactly this order (this matters only for scripted tests; the result is a uniform random permutation).

FEA-02.9 Consequences App must keep (they are what the reference produces): with every group on, every password holds at least one character of each non-empty group; all positions have the same distribution; characters of small groups are more common than in a uniform draw: the expected number of characters from group g is 1 + (length − G) × size(g) / pool size. Example: the command line default (length 32, groups 25, 22, 6, pool 53) gives on average 227/53 = 4.28 digits, against 3.62 for a uniform draw. The generator shows no formula entropy for passwords; the strength line is FEA-05's estimate of the text (FEA-02.15), so nothing over-claims.

FEA-02.10 Length. Reference screen: a slider 1 to 128 (tick every 8) and a number field 1 to 999, kept in step (a number above 128 puts the slider at its end); default 20. Reference command line: default 32; any whole number from 1 up to the 32-bit signed maximum is taken (observed: 100,000 works); 0, negative numbers, non-numbers and numbers too big for 32 bits give an error saying the length is not valid, and status 1. App limits: D-02-4.

FEA-02.11 Defaults are the values in "Settings and defaults". The command line ignores the saved settings and starts from the built-in fallback options (FEA-02.21).

FEA-02.12 Reference views. Simple view (default): five chips: upper, lower, digits, special, extended. Here "special" selects all six symbol classes as six separate groups. Exclude look-alike, every group, extra and excluded are hidden and not applied, whatever their saved values. Advanced view: chips upper, lower, digits, extended, brackets, punctuation, quotes, dashes, math, and the chip that means "special" in the simple view now means signs only; plus the extra field, the excluded field, the hex preset (FEA-02.13), exclude look-alike and every group. That shared chip keeps its on or off state when the view changes; its state is saved as `special` in the simple view and as `signs` in the advanced view. App follows the mockup instead (D-02-2): one view with length, the five chips, exclude look-alike and every group, both always applied; the advanced controls behind an "Advanced" control. In App's simple view the special chip is the `special` class (one group), and hidden advanced options (six symbol chips, extra, excluded) are not applied.

FEA-02.13 Hex preset (action `ACT-GEN-HEX`, advanced view). Reference: sets the excluded text to `GHIJKLMNOPQRSTUVWXYZ`, turns upper and digits on, turns every other class off, and leaves extra, exclude look-alike and every group as they are. With look-alike on (its default) the output then uses only the 11 characters `A C D E F 2 3 4 5 7 9`, and any extra characters stay in. App: D-02-6.

FEA-02.14 The value is regenerated at once when the generator opens, on every option change (each keystroke in the extra, excluded and length fields), on a tab switch, and on Regenerate (`ACT-GEN-REGENERATE`, Command-R in the reference). Invalid options: D-02-3.

FEA-02.15 Strength line, for the text currently in the output field, recomputed on every change: the FEA-05 estimate in bits, shown with 2 decimals; a quality word from the FEA-05 bands (below 40 bits Poor, 40 to below 75 Weak, 75 to below 100 Good, 100 and up Excellent; the reference also shows Poor at 0 bits, a value its reports call Bad); a bar from 0 to 200 bits filled to min(whole bits, 200), coloured by quality; and the character count. App's look follows the mockup ("quality · bits", its own bar scale); the numbers come from FEA-05.

FEA-02.16 The output field is editable. Copy and Apply use the text as shown, including the user's edits, and the strength line follows the edits (SC-06).

FEA-02.17 Entry points.

| Entry point | Buttons | Output shown | Start length |
|---|---|---|---|
| Toolbar generator (`ACT-GEN-OPEN-TOOL`) | Regenerate, Copy, Close | in the clear | saved length |
| Popup on a password field (Control-G in the reference on Mac, from the field; APP-08) | Regenerate, Copy, Close (Escape), Apply (Command-Return or Command-S) | masked or clear, following the field's current state (reference); App: as the mockup shows | the length of the field's current text when it is not empty (capped at 999), else the saved length |
| Browser request (`password.generate`, INT-01.34) | none: no App window opens | none in App; the extension's generator page shows the value | the request's `length`, else the saved length |

Apply (`ACT-GEN-APPLY`) is enabled only when the output is not empty. It fills the field, and its repeat field when there is one (master key, shared-group password), then closes the popup. A browser request from an associated session gets a value at once: App makes it with this core and the saved settings, or the request's options (INT-01.34), and returns it with its strength in bits; no window, no Apply, options from the bridge are never saved and the value is not kept (LD-189, D-INT01-5). Reference: the request opens the popup and the value goes to the extension only after Apply; closing without Apply sends the "cancelled or denied" error, and a second request while the popup is open gets that error too.

FEA-02.18 Saving settings. The reference saves all generator settings (both tabs) when the user applies a value from a popup, when the toolbar generator closes, and, as a side effect, at every switch between simple and advanced view. Closing a popup without Apply keeps the earlier saved settings, except for such a view switch. Opening a generator loads the saved settings. Generated values are never saved. App saves on Apply and on closing the toolbar generator; it need not copy the view-switch side effect.

FEA-02.19 Optional password for new entries (setting owned by APP-01, default off). Reference source: when on, a new entry gets a generated password built from the saved password settings (always the password kind, even if the passphrase tab was used last; in simple view without look-alike, every group, extra or excluded, as FEA-02.12); when those settings are invalid, the built-in fallback options are used. Installed version 2.7.11 differs: it always uses the built-in fallback options (32 characters from the 53-character pool). App follows the source, with App's view meaning (D-02-2): the new entry gets what the password tab would generate with the saved settings, and the built-in fallback options when they are invalid.

FEA-02.20 Copy (`ACT-GEN-COPY`, Command-C in the reference) puts the output on the clipboard under APP-03: concealed, cleared after the timeout (10 seconds by default) only if the clipboard still holds it, cleared on lock and quit (SC-01, SC-02, SC-03). Copy is enabled only when the output is not empty.

FEA-02.21 Command line options (INT-10 owns syntax, help text and exit codes). Class options: lower, upper, numeric, special (the six symbol classes as six groups), extended. If no class option and no custom set is given, the classes are lower, upper, digits. A custom set (`-c`) is the extra group; given alone, it is the only group. Exclude (`-x`) is the excluded text. Flags: if neither `--exclude-similar` nor `--every-group` is given, both are on; if either is given, only the given ones are on (so giving one turns the other off). An empty custom set with no class gives "invalid generator". Length per FEA-02.10. Invalid options: one error line and status 1. `app` matches all of this (parity).

FEA-02.22 App works on Unicode scalar values: an extra or excluded character outside the Basic Multilingual Plane is one character, counted once. A combining mark is its own character (so `e` plus U+0301 gives two characters, as in the reference). The reference works on UTF-16 units instead: it splits such a character into two halves and can output broken halves (observed). App never outputs a lone surrogate (Rust strings cannot hold one). The character count in FEA-02.15 counts scalar values.

FEA-02.23 The output is a secret. It lives in Rust as a `SecretString`. The screen receives it only to show it while the generator is open (the generator is a Show of a value the user asked for, AGENTS rule 4) and drops it when the generator closes. Apply and Copy are commands on the value Rust holds; the value does not travel back from the screen. It is never logged, never put in settings, never part of an error. On lock: D-02-5.

## Edge cases and errors

| Case | Expected |
|---|---|
| No class and empty extra | `InvalidOptions(NoCharacters)`, message `MSG-GEN-NO-CHARS` ("choose at least one character type"). Reference: Regenerate disabled, no message; command line: an error saying the generator settings are not valid, status 1. |
| Every class emptied by the excluded text (digits only, excluded `0123456789`) | same as above |
| Every group on, length below the number of groups (lower, upper, length 1) | `InvalidOptions(TooShortForEveryGroup(needed))`, message `MSG-GEN-TOO-SHORT` naming the needed length |
| Every group on, one class fully excluded (lower, upper, digits, excluded `0123456789`, length 2) | valid: only 2 groups count |
| Length 0, negative, too big, not a number | `InvalidOptions(LengthOutOfRange)`, message `MSG-GEN-LENGTH`; reference command line: an error saying the length is not valid, status 1 |
| Extra character also in a selected class | allowed; picked twice as often (FEA-02.3) |
| Extra `l` with look-alike on | `l` can appear (FEA-02.2) |
| Character both in extra and excluded | never appears |
| Popup opened on a field holding 1,500 characters | start length 999 |
| Random source fails | `RandomFailed`, message `MSG-GEN-RANDOM` ("could not get random numbers from macOS"); nothing shown |
| Reference simple view after an advanced session in the same open generator | the reference keeps applying the extra and excluded text typed earlier, although both fields are hidden (source, re-read by Verify in Sprint 3: in simple view the generator is given only the classes, and the extra and excluded sets it was given in advanced view are never reset). App never applies hidden options (FEA-02.12). |

Not on Mac: nothing. The generator behaves the same on every platform; only shortcut keys differ (APP-08).

## Lead decisions

| ID | Question | Options | Recommendation |
|---|---|---|---|
| D-02-1 | Which extended character look-alike exclusion removes | (a) U+00F9, as the reference; (b) U+00B7 middle dot, the dot the reference's hint promises (its code value matches a dot only in an old DOS code page); (c) both | (b): the option promises to drop a dot-like sign |
| D-02-2 | Views: the mockup shows exclude look-alike and every group next to the five chips, with no advanced view | (a) reference views exactly (the two options hidden and off in the simple view; mockup changed); (b) mockup: both options visible and applied; the special chip is one combined group (`special`); advanced controls (six symbol chips, extra, excluded, hex) behind an "Advanced" control, which the mockup does not show yet; (c) like (b) but the special chip is six groups, so every group forces at least 6 symbols and a length of 9 or more | (b). Needs the owner's look approval for the added Advanced control (AT-K05). The mockup's length slider is 8 to 64: App keeps the reference range 1 to 999 in the number field, and the slider may stay 8 to 64. |
| D-02-3 | Invalid options in the screen | (a) as the reference: keep the old value, disable Regenerate, no message; (b) clear the output, disable Copy and Apply, show the reason (`MSG-GEN-NO-CHARS`, `MSG-GEN-TOO-SHORT`, `MSG-GEN-LENGTH`) | (b). The mockup's own handler turns lower back on when the last chip is turned off; App may do that too, so the chips alone never make the options invalid. |
| D-02-4 | Limits (Rust rule 5, AT-E03) | Reference: screen 1 to 999, command line up to 2^31 − 1; extra and excluded up to 32,767 characters (text field default) | Length 1 to 999 on screen, 1 to 10,000 in core and command line; extra and excluded at most 1,024 characters each, control characters (U+0000 to U+001F, U+007F to U+009F) dropped from extra |
| D-02-5 | Generator value on lock | (a) as the reference, where the toolbar generator is not tied to a vault and stays as it is (source, re-read by Verify in Sprint 3: the main window's generator is touched only when it is shown or hidden; nothing in the lock path reaches it); (b) on lock App closes generator popups of that vault and clears the toolbar generator's value | (b): stricter, costs nothing |
| D-02-6 | Hex preset | (a) as the reference (FEA-02.13); (b) also turn look-alike off and clear extra, so the output uses exactly `0-9 A-F` | (b): "hex" should mean all 16 hex digits |

## Security notes

- SG-01 and AT-B04: every pick goes through `app-crypto::random`. Never a seeded, time-based or non-cryptographic generator, never a value reused. A source failure must fail closed (FEA-02.6).
- Modulo bias: `below(n)` must reject, never take a plain `random mod n` (FEA-02.6). A biased picker would favour the first characters of the pool.
- SG-02: classes, look-alike exclusion, every group, extra and excluded characters are all here. Every group makes the distribution non-uniform (FEA-02.9) and duplicates between extra and classes double a character's weight (FEA-02.3). Both are reference behavior, kept for parity; the strength line uses the estimate of the actual text (FEA-05), so it never shows a pool-size number that the distribution does not deliver.
- The output is a secret (FEA-02.23): never logged (AT-C06), gone from the screen after close (AT-C02, AT-E07), copied only under APP-03 rules (AT-D01, AT-D02, AT-D03).
- Hostile command arguments (AT-E03): huge lengths and texts are refused by D-02-4 before any allocation.
- Browser bridge: the reference opens the generator for any client that can send an encrypted message, without checking for an association (source reading); the value reaches the extension only after the user presses Apply (INT-01, INT-02; AT-F01, AT-F04). App must keep "only after Apply"; whether it also requires association is for INT-01.
- The saved settings (including extra and excluded text) are not secret and hold no generated value.

## Test cases

Statistical cases use the real random source and a fixed bar of α = 10^-6, so a correct build fails less than once in a million runs. "Scripted source" means a test-only index source that returns given values and records each requested bound `n`; it exists only in tests and never in release code (AT-B04).

| Case | Given | When | Then |
|---|---|---|---|
| FEA-02.1 order | classes digits and brackets, look-alike off, every group off, scripted source [0, 9, 10, 15], length 4 | generate | `0 9 ( }` joined: `09(}`; bounds requested [16, 16, 16, 16] |
| FEA-02.1 sets | each class alone, look-alike off, length 2,000 | generate once per class | every character is in that class's table row; for extended none is in U+0080 to U+00A0 or U+00AD |
| FEA-02.2 removed set | lower, upper, digits, dashes, extended, look-alike on, length 50,000 | generate | none of `l B G I O 0 1 6 8`, U+007C, U+00B7 appears; `o S 5 Z 2` and U+00F9 do appear (App, D-02-1) |
| FEA-02.2 extra untouched | lower, look-alike on, extra `l`, length 5,000 | generate | `l` appears |
| FEA-02.3 dedupe within extra | no class, extra `aab`, length 3,000 | generate | only `a` and `b`; each count within 1,500 ± 134 |
| FEA-02.3 doubled weight (statistical) | lower, extra `a`, look-alike off, every group off, length 270,000 | generate once | count of `a` within 20,000 ± 666; count of `b` within 10,000 ± 480 |
| FEA-02.3 extra alone | no class, extra `abc`, length 2,000 | generate | only `a b c` |
| FEA-02.4 excluded | lower, upper, excluded `xyzXYZ`, look-alike off, length 20,000 | generate | none of `x y z X Y Z` |
| FEA-02.4 excluded wins over extra | digits, extra `#`, excluded `#5`, length 5,000 | generate | no `#`, no `5` |
| FEA-02.5 no characters | no class, extra empty, length 32 | generate | `InvalidOptions(NoCharacters)` |
| FEA-02.5 all excluded | digits, excluded `0123456789` | generate | `InvalidOptions(NoCharacters)` |
| FEA-02.5 too short | lower, upper, every group on, length 1 | generate | `InvalidOptions(TooShortForEveryGroup(2))` |
| FEA-02.5 excluded group does not count | lower, upper, digits, every group on, excluded `0123456789`, length 2 | generate | valid; one lower and one upper letter |
| FEA-02.5 extra counts as group | lower, upper, digits, every group on, extra `012345`, length 3 | generate | `InvalidOptions(TooShortForEveryGroup(4))`; length 4 valid |
| FEA-02.5 length 0 | defaults, length 0 | generate | `InvalidOptions(LengthOutOfRange)` |
| FEA-02.6 bound | `below` test in `app-crypto` with a scripted 32-bit draw stream that starts with one draw from the biased zone, then 7, and n = 10 | below(10) | first draw rejected, result 7. The reference rejects the high zone (it keeps only v below 4,294,967,290); App's `below` rejects its biased zone at the low end; both are unbiased (LD-124) |
| FEA-02.6 fail closed | random source forced to fail (test build) | generate | `RandomFailed`; output field empty; Copy and Apply disabled |
| FEA-02.7 uniform (statistical) | digits only, every group off | 10,000 passwords of length 100 | chi-square over the 10 digits below 44.81 (9 degrees of freedom) |
| FEA-02.7 uniform full set (statistical) | upper, lower, digits, brackets, punctuation, quotes, dashes, math, signs, look-alike off, every group off | 10,000 passwords of length 94 | all 94 characters seen; chi-square below 172.75 (93 degrees of freedom) |
| FEA-02.7 extended (statistical) | extended only, look-alike on, every group off | 10,000 passwords of length 93 | exactly the 93 characters seen; chi-square below 171.40 (92 degrees of freedom) |
| FEA-02.7 scripted | lower, look-alike on, scripted [0, 10, 24], length 3 | generate | `akz` (index 10 is `k`, 11 would be `m`); bounds [25, 25, 25] |
| FEA-02.8 scripted | digits, extra `x`, look-alike off, every group on, scripted [4, 0, 10, 0, 1], length 3 | generate | `xx4`; bounds requested [10, 1, 11, 3, 2] |
| FEA-02.8 exact distribution (statistical) | digits, extra `x`, look-alike off, every group on, length 2 | 200,000 passwords | only the 20 strings digit+`x` and `x`+digit; chi-square below 63.68 (19 degrees of freedom) |
| FEA-02.9 positions (statistical) | as above, length 3 | 330,000 passwords | every password has a digit and an `x`; `x` at each position 120,000 ± 1,352 times (probability 4/11); passwords with two `x` 30,000 ± 808 (1/11). Reference command line, 2,000 runs: 0.360, 0.359, 0.370 and 0.088 |
| FEA-02.9 small groups | built-in fallback options, length 32 | 20,000 passwords | mean digit count within 4.283 ± 0.06 |
| FEA-02.10 screen range | screen | type 1,000 in the length field; type 128; type 500 | 999 kept; slider at 128; slider at its end, length 500 |
| FEA-02.10 command line | `app generate -L 0`, `-L abc`, `-L -5`, `-L 99999999999` | run | each: one error line, status 1 |
| FEA-02.11 defaults | fresh settings | open the toolbar generator | password tab; length 20; upper, lower, digits, special on; extended off; App: look-alike and every group on and applied (D-02-2) |
| FEA-02.11 command line defaults | `app generate` | run 300 times | each 32 characters; together exactly the 53 characters of the fallback pool; each has at least one lower, one upper, one digit |
| FEA-02.12 reference simple view | reference settings: simple view, special on, look-alike on, every group on | generate 300 × 100 characters | all 94 characters appear (look-alike and every group not applied) |
| FEA-02.12 App simple view | App defaults (D-02-2 b), length 4 | generate 10,000 | every password has one lower, one upper, one digit, one symbol; no `l B G I O 0 1 6 8` or U+007C |
| FEA-02.12 hidden options | App: advanced view, extra `€`, excluded `a`; switch to simple view | generate 2,000 × 50 | `€` never appears, `a` appears |
| FEA-02.12 shared chip | reference advanced view, signs chip on | switch to simple view | special chip on |
| FEA-02.13 reference hex | reference defaults in advanced view, look-alike on | press Hex, length 2,000 | only `A C D E F 2 3 4 5 7 9` |
| FEA-02.13 App hex | App, extra `xyz` | press Hex, length 2,000 | exactly the 16 characters `0-9 A-F` appear; extra empty; look-alike off (D-02-6) |
| FEA-02.14 live | toolbar generator open | type `#` into extra | a new value appears at once |
| FEA-02.14 invalid | App, lower and upper only, every group on, length 2 | set length 1 | output cleared, `MSG-GEN-TOO-SHORT` shown, Copy and Apply disabled (D-02-3) |
| FEA-02.15 strength | output field | type `YQC3kbXbjC652dTDH`, then `Bs5ZFfthWzR8DGFEjaCM6bGqhmCT4km` | bits and quality word equal FEA-05's result for each text, bits with 2 decimals (the reference shows Good, then Excellent); count 17, then 31 |
| FEA-02.15 empty | output field | clear it | 0 bits, lowest quality word, count 0, Copy and Apply disabled |
| FEA-02.16 edit | popup on an entry's password field | edit the output to `demo-pass-42`, press Apply | the field holds `demo-pass-42` |
| FEA-02.17 popup length | entry "Demo Mail" with password `abcdefghijkl` (12 characters), saved length 20 | open the popup from its field | length 12 |
| FEA-02.17 repeat field | new vault wizard, master key fields | open the popup, Apply | both fields hold the same value |
| FEA-02.17 browser request | associated bridge session, saved length 20 | `password.generate` with `{"kind":"password","options":{"length":16}}` | a 16-character value and its bits come back; no window opens; the saved length is still 20 (INT-01 T53) |
| FEA-02.18 save on Apply | popup; set length 24; Apply | open the toolbar generator | length 24 |
| FEA-02.18 no save on Close | popup; set length 30; Close | open the popup on an empty field | length 24 (the earlier saved value) |
| FEA-02.19 new entry | setting on; saved: simple view, upper only, length 16 | create entry "Demo Shop" | password of 16 characters, all `A-Z` |
| FEA-02.19 invalid saved | setting on; saved settings with no class | create an entry | 32 characters from the 53-character fallback pool, with lower, upper and digit |
| FEA-02.20 copy | toolbar generator | Copy, wait 10 s | clipboard holds the value marked concealed, then is cleared (APP-03) |
| FEA-02.21 flags | `app generate --exclude-similar -L 1` | run | valid, 1 character from the 53-character pool (every group off) |
| FEA-02.21 flags | `app generate --every-group -L 1` | run | invalid, status 1 (3 groups) |
| FEA-02.21 custom alone | `app generate -c abc -L 10` | run | 10 characters from `a b c` only |
| FEA-02.21 empty custom | `app generate -c ""` | run | invalid generator, status 1 |
| FEA-02.21 special | `app generate -s --every-group -L 6` | run 1,000 times | each password has exactly one character from each of the six symbol classes; U+007C appears somewhere in the 1,000 |
| FEA-02.22 scalar | no class, extra U+1F600 and `a`, length 1,000 | generate | 1,000 characters, each U+1F600 or `a`; valid UTF-8 |
| FEA-02.23 secret | debug build with attach allowed | generate in the toolbar generator, close it, dump memory | the value is not found (AT-C02) |
| FEA-02.23 logs | highest log level | generate, copy, apply | the value is not in any log (AT-C06) |
| FEA-02 AT-B04 | the source tree | search for random sources outside `app-crypto` (`rand::`, `getrandom`, `OsRng`, `thread_rng`, time-seeded code) | none in the generator; it calls only `app-crypto::random` |

## How this was learned

- Read the reference's password generator core: the character groups and their exact code points, the look-alike rules, the extra and excluded handling, the validity check, the minimum length, the defaults, and the generation steps (picks, then shuffle).
- Read the random module: the system random source of its crypto library and the rejection rule of its bounded pick.
- Read the generator screen and its layout file: slider and field ranges, chip labels, the simple and advanced views, the hex preset, live regeneration, strength line, character count, shortcuts, when settings are saved and loaded, popup versus toolbar mode, and the start length taken from the password field.
- Read the app settings defaults table, the entry editor's new-entry path, the password field widget, the toolbar handling, the browser bridge's generate request handler, and the command line tool's generate command (shared by add and edit).
- Read the reference unit tests for the generator (class sets, look-alike, validity, minimum length, settings loading) and the screen tests for the strength labels.
- Compared the installed version 2.7.11 with the source: the generator core, screen and command line match, except FEA-02.19.
- Ran the installed command line tool in `/tmp/spec-fea02-fea03`: defaults (300 × 100 characters: exactly 53 distinct characters), extended with and without look-alike (93 and 94 characters, U+00F9 missing with look-alike), special with and without (31 and 32), the flag interplay, length errors, `-c aab` (equal weights), lower plus `-c a` (`a` about twice as common), 2,000 runs of digits plus `x` with every group (position shares above), and an emoji in the custom set (broken halves printed).
- Statistical bars computed with python3 (chi-square and normal quantiles at α = 10^-6); exact distributions computed by enumeration.

Note (LD-124): statistical cases whose single password would pass the 10,000-character limit of D-02-4 are run as several passwords of at most 10,000 characters joined together, which is the same draw.
