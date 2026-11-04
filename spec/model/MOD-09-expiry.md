# MOD-09 Expiry

Status: reviewed
Epics: E4-S7
Parity rows: SR-08, SG-04, SI-04

## What it does

Every entry and every group can carry an expiry date. Past that moment the item counts as expired. An expired entry still works: App only marks it, can list it, warns about it after unlock, and lets other features treat it differently (the browser bridge refuses it by default, Health Check scores it 0).

This card owns:
- the two expiry fields and their defaults,
- how "expired" and "expires within N days" are computed, including time zones,
- the expired-entries notice after unlock, with its settings (SR-08, AT-K04),
- the "Expire now" action,
- the expiry controls and presets in the editors,
- how expired items look,
- which other features read expiry, with pointers to their cards.

FMT-11 and FMT-12 own how the fields are stored: `Times/Expires` (boolean) and `Times/ExpiryTime` (UTC, whole seconds). FEA-01 owns the search language. This card owns only what `is:expired` computes.

## Inputs and outputs

In: an entry's or group's `Expires` flag and `ExpiryTime`, the current instant, the Mac's time zone rules, two app settings.
Out: an expired yes or no, an expires-within-N-days yes or no, the notice after unlock, new field values from the editor, presets and Expire now.

Settings (APP-01 owns the final IDs and the settings screen):

| Proposed ID | Meaning | Type | Default | Range |
|---|---|---|---|---|
| `expiry.notice_on_unlock` | show the expiry notice after unlock | boolean | on | |
| `expiry.notice_days` | notice window, in days | integer | 3 | 0 to 90; the control is disabled while the notice is off |

## Rules

MOD-09.1 **Fields and defaults.** Each entry, history item and group has `Expires` (boolean) and `ExpiryTime` (an instant in UTC). A new entry or group gets `Expires` = false and `ExpiryTime` = its creation time. `ExpiryTime` keeps its value while `Expires` is false. Nothing clears it.

MOD-09.2 **Expired.** An entry or group is expired when `Expires` is true and `ExpiryTime` is strictly earlier than the current instant, compared at full clock precision. At exactly the stored second (`.000`) the item is not yet expired. From `.001` on it is. The time zone plays no part.

MOD-09.3 **Expires within N days.** True when `Expires` is true and `ExpiryTime` is strictly earlier than the local wall-clock time now plus N calendar days. The local date moves by N days and the local time of day stays. Across a daylight-saving change, the window is therefore N × 24 hours plus or minus one hour. N = 0 is the same as MOD-09.2. Already expired entries are always inside the window. The comparison itself is between instants.

MOD-09.4 **Groups.** A group's expiry marks only the group (MOD-09.14). It does not make the group's entries expired. It has no effect on search, the notice, the browser bridge, Auto-Type, Health Check or statistics.

MOD-09.5 **History items never count.** No list, count, notice or search treats a history item as expired, whatever its fields say.

MOD-09.6 **Recycle bin.** An expired entry in the recycle bin is still drawn as expired (MOD-09.14). The expired search, the notice (MOD-09.7) and the expired count in statistics (FEA-07) leave out every entry in the recycle bin or below it.

MOD-09.7 **Notice after unlock (SR-08).** It runs after a vault is unlocked, when `expiry.notice_on_unlock` is on, and only on the first unlock since the vault was opened. Unlocking again after a lock shows no notice. Quick unlock counts as unlock (APP-04). Steps:
1. Run the search `is:expired-N` (N = `expiry.notice_days`) over the whole vault. The setting that limits search to the current group is ignored.
2. If nothing matches, show nothing and leave the normal view.
3. Otherwise put the search text `is:expired-N` in the search field, show the matches as search results, and label them with message `MSG-09-1` ("expired entries") when N = 0, or `MSG-09-2` ("Expired or due to expire in N days", "1 day" when N = 1) when N > 0.

The search finds the entries that are within N days (MOD-09.3) and not in the recycle bin (MOD-09.6).

MOD-09.8 **Search word.** A search term `is:` followed by a word that starts with `expired` (any case) selects entries per MOD-09.3, minus the recycle bin. N comes from the word: split it on `-` and drop empty pieces. If a second piece exists and is a whole number, N is that number. Otherwise N = 0. Examples: `expired` → 0, `EXPIRED` → 0, `expired-3` → 3, `expired--3` → 3, `expired--1` → 1, `expired-+3` → 3 (a leading `+` is allowed), `expired-3x` → 0, `expired-abc` → 0, `expiredX` → 0, `expiredfoo-3` → 3, `expired-2147483647` → every entry with expiry on, and a number too large for 32 bits (`expired-2147483648`) → 0. N can never be negative. App caps the window end instead of overflowing: a window that reaches past the largest time App can compute holds every entry with expiry on. FEA-01 owns the rest of the search syntax.

MOD-09.9 **Expire now.** The action `entry.expire_now` (in the entry menu and the entry context menu) applies to every selected entry. It is enabled when at least one entry is selected, the recycle bin included. For each entry: `ExpiryTime` = now (UTC), `Expires` = true, and the modification and access times = now. No history item is made. The vault counts as changed (auto-save, APP-05). There is no such action for groups.

MOD-09.10 **Entry editor.** The general page has an expires check box, a date-time field showing local time, and a Presets button.
- Loading: the box shows `Expires`, and the field shows `ExpiryTime` in local time.
- Ticking the box enables the field and sets it to now (local). Unticking disables the field and keeps its value.
- Saving: `Expires` = the box, and `ExpiryTime` = the field's value converted to UTC. Both are written even while the box is unticked. So ticking and then unticking the box sets `ExpiryTime` to the moment of ticking, and that counts as a change (MOD-03 history item).
- For a history item the box is disabled, the field is read-only and Presets is disabled.

MOD-09.11 **Presets.** The Presets button opens a menu. Choosing an item ticks the box and sets the field to local now plus the amount:

| Group | Items |
|---|---|
| hours | 12 hours, 24 hours |
| weeks | 1, 2, 3 weeks (7, 14, 21 days) |
| months | 1, 2, 3, 6 months |
| years | 1, 2, 3 years |

Hours add exact elapsed time. Weeks add calendar days in local time, keeping the wall-clock time. Months and years add calendar months or years, keeping the day where possible and otherwise taking the month's last day (31 January + 1 month = 28 February, or 29 in a leap year; 29 February + 1 year = 28 February). A result that falls in a daylight-saving gap moves forward by the gap (check with Verify).

MOD-09.12 **Group editor.** The group editor has the expires box and the date-time field, with no presets. Ticking the box only enables the field. The time does not change, so a new group shows its creation time. Saving works as in MOD-09.10.

MOD-09.13 **Storage precision.** The file keeps whole seconds (FMT-12). Sub-second parts are dropped on save. A preset at local 22:00:00.700 is stored as 22:00:00 local.

MOD-09.14 **How expired items look.** An expired entry is drawn with a line through its text in every column of the entry list and in the Auto-Type selection list. Its icon gets the expired badge: a small mark in the bottom-right corner, 60% of the icon's size at the normal size and 50% at larger sizes. An expired group gets the same line through its name in the group tree, and the same badge, which takes priority over the shared-group badge. The look follows design/mockup.html. These are the facts it must express.

MOD-09.15 **Expiry shown as text.** The entry preview has an expiry field: the local date and time in the short format, or a "never" text when `Expires` is false. The entry list's Expires column (hidden by default) shows the same text. It sorts by `ExpiryTime`, with "never" sorting as 9999-01-01. The group preview shows the group's expiry the same way. The reference shows the group's time in UTC without converting it. App shows local time (lead decision D-09-2).

MOD-09.16 **Other features that read expiry.**

| Feature | Behavior | Owner |
|---|---|---|
| Browser bridge | expired entries are refused unless the user allows them (setting off by default); when allowed, the reply marks them expired | INT-02, SI-04 |
| Auto-Type | the option "hide expired entries" (off by default) leaves them out of matching and of the selection list | INT-05 |
| Health Check | expired: score 0, with an "expired" reason; expiring within 30 days: lowered score | FEA-05, SG-04 |
| Statistics, command line `db-info` | number of expired entries, recycle bin left out | FEA-07, INT-10 |
| Command line `search` | supports `is:expired-N` | INT-10 |
| Clone | keeps `Expires` and `ExpiryTime` | MOD-10 |
| Merge | merges the expiry fields like the other times | MOD-11 |

MOD-09.17 **No "expiring soon" state.** The reference has no visual state for "expires soon". The only windows are the notice's N days (MOD-09.7) and Health Check's 30 days (FEA-05). The expired state is worked out each time an item is drawn. Nothing redraws when an entry expires while it is on screen. App re-checks visible items at least once a minute and at unlock (lead decision D-09-3).

MOD-09.18 **Times outside the range.** FMT-12.8 keeps any stored `ExpiryTime`, also one outside the calendar range 0 to 315537897599 seconds (0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z). For such a value:
- Expired (MOD-09.2) and within N days (MOD-09.3) are worked out from the raw seconds count, with no calendar conversion. A value below the range counts as past: the item is expired when `Expires` is true, and it is inside every window. A value above the range is never expired and is in no window.
- Where a date would be shown, the entry preview, the group preview, the Expires column and the editors' date-time field show the fixed text `MSG-09-3` ("invalid date") instead. With `Expires` false the preview and the column still show the "never" text (MOD-09.15).
- The editors keep the stored value unchanged on save unless the user picks a date or a preset. Ticking the box still sets now (MOD-09.10).
- The Expires column sorts by the raw value, so a value below the range sorts before every date and a value above it after "never".
- No conversion of such a value may panic or wrap (FMT-12.8).

## Edge cases and errors

- `Expires` = true with `ExpiryTime` = the creation time (box ticked and saved at once): expired from the next millisecond.
- An `ExpiryTime` missing from the file reads as the open time (FMT-11). With `Expires` = true, the entry is expired from just after opening.
- A very old `ExpiryTime`, such as year 1 (written by some tools): it is earlier than the reference's date-time field can show (14 September 1752). Opening and saving the entry in the reference editor may move `ExpiryTime` to that minimum (check with Verify). App's editor keeps any stored value it does not show, unless the user changes the date.
- A far-future `ExpiryTime` (year 9999) works normally. It never expires within the lifetime of the app.
- An `ExpiryTime` outside the calendar range: MOD-09.18.
- The time zone changes while App runs: expired is unaffected (MOD-09.2). Presets and the notice window use the zone at the moment of the action.
- The notice with N = 90 and a 10,000-entry vault: one search, under 50 ms (FEA-01 budget).
- Expire now on 500 selected entries: one change event and one auto-save, not 500 (APP-05).

## Security notes

- The notice (SR-08, AT-K04) is the only reminder of stale credentials. It must run on the first unlock with the defaults (on, 3 days), and no setting may turn it on silently for other vaults. Its search must never include the recycle bin or history.
- Expiry is advisory. An expired entry still copies, fills (when allowed) and types. App must not delete or hide data because of expiry.
- The browser bridge default (refuse expired) protects users from filling a credential they meant to retire (INT-02). Keep the default off.
- Clock tampering: expiry uses the system clock. That is accepted, as for every password manager, and is out of scope.
- Expiry dates are not secret. They may appear in lists, logs of counts (never with titles) and exports.

## Test cases

Vault R9 (built in `/tmp/spec-mod08-10/m09.appvault`, password `demo`). Times are relative to now = 2026-10-24T22:50:59Z:

| Entry | Place | Expires | ExpiryTime |
|---|---|---|---|
| X1past | Root | true | now − 1 day |
| X2flagoff | Root | false | now − 1 day |
| X3in2days | Root | true | now + 2 days |
| X4in5days | Root | true | now + 5 days |
| X7in40s | Root | true | now + 40 s |
| X9hist | Root | false; its one history item: true, now − 10 days | |
| X6inExpiredGroup | group ExpiredGroup (Expires true, now − 3 days) | false | |
| X5binned | Recycle Bin | true | now − 1 day |

| Case | Given | When | Then |
|---|---|---|---|
| 09-01 defaults | App creates an entry and a group at 2026-10-25T08:00:00Z | read their fields | `Expires` false, `ExpiryTime` 2026-10-25T08:00:00Z for both (MOD-09.1) |
| 09-02 expired, at once | R9 at 2026-10-24T22:51:00Z | command line `search is:expired` | `/X1past` only (MOD-09.2, MOD-09.4, MOD-09.5, MOD-09.6; observed) |
| 09-03 expired, later | R9 at 2026-10-24T22:54:16Z | `search is:expired`; `db-info` | `/X1past /X7in40s`; the expired count is 2 (MOD-09.2; observed) |
| 09-04 strict boundary | an entry with Expires true, ExpiryTime 2026-10-25T12:00:00Z | check expired at 11:59:59.999Z, at 12:00:00.000Z, at 12:00:00.001Z | no, no, yes (MOD-09.2) |
| 09-05 window | R9 at 22:51:00Z | `search is:expired-3`; `search is:expired-7` | `/X1past /X3in2days /X7in40s`; `/X1past /X3in2days /X4in5days /X7in40s` (MOD-09.3; observed) |
| 09-06 window across a daylight-saving change | zone Europe/Berlin, now local 2026-10-24 22:00 CEST (20:00:00Z), N = 3; entries expiring at 2026-10-27T20:30:00Z, 21:00:00Z, 21:00:01Z | within 3 days? | yes, no, no. The window ends at local 2026-10-27 22:00 CET = 21:00:00Z (MOD-09.3) |
| 09-07 group does not spread | R9 | is X6inExpiredGroup expired? Is ExpiredGroup expired? | no; yes. The group shows the line-through and the badge, the entry shows neither (MOD-09.4, MOD-09.14) |
| 09-08 history and bin | R9 at 22:51:00Z | `search is:expired-7`; `db-info`; show the Recycle Bin group | X9hist and X5binned not listed; the count leaves out X5binned; X5binned is drawn line-through with the badge (MOD-09.5, MOD-09.6) |
| 09-09 notice, N = 3 | R9 at 22:51:00Z, defaults | unlock in App (first unlock) | the search field holds `is:expired-3`; results X1past, X3in2days, X7in40s; label `MSG-09-2` with 3 (MOD-09.7) |
| 09-10 notice, N = 0 | R9, `expiry.notice_days` = 0 | first unlock | `is:expired-0`; result X1past; label `MSG-09-1` (MOD-09.7, MOD-09.8) |
| 09-11 notice, nothing found | a vault with no expiring entries | first unlock | normal group view; empty search field; no label (MOD-09.7) |
| 09-12 notice, relock | R9 unlocked once (notice shown), then locked | unlock again | no notice (MOD-09.7) |
| 09-13 notice off | R9, `expiry.notice_on_unlock` off | first unlock | no notice; the days control is disabled in settings (MOD-09.7) |
| 09-14 notice ignores the group limit | R9; "limit search to current group" on; ExpiredGroup selected before the lock | first unlock | results come from the whole vault (MOD-09.7) |
| 09-15 search word | R9 at 22:51:00Z | `search` with `is:EXPIRED`, `is:expired-abc`, `is:expired--3`, `is:expiredX`, `is:expired-0`, `is:expired--1` | `/X1past`; `/X1past`; `/X1past /X3in2days /X7in40s`; `/X1past`; `/X1past`; `/X1past /X7in40s` (MOD-09.8; observed) |
| 09-15b search word, more forms | R9 rebuilt at 2026-10-25T07:39:01Z in `/tmp/spec-mod0809-rv/` | `search` with `is:expired-+3`, `is:expiredfoo-3`, `is:expired-3x`, `is:expired-2147483647`, `is:expired-2147483648` | `/X1past /X3in2days /X7in40s`; the same; `/X1past`; `/X1past /X3in2days /X4in5days /X7in40s`; `/X1past` (MOD-09.8; observed in review) |
| 09-16 expire now | entries P (Expires false, modified 2026-01-01T00:00:00Z) and Q (Expires true, ExpiryTime 2030-01-01T00:00:00Z) selected at 2026-10-25T09:00:00Z | `entry.expire_now` | both: Expires true, ExpiryTime 2026-10-25T09:00:00Z, modification and access 2026-10-25T09:00:00Z; history count unchanged; vault marked changed (MOD-09.9) |
| 09-17 expire now in the bin | X5binned selected | `entry.expire_now` | the action is enabled; ExpiryTime = now (MOD-09.9) |
| 09-18 editor tick and untick | entry with Expires false, ExpiryTime 2020-01-01T00:00:00Z; local now 2026-10-25 10:15 CET | tick the box, untick it, save | Expires false; ExpiryTime = 2026-10-25T09:15Z (the moment of ticking); one history item added (MOD-09.10) |
| 09-19 editor on history | open a history item of X9hist | look at the expiry controls | box disabled, field read-only, Presets disabled (MOD-09.10) |
| 09-20 presets, hours and weeks | zone Europe/Berlin, local now 2026-10-24 22:00:00 CEST | choose 12 hours; 24 hours; 1 week | ExpiryTime 2026-10-25T08:00:00Z (09:00 CET); 2026-10-25T20:00:00Z (21:00 CET); 2026-10-31T21:00:00Z (22:00 CET); the box is ticked each time (MOD-09.11) |
| 09-21 presets, months and years | Europe/Berlin; local now 2026-01-31 10:00 CET; then 2026-01-15 10:00 CET; then 2028-02-29 12:00 CET | 1 month; 3 months; 1 year | 2026-02-28T09:00:00Z; 2026-04-15T08:00:00Z (10:00 CEST); 2029-02-28T11:00:00Z (MOD-09.11) |
| 09-22 preset list | entry editor | open Presets | exactly 12 items in 4 groups, in the order of MOD-09.11 (MOD-09.11) |
| 09-23 group editor | new group created at 2026-10-25T08:00:00Z | tick Expires, save | the field showed the creation time; ExpiryTime 2026-10-25T08:00:00Z; the group is expired from then on (MOD-09.12) |
| 09-24 precision | preset 1 week chosen at local 22:00:00.700 CEST | save, reopen | ExpiryTime has whole seconds: 2026-10-31T21:00:00Z (MOD-09.13) |
| 09-25 look | R9 at 22:51:00Z | show Root in the entry list and in the Auto-Type list | X1past line-through with the badge; X3in2days normal (MOD-09.14) |
| 09-26 text | X3in2days; X2flagoff; ExpiredGroup | preview; Expires column; sort by Expires ascending | local short date and time; the "never" text; the group preview shows local time in App (D-09-2); X2flagoff sorts last (MOD-09.15) |
| 09-27 browser | X1past matches the site; browser "allow expired" off, then on | ask for credentials | none, then X1past marked expired (MOD-09.16, INT-02) |
| 09-28 Auto-Type | X1past matches the window; "hide expired" off, then on | global Auto-Type | offered (line-through), then not offered (MOD-09.16, INT-05) |
| 09-29 live re-check | X7in40s on screen in App | wait 100 s, no input | it gains the line-through and the badge within 60 s of expiring (MOD-09.17, D-09-3) |
| 09-30 time below the range | entry B with Expires true, ExpiryTime -1 (binary `//////////8=`); entry A in range with Expires true, ExpiryTime 2026-01-01T00:00:00Z | check expired; `is:expired`; `is:expired-3`; preview; Expires column sorted ascending | B expired and in both results; preview and column show `MSG-09-3`; B sorts before A (MOD-09.18) |
| 09-31 time above the range | entry C with Expires true, ExpiryTime 315537897600 (binary `gDiGd0kAAAA=`); entry N with Expires false | check expired; `is:expired-90`; preview; Expires column sorted ascending | C not expired, not listed; preview and column show `MSG-09-3`; C sorts after N ("never") (MOD-09.18) |
| 09-32 editor keeps the raw value | entry C from 09-31 | open the editor: the field shows `MSG-09-3`; change only the title, save; then open again and choose the 1 week preset, save | first save: ExpiryTime still 315537897600 (written `gDiGd0kAAAA=`); second save: ExpiryTime = local now + 7 days, box ticked (MOD-09.18, MOD-09.11) |

## How this was learned

- Read in the reference source: the entry and group expiry checks, the "expires within days" check, Expire now and its menu action, the unlock routine that starts the notice and the search label logic, the search term for `is:expired`, the general settings screen (notice box and days box, with default, range and enable rule), the entry editor (expiry box, date-time field, presets menu, load and save), the time-delta helper behind the presets, the group editor, the entry list model (line-through, Expires column and sort), the group tree model, the icon badge code, the preview pane, Health Check scoring, statistics, the browser bridge access check and entry reply, and the Auto-Type match filters.
- Compared with the installed version's tag in the reference history: the expiry rules and the clone dialog are the same.
- Ran the installed command line tool on demo vault R9, built from hand-written XML at 2026-10-24T22:50:59Z in `/tmp/spec-mod08-10/`: `search` with nine forms of the expired term, and `db-info`, once at once and again after X7in40s passed its time. Daylight-saving and preset values were computed with the Europe/Berlin zone rules. The GUI behaviors (notice, editor, look) come from the source only. Review round: rebuilt R9 in `/tmp/spec-mod0809-rv/` and ran the five extra search forms of 09-15b and `db-info`.

### Lead decisions

| ID | Question | Options | Recommendation |
|---|---|---|---|
| D-09-1 | Where local time zone rules come from (no approved crate; app-core makes no OS calls) | (a) a pure Rust date crate with a zone database; (b) app-core defines a small time-zone interface (offset at an instant, add local days, months and years), and app-platform implements it with macOS Foundation (already approved) | (b); tests use a fixed Europe/Berlin implementation |
| D-09-2 | Group expiry shown in UTC by the reference | (a) parity; (b) local time, like entries | (b) |
| D-09-3 | Live update when an item expires on screen | (a) only on redraw, as the reference does; (b) re-check at least every 60 s and at unlock | (b) |
| D-09-4 | Precision of the editor's date-time field | (a) minutes shown, the stored seconds kept until the user edits the field, and seconds set to 0 after a manual edit; (b) seconds shown | (a); check with Verify what the reference field does with seconds |

### Check with Verify

- V-09-1: the reference date-time field with a year-1 expiry: does saving move it to 1752-09-14?
- V-09-2: a preset that lands in a daylight-saving gap (local 02:30 on a spring-forward day).
- V-09-3: whether the reference field drops seconds on save when the user did not edit it.

### Not on Mac

- The Linux secret-service integration flags expired groups in its settings list.
