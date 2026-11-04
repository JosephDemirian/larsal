# MOD-13 Master key change reminders

Status: reviewed
Epics: E4-S14 (the window part is built in E5, the command line part in E12)
Parity rows: SF-13, SR-04

## What it does

A vault can ask its owner to change the master key (the composite key: password, key file, hardware key) after some days: as a recommendation, as a requirement, or once at the next unlock. The values live in the vault's metadata. This card says what the values mean, how App counts the days, what App does at unlock in the window and in the command line tool, and how the values are set, kept and merged.

The reference stores and writes back the values but never acts on them (MOD-13.2). Reminders are therefore an App extra. Parity row SF-13 now says so (flagged in FMT-10.19, fixed in E1-S7).

Encoding of the values: FMT-10.10, FMT-10.19 and FMT-10.24 (when `MasterKeyChanged` moves). The credentials page that changes the key: MOD-12.10. Unlock: APP-06. Lock: APP-02. Saving: APP-05.

## Inputs and outputs

- In: `MasterKeyChanged` (UTC time), `MasterKeyChangeRec` (days, signed 32-bit), `MasterKeyChangeForce` (days, signed 32-bit), the force-once flag (MOD-13.13), the current UTC time, the unlock event.
- Out: a status (none, recommended, forced) after each unlock; a notice or a blocking prompt in the window; one notice line in the command line tool.
- App ids: `keychange.*` for settings, `keychange.msg.*` for messages.

## Rules

MOD-13.1 **Stored values.**

| Value | Meaning | Default (new vault) | Off |
|---|---|---|---|
| `MasterKeyChanged` | when the composite key was last changed | creation time | — |
| `MasterKeyChangeRec` | days after which a change is recommended | −1 | −1 |
| `MasterKeyChangeForce` | days after which a change is required | −1 | −1 |
| `MasterKeyChangeForceOnce` | require a change at the next unlock, once | absent (false) | absent |

The first three are known `Meta` children in both apps (FMT-10.10). The fourth is a boolean `Meta` element that other apps writing this format use; the reference does not know it: it skips it on read (it logs the element name) and drops it on save (observed). Its handling in App is MOD-13.13. FMT-10 lists it as `Meta` row 28 (FMT-10.10, FMT-10.11; decided: spec/decisions.md LD-62).

MOD-13.2 **Reference behavior: none.**
- Source: a search of the whole source tree finds the three known values only in the metadata model and in the document reader and writer; the only other use is the key setter that moves `MasterKeyChanged` (FMT-10.24). No screen shows or edits the two day values, and nothing compares them with the date.
- Command line tool (observed, 2.7.11): a demo vault with `MasterKeyChanged` 2020-01-01T00:00:00Z, `MasterKeyChangeRec` 1 and `MasterKeyChangeForce` 1 opened with `ls`, `db-info` and `show` printed no notice and exited 0. `db-info` does not show the key change date either.
- Window: not run (rule); from the source, no reminder exists (source, re-read by Verify in Sprint 3: outside the vault file reader and writer, nothing reads the two reminder settings; they are only stored, edited and written back).
- The reference's own test sample for a new vault holds `MasterKeyChangeRec` 101 and `MasterKeyChanged` 2012-04-05T17:09:34Z; its tests check only that the time is read.

MOD-13.3 **App acts on the values** (lead decision D-13-1, recommended). App implements MOD-13.4 to MOD-13.16. Whatever App shows, it stores and writes the three known values back unchanged unless the user changes them (FMT-10.19), so other apps see the same settings.

MOD-13.4 **Counting days** (lead decision D-13-8). Elapsed days = the whole number of 24-hour periods from `MasterKeyChanged` to now, both in UTC: floor((now − `MasterKeyChanged`) in seconds / 86,400). Local time zone and daylight saving play no part. A `MasterKeyChanged` in the future gives a negative count, which is never due.

MOD-13.5 **Active values** (lead decision D-13-6). A day value counts only when it is 1 or more. −1 (the off value), 0 and any other negative value mean off. Such values are kept and written back as read.

MOD-13.6 **Status.** After an unlock:
1. **Forced** when the force-once flag is true, or `MasterKeyChangeForce` is active and elapsed days ≥ `MasterKeyChangeForce`.
2. Otherwise **recommended** when `MasterKeyChangeRec` is active and elapsed days ≥ `MasterKeyChangeRec`.
3. Otherwise **none**.
Forced wins when both apply. No ordering between the two day values is required.

MOD-13.7 **When the check runs.** Once after every successful unlock of a vault in the window, whatever unlocked it: password, key file, hardware key, or quick unlock (APP-04). It does not run on a reload or merge after a change on disk (MOD-11.29), on save, on applying vault settings, or on switching between open vaults.

MOD-13.8 **Forced, in the window** (lead decision D-13-3). Before any entry, group name or tag of the vault is shown, a blocking prompt `keychange.msg.forced` says the vault requires a new master key and why (the days since the last change and the required interval, or that the vault asks for a change at this unlock). Buttons:
- Change now (default): opens the credentials page alone (MOD-12.10). After the new key is applied and saved, the vault opens normally. Cancel on the credentials page returns to the prompt.
- Lock: locks the vault again (APP-02). Nothing changes in the file.
While the prompt is open, the vault counts as locked for every other part of App: no browser bridge answers, no Auto-Type, no SSH keys added (INT-02, INT-05, INT-06).

MOD-13.9 **Forced, when the save fails** (lead decision D-13-4). If the save after the key change fails (APP-05 error, for example a folder that is not writable), App shows the save error, keeps the changed key in memory with the vault marked unsaved, and opens the vault. App never locks a user out of a vault whose key they have just changed.

MOD-13.10 **Recommended, in the window.** After the vault opens, a notice `keychange.msg.recommended` in the vault view gives the days since the last change and the chosen interval. Buttons: Change now (opens the credentials page) and Later (hides the notice until the next unlock). The vault is usable while the notice shows. It appears at most once per unlock.

MOD-13.11 **What counts as a key change.** A confirmed change of the composite key: the credentials page (MOD-12.10) or the command line tool's vault edit command. It sets `MasterKeyChanged` to now, even when the same password was typed again (FMT-10.24), and clears the force-once flag. Changing only the cipher, the KDF or its settings is not a key change. Opening and saving never move `MasterKeyChanged`.

MOD-13.12 **Settings controls** (App only; on the security page, MOD-12.1; lead decision D-13-7 for the range).

| App id | Control | Stored | Range | Default |
|---|---|---|---|---|
| `keychange.recommend` | check box + days | `MasterKeyChangeRec`, −1 when off | 1 to 3,650 | off |
| `keychange.force` | check box + days | `MasterKeyChangeForce`, −1 when off | 1 to 3,650 | off |
| `keychange.force_once` | check box "require a change at the next unlock" | force-once flag | — | off |
| `keychange.last_changed` | read-only line | `MasterKeyChanged`, shown in local date and time | — | — |

A control the user did not touch keeps the stored value, even one outside the range (for example 0 or 5,000). A value read outside the range shows the check box off; only when the user turns it on is a value in range required. Changing either day value moves `SettingsChanged` (MOD-12.9); the force-once flag belongs with `MasterKeyChanged` (MOD-13.14).

MOD-13.13 **The force-once flag in the file** (decided: spec/decisions.md LD-62; `Meta` row 28 of FMT-10.10).
- Read: App recognizes a `Meta` child named `MasterKeyChangeForceOnce`. Its text is true when it equals `true` under FMT-12.10's comparison; anything else (`False`, empty, `1`, other text) is false. An unreadable value never rejects the document (the reference ignores the element). When it appears more than once, the last one wins. It never takes keystream bytes, even with `Protected="True"`, so the protected-field stream stays in step with the reference (FMT-09.14). Because App knows it, it is not kept as an unknown element.
- Write: only when true, as `<MasterKeyChangeForceOnce>True</MasterKeyChangeForceOnce>`, right after `MasterKeyChangeForce`. Never written when false. It raises no file version (FMT-16).
- A save by the reference removes it (MOD-13.1), so after such a save the force-once request is gone.

MOD-13.14 **Merge.** Not a same-vault merge (MOD-11.19): the target's values stay. Same-vault merge (MOD-11.19, decided LD-60): the composite key, `MasterKeyChanged` and the force-once flag travel together and come from the side with the newer `MasterKeyChanged`. The source's three are taken automatically only in the merge after a change on disk (MOD-11.29); in any other merge only after the preview says so and the user confirms (MOD-11.19). When they are not taken, the target keeps all three and the merge records a Conflict. When both times are equal, the key and the time stay the target's and the force-once flag is true if either side has it true (decided LD-62). The two day values travel with the settings group (`SettingsChanged`, MOD-12.9). A merge never runs the check (MOD-13.7).

MOD-13.15 **Missing or odd times.** A missing `MasterKeyChanged`, or one that cannot be read, becomes the open time (FMT-10.10, FMT-10.14), so the count starts again at 0 and is written back as that time. App shows no warning about it, the same as the reference. A future time is not due (MOD-13.4).

MOD-13.16 **Command line tool** (lead decision D-13-5). Every `app` command that unlocks a vault (INT-10) computes the status after the unlock. Forced or recommended prints one line on standard error, `keychange.msg.cli_forced` or `keychange.msg.cli_recommended`, with the elapsed days and the interval, and points to the vault edit command. The line is not printed with the quiet option. The command never blocks or asks, and its exit code does not change. The tool's vault edit command that changes the key follows MOD-13.11.

MOD-13.17 **Messages.**

| Id | Where | Says, in App's words |
|---|---|---|
| `keychange.msg.forced` | window, blocking | This vault requires a new master key: last changed N days ago, the vault requires a change every F days (or: the vault asks for a change at this unlock). Buttons Change now, Lock |
| `keychange.msg.recommended` | window, notice | The master key was last changed N days ago; a change every R days is recommended. Buttons Change now, Later |
| `keychange.msg.cli_forced` | command line, standard error | Note: this vault requires a master key change (last changed N days ago, required every F days, or requested once); use the vault edit command |
| `keychange.msg.cli_recommended` | command line, standard error | Note: a master key change is recommended (last changed N days ago, recommended every R days) |

N is the elapsed day count of MOD-13.4; R and F are the stored day values.

## Edge cases and errors

- Both values on, force 30 and recommend 10, elapsed 45: forced only, one prompt.
- Recommend 90, elapsed exactly 90 days to the second: recommended (≥).
- `MasterKeyChangeRec` 0: off; no notice at any unlock; written back as 0.
- `MasterKeyChangeForce` 2,147,483,647: active; due after that many days (never in practice); the settings page shows it off until edited (outside 1 to 3,650).
- Clock moved backwards so that `MasterKeyChanged` lies in the future: no status until the count reaches the interval.
- Force-once true in a vault opened only with the reference afterwards: the reference drops it on its next save (MOD-13.13).
- Forced prompt and the vault is locked by the idle timer (APP-02) while the prompt is open: the prompt closes; the next unlock shows it again.
- A merge brings a newer `MasterKeyChanged` and an older key: impossible by MOD-13.14, the key and the time travel together.
- Quick unlock (Touch ID) while forced: the prompt shows after the biometric unlock; changing the key removes the quick unlock data (MOD-12.10), so the next unlock needs the new password.

## Security notes

- **Advisory, set by the vault owner.** A reminder is a policy stored in the vault. Only App enforces it; the reference and other apps may ignore it. It must never be presented as protection against an attacker who has the file.
- **No lock-out.** The forced flow always offers Lock, and a failed save never strands the user (MOD-13.9). A hostile vault can set force-once or a 1-day interval to nag; the worst result is a prompt at each unlock.
- **Nothing shown before the change.** While forced, no vault content reaches the screen and no integration answers (MOD-13.8), so a forced change cannot be skipped by using the browser bridge or Auto-Type.
- **Values only after unlock.** The values sit in the encrypted document, so nothing about them is known before the key is proven (FMT-05). Messages hold day counts only, never key material or names from the vault.
- **Key change side effects.** A key change clears force-once, moves `MasterKeyChanged` and removes quick unlock data (MOD-12.10, SR-04).
- **Logs (AT-C06).** The status may be logged; no value from the vault other than the status and the day count.

## Test cases

| Case | Given | When | Then |
|---|---|---|---|
| T01 MOD-13.1 defaults | App creates a vault at 2026-10-25T10:00:00Z | Save; read `Meta` | `MasterKeyChanged` 2026-10-25T10:00:00Z, `MasterKeyChangeRec` −1, `MasterKeyChangeForce` −1, no `MasterKeyChangeForceOnce` |
| T02 MOD-13.1 reference drops force-once (observed) | Demo XML with `<MasterKeyChangeForceOnce>True</MasterKeyChangeForceOnce>` after `MasterKeyChangeForce` | Reference command line import, then export | Import logs that it skipped the element; the export has no `MasterKeyChangeForceOnce`; the other three values are kept |
| T03 MOD-13.2 reference silent (observed) | Demo vault: `MasterKeyChanged` 2020-01-01T00:00:00Z, Rec 1, Force 1, password `demo` | Reference `ls`, `db-info`, `show -s` | Normal output, no notice on stdout or stderr beyond the password prompt, exit 0 |
| T04 MOD-13.3 values kept | Vault with Rec 101, Force −1, `MasterKeyChanged` 2012-04-05T17:09:34Z (as the reference's sample) | App opens and saves without touching the settings | The same three values are written back |
| T05 MOD-13.4 boundary | `MasterKeyChanged` 2026-07-27T12:00:00Z, Rec 90 | Unlock at 2026-10-25T11:59:59Z; again at 2026-10-25T12:00:00Z | First: elapsed 89, none. Second: elapsed 90, recommended |
| T06 MOD-13.4 not calendar days | `MasterKeyChanged` 2026-10-24T23:59:59Z, Rec 1 | Unlock at 2026-10-25T00:00:01Z | Elapsed 0, none |
| T07 MOD-13.4 sample vault | Values of T04 | App unlock at 2026-10-25T09:00:00Z | Elapsed 5,315 days; recommended; notice says 5,315 days and 101 |
| T08 MOD-13.5 zero and negatives | Rec 0, Force −5 | Unlock at any time | None; save writes 0 and −5 back |
| T09 MOD-13.6 force wins | `MasterKeyChanged` 45 days ago, Rec 10, Force 30 | Unlock | Forced prompt only; no recommended notice |
| T10 MOD-13.6 force-once | Force-once true, Rec −1, Force −1, `MasterKeyChanged` = now | Unlock | Forced, the prompt says the vault asks for a change at this unlock |
| T11 MOD-13.7 quick unlock | Recommended status; quick unlock set up | Unlock with Touch ID | Notice shown |
| T12 MOD-13.7 not on reload | Recommended status, notice dismissed with Later | The file changes on disk and App merges it (MOD-11.29) | No new notice |
| T13 MOD-13.8 forced, change | Forced status; password `demo` | Unlock; prompt; Change now; new password `demo2`; Apply at time T5 | Entries shown only after the save; `MasterKeyChanged` T5; no force-once element in the saved file; reopening needs `demo2` |
| T14 MOD-13.8 forced, lock | Forced status | Unlock; prompt; Lock | Vault locked; no entry, group name or tag was sent to the screen; file bytes unchanged |
| T15 MOD-13.8 integrations blocked | Forced prompt open; browser extension associated | The extension asks for credentials for a matching site | Treated as a locked vault (INT-02); no credential returned |
| T16 MOD-13.9 save fails | Forced status; vault folder read only | Change now, new key applied, save fails | Save error shown; vault opens, marked unsaved; file unchanged |
| T17 MOD-13.10 later | Recommended status | Unlock, Later | Notice hidden; vault usable; lock and unlock again: notice shown again |
| T18 MOD-13.11 KDF change only | Force-once true, `MasterKeyChanged` T0 | Change only the KDF iterations, Apply, save | `MasterKeyChanged` T0; force-once still written |
| T19 MOD-13.11 command line key change | Force-once true | `app db-edit --set-password` with a new password at T5 | `MasterKeyChanged` T5; force-once gone from the saved file |
| T20 MOD-13.12 settings | Rec −1 | Turn recommend on with 90, Apply at T5 | `MasterKeyChangeRec` 90; `SettingsChanged` T5. Turn it off: −1 |
| T21 MOD-13.12 untouched out of range | Force 0 stored | Open settings (shown off), change only the vault name, Apply | Force still 0 in the saved file |
| T22 MOD-13.12 range | Settings page | Enter 0 or 3,651 days for recommend | Refused by the control; 1 and 3,650 accepted |
| T23 MOD-13.13 read forms | `MasterKeyChangeForceOnce` with text `TRUE`; separately `1`; separately empty | App reads | True; false (document opens); false |
| T24 MOD-13.13 no keystream | Version 4 demo vault, inner stream key 64 bytes of 0x00: `<MasterKeyChangeForceOnce Protected="True">QUJD</MasterKeyChangeForceOnce>` then `<DatabaseName Protected="True">RxjmIZKk</DatabaseName>` | App reads | Force-once false (text `QUJD`); name `Secret`, decoded from keystream byte 0 (same vector as FMT-10.11's test) |
| T25 MOD-13.13 write | Force-once set in App's settings | Save; read `Meta` | `<MasterKeyChangeForceOnce>True</MasterKeyChangeForceOnce>` directly after `MasterKeyChangeForce`; file version unchanged |
| T26 MOD-13.14 merge, newer key | Same vault. A: `MasterKeyChanged` T0, force-once true. B: `MasterKeyChanged` T2 (key changed), no force-once | App window merge B into A; the user confirms the key question (MOD-11.19) | Result: B's key, `MasterKeyChanged` T2, force-once false |
| T26b MOD-13.14 key not confirmed | Same as T26 | Window merge, the user answers No to the key question; separately `app merge` | A keeps its key, `MasterKeyChanged` T0 and force-once true; one Conflict record |
| T27 MOD-13.14 merge, tie (LD-62) | Same vault, both `MasterKeyChanged` T0; force-once true in B only; separately true in A only | App merge B into A | Force-once true in both runs; A's key unchanged; no key question |
| T28 MOD-13.15 missing time | Vault without `MasterKeyChanged`, Rec 1 | App opens at time T9, saves | None at this unlock; `MasterKeyChanged` written as T9 |
| T29 MOD-13.15 future time | `MasterKeyChanged` 2027-01-01T00:00:00Z, Rec 1 | Unlock at 2026-10-25T00:00:00Z | None |
| T30 MOD-13.16 command line notice | Values of T03 | `app ls` with password `demo` at 2026-10-25 | One notice line on stderr (forced, Force 1); entry list on stdout; exit 0. With `-q`: no notice |
| T31 MOD-13.17 messages | Values of T07 | Unlock in the window | `keychange.msg.recommended` shows 5,315 and 101, no vault name or entry data in the message |

## How this was learned

- Searched the whole reference source tree for every use of the three stored values and of the key change time; read the metadata model, the document reader and writer, and the vault core's key setter. Read the reference's new-vault test sample and the format test that reads it.
- Ran the installed command line tool 2.7.11 on a demo vault made from XML in `/tmp/spec-mod11-13/` (password `demo`) with old key change dates and short intervals: T02 and T03 are observations.
- The force-once element is a format fact used by other apps that write this format; no demo file in the reference test data holds it, and the reference drops it. Checked by Verify in Sprint 3: App wrote it into a demo vault (`True`, set through the settings), App read that vault and saved it again with the element still `True` (checked by decrypting both files with an independent reader), and the reference command line tool's own save of the same vault (`mkdir`) dropped it.
- Everything App does at unlock is App's own design, under lead decisions D-13-1 (implement reminders), D-13-2 (force-once read and write, decided by LD-62), D-13-3 (forced flow), D-13-4 (no lock-out on save failure), D-13-5 (command line notice), D-13-6 (values of 0 or less are off), D-13-7 (1 to 3,650 days), D-13-8 (24-hour periods in UTC). D-13-2 is LD-62; the others are not listed in spec/decisions.md, so each is decided by its default rule: the recommended option. The merge rule follows LD-60 and LD-62.
