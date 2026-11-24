# E1-S5 Checker sample

Story: E1-S5 Larsal cards (APP-01 to APP-11), the Checker sample before Verify.
Date: 2026-10-28. Role: Checker (clean room: the reference was not opened; only cards, spec/decisions.md, plan/ and Larsal's own code and tests were read).
Verdict: **sent back (4)**. Four blocking findings (F1 to F4); ten notes (F5 to F14).

## What was checked

45 rules, at least 2 per card, 31 of them on the security cards (APP-02, APP-03, APP-04, APP-06, APP-10, APP-11). For each rule: (1) template: numbered, behaviour only, our words; (2) at least one runnable test whose expected result matches the rule; (3) agreement with the LD rows that touch it, and a note in the card when a later row changed it; (4) no contradiction with the cards it names; (5) no "check with Verify" without a V-number; (6) where a story built it (APP-02 E6-S2, APP-03 E6-S1, APP-06 E3-S9/E5-S3, APP-09 E5-S1, APP-11 E6-S4), the code and its tests. Tests were read, not run.

Verdicts: **Pass**; **Pass, fixed** (a wrong reference or wording fixed in the card during this sample); **Note** (non-blocking finding); **Fail** (blocking finding).

## Sample

| # | Rule | Verdict | Note |
|---|---|---|---|
| 1 | APP-01.2 defaults | Pass | Larsal column D values match the tables (LD-51, LD-64, S-TIME-04 300); test APP-01.2 a. |
| 2 | APP-01.8 minimize after unlock excludes lock on minimize | Pass | Same rule as APP-02.9; tests APP-01.8 a, b. Built in `LockSettings.locksOnMinimize`, test `t24`. |
| 3 | APP-01.11 import, weakening list (LD-54) | Fail | F3. |
| 4 | APP-02.2 what counts as activity | Pass | `LockSignals.watchInput` counts only Larsal's window input (local monitor); tests `t03`, `t04`, `lateTimer`. |
| 5 | APP-02.3 idle lock, 10 to 43,200 s | Note | Built (`LockSettings.idle`, tests `t07t08`, `t09`, `t10`). LD-187's wall-clock timer (sleep time counts) is not in the card: F5 (a). |
| 6 | APP-02.5 screen lock | Note | Built (`observe`, `.deliverImmediately`; tests `t12t13`, `t12Background`). LD-187's immediate delivery in the background is not in the card: F5 (a). |
| 7 | APP-02.8 minimize delay `clamp(r, 1, 20)` | Pass | Tests `t16` to `t20` inject `r` and match T16 to T20. Built with `r` = 0 until the clipboard countdown is exported (marked in `LockSignals.swift`, recorded in LD-187 "Later"); the switch does not exist before E5-S9. |
| 8 | APP-02.13 manual lock actions | Pass, fixed | "File menu" was wrong: APP-08.5 puts Lock Everything in the Vault menu. T32, T33. |
| 9 | APP-02.16 automatic triggers never wait (LD-50) | Pass | Same as LD-50 (recovery copy, `.lost` marker, manual lock keeps the questions); T46, T47, T53 to T59; APP-05.28 agrees. |
| 10 | APP-03.1 every copy action | Note | The fingerprint copy (LD-181 (4), INT-06.43, built: `copy_fingerprint`, test `app_03_copy_fingerprint`) is missing from the table: F5 (b). |
| 11 | APP-03.5 empty values | Pass, fixed | "Decided: LD-168 (a)" added. Text from LD-181 (2). Code `Session::copy_value`; test `app_03_5_empty_value_copies_nothing`. See F9 for INT-10. |
| 12 | APP-03.9 markers, current host only | Pass, fixed | "Decided: LD-168 (b)" added. Code `macos/pasteboard.rs`; test `copy_writes_text_and_both_markers` (T16). |
| 13 | APP-03.10 and APP-03.12 still ours | Note | Code keeps only the change count (`clipboard.rs`); tests `clear_only_while_still_ours`, `countdown_leaves_newer_content`, `clear_stops_countdown`. LD-170 (1), a copy first clears Larsal's old copy, is not in the card: F5 (b). |
| 14 | APP-03.15 clear on lock, close, quit | Pass | `Session::lock`, `lock_all`, `close`, `clear_clipboard` clear first; tests `app_03_15_lock_close_and_quit_clear`, `app_03_15_lock_of_another_vault_clears`, Swift `clearsState`. |
| 15 | APP-03.19 copies started in the screen layer | Note | Written for the withdrawn web view: F5 (d). LD-181 (4), (5) cover the native fields. |
| 16 | APP-03.20 command line tool, against INT-10.29 | Pass | Same routine, markers and change count, own delay, 0 = never (APP-03.13 (c)). F9 for the empty value. |
| 17 | APP-04.4 memory part (AES-256-GCM) | Pass, fixed | Added: D-A04-2 is not yet ruled; LD-156 (7) decides it at E6-S3 start. T11, T12, T46. |
| 18 | APP-04.5 Keychain item, service plus label (LD-49) | Pass | T13 to T15, T47. |
| 19 | APP-04.6 never a weaker item | Pass | T16. |
| 20 | APP-04.16, APP-04.17 removal, no time limit (LD-55) | Pass | T38 to T44; APP-02.11 step 3 agrees. |
| 21 | APP-05.14 repeated failures (LD-52) | Pass | Cancel default, this vault only; T25, T26. |
| 22 | APP-05.28 changed on disk found by a save (LD-50) | Pass | T49, T50, T60; agrees with APP-02.16. |
| 23 | APP-05.33 old copies after a key change (LD-53) | Pass | T56. |
| 24 | APP-06.4 Touch ID open error (LD-101 (4)) | Pass | Agrees with APP-04.14 last row; T07, T63. |
| 25 | APP-06.5 the password field | Pass, fixed | `larsal-desktop` (gone, LD-156 (1)) now `larsal-ffi`. Built: `UnlockModel.unlock` empties the field when the attempt starts (LD-95); Swift test `clearsUnlockField` (lock clears it). |
| 26 | APP-06.6 Caps Lock note | Note | V-A06-6 asks how the web view reports Caps Lock; the built screen reads `NSEvent.modifierFlags`: F5 (d). T12. |
| 27 | APP-06.17 after a failure (LD-95) | Pass | Field empty, shake for M06-05/M06-06, key file errors focus UL-KEY (`UnlockView` `onChange(of: model.message)`); T35 to T38. |
| 28 | APP-06.18 one message per error | Fail | F1. |
| 29 | APP-06.21 newer minor version (LD-96) | Pass | T44. |
| 30 | APP-06.30 save and create reasons | Pass, fixed | The five reasons said "hardware key"; LD-101 (3) and LD-175 (R07-2) want "security key", as T62 and INT-07's MI07-02 already quote. The `NotPermitted` reason is still missing: F1. |
| 31 | APP-07.13 new key file (LD-99) | Pass | Refuses an existing file (M07-26), mode 0400; T22 to T24. |
| 32 | APP-07.17 save panel and first write (LD-98) | Pass | T33 to T38. |
| 33 | APP-08.6 Entry menu labels (LD-100, LD-101 (2)) | Pass, fixed | The "Show as QR Code" row still called its label an open question; LD-101 (2) decided it. T14. |
| 34 | APP-08.19 closing and minimizing the window | Pass | Agrees with APP-02.11 and APP-02.8; T33 to T35. |
| 35 | APP-09.9, APP-09.13 no answer and channel (LD-47, LD-159 (8)) | Pass | `instance.rs`: 3 tries 150 ms apart, 1 s answer wait, 65,536 / 64 / 1,024 limits; tests `app09_9_a_*`, `app09_13_*`. |
| 36 | APP-09.11 lock with no instance (M09-04, LD-167) | Pass | `NOT_RUNNING` holds the new text; `start()` step 8; tests `app09_11_a_*`, `app09_11_b_*`. |
| 37 | APP-09.16 password from standard input | Note | F7. |
| 38 | APP-09.26 drops on the window (LD-153, LD-165) | Pass, fixed | "recommended" now "decided"; the security note and D-APP09-7 no longer say AT-E06 conflicts (AT-E06 holds the exception). Test APP-09.26-a. |
| 39 | APP-10.1 protected from the start | Pass | Not built (E6-S5); tests APP-10.1-a to -c. |
| 40 | APP-10.8 secure input: when it is on | Pass | Card fine. Code note for E6-S5: F13. |
| 41 | APP-10.11 the native side owns secure input | Fail | F2. |
| 42 | APP-11.1, APP-11.4 order and a failed step (LD-174) | Pass, fixed | "All decided: LD-174" added. `start()` step 1 hardens first; `hardening::apply` runs both steps; test `app11_4_a_failed_core_limit_still_denies_attach`. |
| 43 | APP-11.7 no protection switch in the environment | Note | F6. |
| 44 | APP-11.9 secrets wiped, key pages locked | Note | F5 (c). |
| 45 | APP-11.10 crypto self-test | Pass | `larsal-crypto/src/selftest.rs` holds the card's nine checks and vectors in order; M11-02 through the M09-06 alert path (LD-174); tests APP-11.10-a to -d. |

Result: 33 Pass (9 of them fixed in the card), 9 Note, 3 Fail (rules 3, 28, 41); F4 is a card-wide count.

## Counts across APP-01 to APP-11

**Open "check with Verify" markers: 48.** With a V-number: 19 (APP-02 4, APP-03 3, APP-04 4, APP-06 3, APP-07 1, APP-08 4). **Without a V-number: 29** (APP-01 7, APP-05 2, APP-09 3, APP-10 8, APP-11 9): F4.

**Lead decisions without an LD row: 26 of 55.**
- APP-01: D-01-1, -2, -3, -5, -7, -8, -9, -10, -11 (9). D-01-7 matches D-APP09-8 (LD-153).
- APP-02: D-A02-1 to -4 (4). D-A02-1 (sleep) and -2 (Hide as minimize) are what LD-187 built, but LD-187 does not name them.
- APP-04: D-A04-1 to -5 (5). D-A04-2 is deferred by LD-156 (7), not ruled.
- APP-05: D-A05-1 to -5 (5).
- APP-10: D-APP10-1 to -3 (3).

With a row (29): D-01-4 (LD-47), D-01-6 (LD-49), D-A02-5 (LD-50), D-A03-1 to -6 (LD-168), D-A04-6 (LD-55), D-A06-1 to -3 (LD-95 to LD-97), D-A07-1, -2 (LD-98, LD-99), D-A08-1 (LD-100), D-APP09-1 to -9 (LD-153; D-APP09-4 through LD-47), D-APP11-1 to -4 (LD-174). The 26 take the card's recommendation under the default rule at the top of spec/decisions.md, so they block nothing; F11 asks for one row.

## Findings

**F1 (blocking). APP-06 has no message for `HardwareKey(NotPermitted)`.** spec/app/APP-06-unlock-screen.md:88-91 (table), :185 (APP-06.18 claims every `Error` value has a row), :257-265 (APP-06.30), :389 (T39). LD-173 added the reason and LD-175 (R07-2) told the APP-06 owner to take MI07-01 and a save reason. The code already has it: `crates/larsal-ffi/src/messages.rs:230` maps it to MI07-01, `crates/larsal-ffi/tests/messages.rs:158-165, 251` test it. So the card no longer matches the LD rows or the built code. Smallest fix: one table row `| MI07-01 | HardwareKey(NotPermitted) (INT-07.7, LD-173) | line | macOS did not let Larsal reach your security key. Allow Larsal under System Settings › Privacy & Security › Input Monitoring, then try again. |`; one APP-06.30 row `| HardwareKey(NotPermitted) | macOS did not let Larsal reach the security key |`; T39 lists MI07-01; APP-06.17 gives its focus (the hardware key list, as the other hardware key errors).

**F2 (blocking). APP-10 still describes the withdrawn web view shell.** spec/app/APP-10-screen-protection.md:54 (APP-10.11: the screen layer reports focus to `larsal-desktop`, "the web engine's own secure input"), :84 (security note: "a hung or hostile page"), :36 (APP-10.2: "In the shell this is the window's content-protection option"), :44 (APP-10.6: "whenever the shell returns an error"). LD-155 removed the web view and LD-156 (1), (7) removed `larsal-desktop` and put secure input and `sharingType` in Swift. The built code does so (`macos/Larsal/Platform/SecureInput.swift`; `UnlockView.swift:52`). E6-S5 builds from this card, so a Builder would get a rule about parts that no longer exist. Smallest fix: APP-10.11 reads "The Swift side owns secure input (LD-156 (7)). A masked secure field turns it on by itself while it has focus; Larsal's own call covers a password-kind field while Show is on, and Larsal turns its own call off on focus out, window close, app deactivation, lock and quit, whatever the field reports."; APP-10.2 names `NSWindow.sharingType` and drops the shell sentence; APP-10.6 says AppKit's setter reports no failure, so M10-01 cannot appear on macOS (or names the failure Larsal can detect); the security note drops "page".

**F3 (blocking). APP-01.11's list of imports that lower protection misses three settings.** spec/app/APP-01-settings.md:329. LD-54 names locks turned off, but S-LOCK-04 (lock on minimize) turned off is not listed. The card's own security note (:473) says an import that turns a network feature on is listed, but S-ENTRY-11 (icon downloads, LD-64) is not. S-BRW-23 turned on, or a changed S-BRW-24, is not listed either, yet S-BRW-24 is portable and becomes the `path` of every browser manifest (INT-01.9, rewritten at start by S-BRW-21). So an imported file could make the browsers start another program as Larsal's bridge without asking. Smallest fix: add "S-LOCK-04 turned off; S-ENTRY-11 turned on; S-BRW-23 turned on or S-BRW-24 changed while S-BRW-23 is on" to the list, and one test case APP-01.11 g.

**F4 (blocking). 29 "check with Verify" markers have no V-number.** APP-01-settings.md:94, 324, 374, 380, 456, 499, 562; APP-05-saving.md:80, 266; APP-09-single-instance.md:87, 149, 153; APP-10-screen-protection.md:36, 54, 56, 65, 82, 90, 98, 116; APP-11-hardening.md:47 (two), 62, 64, 76, 80, 88, 90, 140. Smallest fix: number them as the other six cards do (V-A01-1 to -7, V-A05-1, -2, V-A09-1 to -3, V-A10-1 to -8, V-A11-1 to -9; a marker that shares a question with another may reuse its number). No meaning changes.

**F5 (note). Later LD rows that changed a card the card does not mention.**
- (a) APP-02 and LD-187: the idle timer runs on the wall clock, so time asleep counts (APP-02.3, :48); the screen-lock observer is delivered at once while Larsal is in the background (APP-02.5, :52). Fix: one sentence each, citing LD-187.
- (b) APP-03 and LD-170 (1): a copy first clears Larsal's previous copy while it is still ours, so a refused write leaves nothing of Larsal's (edge case :131 says only "nothing tracked"). LD-181 (4) and INT-06.43: the fingerprint copy is a copy action missing from APP-03.1 (:39, "every copy action") and from APP-03.21's labels (:115). Fix: add the row `copy.ssh_fingerprint`, label "Fingerprint", and extend the edge case.
- (c) APP-11 and LD-193: M11-01 is also written once for a refused `mlock` (the M11-01 row at :32 names only APP-11.2 and APP-11.3); LD-193 (6) leaves the field stream state and the decompressed payload unlocked, while APP-11.9 (:66) lists "the field stream key of FMT-09" among locked key material (the stream key itself is locked). Fix: cite LD-193 in APP-11.9 and in M11-01's "When".
- (d) Web view wording left by LD-155 in rules that are already built or nearly so: APP-03.19 (:111), its T39 (:198) and the security note (:147); APP-06.6 (:135) and :422 (V-A06-6); APP-08.4 (:75) and the ⌃H edge case (:264, V-A08-5); APP-09.4 (:89, "shell and web engine versions"; the code prints "Web engine: none"); APP-11.6 (:47, "the web engine runs page scripts"); APP-11.7 (:49, "content security policy"). Fix: name the native screen layer; V-A06-6 and V-A08-5 become checks of the native behaviour or are closed.

**F6 (note). APP-11.7 and the environment.** spec/app/APP-11-hardening.md:49 says the only environment variable Larsal reads is the debug log filter. The release window app reads `HOME` for `~/` key file paths (`crates/larsal-ffi/src/session.rs:877`); debug builds also read the `LARSAL_TEST_*` test variables. Already listed in security/parity/E6-S4-hardening.md:257 (with `TZ` in the tool) for the APP-11.7-a check. Fix: read the home folder from the OS, as APP-09.7 does for the temp folder, or let the card name `HOME`; the card also names the debug-only test variables.

**F7 (note). APP-09.16 does not state two limits the code has.** spec/app/APP-09-single-instance.md:113 says nothing else is trimmed. `crates/larsal-ffi/src/cli.rs:216` caps a password line at 65,536 bytes (the rest of the line is dropped) and turns a line that is not UTF-8 into an empty line (tests `app09_16_line_ends_go_nothing_else_is_trimmed`, `app09_16_one_line_per_call_and_long_lines_are_cut`). Fix: add both to APP-09.16 and one test case.

**F8 (note). The quick unlock setting has two labels.** spec/app/APP-04-quick-unlock.md:30 says Larsal's text is "Unlock with Touch ID"; APP-01 S-LOCK-01 (spec/app/APP-01-settings.md:133) shows "Quick unlock with Touch ID". APP-01 owns the inventory. Fix: APP-04:30 points to APP-01's label.

**F9 (note). An empty field in the command line tool's `clip`.** spec/integrations/INT-10-command-line.md:359 copies an empty value and so wipes the user's clipboard, which APP-03.5 calls the reference's defect and LD-168 (D-A03-1) rules out for Larsal. APP-03.20 binds the tool only to APP-03.2, .9 and .12, so this is not a contradiction. Fix: INT-10 follows APP-03.5 (nothing copied, a message, exit 1), or APP-03.20 says the tool keeps parity here on purpose.

**F10 (note). LD-168 misnames D-A03-5.** spec/decisions.md:191 says "D-A03-5: lock on minimize sends focus back to the previous app"; the card's D-A03-5 is hide on copy, mode `background` (APP-03.17). Fix in LD-168: "hide on copy in `background` mode gives focus back to the previous app".

**F11 (note). 26 lead decisions have no LD row** (list under Counts). They take the card's recommendation by the default rule. Fix: one LD row "APP-01, APP-02, APP-04, APP-05, APP-10: card recommendations", naming D-A04-2 as left open by LD-156 (7).

**F12 (note). APP-02 T21 has a step that cannot run.** spec/app/APP-02-lock.md:197 says "Unlock A again" although A was never locked in that case. Fix: "At t = 30, minimize".

**F13 (note, code, for E6-S5). Secure input turned on by Larsal's own call stays on when Larsal deactivates.** `macos/Larsal/UnlockView.swift:52`, `DialogSheets.swift:30`, `EditorEntryPage.swift:286` turn it on while a shown or secret field has focus; no handler turns it off on app deactivation, which APP-10.8 and APP-10.12 require. The masked secure fields are handled by the system. Fix in E6-S5 (or E5-S3): turn Larsal's own call off on `NSApplication.didResignActiveNotification`, and back on when Larsal becomes active with the field still focused.

**F14 (note). Test order.** spec/app/APP-04-quick-unlock.md:203 puts T47 between T42 and T43. Cosmetic.

## Fixed in the cards during this sample (references and wording only, no meaning change)

- spec/app/APP-02-lock.md APP-02.13: "File menu" now "Vault menu" (APP-08.5).
- spec/app/APP-03-clipboard.md APP-03.5, .9, .10, .13, .17, .20: "Decided: spec/decisions.md LD-168" added to D-A03-1 to -6.
- spec/app/APP-04-quick-unlock.md APP-04.4: D-A04-2 is not yet ruled; LD-156 (7) decides it at E6-S3 start.
- spec/app/APP-06-unlock-screen.md: UL-HW no longer calls the item form an open question (LD-101 (1)); APP-06.5 and the test intro say `larsal-ffi`, not `larsal-desktop` (LD-156 (1)); APP-06.30's five reasons say "security key" (LD-101 (3), LD-175 R07-2; T62 and INT-07's MI07-02 already did).
- spec/app/APP-08-menus-shortcuts.md APP-08.6: "Show as QR Code" is decided (LD-101 (2)), not an open question.
- spec/app/APP-09-single-instance.md APP-09.26 "recommended" now "decided" (LD-153, LD-165); the security note and D-APP09-7 now say AT-E06 holds the vault-drop exception.
- spec/app/APP-11-hardening.md Lead decisions: "All decided as recommended in LD-174" added.

## Proof

- Markers: `grep -o -i "check with verify[^.;)]*"` per card, counted with and without `V-A`: 48 and 19 (the per-card numbers above).
- Lead decisions: `grep -oE "\bD-(A?[0-9]+|APP[0-9]+|A[0-9]+)-[0-9]+"` over spec/app compared with the same over spec/decisions.md, then each card's own "Decided" pointers read by hand.
- `Limit` has 28 values (`crates/larsal-format/src/limits.rs`), as APP-06.18 and T39 say.
- `bash scripts/check-names.sh`: `names: PASS (2713 files scanned, 15 vault files name-only)`, exit 0.
- No cargo, no check.sh, no git; no code changed.

## Next step

The Spec owner of APP-06, APP-10 and APP-01 closes F1 to F3, and numbers the markers of F4; then a Checker re-reads those four items only, and Verify starts. F5 to F14 can go with that pass or later; F6 and F13 belong to the code stories named.

## Fixes 2026-10-28

Spec pass on the findings, as ruled in spec/decisions.md LD-200. Cards and spec/decisions.md only; no code changed. Clean room: wording is our own.

- **F1 (LD-200 (1)).** APP-06: table row MI07-01 for `HardwareKey(NotPermitted)` (text as `larsal-ffi/src/messages.rs`); APP-06.30 reason "macOS did not let Larsal reach the security key"; T39 lists `NotPermitted` and MI07-01; APP-06.17 names MI07-01 among the hardware key errors.
- **F2 (LD-200 (2), (10)).** APP-10 rewritten for the native app: both protections belong to Swift (LD-155, LD-156 (7)). APP-10.2 names `NSWindow.sharingType`, the shell sentence gone; APP-10.6: the setter reports nothing, so Larsal reads `sharingType` back and shows M10-01 when it is not `.none` (test APP-10.6-a uses a read-back hook); APP-10.9 names Larsal's password field views, not a marking attribute; APP-10.10: Larsal's own calls add at most 1; APP-10.11 uses the replacement text (masked secure field on its own, Larsal's call for unmasked fields, off on focus out, close, deactivation, lock, quit); test APP-10.11-a reworded; security note without "page". New rule APP-10.13: Larsal's own secure input stays on only while Larsal is active (off on `didResignActiveNotification`, back on with the field still focused), tests APP-10.13-a, -b. No `larsal-desktop`, shell or web wording left.
- **F3 (LD-200 (3)).** APP-01.11 lists S-LOCK-04 turned off, S-ENTRY-11 turned on (with the network features), and S-BRW-23 on or S-BRW-24 changed while S-BRW-23 is on; states that an imported bridge path never reaches a browser manifest without Apply. Security note extended; test APP-01.11 g.
- **F4 (LD-200 (4)).** The 29 markers numbered in line order: V-A01-1 to -7, V-A05-1, -2, V-A09-1 to -3, V-A10-1 to -8, V-A11-1 to -9. Numbering only, except APP-10's and APP-11.6's marker sentences, which the F2 and F5 (d) rewrites reworded with the same question.
- **F5 (a) (LD-200 (6)).** APP-02.3: wall-clock timer, sleep counts; APP-02.5: observer delivered at once in the background (`.deliverImmediately`); both cite LD-187; tests T60, T61. D-A02-1 and -2 note "built so in LD-187".
- **F5 (b).** APP-03.1 row `copy.ssh_fingerprint` ("Copy fingerprint", INT-06.43, LD-181 (4)); APP-03.21 label "Fingerprint"; APP-03.10 states LD-170 (1) (old copy cleared first) and (2) (count from `prepareForNewContents`); the refused-write edge case extended; tests T44 (`refused_copy_leaves_nothing_of_ours`), T45 (`app_03_copy_fingerprint`).
- **F5 (c).** APP-11: M11-01 "When" adds a refused `mlock` (LD-193 (4)); APP-11.9 names what LD-193 (6) leaves unlocked and the zeroing allocator (LD-193 (1) to (3)); test APP-11.9-d (`app11_9_refused_locks_still_unlock_with_one_warning`).
- **F5 (d).** Web-view wording removed: APP-03.19 (native no-copy field, LD-181 (4), (5), LD-199), APP-03.7 one clause, T39 (Swift test `shownPasswordNoCopy`), security note; APP-06.6 and V-A06-6 (`NSEvent.modifierFlags`); APP-08.4, the ⌃H edge case and V-A08-5, the test intro and V-A08-4; APP-09.4 (the built `Shell` and `Web engine: none` lines); APP-11.6 (no web or script engine).
- **F6.** APP-11.7 now says what a release build reads and why: `HOME` in the window app (`~/` key file paths, UL-PATH), `TZ` through the system time functions in the tool; debug builds also read `LARSAL_TEST_…` and `LARSAL_DEBUG_…`, behind debug-only guards (E6-S4 proof). The old "debug log filter only" sentence went; no such read exists. Test APP-11.7-a updated.
- **F7 (LD-200 (6)).** APP-09.16: a line keeps at most 65,536 bytes, the rest dropped; a line that is not UTF-8 (also after a cut inside a character) counts as empty, as does a read error (`cli.rs` `read_password_line`). Tests APP-09.16-g, -h.
- **F8 (LD-200 (7)).** APP-01 S-LOCK-01 now reads "Unlock with Touch ID", APP-04's label; APP-04 points to it.
- **F9 (LD-200 (8)).** INT-10.29: an empty value copies nothing, new message M10-98, exit 1; exit table, edge case and C6 row follow; test INT-10.29-h. APP-03.20 binds the tool to APP-03.5. The larsal-cli change is a separate code task.
- **F10 (LD-200 (9)).** LD-168's D-A03-5 note now says hide on copy in `background` mode, matching APP-03.17.
- **F11 (LD-200 (5)).** The 25 listed decisions say "Decided: spec/decisions.md LD-200 (as recommended)": APP-01 9, APP-02 4, APP-04 4, APP-05 5, APP-10 3. D-A04-2 stays open (LD-156 (7)).
- **F12.** APP-02 T21: A and B unlocked, B locked at t = 2, minimize at t = 3, A locked at t = 4 (± 1). The old "Unlock A again" step could not run because A was never locked; t = 3 also catches a countdown that keeps running after the early clear.
- **F13.** Code for E6-S5; the card side is APP-10.13.
- **F14.** Not changed (cosmetic, outside LD-200).

New counts over APP-01 to APP-11: open "check with Verify" markers 48, without a V-number 0. Lead decisions without an LD ruling: 1 (D-A04-2, left open by LD-156 (7) until E6-S3). `bash scripts/check-names.sh`: `names: PASS (2716 files scanned, 15 vault files name-only)`, exit 0.

## Checker re-read 2026-10-28

Re-read F1 to F4, the LD-200 marking, and the spot checks F5, F7 and F9 against the cards, LD-200 and the code. **Passed.**

- **F1 closed.** APP-06 has the MI07-01 row for `HardwareKey(NotPermitted)` (line 92), with the same text as `larsal-hwkey` `MI07_01`. APP-06.30 has the reason "macOS did not let Larsal reach the security key", the same as `MI07_02_NOT_PERMITTED` (line 267). T39 names `NotPermitted` and MI07-01 (line 391), and APP-06.17 gives it the hardware key focus (line 182).
- **F2 closed.** APP-10 no longer says `larsal-desktop`, shell or web. APP-10.2 names `NSWindow.sharingType`. APP-10.6 reads the value back and shows M10-01 when it is not `.none` (test APP-10.6-a). APP-10.11 matches LD-156 (7) and the built `SecureInput.swift`. The new APP-10.13 (off on `didResignActiveNotification`, back on when Larsal is active again) with tests APP-10.13-a and -b covers F13 for E6-S5.
- **F3 closed.** APP-01.11 adds S-LOCK-04 turned off, S-ENTRY-11 turned on (as a network feature), and S-BRW-23 on or S-BRW-24 changed. It states that no manifest is rewritten without Apply. The security note is extended and test APP-01.11 g checks the list, Cancel, the manifest `path` and a restart.
- **F4 closed.** 48 markers, none without a V-number (`grep -o -i "check with verify[^.;)]*"` per card). V-A01-1 to -7, V-A05-1, -2, V-A09-1 to -3, V-A10-1 to -8 and V-A11-1 to -9 each appear once.
- **LD-200 (5) marking.** The 25 decisions each carry "LD-200". D-A04-2 stays open under LD-156 (7), as LD-200 says. Lead decisions without a ruling: 1 (D-A04-2).
- **F5 spot check, passed.**
  - APP-02.3 and APP-02.5 cite LD-187, with tests T60 (a clock jump after sleep) and T61 (background delivery).
  - APP-03.1 has `copy.ssh_fingerprint`, APP-03.21 lists "Fingerprint", and APP-03.10 and the refused-write edge case state LD-170 (1) and (2).
  - APP-11 M11-01 adds a refused `mlock`, APP-11.9 cites LD-193, and test APP-11.9-d covers it.
  - The only web wording left says that there is none (APP-09.4, APP-11.6).
- **F7 spot check, passed.** APP-09.16 gives the 65,536-byte cap, says a line that is not UTF-8 counts as empty and that a read error does the same. This matches `read_password_line` and its caller `read_passwords` in `cli.rs`. Tests APP-09.16-g and -h.
- **F9 spot check, passed.** INT-10.29: an empty value copies nothing (M10-98, exit 1), and the exit table, edge case, C6 row and INT-10.29-h follow. APP-03.20 binds the tool to APP-03.5. `crates/larsal-cli/src/commands.rs:704` already prints the M10-98 text. LD-168's D-A03-5 note is corrected.
- **Left (non-blocking).** APP-01.11 says a change to S-BRW-24 is "always in the list", but the condition just before it limits that to S-BRW-23 being on after the import. The conditional sentence is the rule, so "always" could go. APP-10 lists the APP-10.13 tests before APP-10.12's, and APP-04's T47 still sits between T42 and T43 (F14). Both are cosmetic.
- `bash scripts/check-names.sh`: `names: PASS (2718 files scanned, 15 vault files name-only)`, exit 0. No cargo, no check.sh, no git; no code or card changed in this re-read.

