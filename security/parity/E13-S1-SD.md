# E13-S1 Parity sign-off: Data safety (SD-01 to SD-13)

Story: E13-S1 (final verification fleet, parity group SD). Rows: the SD table in [plan/security.md](../../plan/security.md). Cards: APP-05, MOD-03, MOD-04, MOD-05, MOD-08, FMT-10, FEA-09. Earlier proof used as a map: [SD-01-SD-02-SD-03-SD-09](SD-01-SD-02-SD-03-SD-09.md), [SD-04](SD-04.md), [SD-05](SD-05.md), [SD-06](SD-06.md), [E5-S10-saving](E5-S10-saving.md), [E5-S5-editor](E5-S5-editor.md).
Date: 2026-10-29. Role: Verify. I re-read the reference source for every row and ran the reference command line tool (installed 2.7.11) on demo vaults with a throwaway HOME under /tmp. Every check of App below ran today.

| Row | Result |
|---|---|
| SD-01 safe save | **Fails one part.** Safe save, links, permissions, hard links, 1,000 random kills, a real full disk, the locked, keyless and overlapping-save guards all hold and match the reference tool. Missing: after three failed safe saves the reference offers to turn safe saving off; App never offers it (app-core's counter is built and tested, nothing calls it). Finding 3, Medium. Creation date: both tools lose it on this Mac (finding 5, Low). Row stays built. |
| SD-02 backup | **Verified** again. |
| SD-03 changes on disk | **Fails one part.** Silent reload, the questions (Merge, Discard, Ignore, Cancel), the refused save and the merge all hold, on screen too, and the merge equals the reference tool's. Missing: when the file was re-keyed elsewhere, the reference asks for the new credentials and then merges; App's Merge and Discard stop with a notice, and the only choice that writes, Keep mine, drops the other side's entries and puts the old password back. Finding 1, High. Row stays built. |
| SD-04 history limits | **Verified** again (side by side with the reference tool). |
| SD-05 recycle bin | **Verified.** Delete to the bin and for good equal the reference tool; search and Auto-Type keep bin entries out whatever the group flags say. |
| SD-06 unknown data | **Verified** again (App extra). |
| SD-07 export warnings | **Waits for a story.** App has no export to a file and no passkey export yet (File > Export items are disabled). The command line part holds: App warns on every plain export, the reference tool on none. |
| SD-08 references bounded | **Waits for E13-S2** (the Red team run of AT-G03). MOD-08 tests pass today. |
| SD-09 permissions | **Verified.** Every file App writes today is 0600 (key files 0400); exports and passkey files have no file path in App yet. |
| SD-10 autosave | **Verified.** Save after each change, before lock (manual, automatic, lock request) and before quit, on screen. App makes no view-state changes, so there is nothing to save silently. |
| SD-11 opened attachments | **Fails.** Private 0600 copy, wiped with random bytes on close and lock, asks before risky types. Missing: the reference watches the copy and asks to save a changed file back; App has no watch, so an edit made in the other app is wiped without a question. Finding 2, High. Row stays todo. |
| SD-12 backups after a key change | **Parity part holds; the App extra is not built** (APP-05.33 notice and delete offer). Finding 4, Medium. Row stays todo. |
| SD-13 attachment previews | **Waits for a story.** App has no attachment preview, so nothing is rendered as rich text and no link is followed (AT-E01 lint rule, http/https-only opener). No story in plan/epics.md builds the preview (MOD-05.9). |

## Setup and rules

- Shared tree, read-only build: `CARGO_TARGET_DIR=/tmp/e13s1-target` for the Rust suites and the command line tool (`/tmp/e13s1-target/debug/app`).
- Private copy for probes and Swift: `rsync -a --exclude target --exclude app-shots --exclude fuzz/target` to /tmp/e13s1-SD-copy at 20:51, own target /tmp/e13s1-SD-target, derived data /tmp/e13s1-SD-dd. Probe tests (3 files) only in the copy. At the end the code checked was byte-equal to the tree (`cmp`) for saving.rs, autotype.rs, session.rs, vault_settings.rs, matching.rs, Saving.swift, SavingSheets.swift, VaultEdits.swift and the three Swift test files. Changed meanwhile by other workflows: edit.rs (test formatting only) and storage.rs (the `test-faults` hook's derives); neither changes a checked path.
- Note: my first Swift attempt ran build-core in the copy against the shared target by mistake; I stopped it by PID, then repeated everything with the copy's own target. Only the second, clean run (swift2) counts below.
- Reference: `--version` 2.7.11; `HOME` and `CFFIXED_USER_HOME` set to /tmp/e13s1-SD/refhome; our tool with `HOME=/tmp/e13s1-SD/apphome`. Demo vaults from testdata/ only.
- Rule 10: no window; the Swift tests draw offscreen in the test runner; the general pasteboard was never used (test sessions use the private one). Rule 11: I stopped only my own PIDs (my first build-core run, a session test stuck for 16 minutes, my log tail). Load average 140 to 395 from other agents during the runs.

## SD-01 Safe save

**Reference (source and tool).** The vault object refuses a save while one runs, and refuses a vault without a key. The window refuses to save a locked vault. Safe save writes a new file and renames it over the old one; the other two methods are a temp file moved in after deleting the vault (not atomic, restored from the backup when the move fails) and a direct write. The real path is used, so a link stays a link. New files get owner-only bits; a re-save keeps the bits. The source asks its toolkit to keep the creation date. After the third failed save in a row (with safe saving on) the window asks to turn safe saving off and tries again.

**App.** app-core storage: one safe save (exclusive 0600 temp file, full sync, rename, folder sync), temp-move and direct methods with restore, the pre-save check, links and permissions. app-ffi saving: one save at a time per vault (the save lock), a locked vault answers `Locked`, a vault without key parts gives `NoCredentials`. Settings > Safe saving picks the method.

Commands and output:
```
same steps with both tools on a copy of password-only.appvault (mode 644, creation date set to 2020-01-01, a symbolic link l and a hard link h):
  echo demo-pass-1 | <tool> add -q -u sd01-user l.appvault "SD01 via link"
reference: link: Symbolic Link v.appvault | before ino=432275314 mode=644 birth=Jan 1 2020 | after ino=432275908 mode=644 birth=Oct 29 20:39:52 2026 | hard link keeps the old bytes: yes
App:       link: Symbolic Link v.appvault | before ino=432471539 mode=644 birth=Jan 1 2020 | after ino=432473475 mode=644 birth=Oct 29 20:48:03 2026 | hard link keeps the old bytes: yes
reference ls of App's result: Demo login, SD01 via link (exit 0)
```
- `cargo test -p app-core --test app05`: 32 passed, 0 failed, 2 ignored, among them `at_i01_killed_mid_save` (1,000 kills, 8 at a time), `app05_09_real_path_and_links`, `app05_10_pre_save_check`, `app05_11_safe_save`, `app05_13_failed_write_leaves_the_old_file`, `app05_14_repeated_failures`, `app05_15_temp_move`, `app05_16_direct`, `at_i03_no_permission`, `at_i04_link_tricks`, `at_i05_two_writers`, `at_i06_owner_only_permissions`, the five `ld131_*` link and race tests. `-- --ignored at_i02`: `at_i02_real_disk_full ... ok` (a 1 MiB disk image attached with `-nobrowse`).
- `cargo test -p app-ffi --lib -- edit::tests::ld_199_4`: `a_waiting_save_writes_the_change_made_while_it_waited`, `a_save_waiting_across_a_lock_writes_nothing`: ok (overlapping saves run in turn; App queues where the reference refuses).
- `cargo test -p app-format --test write_file fmt_04_16`: `fmt_04_16_a_no_credentials ... ok`.
- Probe (copy) `sd01_a_locked_vault_is_never_saved`: `PROBE sd01 save after lock: Err(Locked)`, file bytes unchanged.
- The offer after three failures: `grep -rn "Failures" crates/app-ffi/src crates/app-cli/src` gives nothing. app-core's `storage::Failures` (tested by `app05_14_repeated_failures`) has no caller, and no Swift sheet carries MSG-SAVE-UNSAFE-ASK. A failed save shows the save-failed sheet (Try Again, Save As…, Close; ParitySavingTests `saveFailed` passes), and the user can change Safe saving in Settings, but App never offers it. Finding 3.
- Creation date: both tools give the new file the save time (above). The reference's source tries to keep it and fails on this Mac; App does not try. Not weaker. App's own card (APP-05.11 step 5, LD-129 (4), LD-200) promises the creation date, Finder tags and the access list, and `grep -rni "birth\|crtime\|setattrlist\|_kMDItemUserTags\|copyfile"` finds none of it. Finding 5.

**Result: fails one part (finding 3).** Row stays built.

## SD-02 Backup before saving

**Reference (source).** With the backup option on (off by default), each save first copies the vault to the backup path pattern (default: next to the vault), creating the folder, and gives the copy the vault's permission bits. When the temp-file method cannot move the new file in, it copies the backup back.

**App.** Backup on by default (S-FILE-05), pattern `{FILE_NAME}.old.appvault`; the backup is written fresh at 0600, never through a planted link; the temp-move method restores from it.

Commands and output: app05 above: `app05_19` to `app05_22` (backup before save, path pattern, resolution, time slots), `app05_15_temp_move` (restore), `ld131_backup_never_written_through_a_planted_link`, `at_i06_owner_only_permissions` (backup 0600): ok. `cargo test -p app-ffi --lib -- saving::`: `app_05_19_the_backup_holds_the_file_before_each_save ... ok`. Probe `sd12_*` below: the backup made by a save exists, mode 600.

**Result: verified** (App goes further: 0600 instead of the vault's bits).

## SD-03 Changes on disk

**Reference (source).** The vault is watched (system events plus a 30-second checksum of the first 1,024 bytes). With no unsaved changes it reloads silently (option, on) or asks "load the changes?". With unsaved changes it asks: Merge, Ignore the changes on disk until save, Discard, Cancel. A save first compares the checksum and refuses with "unmerged changes", then asks: Merge then save, Overwrite, Discard, Cancel. When the file on disk does not open with the current key, it shows its unlock dialog with "cannot be unlocked with current credentials", then merges or reloads with what the user enters.

**App.** Swift DiskWatch (folder and file events, 30 s tick); Rust decides by SHA-256 of the first 1,024 bytes plus length; the same choices (Merge, Discard, Keep mine, Later); Merge keeps both sides (MOD-11.29).

Commands and output:
- `cargo test -p app-ffi --lib -- saving::`: 19 passed, 0 failed (`app_05_10_a_file_changed_on_disk_is_not_overwritten_and_asks`, `app_05_24_*`, `app_05_25_*`, `app_05_26_an_unchanged_vault_reloads_or_asks_by_the_setting`, `app_05_27_merge_keeps_both_sides_and_saves`, `app_05_27_discard_takes_the_disk_version`, `app_05_28_keep_mine_saves_over_the_disk_version`, `app_05_30_*`, the four `at_i05_*`, the two "change made during" tests).
- `cargo test -p app-core --test mod11`: 45 passed, 4 ignored.
- Swift, copy, alone: `xcodebuild … test -only-testing:AppTests/ParitySavingTests -only-testing:AppTests/LockSignalsTests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` → `✔ Suite ParitySavingTests passed after 68.977 seconds.` `✔ Test run with 36 tests in 2 suites passed after 68.978 seconds.` `** TEST SUCCEEDED **`. Among them: "the watch sees another writer while changes wait; Merge keeps both (AT-I05)", "a save that finds the change asks; Cancel keeps; Overwrite saves over it", V-B1 (Merge then save), V-B3 (an edit in place reloads, or asks: Discard, Keep), V-B4 (deleted or moved), V-B6 (after App's own rename).
- Merge side by side (both tools, `merge -q -s`, target a copy of rich-v4 with "A only", source with "B only", a changed user name and an entry moved to the bin): reference 19 lines in `ls -R -f`, App 19, `diff` equal, both `UserName: b-edited`.
- Re-keyed disk version, probe (copy) `sd03_disk_version_with_another_key_and_unsaved_changes`: window A has one unsaved entry; a second session adds "Theirs", changes the password and saves.
```
PROBE sd03 check_disk: Ask { ask: Unsaved, changes: 1 }
PROBE sd03 save after: on_disk Some(OnSave) failure None
PROBE sd03 Merge: Ok(NewKey); titles ["Mine unsaved"]
PROBE sd03 Discard/Load: Ok(NewKey)
PROBE sd03 after Keep mine + save: Ok(None), save failure None; file opens with the OLD password: Unlocked
PROBE sd03 file entries now: ["Mine unsaved"]
```
  On `NewKey`, Saving.swift (`handle`, `.newKey`) only answers Later and shows "This vault's password or key was changed elsewhere. Unlock the changed file to go on." There is no unlock sheet for the changed file (APP-05.29; the code comment says it is "not in Option A yet"). So Merge and Discard cannot finish, and the only choice that writes, Keep mine, replaces the other side's version: "Theirs" is gone and the file opens with the old password again. The reference asks for the new credentials and merges both. Finding 1.

**Result: fails one part (finding 1).** Row stays built.

## SD-04 Entry history limits

**Reference (source and tool).** An edit keeps the old version as a history item; history is cut to the vault's limits (10 items, 6 MiB by default), oldest first.

**App.** MOD-03: the same, in app-core's edit session.

Commands and output: `cargo test -p app-core --test mod03`: 18 passed. Side by side: rich-v4 (`HistoryMaxItems` 10, `HistoryMaxSize` 6291456; "Full demo entry" has 3 items), `edit -q -u user-$i` nine times with each tool, then the reference exported both:
```
ref current ['user-9'] history 10 ['demo-user', 'demo-user', 'user-1', 'user-2', 'user-3', 'user-4', 'user-5', 'user-6', 'user-7', 'user-8']
app current ['user-9'] history 10 ['demo-user', 'demo-user', 'user-1', 'user-2', 'user-3', 'user-4', 'user-5', 'user-6', 'user-7', 'user-8']
```

**Result: verified.**

## SD-05 Recycle bin

**Reference (source and tool).** Deleting moves an entry or group to the bin, made on first use with search and Auto-Type turned off; deleting from the bin removes it for good with a deleted-object record. Browser fill, the SSH agent and the breach check skip bin entries by asking "is it recycled". Search and Auto-Type walk the group flags only (inherit, on, off), so a group inside the bin with the flag turned on brings its entries back into search and Auto-Type.

**App.** app-core recycle; search leaves the bin's subtree out whatever the flags say (LD-57); app-autotype's candidate walk skips the bin's subtree; the session's Auto-Type picker takes its rows from that walk.

Commands and output:
- Side by side on copies of password-only.appvault: `rm -q v "Demo login"`, then `rm -q v "Recycle Bin/Demo login"`, with each tool; the reference listed and exported both:
```
r after rm 1: Recycle Bin/, Recycle Bin/Demo login        a after rm 1: the same
r after rm 2: DeletedObject records: 1; bin icon 43 autotype false search false entries 0
a after rm 2: DeletedObject records: 1; bin icon 43 autotype false search false entries 0
```
- `cargo test -p app-core --test mod04`: 25 passed (incl. `mod_04_14_left_out_elsewhere`). `--test fea01`: 35 passed, 2 ignored (incl. `fea01_21_recycle_bin_never_searched`: a group inside the bin with searching on is still never searched).
- `cargo test -p app-autotype --test int05_match`: `candidates_walk_agrees_with_app_core ... ok`, `t42_candidates ... ok` (E9 sits in a group inside the bin with Auto-Type on: no row). The first run reported 36 passed, 1 failed at load average about 390; the re-run with the same sources (last changed 2026-10-28 21:58) gave 37 passed, 0 failed. The file's only wall-clock assertions are the AT-G03 `timed` checks.
- Probe (copy) `sd05_bin_entries_are_never_auto_type_rows`, through the session on option-a-personal (bin: "Twitter (old account)", "MySpace"):
```
PROBE sd05 window "Twitter (old account)": start rows 24, all rows 24 (live entries 23), bin rows in start 0, in all 0, by search []
PROBE sd05 window "MySpace": start rows 24, all rows 24 (live entries 23), bin rows in start 0, in all 0, by search []
PROBE sd05 window "Sign in to GitHub · GitHub — Safari": start rows 2, all rows 2, bin rows in start 0, in all 0, by search []
```
  The Auto-Type window itself (E8-S2's Swift part, being built) shows these rows; its real typing waits for E8-S3 and Mac QA.

**Result: verified.**

## SD-06 Unknown data kept

**Reference (source).** Its document reader skips every element it does not know (23 skip calls), so its next save drops them. App goes further.

**App.** app-format keeps unknown elements and attributes under their parent and writes them back (FMT-10.20, FMT-10.27).

Commands and output: `cargo test -p app-format --test write_meta` 46 passed (incl. `fmt_10_5_unknown_top_child`, `fmt_10_20_unknown_meta_child_kept`, `fmt_10_20_order_of_kept_elements`, `fmt_10_20_protected_in_unknown`, `fmt_10_27_elements_only`, `fmt_10_27_mixed`, `fmt_10_27_stable_over_saves`); `--test write_groups` 45 (`row_11_51_unknown_elements`, `row_11_62_unknown_children_of_repeated_parents`); `--test write_pool` 53 (`row_14_28_unknown_key`, `row_15_22_unknown_children`); `--test write_version` 32 (`fmt_16_24_kept_unknown_part_4_1`); `--test testdata` 4 (`every_vault_round_trips_as_version_4`).

**Result: verified** (App extra).

## SD-07 Plain export warnings

**Reference (source and tool).** The app asks "You are about to export your database to an unencrypted file…" (default No) before CSV and XML, and shows the same warning in the HTML export dialog. Its passkey export writes each private key to a plain file with no warning. Its command line `export` prints no warning.

**App.** No export to a file in the app yet: AppCommands.swift's File > Export > CSV…, HTML…, XML… are disabled ("FEA-09 (E12)"), and there is no passkey export (the Passkeys report has Remove only). The command line tool warns every time (LD-42):
```
ref xml exit=0 stdout=4525B stderr:
app xml exit=0 stdout=4447B stderr: Warning: this export is not encrypted. Anyone who can read it can read every password in it.
ref csv exit=0 stdout=241B stderr:
app csv exit=0 stdout=241B stderr: Warning: this export is not encrypted. … A spreadsheet may run values that start with =, +, - or @ as formulas. …
ref html exit=0 stdout=1034B stderr:
app html exit=0 stdout=1061B stderr: Warning: this export is not encrypted. …
```
`cargo test -p app-core --test fea09`: 24 passed.

**Result: waits for a story.** Nothing in App writes a plain export file today, so App is not weaker, but the row's subject (the app's export warning) does not exist yet, and no open story in plan/epics.md names the app's export screens. For the lead.

## SD-08 References and placeholders bounded

**Reference (source).** Placeholders and references resolve at most 10 levels deep, but a reference gives its depth back (`++` on the budget), so some loops never end.

**App.** MOD-08 with a work meter; every loop ends.

Commands and output: `cargo test -p app-core --test mod08`: 47 passed. The AT-G03 bounds of the Auto-Type parser were proven at E8-S1 ([E8-S1-autotype-parser](E8-S1-autotype-parser.md)).

**Result: waits for E13-S2**, the Red team run of AT-G03 that the row names (LD-186 (4)). Not re-run here.

## SD-09 Owner-only files

**Reference (source and tool).** New vaults 0600; saved attachments and opened-attachment temp files owner read and write; new key files owner read only; backups copy the vault's bits; CSV, HTML, XML and passkey files get default bits. Its command line `attachment-export` writes with default bits (0644 here).

**App.**
```
db-create, both tools:  600 app-new.appvault   600 ref-new.appvault   600 app-key.appvault   600 ref-key.appvault
                        400 app-new.appkey     400 ref-new.appkey
attachment-export of notes.txt from rich-v4:   600 app-notes.txt      644 ref-notes.txt   (same bytes)
```
`at_i06_owner_only_permissions` (new vault 0600, a re-saved 0644 vault keeps 0644, backup 0600): ok. `cargo test -p app-ffi --test edit`: 19 passed, incl. `mod_05_open_save_and_wipe` (opened copy 0600 in `App/open-attachments` of the per-user temp folder, which `open_folder` makes 0700 and checks for owner and mode; a saved attachment 0600) and `mod_05_12_risky_types_ask_first`. Recovery copies 0600: ParitySavingTests (lock request, T56/T60) pass. Exports and passkey files: App writes none to a file today (command line export goes to standard output, the app's export items are disabled).

**Result: verified.** App goes further for every file it writes; the 0600 rule for export files is checked again when export to a file lands.

## SD-10 Autosave

**Reference (source).** Saves after every change (option, on; a short timer joins quick changes; a per-vault delay restarts on each change), saves before lock, close and quit (option, on; asks when the save fails), and saves non-data changes (a group expanded or collapsed, an entry moved up or down) silently at lock, ignoring errors (option, on).

**App.** S-FILE-01 to -03 on by default (app_settings.rs); the 150 ms window or the vault's delay (Saving.swift `scheduleSave`); `saveAll` before lock, close and quit, with the save-or-discard question when a manual lock's save fails and a 0600 recovery copy for an automatic one.

Commands and output (the Swift run above, 36 of 36): "APP-05.3 T06: S-FILE-01 turned off while the vault is open stops the save after each change; on, it saves", "APP-02.15 step 8 (quit): a changed vault saves first; one that cannot be saved asks and the quit waits", "APP-02.15 step 8, APP-02.16: Lock Everything and automatic locks save first; a failed save asks on the menu", "APP-09.12, APP-02.16 (LD-217 (4), R-OFF): a lock request saves the change, or keeps it in a recovery copy", "APP-02.16 T56, APP-05.28 T60: an automatic lock meeting a changed file keeps the change in a recovery copy", "Parity dialogs-save-failed: …", and the 22 LockSignalsTests (screen lock, sleep, idle, minimize). Non-data changes: App's sidebar has no expand or collapse and App has no entry move up or down (`grep -n -i "expand\|collapse" macos/App/SidebarView.swift macos/App/RailView.swift`: nothing; views.rs only reads `expanded`), so App makes no view-state change and S-FILE-03 has nothing to save.

**Result: verified.**

## SD-11 Opening an attachment in another app

**Reference (source).** Writes the attachment to a temp file (12 random characters plus the extension) with owner read and write, opens it in the default app with no warning, watches it every 5 seconds, and when it changes asks "The attachment … was modified. Do you want to save the changes to your database?" (Save, Discard; default Save). The copy is overwritten with random bytes and deleted when the attachment is removed or the entry or vault closes.

**App.** app-ffi `open_attachment`: an exclusive 0600 copy in its own 0700 folder, random name plus the extension, risky types ask first (MOD-05.12 rule 3; DialogSheets "Files of this type can run programs or commands on this Mac when opened."), wiped with random bytes on editor close, remove, a new edit and lock, and leftovers wiped at start. No watch of the copy: `grep -rn -i "MOD-05.13\|attachment.*watch" macos/App crates/app-ffi/src` finds nothing, and no Rust call reads a copy back.

Commands and output: `mod_05_open_save_and_wipe`, `mod_05_12_risky_types_ask_first`, `ld_199_6_7_copies_go_on_remove_and_on_a_new_edit`: ok. Probe (copy) `sd11_an_outside_change_to_an_open_copy_is_not_saved_back` (the copy rewritten as another app would save it, then 6 s, longer than the reference's watch):
```
PROBE sd11 copy still there before close: true
PROBE sd11 copy after the editor closed: exists false
PROBE sd11 attachment after commit and save: 1229 bytes, holds the outside edit: false
```

**Result: fails (finding 2).** The edit made in the other app is wiped with no question; the reference asks to save it into the vault. Row stays todo.

## SD-12 Backups after a master key change

**Reference (source).** A key change does nothing to existing backups; they still open with the old key, and nothing says so.

**App.** The password sheet says "The next save locks the vault with the new password. Copies made before still open with the old one." (VaultSettingsPages.swift). The APP-05.33 notice after the save (list App's backups and recovery copies of this vault, offer Delete checked) is not built: app-core's `storage::old_copies` has no caller (`grep -rn "old_copies\|KEY-OLD-COPIES" crates/app-ffi/src macos/App`: nothing).

Commands and output: probe (copy) `sd12_backup_before_a_key_change_opens_with_the_old_key` on option-a-family:
```
PROBE sd12 save: changes 0 failure None notice None; backup exists true mode 600; vault opens with new true old false; backup opens with old true new false
```

**Result: the parity part holds (App is not weaker; it says more than the reference), the App extra of LD-53 is not built (finding 4).** Row stays todo.

## SD-13 Attachment previews

**Reference (source).** Its preview shows HTML and Markdown attachments as rich text in a text browser that opens clicked links with the system handler, no confirm; image attachments are decoded by its UI toolkit.

**App.** No attachment preview: attachments are listed by name (DetailFields.swift, EditorPages.swift: Open, Save…, Remove). Vault text is plain text only: macos/.swiftlint.yml's error rule "Show vault text with Text(verbatim:) (AT-E01); never AttributedString(markdown:) or Text("…\(…)")."; the URL opener takes http and https only (E5-S4, AT-E02).

**Result: waits for a story.** App renders no attachment, so it follows no link and decodes no attachment image, but the row's App extra (preview with a link confirm, images through the Rust decoder, MOD-05.9, LD-65) has no story in plan/epics.md. For the lead.

## Findings (for the lead; security/findings.md not edited)

1. **High, SD-03, APP-05.29 not built.** File re-keyed elsewhere while this window has unsaved changes: Merge and Discard answer `NewKey` and stop; Keep mine then overwrites the other side's version with the old key (probe above: "Theirs" lost, the old password opens the file). The reference asks for the new credentials and merges. Smallest fix: the APP-05.29 unlock sheet; a saving.rs call that opens the disk version with the credentials the user enters, continues the chosen Merge or Discard, and then keeps the new key parts for the next saves.
2. **High, SD-11, MOD-05.13 not built.** Changes saved into an opened attachment copy by another app are wiped without a question on editor close, remove or lock. The reference watches the copy and asks to save it back. Smallest fix: a DiskWatch-style watch of each open copy (file events plus a 5-second SHA-256 check) in Swift, the Save/Discard question, and a Rust call that reads the copy (bounded by the attachment limit) into the draft.
3. **Medium, SD-01, APP-05.14 not wired.** After repeated failed safe saves App shows the save-failed sheet but never offers to switch this vault to the unsafe method; app-core's `storage::Failures` exists and is tested but unused. Smallest fix: keep a `Failures` in the vault's edit state, call it on each failed save, return a flag in `SaveStatus`, show MSG-SAVE-UNSAFE-ASK, and use `save.unsafe_method` for that vault after Turn off.
4. **Medium, SD-12, APP-05.33 not built (LD-53).** After a key change App does not list or offer to delete its backups and recovery copies of the vault, including the backup that key-change save made. `storage::old_copies` is ready. Smallest fix: after a save that wrote new key parts, call `old_copies` and show MSG-KEY-OLD-COPIES with Delete checked and Keep.
5. **Low, SD-01, APP-05.11 step 5, LD-129 (4), LD-200.** The creation date, Finder tags and access list are not copied to the new file. The reference loses the creation date on this Mac too (observed today), so App is not weaker; App's card promises more. Smallest fix: the app-platform step the card names, before the rename.
6. **Low, test hygiene (not an SD behaviour).** `app06_16_lock_during_unlock_drops_the_result` (crates/app-ffi/tests/session.rs:423) waits in a loop for `unlocking` with no time limit; at load average about 390 it never saw it and spun for 16 minutes until I stopped it by PID. Smallest fix: a deadline on the loop (or a test hook that holds the unlock open).

Open for the lead: SD-07 and SD-13 have no story that builds the app's export screens and the attachment preview. SD-08 waits for E13-S2.

## Cleanup

Removed /tmp/e13s1-SD (work folders, the two throwaway homes, logs), /tmp/e13s1-SD-copy, /tmp/e13s1-SD-target and /tmp/e13s1-SD-dd. The shared /tmp/e13s1-target stays for the other groups. Test folders the probes made lived under the copy's target and went with it.
