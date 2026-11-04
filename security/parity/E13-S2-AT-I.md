# E13-S2 attack campaign, group AT-I: Disk and sync (AT-I01 to AT-I08)

Story: E13-S2. Catalog: [plan/attacks-and-checks.md](../../plan/attacks-and-checks.md), group AT-I. Cards: [APP-05](../../spec/app/APP-05-saving.md), [APP-01](../../spec/app/APP-01-settings.md) (APP-01.10), [INT-09](../../spec/integrations/INT-09-remote-sync.md) (INT-09.30), [INT-10](../../spec/integrations/INT-10-command-line.md) (INT-10.20), MOD-11.18, FEA-08.1. Decisions: LD-129, LD-131, LD-200, LD-218, W-15. Finding F-047.
Date: 2026-10-29. Role: Red team. I did not build or review these stories.
Earlier proof, history only: [SD-01, SD-02, SD-03, SD-09](SD-01-SD-02-SD-03-SD-09.md) (E4-S15), [E5-S10 saving](E5-S10-saving.md). Every result below was run again on today's tree.

| Row | Result | One line |
|---|---|---|
| AT-I01 | passed | 1,000 SIGKILLs during saves (the `app` tool on a 2 KB and a 3 MiB vault, and the Mac app's Rust layer with backups on): 0 broken files. Every vault opened as the old or the new version, every backup opened, the reference tool opened all 100 sampled vaults. |
| AT-I02 | passed | Full HFS+ and APFS disk images (attached `-nobrowse` under /tmp, detached after): every save failed with "no storage space" / "There is no space left on the disk.", the vault's SHA-256 unchanged, no temp file left, the change kept in memory, and Save As elsewhere kept it. |
| AT-I03 | passed | Read-only folder (0555), read-only file (0400), locked file (`chflags uchg`): "permission denied" / "This vault's file or its folder cannot be written.", vault unchanged, nothing left behind, Save As keeps the change. |
| AT-I04 | **failed** | Every vault-path probe passes (symbolic link, hard link, links planted at the backup name and at an export target, a dangling link, a path swapped after unlock). **But** the settings export writes through a link planted at its fixed temp name and overwrites the linked file (F-I2, Medium); and a racing attacker still turns the vault path into its own link while `app` says "saved" (F-047 re-confirmed, F-I3, Low). |
| AT-I05 | **failed** | Cloud conflict copies merge without loss, both ways, the same as the reference tool's merge. Two windows of one App share one vault slot, so they cannot race. **But** two separate writers (two `app` processes, or two sessions) that save at the same instant both report "saved" and one save is lost: 4 of 150 process pairs, 6 of 100 session races (F-I1, Medium). |
| AT-I06 | passed | New vaults 0600 (wizard and `app db-create`, `app import`), new key files 0400, backups 0600, attachment Save… and `app attachment-export` 0600, settings export 0600; a re-saved 0644 vault keeps 0644 (APP-05.12). The planted-temp case of the settings export is F-I2. The Mac app's vault export (FEA-09) is not built yet. |
| AT-I07 | waits for story (W-15) | The part that applies today passed: planted sync commands (also through `/bin/sh -c`) never ran on open, save, a merge whose custom data wins, or change-on-disk merges; no marker file; the item was kept byte for byte. Picking a sync, Cancel, Test and Apply wait for remote sync (INT-09.30). One Low: F-I4. |
| AT-I08 | waits for story (W-15) | No sync runner exists: no product code starts a process (Rust or Swift); the planted hostile commands of AT-I07 never ran. The run limits, process groups and download checks wait for remote sync. |

Findings: **F-I1 Medium** (two writers lose a save), **F-I2 Medium** (settings export follows a planted link), **F-I3 Low** (F-047 re-confirmed, no story owns it), **F-I4 Low** (the IMP-REMOTE import kind is still listed). Details at the end.

## Setup

- **Tree.** Today's tree, read only; no product file changed. `. "$HOME/.cargo/env"`, toolchain 1.99.1, `CARGO_TARGET_DIR=/tmp/e13s2-target` (shared red team build), `--offline`. `cargo build --release -p app-cli` gives `app` 0.1.0.
- **Harness.** My own crate `/tmp/e13s2-I/harness` (binary `e13s2-i-harness`), outside the workspace, with path dependencies on app-ffi and app-core, the tree's `Cargo.lock`, release profile and two `[patch.crates-io]` lines. It calls the same exports the Swift screens call: `Session::new` (memory settings, backup on by default), `open`, `unlock`, `begin_new`, `set_text`, `commit_edit`, `save`, `confirm_format_notice`, `save_as`, `check_disk`, `resolve_disk`, `list`, `begin_edit`, `save_attachment`, `cancel_edit`, `Wizard::new/measure/new_key_file/set_password/set_repeat/create`, `settings().export_to`. Modes: `saver` (add `kN`, save, print N, forever), `count`, `titles`, `add-save` (one add and save, optional Save As), `two-windows`, `modes`. The Swift save layer (`macos/App/Saving.swift`) only calls `session.save` / `saveAs`; it writes no vault file itself.
- **Data.** Copies of `testdata/` vaults under `/tmp/e13s2-I` (demo passwords from testdata/README.md), vaults made there by `app import` from our own XML export, and one 3 MiB vault (`password-only` plus a 3 MiB random attachment, `app attachment-import`).
- **Reference.** The reference command line tool (2.7.11), read only, with `HOME=/tmp/e13s2-I/refhome`, on the same /tmp copies.
- **Owner's session.** No window, no focus, no pasteboard, no keychain, no ssh. Every process I started was stopped by its PID. One slip: my first sanity run of `saver` killed the wrong PID (the `time` wrapper), so that saver (PID 23352) went on saving into `/tmp/e13s2-I/sanity` for 28 minutes until I found it and stopped it by its PID. It used 6.2 CPU minutes and wrote only there. Its last vault (6,829 saves, 230 KB) opened with all 6,829 entries, and its backup with 6,828. CPU used by the group: about 25 minutes (builds 3.6, AT-I01 12.7, that saver 6.2, the AT-I05 races 1.2, the rest under 2), under the 30-minute cap. Machine load during the runs: 50 to 380.

## AT-I01 Crash during save

**Method.** `scripts/i01.py` (python3 -I), 1,000 runs, 4 at a time, seed 1301. Each run copies a demo vault into its own folder, starts a writer that saves again and again, and sends SIGKILL to that PID at a random point; then it checks the file.

| Variant | Writer | Vault |
|---|---|---|
| cli-small | `app open V.appvault` fed `add e1`, `add e2`, … (each add is one save, INT-10.20; "New entry eN saved." logs each) | `password-only.appvault` (AES-KDF 13 M rounds, 2 KB) |
| cli-big | the same | `password-only` plus a 3 MiB attachment (3.1 MB) |
| ffi | harness `saver` (the Mac app's save, backup `V.old.appvault` before each save) | `option-a-personal.appvault` |

Kill points: `cycle`: after the first logged save, at a uniform random point of one save period (median of the measured gaps), so kills fall in building, the key derivation, the write, the sync and the rename. `temp`: 0 to 3 ms after the save's temp file appears (polled every 0.2 ms), so kills fall in the write, sync and rename. Check after each kill: the vault opens (our tool `app ls` or the harness `count`); its entry count equals the last logged save (old) or one more (new); for ffi the backup opens and holds N−1 or N; every 10th vault also opens with the reference tool.

**Output** (`i01-out.txt`):

```
runs 1000; wall 933 s; child CPU 760 s
cli-small cycle: runs 125; fails 0; old 125; new 0; broken 0; temp left 1; temp modes ['0o600']
cli-small temp : runs 125; fails 0; old 120; new 5; broken 0; temp left 118; temp modes ['0o600']
cli-big   cycle: runs 125; fails 0; old 125; new 0; broken 0; temp left 0; temp modes []
cli-big   temp : runs 125; fails 0; old 115; new 10; broken 0; temp left 112; temp modes ['0o600']
ffi       cycle: runs 250; fails 0; old 218; new 32; broken 0; temp left 100; temp modes ['0o600']
ffi       temp : runs 250; fails 0; old 250; new 0; broken 0; temp left 246; temp modes ['0o600']
ffi backups: opened 500 none 0 not opened 0
reference tool opened 100 of 100
exit 0
```

**Result: passed.** 0 broken of 1,000. 577 kills landed while a temp file was open (left behind, 0600, as APP-05.17 says); 47 landed after the rename and before the log line (the new version). Every backup opened.

## AT-I02 Disk full

**Method.** `scripts/i02.sh HFS+ 20m` and `scripts/i02.sh APFS 40m`: `hdiutil create … -layout NONE img.dmg`, `hdiutil attach -quiet -nobrowse -noautoopen -mountpoint /tmp/e13s2-I/i02-<fs>/mnt`, the disk filled with a `dd` file to a set free space, a save, then the SHA-256, the folder listing and an open by both tools; `hdiutil detach` at the end. Cases: A `app add` on the 2 KB vault, 0 KiB free; B `app add` on the 3 MiB vault, 1 MiB free (fails in the middle of the write); C harness `add-save` (backup on), 8 KiB free, then Save As to /tmp; D the same with 16 KiB free (room for the backup, not for the vault); E the reference tool, 0 KiB free.

**Output** (HFS+; APFS gives the same lines, its df reserves about 1.3 MiB):

```
A: app: could not save …/mnt/C.appvault: no storage space. The file on disk is unchanged.  exit 1
   vault unchanged: yes; temp left: []
B: app: could not save …/mnt/B.appvault: no storage space. The file on disk is unchanged.  exit 1
   vault unchanged: yes; temp left: []
C: save: changes=1 failure=Some("There is no space left on the disk.") on_disk=None
   save_as: changes=0 failure=None
   vault unchanged: yes; temp left: []; saved elsewhere opens: 1
D: save: changes=1 failure=Some("There is no space left on the disk.")
   vault unchanged: yes; temp left: []; files: B.appvault C.appvault P.appvault P.old.appvault filler
E: Writing the database failed No space left on device.  exit 1;  vault unchanged: yes
C ours: Demo login  ref: Demo login;  B ours: Demo login  ref: Demo login;  P ours: 23 entries
detached
```

**Result: passed.** Old file intact (same SHA-256), clear error, no temp file left, the change kept (changes=1) and saved by Save As. In D the backup (a whole copy of the old file) stays, as APP-05.22 allows. A first try with 8 KiB free let the 2 KB save succeed: correct, the disk was not full; the rows above use 0 KiB.

## AT-I03 No permission

**Method.** `scripts/i03.sh`: three folders: `ro` (folder 0555), `rw` (vault files 0400), `lk` (vault files `chflags uchg`). In each: `app add`, harness `add-save` with Save As to a writable folder, and the reference tool's `add`.

**Output** (`i03-out.txt`):

```
== ro:folder 0555
app: could not save ro/C.appvault: permission denied. The file on disk is unchanged.  exit 1
save: changes=1 failure=Some("This vault's file or its folder cannot be written.")
save_as: changes=0 failure=None;  vault unchanged: yes; folder: . .. C.appvault P.appvault;  Save As copy has the change: 1
reference: Writing the database failed Permission denied.  exit 1
== rw:file 0400   (same lines; reference: "Existing file … is not writable.")
== lk:file locked (uchg)   (same lines; the backup P.old.appvault is made first, then the rename is refused)
```

**Result: passed.** Clear error, vault unchanged, nothing left behind, nothing lost (Save As holds the change).

## AT-I04 Link tricks

**Method.** `scripts/i04.sh`, plus `scripts/swap.py` and `scripts/racer.py`; victim file `other/victim.txt` ("victim, demo text").

**Output** (`i04-out.txt`):

```
1 symbolic link at the vault path: link stays a link; target got a new inode and the entry; backup next to the real file (0600)
2 hard link at the vault path (app and harness): other hard link unchanged: yes
3 symbolic link / hard link planted at the backup name: victim unchanged: yes; backup: file mode 600 links 1
4 dangling link (app): "links/D.appvault does not exist." exit 1; nothing made at the target
5 link at the export target: without -f "exists and was left alone" exit 1; with -f exit 0, victim unchanged, out.bin a file 0600
7 path swapped after unlock (app shell):
  to a dangling link: "New entry swapped saved."; the path is now a file 0600; the dangling target was not made
  to a link to the victim: "…changed on disk while this command ran. Nothing was saved"; victim unchanged
```

The vault-path behaviour matches APP-05.9 and APP-05.12 in every case.

Two failures:

```
6 racing attacker (renames each new temp file away and puts a link to the victim at its name), app shell, 300 adds:
  saved: 240; refused: 60 (16 "other error", 43 "changed on disk")
  victim unchanged: yes; vault path: link -> /tmp/e13s2-I/i04/other/victim.txt
  app: "X.appvault" is not a vault file.
  tail of the output: "New entry r256 saved." ; saves r257 to r300 all refused
settings export (harness `modes`, folder with `.settings-export.json.tmp` -> victim.txt planted):
  settings export: mode 644
  victim now: {   "format": "app-settings",   "settings": {},   "version": 1 }
  settings-export.json -> /tmp/e13s2-I/i06/victim.txt
settings export with a 0666 file planted at the temp name: settings-export.json mode 666
```

**Result: failed.** The settings export (`app_settings.rs` `write_json`) uses the fixed temp name `.<name>.tmp` opened with create and truncate, so it writes through a planted link into another file and then renames the link onto the export path (F-I2). The race of case 6 is F-047: save r256 was reported saved while the rename moved the attacker's link onto the vault path; the victim was never written and the r256 bytes are in the moved-away temp file (F-I3). Not a finding: a temp file replaced behind App's back is reported as "other error", which says little.

## AT-I05 Two writers

**Method.** `scripts/i05.sh` and `scripts/i05_procs.py`.

1. Harness `two-windows` on a copy of `option-a-personal`: two sessions open one vault. In turn: window 2's save answers `OnSave`, Merge, save; window 1 reloads; an unsaved change in window 1 gets `Ask Unsaved`, Merge, save. Then N races: both windows add an entry and call `save` on two threads at once; a save that answers `on_disk` is merged and saved again; then both check the disk. At the end a third session lists the file.
2. 20 pairs of `app add` processes on one vault at the same time.
3. Cloud conflict copy: `V.appvault` and `V (conflicted copy).appvault` from one base (5 entries), edited apart (V: add, edit notes of a1, delete a2 to the bin, move a3 into a new group; the copy: add, edit a4's notes, edit a1's user name), then `app merge -s` both ways and the reference tool's `merge -s` both ways; each result listed with path, user name and first notes line by the reference tool.
4. `i05_procs.py`: 150 trials of two `app open R.appvault` processes on a copy of `option-a-personal`; both unlock (they answer `db-info`), then `add raceT-0` and `add raceT-1` are written to the two shells in the same instant.

**Output:**

```
1 w2 save: changes=1 failure=None on_disk=Some(OnSave) / w2 merge: Reloaded / w2 save after merge: changes=0
  w1 check_disk: Reloaded / w1 check_disk with unsaved: Ask { ask: Unsaved, changes: 1 } / w1 merge: Reloaded
  two-windows: 20 races, 66 entries on file, lost 1  (LOST r16-w2)
  two-windows: 100 races, 221 entries on file, lost 6  (LOST r32-w1 r58-w2 r61-w1 r79-w2 r86-w1 r92-w2)
2 saved 20, refused (changed on disk) 20, lost 0
3 ours, the copy merged into V:
  Demo login | demo-user | A demo entry.
  G1/a3 |  | base 3
  Recycle Bin/a2 |  | base 2
  a1 | user from copy | base 1
  a4 |  | edited in the copy
  a5 |  | base 5
  only in V |  |
  only in the copy |  |
  ours V into the copy: same;  reference copy into V: same;  reference V into the copy: same
4 trial 3: both reported saved; missing on file: ['race3-0']
  trial 52: … ['race52-0'];  trial 105: … ['race105-0'];  trial 118: … ['race118-1']
  trials 150; both saved 4; one refused (changed on disk) 144; lost an entry 4
```

(In 3, a1 shows the copy's newer version. V's notes edit "edited in V" is in a1's history, in our result and in the reference tool's result alike: the newest version wins and the older one goes to history, MOD-11.)

**Result: failed.** Conflict copies and the window flow pass. In the Mac app two windows of one vault share one slot and its save lock (`session.rs` `open_path` finds the slot by path), so they cannot race. Two separate writers can: both pass the pre-save check and the second check, both rename, the later rename wins, both say "saved", and the loser's entry is gone; a reload then drops it from that writer's memory too (F-I1).

## AT-I06 File permissions

**Method.** Harness `modes` with `umask 022` (wizard new vault and new key file, a save with backup, a 0644 demo vault saved, attachment Save…, settings export) and `app` with `umask 022` (`db-create -p`, `db-create --set-key-file`, `import -p`, `attachment-export`, `add` on a 0644 vault, `export` to stdout).

**Output:**

```
new vault …/new.appvault: mode 600          new key file …/new.appkey: mode 400
backup …/new.old.appvault: mode 600         vault after save: mode 600
0644 vault after save: 644; its backup: 600
attachment "github-recovery-codes.txt" saved=true: mode 600
settings export: mode 600
app: imp.appvault 600, n1.appvault 600, n2.appvault 600, nk.appkey 400, out.bin 600, keep644.appvault 644 (re-saved)
app export --format csv > export.csv: 644 (made by the shell's redirect, not by App)
```

**Result: passed.** Everything App makes is owner-only (key files owner read-only, SD-09). A re-save keeps the vault's own bits, as APP-05.12 says. A planted temp file makes the settings export 0666: F-I2. The Mac app's vault export (FEA-09.15) and the recovery copy in the real settings folder were not run: the first is not built, the second needs the owner's settings folder.

## AT-I07 Planted sync commands

**Method.** `scripts/i07_make.py` writes two XML documents from our own XML export of `password-only`, with a vault custom data item under the INT-09.1 key (`4B 50 58 43 5F 52 45 4D 4F 54 45 5F 53 59 4E 43 5F 53 45 54 54 49 4E 47 53`, built from hex) holding two syncs each: `/usr/bin/touch /tmp/e13s2-I/i07/MARK-<tag>-dl` (and `-ul`, and a touch in the input field), and `/bin/sh -c "touch …/MARK-<tag>-sh; cp /dev/null {TEMP_DATABASE}"`. `app import -p -t 100` makes T (target) and S (source). `scripts/i07_run.sh`: open with `app ls`, `show`, `db-info`, `search` and the harness; save with `app add` and harness `add-save` (backup on); `app merge -s T S` after S was edited last, so S's custom data wins (MOD-11.18); harness `two-windows T 5` (change-on-disk merges and saves); the reference tool opens T. After each step: the marker count and the item's SHA-256 (from our XML export). Code read: no product code starts a process.

**Output:**

```
T: items 1 sha256 e5073a702f5c2bdb starts [{"name": "target sync", …   S: items 1 sha256 b6583b1dc6bf6aa8 …
markers before: 0 / after open (cli): 0 / after open (ffi): 0
T after cli save: sha256 e5073a702f5c2bdb; markers: 0
T after ffi save: sha256 e5073a702f5c2bdb; backup: sha256 e5073a702f5c2bdb; markers: 0
merge: Added: '/Demo'/'Source edit after target'; Metadata: (custom data set: <the sync key>); saved
T after merge: sha256 b6583b1dc6bf6aa8 (the source's value, byte for byte); markers: 0
T after ffi save and cli save: sha256 b6583b1dc6bf6aa8; markers: 0
two-windows: 5 races …; markers: 0;  reference tool opens T: exit 0;  markers at end: 0
```

Code read (today's tree): every `std::process::Command` in `crates/` is inside a `#[cfg(test)]` module (app-ffi `edit.rs`, app-platform `memory.rs`, `pipe.rs`, `terminal.rs`, `signals.rs`, `process.rs`, `instance.rs`, `system.rs`); no `popen`, `exec` or `posix_spawn`; no `Process`, `NSTask` or `posix_spawn` in `macos/`. The Mac app has no Remote sync menu, page or import kind (`Import…` and `Merge Another Vault…` are disabled menu items).

**Result: waits for story.** Nothing runs on open, merge or save, no marker, and the item is kept byte for byte (INT-09.30, T51). A winning merge source replaces the stored commands silently, as MOD-11.18 says; INT-09.20's approval would cover that once syncs can run. Picking a sync, Cancel, Test and Apply (INT-09.5 to INT-09.7, INT-09.20) wait for remote sync (W-15). F-I4: app-core still lists the IMP-REMOTE kind.

## AT-I08 Hostile sync commands and downloads

**Result: waits for story.** There is no command runner, so no run, timeout, process group, output limit, download check or temp folder exists to attack. The planted `/bin/sh` commands of AT-I07 never ran. Re-run this row when D-INT09-1 is ruled (a).

## Findings

| ID | Severity | Area | Steps to reproduce (demo data) | Smallest fix |
|---|---|---|---|---|
| F-I1 | Medium | app-core storage, two writers (AT-I05, APP-05.10, SD-03) | 1. `cargo build --release -p app-cli`; `cp testdata/option-a-personal.appvault /tmp/r/R.appvault`. 2. Start two `app open /tmp/r/R.appvault` processes; write `demo-pass-7` and `db-info` to each and wait for the "One-time code entries" line from both. 3. Write `add race-0` to the first and `add race-1` to the second in the same instant, then `quit`. 4. Repeat 150 times on a fresh copy. Seen: 4 of 150 trials both print "New entry … saved." and `app ls` shows only one of the two entries; with two `Session`s on two threads (`save` at once) 6 of 100. The reference app has no guard either. | In `storage::replace_file`, for a vault save that ran the pre-save check, open the vault file now on disk and hold an exclusive advisory lock on it (`File::lock`, std; no lock file, so APP-05.17 holds) across `recheck`, `still_ours` and the rename. A second App writer blocks on the old file, then its second check sees the new checksum and answers ChangedOnDisk (the merge question). |
| F-I2 | Medium | app-ffi settings export (APP-01.10; AT-I04, AT-I06) | 1. `mkdir /tmp/r; printf 'victim\n' > /tmp/r/victim.txt`. 2. `ln -s /tmp/r/victim.txt /tmp/r/.settings-export.json.tmp`. 3. Export the settings to `/tmp/r/settings-export.json` (`Session::new().settings().export_to(…)`, the Settings page's Export). Seen: victim.txt now holds the settings JSON, `settings-export.json` is a link to victim.txt, mode 644; with a 0666 file planted at the temp name instead, the export is 0666 and owned by whoever planted it. Anyone who can write into the chosen folder (shared or synced folder) can do this. | Make `write_json` (app_settings.rs) write through `app_core::storage::write_export` after it makes the folder: an exclusive random temp file, 0600 on the open file, a link at the target replaced, never followed. One change covers the export and the store's own files. |
| F-I3 | Low | app-core storage rename (F-047, LD-131) | 1. Copy `testdata/password-only.appvault` to a folder. 2. Run a loop that renames every new `*.tmp` in that folder away and puts a symbolic link to another file at its name. 3. Feed `app open` 300 `add rN` lines. Seen: "New entry r256 saved.", but the vault path is now the attacker's link ("is not a vault file"), r257 to r300 refused; the other file was never written. F-047 said a folder-relative rename would come in E6; no E6 story did it, and the finding is still open. | For the filer: update F-047 rather than add a row. A small first step: keep the temp `File` open across the rename and compare `symlink_metadata(target)` dev and inode with it after the rename; on a mismatch report a failed save, so App never says "saved" when the file is not its own. The full fix stays F-047's folder-relative rename. |
| F-I4 | Low | app-core import kinds (INT-09.30, FEA-08.1, W-15) | `crates/app-core/src/import/mod.rs` `KINDS` lists `Kind::Remote` (IMP-REMOTE). INT-09.30 says App shows no IMP-REMOTE kind while remote sync is not built. Nothing shows today, because `Import…` is a disabled menu item. When the import assistant is wired from `KINDS`, a Remote vault kind with no runner behind it would show. | Leave `Kind::Remote` out of `KINDS` (keep the enum) until D-INT09-1 is ruled, and say so in FEA-08.1. |

## Clean-up

My work folder `/tmp/e13s2-I` (scripts, data copies, outputs, harness sources) was deleted at the end. Both disk images were detached; `mount` shows no `e13s2` volume. The shared build folder `/tmp/e13s2-target` stays for the other red team agents. It holds my harness binary `release/e13s2-i-harness` and its build files.
