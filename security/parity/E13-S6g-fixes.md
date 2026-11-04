# E13-S6 part g: re-test of F-101, F-110, F-111, F-098, F-112

Story: E13-S6 part g ([plan/epics.md](../../plan/epics.md)). Rows: [security/findings.md](../findings.md). Earlier proof: [E13-S2 AT-E](E13-S2-AT-E.md) (RT-E-1, F-101), [E13-S2 AT-I](E13-S2-AT-I.md) (F-I1 = F-110, F-I2 = F-111, F-I4 = F-112), [E13-S2 AT-B](E13-S2-AT-B.md) (RT-B1 = F-098). Ruling: LD-225 (1).
Date: 2026-10-29 (the runs took place from 00:57 to 02:00 on 2026-10-30 by the Mac's clock). Role: Verify, round 1. I did not find, build or check these fixes.

| Finding | Result | One line |
|---|---|---|
| F-101 (High) | **fixed, re-tested** | RT-E-1's own steps: `lockAll()` returns in 0.34 s, the vault is locked and its change is in the recovery copy (before: it never returned). Every Rust path answers a FIFO in under 0.3 s. An automatic lock behind a slow save waits 1.01 s (3.38 s with the wait undone). One residual is listed for the lead: the menu's Lock Everything. |
| F-110 | **fixed, re-tested** | The finding's 150 two-process trials: exactly one save in each, and the other process says "changed on disk"; 0 lost (before: 4 of 150). 100 two-session races: 0 lost (before: 6 of 100). With the lock undone, the same 150 trials lose 5. |
| F-111 | **fixed, re-tested** | A link or a 0666 file planted at the old temp name, or a link at the target: the victim file is unchanged, and the export is a real file with mode 0600. With the old write, the victim gets the settings JSON. |
| F-098 | **fixed, re-tested** | 28 busy processes: `db-create` stored 43, 41 and 45 Argon2id iterations, and the KDF takes 1.40-1.48 s of CPU (before: 11 iterations, 0.33 s). With the wall clock back, the same load gives 30, 30 and 39. |
| F-112 | **fixed, re-tested** | `KINDS` lists six kinds and no Remote kind; nothing else lists import kinds. With Remote listed again, f_112 and fea08_01 fail. |

All 5 rows were re-tested and are fixed. One new problem from a side check (below, for the lead): `check_writable` empties a file through a planted link. It is a sibling of F-111 that existed before part g, not a regression.

## Setup

- **Private copy.** `rsync -a --exclude target --exclude app-shots --exclude fuzz/target` to `/tmp/e13s6g-verify-copy`, made at 00:59. I re-synced it from the tree at about 01:25 after part f's `hwkey` module landed. Its own target was `/tmp/e13s6g-verify-target` and its DerivedData `/tmp/e13s6g-verify-dd`. Patches made only in the copy:
  - before the re-sync, a stub `hwkey` module, because app-ffi did not compile in the tree then. Part f's real module replaced it;
  - LockSignalsTests.swift:323 `allSatisfy { $0.locked }` and :345 `nonisolated private final class Took`. The tree's AppTests still do not compile under `SWIFT_TREAT_WARNINGS_AS_ERRORS` without these two lines (not part g's file);
  - my own harnesses: `crates/app-ffi/tests/verify_e13s6g.rs`, `verify_e13s6g_extra.rs` and `macos/AppTests/VerifyE13S6gTests.swift`, plus one `print` of the measured time after each `lockAll` in SavingWatchTests.swift.
- **Shared tree, own target** (`/tmp/e13s6g-verify-tree-target`, `--locked`), at about 01:55. App-ffi compiles in the tree now.
  - `cargo clippy -p app-core -p app-platform -p app-cli -p app-ffi --all-targets -- -D warnings`: exit 0.
  - The 7 named tests all `ok`: app05 `f_101_a_fifo_vault_path_or_save_as_target_is_refused_at_once` and `f_110_two_writers_take_turns_and_no_save_is_lost`; app-ffi `saving::tests::f_101_save_check_reload_and_save_as_refuse_a_fifo_at_once`, `saving::tests::f_101_a_save_the_lock_overtook_keeps_the_change_in_a_recovery_copy` and `app_settings::tests::f_111_settings_export_follows_no_planted_link`; app-cli `commands::tests::f_098_kdf_tuning_clock_is_the_threads_cpu_time`; fea08 `f_112_no_remote_vault_kind_is_listed`.
- **Full suites in the copy.**
  - `cargo test --no-fail-fast -p app-core -p app-ffi -p app-cli -p app-platform`, first copy: 54 targets, 1,138 passed, 0 failed.
  - Re-synced copy: 56 targets (my two harness targets included), 1,148 passed, 0 failed, 36 ignored.
- **Swift.** `scripts/build-core.sh`, then `xcodebuild … -derivedDataPath /tmp/e13s6g-verify-dd test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`.
  - First copy: 306 tests in 41 suites passed (TEST SUCCEEDED).
  - Re-synced copy: 309 tests ran, 308 passed. The one failure is part d's timing test "APP-01.27 c: … search clear countdown" (21 s under load). Run alone, it passes in 4.1 s. It is not a part g test.
- **Tree changes during the run.** Part f landed `hwkey.rs` and wired F-107 and F-079 into session.rs, saving.rs and commands.rs (00:18 to 01:43). Those edits add the hardware key part and auto-open. Every `open_regular` call, the save path and `MEASURE_CLOCK` are unchanged, and the tree run above came after them.
- **Rules.** Demo vaults only (rich-v4 / demo-pass-5, option-a-personal / demo-pass-7, `demo-b06` for new vaults). `HOME` was isolated for `app`, and `SSH_AUTH_SOCK` was unset. AppTests ran without a host app, with offscreen windows; UI tests were skipped. No window, focus, key events or general pasteboard. The 28 `yes` processes were stopped by their PIDs.
- **A mistake in my first mutant batch, redone.** My first restore used `copy2`, which put back the original mtime, so cargo did not rebuild app-platform after m1 was undone. The m2, m8, m9, m10 and m5 results of that batch were therefore built with m1 still compiled in (the m5 run hung in a blocking FIFO open, seen with `sample`). I stopped those processes by PID, touched every source file and redid all 10 Rust mutants with a fresh mtime on every restore. Every mutant result below comes from the redo. After the redo, the named tests pass on the restored copy.

## F-101 (High): a FIFO at the vault path stops every lock

- **Steps (RT-E-1, demo data).**
  1. Copy rich-v4 to `hang.appvault`.
  2. `MainWindowModel(session: Session())`, open, unlock with demo-pass-5.
  3. `deleteEntry` on the first row, so `changes == 1`. `save.on_lock` is on by default.
  4. `rm` the file and `mkfifo` at its path.
  5. `lockAll()` on the main actor. The finding's watchdog opens the FIFO after 4 s.
  - The test is copy-only `VerifyE13S6gTests/rtE1Steps`. The Rust part is in my harness `verify_f101_rust_steps`: own file swapped for a FIFO, `save`, `check_disk`, `resolve_disk(Reload)`; `save_as` onto a FIFO, a link to a FIFO, a folder and `/dev/null`; after `lock`, `check_header`, `unlock` and a fresh `open`.
- **Before** (red team): `lockAll` never returned; "4.51 s", and only the watchdog ended it. `save`, `check_disk` and `resolve_disk(Reload)` blocked over 3 s each.
  - Re-run with `open_regular` undone (mutant m1): `check_disk(own FIFO)` was still blocked at 3 s, so the harness timed out.
- **After:**
  - `VERIFY F-101 RT-E-1: lockAll took 0.337457792 seconds; locked (read off the main thread) true; recovery copies 1`.
  - Rust paths:
    - `save` 0.27 s, "This vault's path is not a file App can write.", with `changes` still 1;
    - `check_disk` 17 µs, `None`;
    - `resolve_disk(Reload)` 11 µs, `Unreadable`;
    - `save_as` 0.23-0.26 s onto each of the four targets, each with the same message;
    - `check_header` 9 µs, which names the failure;
    - `unlock` 7 µs, `Failed` with M06-26;
    - `open` 0.1 ms.

    The saves take 0.2-0.3 s because the vault is encoded (KDF) before the storage refusal, and no file is opened.
  - Slow save (the builder's AppTest with a 3 s KDF): `lockAll` took 1.010441167 s, the vault was locked, and the file was written after the lock. With the deadline undone (Swift mutant m11), the same test took 3.376807041 s and FAILED.
- **Callers.** Every read of the vault path goes through `app_platform::macos::open_regular` (metadata, then `O_NONBLOCK | O_NOCTTY`, then fstat):
  - storage.rs `read_checksum`, `lock_vault` and `read_bounded` (backup and direct method);
  - saving.rs reload and merge;
  - session.rs `header_look`, `run_open` (unlock) and `check_header`.

  `storage::save` refuses a non-regular `real_path` before any open. The direct method reads through `read_bounded` before its write open, so a FIFO is refused there too.

  The other `File::open` and `OpenOptions` uses in app-core and app-ffi are key files, settings, attachments, the wizard and `/dev/stdin`, none on the vault path. `storage::read_limited` (the import file read) still opens with a plain blocking `File::open`. It is outside F-101's vault-path scope, as the builder said.
- **Swift paths.** LockSignals (AppDelegate.swift:36) and the channel (Front.swift:30) call `lockAll()` with `asks: false`, so they get the 1 s deadline. The menu's Lock Everything (AppCommandsVault.swift:15, Menus.swift:41, MenuBarIcon.swift:179) calls `lockAll(asks: true)`, which still saves synchronously (Saving.swift:351).
- **Residual, measured** (copy-only `VerifyE13S6gTests/lockBehindASlowSave`; an earlier save is still running, a 3 s KDF standing in for a slow disk):
  - `lockAll(asks: true) behind a running 3 s save took 3.860435291 seconds`;
  - `lockAll(asks: false) … took 1.010242417 seconds`.

  A FIFO no longer stops Lock Everything either, because Rust refuses it at once. A slow or stalled disk, or an earlier stalled save of the same vault, still freezes the window for the length of that save when the user picks Lock Everything. That does not meet LD-225 (1)'s words "no lock ever waits on a save on the main thread". It does meet the finding's own steps and its smallest fix (automatic locks). No attacker can cause it with a FIFO. For the lead, with the builder's and the Checker's proposals.
- **Mutants (each fails, run in the private copy):**

  | Mutant | Test | Result |
  |---|---|---|
  | m1, `open_regular` returns a plain `File::open` | app05 f_101 | FAILED, 'waited a second or more on the FIFO' |
  | | ffi f_101_save_check | FAILED, same |
  | | my harness | FAILED: check_disk blocked |
  | m2, the up-front refusal in `storage::save` off | app05 f_101 | FAILED (app05.rs:1477) |
  | | my harness | FAILED: `save_as` onto a FIFO answered "saved" (it renamed a file over the FIFO), and the own-path save said "The vault file cannot be read." |
  | m8, unlock back to `File::open` | ffi f_101_save_check | FAILED, 'waited …' |
  | m9, reload back to `File::open` | ffi f_101_save_check | FAILED, 'waited …' |
  | m10, `check_header` back to `File::open` | ffi f_101_save_check | FAILED, 'waited …' |
  | m5, no recovery copy for an overtaken save | f_101_a_save_the_lock_overtook… | FAILED (saving.rs:877) |
  | m11 (Swift), `lockAll` deadline nil | f101SlowSaveDoesNotHoldTheLock | FAILED: 3.38 s |

  The FIFO tests still pass under m11, as expected, because the Rust refusal answers at once.

## F-110: two writers lose a save

- **Steps (the finding's own).**
  1. Release `app` built in the copy.
  2. `cp testdata/option-a-personal.appvault R.appvault`.
  3. Two `app open R.appvault`; each gets `demo-pass-7` and `db-info`, and the run waits for "One-time code entries" from both.
  4. `add race<T>-0` and `add race<T>-1` are written to the two shells through a barrier, then `quit`, then `app ls`.
  5. 150 trials, each on a fresh copy.

  The script is `race.py`. A second check uses two app-ffi Sessions on rich-v4: each adds an entry, both `save` at once through a barrier, and a third session reads the file. 100 races.
- **Before** (red team): 4 of 150 trials had both processes saying saved, with one entry missing; Sessions lost 6 of 100.
  - With the lock undone (mutant m3), the same 150 trials gave `{"both_saved": 5, "one_saved": 145, "lost_silently": 5, "loser_said_changed_on_disk": 122}` (lost: trials 34, 35, 47, 62 and 145).
- **After:**
  - `F-110 CLI race: {"both_saved": 0, "one_saved": 150, "neither": 0, "lost_silently": 0, "loser_said_changed_on_disk": 150}`. In every trial the loser printed "…/R.appvault changed on disk while this command ran. Nothing was saved; run the command again." `ls` found every saved entry, which is the positive control of the check.
  - Sessions: `trials 100; both saved 0; one saved 100; neither 0; lost 0`.
- **Mutant m3** (`lock_vault` returns `Ok(None)`): app05 `f_110_two_writers_take_turns_and_no_save_is_lost` FAILED (app05.rs:1527), and the CLI race lost 5 as above.
- **Note (agree with the Checker, Low):** `Failures::failed` does not list `ResourceBusy` among the kinds that do not count. So three "Another program is writing this vault's file" errors in a row offer MSG-SAVE-UNSAFE-ASK, which cannot help: the other methods take the same lock (code read, storage.rs `Failures::failed`).

## F-111: the settings export follows a planted link

- **Steps (the finding's own,** in my harness `verify_f111_steps`):
  1. `victim.txt` with "victim\n".
  2. A link at `.settings-export.json.tmp` to it.
  3. `Session::new().settings().export_to(…/settings-export.json)`.

  Then a 0666 file planted at the temp name instead; then a link at the target itself; then the store's own file (`use_folder`, a link at `.settings.json.tmp`, `save_settings`).
- **Before** (red team): victim.txt held the settings JSON, the export was a link to it with mode 644, and the planted 0666 file gave a 0666 export.
  - With the old fixed-name write back (mutant m4): `victim "{ "format": "app-settings", … }"; export file false` (a link).
- **After:**
  - `link at temp name: victim "victim\n"; export file true mode 600`;
  - `0666 planted at temp name: export mode 600; planted kept "planted\n"`;
  - link at the target: replaced by a 0600 file;
  - `store's own file: file true mode 600`;
  - the victim was unchanged throughout.
- **Mutant m4:** `f_111_settings_export_follows_no_planted_link` FAILED (app_settings.rs:2058), and my harness FAILED.
- **Side check (new, for the lead):** `AppSettingsStore::check_writable` (app_settings.rs about lines 1185-1200), the Checker's "sibling", makes its probe at the fixed name `.app-settings-check` with create and truncate, so the open follows a link. Probe (copy only, `verify_e13s6g_extra.rs`): settings folder `use_folder(shared)`, a link `shared/.app-settings-check` to `victim.txt` ("victim, demo text"), then `check_writable()`. Output: `answer None; victim now 0 bytes ""; link left: false`. The linked file is emptied and the link removed.
  - This is the same vector as F-111 (anyone who can write a shared or synced settings folder the user picked) and the same harm class (another file overwritten), so I propose Medium, not Low.
  - It existed before part g; F-111's row covers `write_json` only.
  - Smallest fix, as the Checker said: `create_new` with a random suffix, as `storage::is_writable` does, and check the settings file by metadata and `open_regular` instead of `append(true)`.

## F-098: the command line tunes the KDF with a wall clock

- **Steps (the finding's own,** `f098.sh`):
  1. Release `app`, `HOME` isolated.
  2. 28 × `yes > /dev/null &` (PIDs 39408-39435) on this 14-core Mac.
  3. `printf 'demo-b06\ndemo-b06\n' | app db-create -q -p loadN.appvault`, 3 times.
  4. Stop the 28 by PID.
  5. Run idle `printf 'demo-b06\n' | app db-info -q loadN.appvault` under `/usr/bin/time -p`.
- **Before** (red team): 11 iterations, KDF 330-351 ms CPU.
  - With the wall clock back (mutant m6, PIDs 44653-44680): db-create wall 2.56-2.92 s against 1.02-1.29 s CPU; stored `30`, `30` and `39 iterations`; db-info CPU 1.05-1.28 s.
- **After:**
  - db-create wall 3.48-3.87 s against 1.52-1.69 s CPU, so the contention was real.
  - Stored `Argon2id, 64 MiB, 43 iterations`, `41 iterations` and `45 iterations`; db-info CPU 1.40-1.48 s.
  - The red team's idle default was 41 iterations, so load no longer weakens the KDF.
- **Callers.** `settings::tune` has one caller, app-cli `write_vault` (`db-create` and `import`), with `MEASURE_CLOCK = app_platform::macos::thread_cpu_time`. The only other benchmark caller, app-ffi wizard.rs:253, already used the thread CPU clock.
- **Mutant m6:** `f_098_kdf_tuning_clock_is_the_threads_cpu_time` FAILED (commands.rs:1437).

## F-112: the IMP-REMOTE import kind is listed

- **Steps.** Code read of `import::KINDS`, a grep for any other list of import kinds, and the tests.
- **Before:** `KINDS` held `Kind::Remote` (IMP-REMOTE).
- **After:**
  - `KINDS: [Kind; 6]` = Csv, OnePux, OpVault, Bitwarden, Proton, V1; `Kind::Remote` is kept in the enum (import/mod.rs:275 note).
  - A grep of app-ffi, app-cli and macos/App finds no IMP-REMOTE, no `Kind::Remote` and no use of `KINDS`; File > Import… is still a disabled item.
  - FEA-08.1 and check 08-01 say IMP-REMOTE is listed only once remote sync is built.
- **Mutant m7** (Remote in place of V1): `f_112_no_remote_vault_kind_is_listed` FAILED (fea08.rs:213) and `fea08_01_kinds` FAILED (fea08.rs:185).

## Lints and names

- **Rust.** `rustfmt --edition 2024 --check` passes on storage.rs, app05.rs, saving.rs, session.rs, folder.rs, commands.rs, import/mod.rs and fea08.rs. In app_settings.rs the only diffs are at lines 796, 803 and 836: part f's `note_keys`, not part g.
- **Swift.** `swift format lint --strict` and the project's swiftlint 0.65.1 `lint --strict` both exit 0 on Saving.swift, MainWindowModel.swift and SavingWatchTests.swift.
- **Names.** `scripts/check-names.sh` was run after this file was written (see the E13-S6 status line).

## For the lead

1. **F-101 and LD-225 (1).** Lock Everything (`asks: true`) still saves on the main thread. Behind a slow or stalled save it froze the window for 3.86 s, against 1.01 s for an automatic lock. The FIFO attack is closed on that path too. I agree with the builder and the Checker: accept for now. If the ruling is to hold to the letter, add a follow-up that runs Lock Everything's save in a Task (as `saveNow` does), then asks or locks.
2. **Accept the builder's known costs.**
   - A save the lock overtook keeps a vault copy and the key parts in Rust memory until it ends.
   - N stalled vaults wait N seconds.
   - A lock save queued behind a stalled save of the same vault takes no copy of its own.
   - With both save settings off, an automatic lock's `writeRecoveryCopy` waits on the save lock on the main thread.
3. **New finding (needs an F-number and an owner):** `check_writable` empties a file through a planted link at `.app-settings-check`. Proposed Medium. Proof and smallest fix are in the F-111 section.
4. **The Checker's other Lows.**
   - DiskWatch.swift:49 `O_EVTONLY` without `O_NONBLOCK`: not re-tested by me; Swift, not part g's file.
   - `ResourceBusy` counted for APP-05.14: confirmed by code read.

   Both need owners. The spec cards APP-02.15/.16 and APP-05 do not yet name the 1 s lock deadline, the up-front refusal or the F-110 lock.

## Clean-up

My folders `/tmp/e13s6g-verify-copy`, `-target`, `-tree-target`, `-dd`, `-run` and `-scripts` and my logs were deleted at the end. `ps` showed none of my processes. Nothing in `testdata/` was written.
