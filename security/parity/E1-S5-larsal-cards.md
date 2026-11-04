# E1-S5 Larsal cards: Verify

Story: E1-S5 Larsal cards, APP-01 to APP-11 (`spec/app/`).
Date: 2026-10-28. Role: Verify. I did not write or review these cards.
Read first: AGENTS.md, plan/team.md, the E1-S5 line in plan/epics.md, spec/README.md, E1-S5-wording-sweep.md, E1-S5-checker-sample.md (sample, fixes, re-read), spec/decisions.md LD-200 and the rows the cards cite (LD-47 to LD-55, LD-95 to LD-101, LD-155, LD-156, LD-168, LD-170, LD-174, LD-187, LD-193).

Reference access: the reference source (develop, commit 09e34ba8), the installed 2.7.11 bundle (Info.plist, `codesign`, `strings`, `nm`, `otool` only) and its command line tool, in a throwaway home under `/tmp/v-e1s5/` with demo files only. The reference window app was not started. Nothing touched the owner's clipboard, and no window was shown.

**Verdict: signed.** 37 of the 48 markers are resolved in the cards. The other 11 need Mac QA (owner's go). 20 of 20 spot checks pass. The built rules match the code, and 81 tests pass. Names PASS, and the sweep's results still hold.

## 1. The 48 "check with Verify" markers

Each card had its marker text replaced in place:
- a resolved marker now reads "Verified 2026-10-28, V-…: …", in our own words;
- an open marker now reads "needs Mac QA (owner's go), V-…: <reason>".

`grep -c -i "check with verify" spec/app/*.md` now gives 0 for every card. Only text inside the marker sentences changed. Each card keeps its line count and the number of cells on every line. Six more V-numbers appeared only in the "not checked" notes (V-A06-2 to -5, V-A08-3, -4). They are resolved too.

| V | Card place | How | Result |
|---|---|---|---|
| A01-1 | S-UI-11 | source (tray icon look, settings box) | Verified: an empty value becomes a light or dark monochrome variant chosen by dark mode, but on macOS the same mask image is always drawn; the box shows Monochrome |
| A01-2 | APP-01.9 | source (reset routine, action collection, start-up restore) | Verified: stored shortcuts are emptied; live actions keep their custom keys until the next start |
| A01-3 | APP-01.29 | source (shortcuts page) | Verified: the button resets live actions and drops pending edits; nothing is written unless a later edit is saved |
| A01-4 | APP-01.32 | source (shared groups page, its form) | Verified: the box starts checked and is never loaded; OK stores the box |
| A01-5 | settings file edge case | reference command line tool, its settings path pointed at demo files (see below) | Verified: bad lines are skipped, good keys before and after them are read, an unclosed quote is not used, no message, bad lines are dropped on the next write |
| A01-6 | APP-01.9 c | as A01-2 | Verified |
| A01-7 | APP-01.32 b | as A01-4 | Verified |
| A02-1 | APP-02.10 | source | Verified: the delayed lock has two callers only (minimized-state change, hide routine) |
| A02-2 | APP-02.15 step 2 | source (KDF on a worker with a nested event loop; lock returns "already locked" while the unlock form shows) | Verified |
| A02-3 | APP-02.15 step 4 | source (200 ms retry; quit needs all vaults locked) | Verified |
| A02-4 | APP-02 logout edge case | source for the question | **Mac QA**: whether macOS stops the logout takes a real logout |
| A03-1 | APP-03.9 / AT-D01 | none possible here | **Mac QA**: a third-party clipboard history app on the general pasteboard (AGENTS.md rule 10) |
| A03-2 | APP-03.10 | macOS 26.2 SDK `NSPasteboard.h` (`NSPasteboardAccessBehavior`, macOS 15.4) | Verified |
| A03-3 | APP-03.17 | source (`lower()` on the main window and the dialog), bundle (the toolkit's Mac plug-in has `orderBack:`, no deactivate), AppKit's documented order-back behaviour | Verified; not watched on screen |
| A04-1 | APP-04.13 | source (cancel returns success with no data; no empty-key guard before the KDF) | Verified |
| A04-2 | APP-04.1 | ad hoc probe on this Mac, demo item: add gives -34018, query gives -25300, nothing written | Verified, with a correction: a query alone cannot detect such a build |
| A04-3 | APP-04.5 | SDK `SecAccessControl.h` | Verified: `kSecAccessControlCompanion` from macOS 15, `kSecAccessControlWatch` deprecated, same bit |
| A04-4 | APP-04.7 | SDK `LAContext.h`, `LADomainState.h` | Verified: `domainState.biometry.stateHash` from macOS 15 replaces `evaluatedPolicyDomainState` |
| A05-1 | APP-05.11 | source (birth time since 2.7.0) and a command line tool run | Verified: the creation date became the save time |
| A05-2 | How learned | source (reload routine) | Verified: questions, buttons, Merge default, merge then save |
| A06-1 | APP-06 reference notes, ×2 | source (open routine, reader, key file and hardware key texts) | Verified |
| A06-2 | How learned | source (30,000 ms timer on hide and deactivation) | Verified |
| A06-3 | How learned | source (two Escape presses, 3,000 ms, main window only) | Verified |
| A06-4 | auto-open step 2 | already observed in Sprint 3; source call re-read | Verified |
| A06-5 | How learned | source (touch prompt only outside the main window) | Verified |
| A06-6 | APP-06.6 | none possible here | **Mac QA**: a person pressing Caps Lock while Larsal's field has focus |
| A07-1 | How learned | source (pages, no save panel, tab marked changed, where it measures) | Verified |
| A08-1 | APP-08.15, How learned | source (no swap turned off; its Meta means Control on Mac) and the bundled shortcut guide 2.7.11 ("substitute Ctrl with Cmd") | Verified |
| A08-2 | APP-08.22, How learned | source (hide sets the prohibited policy, show sets regular) | Verified, with a nuance: the reference uses "prohibited", Larsal uses "accessory" |
| A08-3 | How learned | hidden AppKit probe, see below | Verified: only the first ⌘C item in menu order ever runs |
| A08-4 | How learned | SDK `NSApplication.h`, `NSRunningApplication.h`, `NSImage.h`; built `main.swift` calls `setActivationPolicy` | Verified (API); the icon on screen goes with E5-S11 Mac QA |
| A08-5 | ⌃H edge case | none possible here | **Mac QA**: a focused field in a visible key window; the SSH agent item is not built yet |
| A09-1 | APP-09.3 | bundled toolkit library: disassembly of the parse-and-act routine, see below | Verified: version, then help, then long help |
| A09-2 | `open -a … --args` edge case | hidden background-only demo app, see below | Verified |
| A09-3 | request during unlock or dialog | source; Larsal test `app06_16_lock_during_unlock_drops_the_result` | Reference and Larsal's lock part verified; **Mac QA**: vaults added behind an open sheet in Larsal |
| A10-1 | APP-10.2 | none possible here | **Mac QA**: capture paths need a protected window on screen and Screen Recording permission |
| A10-2 | APP-10.11 | SDK notes say nothing about the secure field's own calls | **Mac QA**: a focused secure field in Larsal's key window |
| A10-3 | APP-10.12 | SDK `CarbonEventsCore.h` notes; probe killed with `kill -9` | Verified |
| A10-4 | Dock edge case | none possible here | **Mac QA**: a protected window minimized into the Dock |
| A10-5 | security note | as A10-1 | **Mac QA** |
| A10-6 | test method | probe, see below | Verified, with a correction: the field shows whether secure input is on, but its process id named another process, not the probe |
| A10-7 | APP-10.2-b | none possible here | **Mac QA**: a screen recording and a second user's screen sharing |
| A10-8 | APP-10.12-a | probe killed with `kill -9` | Verified: field gone |
| A11-1 | APP-11.6 | built app: `otool -L`, `nm -u`, Swift imports; E6-S4 Release bundle (runtime, no entitlements) | Verified |
| A11-2 | APP-11.6 | `project.pbxproj` (`CODE_SIGN_IDENTITY = "-"`, `ENABLE_HARDENED_RUNTIME = YES`); `codesign -dv` of the debug build | Verified |
| A11-3 | APP-11.8 table | bundled toolkit library: disassembly of the text buffer release | Verified: one direct `free` |
| A11-4 | APP-11.8 | bundled crypto library: `nm -u`, `strings`, disassembly of the pool-size routine | Verified |
| A11-5 | APP-11.10 | reference self-test source; E6-S4 libgcrypt match; Larsal self-test passes | Verified |
| A11-6 | APP-11.10 | `app11_10_the_whole_test_takes_under_10_ms` | Verified |
| A11-7 | DTrace edge case | none possible here | **Mac QA**: DTrace needs administrator rights |
| A11-8 | core dump edge case | three probes, see below | Verified: no dump without `get-task-allow` |
| A11-9 | APP-11.8-a | source (each memory table row) | Verified |

Count: 48 markers (APP-01 7, APP-02 4, APP-03 3, APP-04 4, APP-05 2, APP-06 3, APP-07 1, APP-08 4, APP-09 3, APP-10 8, APP-11 9). **Resolved 37; left for Mac QA 11:** V-A02-4, V-A03-1, V-A06-6, V-A08-5, V-A09-3 (Larsal part), V-A10-1, V-A10-2, V-A10-4, V-A10-5, V-A10-7, V-A11-7. Also for Mac QA, from V-A10-6: the APP-10 cases that expect "Larsal's process id" as the holder are to be confirmed with Larsal as the active app.

### Proof for the runs

**V-A01-5.** The reference command line tool reads the same settings file through the same routine. The override variables of its config routine pointed it at demo files. The configured language shows in its error text, which made a good probe.

```
HOME=/tmp/v-e1s5/home <settings path override>=/tmp/v-e1s5/cfg/<file> REF_CLI ls /tmp/v-e1s5/none.x
good file, Language=fr                                   -> French error text
bad line without "=" after the key (no version key)      -> French; the file was rewritten without the bad line
broken section header and a bad line before the good section       -> French; file not rewritten (version key present)
binary junk on the first line                            -> French; the junk was gone after the rewrite
Language="fr (unclosed quote)                           -> English (value not used)
broken section header after the good key                 -> French
```

**V-A04-2.** This used a probe with an ad hoc signature, `flags=0x20002(adhoc,linker-signed)`, and demo service `app.larsal.vault.verify-probe-e1s5`. The add printed `add: -34018`, and nothing was written. A query for a missing item printed `-25300` in both the file Keychain and the data protection Keychain.

**V-A05-1.**

```
REF_CLI db-create -p --decryption-time 100 v.vault      (demo password)
touch -t 202001010101 v.vault
before: birth=Jan  1 01:01:00 2020  inode=422340849
REF_CLI mkdir v.vault Demo                               exit 0
after:  birth=Oct 28 09:28:53 2026  inode=422340858
```

**V-A08-3.** This was a hidden AppKit probe with the prohibited policy: no window, no Dock icon, and no pasteboard use, since the actions only print. It had two menu items on ⌘C, Edit > Copy and then Entry > Copy Password.

```
Edit > Copy enabled:   ran: Edit > Copy           handled: true
Edit > Copy disabled:  (nothing ran)              handled: true
```

**V-A09-1.** `otool -tV` of the parse-and-act routine of the toolkit's command line parser, in the toolkit's core library in the bundle, shows three "is set" calls. Each one loads a static string. Read from the library, those strings are `'version'`, then `'help'`, then `'help-all'`. A call to the routine that prints the version follows the first.

**V-A09-2.** This used a background-only demo bundle. Its executable logs its arguments, shows nothing and quits after 12 s.

```
open -g Probe.larsal --args first          -> pid 31594 args ["first"]
open -g Probe.larsal --args --lock         -> nothing new
open -n -g Probe.larsal --args --lock      -> pid 31612 args ["--lock"]
```

Afterwards no probe process was left, and the bundle was unregistered from Launch Services (0 entries).

**V-A10-3, V-A10-6, V-A10-8.** Before the run, `ioreg -l -w 0 | grep -c kCGSSessionSecureInputPID` gave 0. Two probes then held secure input for about 1 to 4 s each: a plain one, then one with an app connection and no window.

```
probe pid 32361 enable: 0   holder while running: "kCGSSessionSecureInputPID"=1005
kill -9 32361               after: count 0
probe pid 34002 enable: 0   holder: "kCGSSessionSecureInputPID"=1005   after normal end: count 0
```

Pid 1005 is the system's alert process. It has a panel on screen at layer 8. That process started on 2026-10-17 and logged nothing during this session. So the field shows that secure input is on, but not which process holds it. The APP-10 test note now says so.

**V-A11-8.**

```
kern.coredump: 1   kern.corefile: /cores/core.%P   ulimit -c 0, -Hc unlimited
plain        flags=0x20002(adhoc,linker-signed)   exit 139   no core file
runtime      flags=0x10002(adhoc,runtime)         exit 139   no core file
runtime_gta  runtime + get-task-allow             exit 139   core file written (5839863824 bytes), deleted
```

I deleted the three crash reports these probes made (`plain-…`, `runtime-…`, `runtime_gta-… .ips`), and `/cores` holds 0 files. This contradicts one line of E6-S4-hardening.md (line 25): there, `sysctl` was read to mean that any process with a core limit above 0 can dump. On this Mac, a process without the debug entitlement did not dump. APP-11.2 is still needed as a second guard.

## 2. "Same as the reference" spot checks (20, weighted to the security cards)

Each check was read in the reference source or bundle, or run with its command line tool. **20 of 20 pass.**

| # | Card claim | Where checked | Result |
|---|---|---|---|
| 1 | APP-02.8: delay clamp(r, 1, 20); stale r after an early clear | tab container's delayed lock; clipboard clear does not reset its seconds | Pass |
| 2 | APP-02.10: Hide Larsal does not lock | two callers of the delayed lock | Pass |
| 3 | APP-02.11 step 1: every vault is tried even after a cancel | lock-all loop | Pass |
| 4 | APP-02.13: after a lock it switches to the first unlocked vault | the lock action is wired to the lock-and-switch slot | Pass |
| 5 | APP-02.15 steps 3, 4, 7: refuses while reloading; 200 ms retry while saving; editor question with Discard and Cancel, Cancel default | vault view lock routine | Pass |
| 6 | APP-03.9: concealed marker holds the value again; no transient marker; no current-host option | clipboard set routine and Mac pasteboard converter | Pass |
| 7 | APP-03.12: clears when the text is the same, whoever wrote it | clipboard clear routine | Pass |
| 8 | APP-03.13: a stored value of 0 or less clears at once; the screen allows 1 to 999 | clipboard set routine; security settings form (1, 999); default 10 | Pass |
| 9 | APP-03.11: bar at floor(100 × remaining ÷ N) | countdown status (integer division) | Pass |
| 10 | APP-04.4: AES-256-GCM, 32-byte key and 16-byte nonce, as hex text in the item | quick unlock save; cipher IV size table | Pass |
| 11 | APP-04.6: retries once without the biometry flag | quick unlock save wrapper | Pass |
| 12 | APP-04.13: a cancel runs the full KDF on an empty key | quick unlock read; unlock form; vault open | Pass |
| 13 | APP-06.5, APP-06.28, APP-06.15: 30 s clear; two Escape presses within 3 s; touch prompt only in the separate dialog | unlock form | Pass |
| 14 | APP-10.3: sets every top-level window on toggle and a window again on each focus change | main window | Pass |
| 15 | APP-10.6: its protect call cannot fail on macOS | Mac utilities return true | Pass |
| 16 | APP-10.10: on enable, disables first when its flag is on; on disable, always disables | Mac utilities secure input routine | Pass |
| 17 | APP-11.3 to 11.5: deny attach; steps chained, so a failed core limit skips it; one warning; release builds only | start-up routine | Pass |
| 18 | APP-11.6: runtime flag; entitlements only the application id and a Keychain access group | `codesign -dv` (`flags=0x10000(runtime)` on all three executables) and `codesign -d --entitlements` | Pass |
| 19 | APP-11.10: the same seven checks in the same order, plus a crypto library version check; fatal | crypto init; window app and command line tool callers | Pass |
| 20 | APP-05.11, APP-05.13: permissions kept, creation date not kept; failed save banner 15 s | command line tool run (V-A05-1); message widget long timeout 15,000 ms on the write failure | Pass |

Also confirmed along the way: APP-01.9's reset flow (Reset or Cancel, Cancel default; refused when the file cannot be written; the extra pages saved again), APP-01.11 (import keeps only roaming keys), and APP-11.8's memory table (V-A11-9).

## 3. Built cards match the code (APP-02, 03, 06, 09, 11)

`CARGO_TARGET_DIR=/tmp/v-e1s5-target` (deleted afterwards). The clipboard tests use private named pasteboards: `Session::new()` uses `Clipboard::private()`, and the tool tests set `LARSAL_TEST_PASTEBOARD`.

```
cargo test -p larsal-ffi --test session --test app09 --test clipboard --test messages
  app09 17 passed; clipboard 9 passed; messages 7 passed; session 11 passed
cargo test -p larsal-platform
  25 passed; 7 ignored (child helpers of other tests)
cargo test -p larsal-cli --test int10 int10_29
  9 passed; 105 filtered out
cargo test -p larsal-crypto --lib selftest
  3 passed
total 81 passed, 0 failed; 94 s wall
```

| Card rule | Code | Tests (passed, or read) |
|---|---|---|
| APP-02.3: idle limit 10 to 43,200 s; time asleep counts (LD-187) | `LockSettings.idle`; `ContinuousClock`; a wall-clock timer deadline | `t07t08`, `t09`, `t10`, `lateTimer` (read; the 22 `LockSignalsTests` passed under E6-S2's Verify) |
| APP-02.5 to APP-02.7: screen lock (delivered at once in the background), sleep, user switch | `LockSignals` observers `com.apple.screenIsLocked` with `.deliverImmediately`, `willSleepNotification`, `sessionDidResignActiveNotification` | `t12t13`, `t12Background`, `t14`, `t15`, `t01` (read) |
| APP-02.8 to APP-02.10: minimize or hide, clamp(r, 1, 20); lock on minimize off with minimize after unlock | `onMinimize`: `min(max(secondsLeft(), 1), 20)`; `didMiniaturize`, `didHide` | `t16` to `t20`, `t24`, `t25` (read) |
| APP-02.15 step 2: a lock during an unlock wins | `Session::lock` | `app06_16_lock_during_unlock_drops_the_result` (run) |
| APP-03.9, APP-03.10: one item, text plus empty concealed and transient markers, current host only; the count comes from the prepare; Larsal's old copy is cleared first | `larsal-platform/src/macos/pasteboard.rs` | `copy_writes_text_and_both_markers`, `refused_copy_leaves_nothing_of_ours` (run) |
| APP-03.11, APP-03.12: countdown; clear only while still ours | `clipboard.rs` | `countdown_clears`, `new_copy_restarts_countdown`, `clear_only_while_still_ours`, `countdown_leaves_newer_content`, `clear_stops_countdown` (run) |
| APP-03.1, APP-03.5, APP-03.15: copy actions incl. fingerprint; empty copies nothing; clear on lock, close, quit | `Session::copy_*`, `lock`, `close`, `clear_clipboard` | `app_03_copy_fields`, `app_03_copy_code`, `app_03_copy_fingerprint`, `app_03_5_empty_value_copies_nothing`, `app_03_15_*` (run) |
| APP-03.20: the command line tool uses the same routine | `larsal-cli` `clip` | `int10_29_a` to `_h` (run) |
| APP-06.18, APP-06.30: one message per error kind; MI07-01 for `NotPermitted`; no file text | `larsal-ffi/src/messages.rs` | `t39_app_06_18_every_kind`, `t40_*`, `t41_app_06_18_names`, `m06_texts_match_the_table`, `ld_101_security_key_wording`, `app06_unlock_messages` (run) |
| APP-09.3, .9 to .13, .16, .27 | `instance.rs`, `cli.rs`; `NOT_RUNNING` holds the new M09-04 text | `app09_3_b_version_wins_over_help`, `app09_11_a_*`, `app09_13_abc_channel_limits`, `app09_16_*`, `app09_27_*` and the rest of `app09` (17, run) |
| APP-11.2 to APP-11.5: core limit 0, then deny attach, each whatever the other did; debug builds skip them | `larsal-platform/src/hardening.rs`, `macos/process.rs` | `app11_2_core_limit_is_zero_and_cannot_be_raised`, `app11_3_deny_attach_refuses_ptrace_attach`, `app11_4_a_failed_core_limit_still_denies_attach`, `app11_5_harden_follows_the_build_kind` (run) |
| APP-11.9: key pages locked; refused lock goes on with one warning; zeroing allocator | `macos/memory.rs` | `app11_9_b_locked_pages_are_wired_until_the_last_guard_drops`, `app11_9_refused_lock_goes_on_with_one_warning`, `freed_blocks_are_zero` (run) |
| APP-11.10: nine checks in order, under 10 ms | `larsal-crypto/src/selftest.rs` | `app11_10_d_every_check_passes`, `app11_10_each_wrong_answer_stops_the_run_at_that_check`, `app11_10_the_whole_test_takes_under_10_ms` (run) |

These APP-06 texts are not in the code yet: M06-31 to M06-36 and M06-38 to M06-40 (key file checks, the empty-password retry, touch, key search, newer minor version, auto-open, purpose texts). These are screen parts of E5-S3 that are still to be built. They are not mismatches. M06-37 (Caps Lock) is in `UnlockView.swift`.

## 4. Text

- `bash scripts/check-names.sh`: `names: PASS (2748 files scanned, 15 vault files name-only)`, exit 0, run after the card edits.
- The sweep's overlap script (`/tmp/e1s5/check.py`, outside this folder) gave the same hit counts before and after my edits. Those counts are 2 exact runs of 6 or more words, 3 runs of 5 words and 9 near sentences, the same set the sweep kept (mockup hits, the time format and generic phrases).
- Its long-line check (`local.py`) found 16 hits. The only one on a line I changed is the generic "did not finish in time" in APP-02's logout row, which the sweep had already kept. My added text is our own words. It quotes no reference string.

## Open, not blocking

- The 11 Mac QA items above. Each needs the owner's go, because it runs on the owner's screen or session or needs administrator rights.
- APP-10's test cases that expect "Larsal's process id" (APP-10.8-a, -c, -e, APP-10.9-a, APP-10.13-a) should read presence or absence, or `IsSecureEventInputEnabled()` in a test build, until Mac QA confirms the id with Larsal active (V-A10-6). E6-S5 builds from this card.
- E6-S4-hardening.md line 25 reads `kern.coredump` as "a process with a core limit above 0 can dump". V-A11-8 shows that a process without `get-task-allow` did not dump on this Mac. This needs a one-line note there, for the lead. The file was not edited.

## Files changed

- `spec/app/APP-01` to `APP-11`: 50 in-place replacements of the marker sentences, and one note in APP-10's "How this was learned".
- `security/parity/E1-S5-larsal-cards.md` (this file).
- `plan/epics.md`: the E1-S5 status line.

CPU: about 10 minutes in total. The longest single run was the cargo build and tests, 94 s wall. The rest were small probe builds of a few seconds each, two overlap script runs and one disassembly. No run came near 30 minutes. No check.sh, no git, and no helper agents were used.
