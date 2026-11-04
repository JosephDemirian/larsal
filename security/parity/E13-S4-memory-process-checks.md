# E13-S4 Memory and process checks on a release build (AT-C01 to AT-C06)

Story: E13-S4. Rows: AT-C01 to AT-C06 in [attacks-and-checks.md](../../plan/attacks-and-checks.md). Security rows: SR-05, SR-07 in [security.md](../../plan/security.md). Earlier proof, on debug builds, kept as history only: [E6-S6](E6-S6-memory-hygiene.md), [E6-S4](E6-S4-hardening.md).
Date: 2026-10-29, 20:38 to 21:35.
Role: Verify. I did not build any of this and I fixed nothing. I did not open the reference source or run the reference app.
Result: **signed.** All six rows pass on release builds. The parts that need a visible window, a debugger prompt or a crash dialog are listed for Mac QA (with the owner's go). No new finding. The known Low F-059 (the command line tool's stdout buffer) still shows on the release tool. It is open and accepted by the lead, so it does not block.

## Summary

| Row | Method | Result |
|---|---|---|
| AT-C01 Secrets after lock | Release-profile copy that only drops the attach denial. An in-process dumper wrote every resident page, before unlock, while unlocked, and after lock. It ran in the `app` tool and in a release test host of app-ffi that drives `Session` as the Mac app does. 12 dumps were searched for 12 needles in 4 forms each. | **Pass.** After lock: 0 hits in the tool and 0 in the host. That covers the master password, both entry passwords, user name, notes, URL, `P`, `C`, `T`, `K_enc`, `K_mac` and the stream key. `P`, `C`, `K_enc`, `K_mac` and the stream key were never found, even while unlocked. The one exception is F-059 (known, Low, accepted): after `show -a Password` then `close`, the value is still there once. |
| AT-C02 Secret after Hide | Same host: Show, then a dump. Hide and switch entries, then a dump. Copy (private pasteboard), then a dump. Clear, then a dump. Lock, then a dump. | **Pass.** The entry password count goes 2 (shown), then 1 (hidden), then 2 (copied), then 1 (cleared), then 0 (locked). The one copy left while unlocked is the decrypted vault, which SR-07 expects. |
| AT-C03 Debugger and core dumps | ptrace attach probe against the shipped release `app` (vault open), the release host with shipped hardening (vault unlocked) and the Release `App.app` (started hidden with `open -g -j`). The copy is the control. Core limit read inside the process. Forced SIGSEGV of the release tool in its own crash folder, with a control that does write a core. | **Pass.** Attach gives `-1 16 true` (EBUSY plus SIGSEGV) in all three. The copy gives `-1 1 false` (EPERM). Core limit goes from unlimited to `0/0`. The forced crash writes no core, even when re-signed with `get-task-allow`. The control with `get-task-allow` wrote a 5.8 GB core. |
| AT-C04 Crash reports | A real panic in the shipped release `app` with a vault open (stdout closed, then `help` → `print!` panics). Explicit panics in the release host with the vault unlocked, once with a shown value held. Only reports whose pid is mine were read. | **Pass.** 5 reports (3 panics, 2 SIGSEGV), all mine by pid. 0 needles in text, hex or register values. The panic messages on stderr hold no secret. |
| AT-C05 Swap | Wired bytes from outside (`proc_pid_rusage`). Per-region `user_wired_count` in the dumps. `cargo test --release` of app-ffi `key_pages` and `memory`. | **Pass.** Wired bytes are 0 at start, 16,384 or 32,768 while unlocked, and 0 after lock or close. The unlocked dumps show the master password and `T` in wired pages. The locked dumps have 0 wired regions. 3 release tests pass, among them `ulimit -l 0`. |
| AT-C06 Logs | `log stream --level debug` (the highest level) for my binaries only. Then `log show --info --debug` with a predicate on my 33 PIDs and my binaries. A broad QA run of the release tool (15 commands), the host flows and the Release App start-up. | **Pass.** 119 streamed events and 15 persisted events, from 3 of my processes. 0 needles. 28 stderr and log files: 0 needles. The tool writes nothing to the system log. |

## Setup

- **Snapshot.** At 20:39:37: `rsync -a --exclude /target --exclude /fuzz --exclude /app-shots --exclude /.claude --exclude /macos/AppCore/Generated` of the project into `/tmp/e13s4-src`. Its `target` links to `/tmp/e13s4-target`.
  - The first copy, at 20:38:54, caught `app-ffi/src/edit.rs` mid-edit. The re-sync 20 s later printed `crates identical`.
  - `vendor`, `macos`, `scripts`, `testdata`, `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml` were identical.
- **SHA-256 (first 16 hex digits) of the files under test:**
  - `app-platform/src/hardening.rs` 3d66e42cda450a1c
  - `macos/process.rs` 7f6f61efe24282dd
  - `macos/memory.rs` ec6b504d580e0ce9
  - `memory.rs` 7b3b6f0ac5ae0e0a
  - `app-ffi/src/lib.rs` 4c5a3729b365163a
  - `session.rs` 1bda6de4ae34692f
  - `views.rs` 6d0777189cb9bc0a
  - `edit.rs` 12f51e9f3d922346
  - `start.rs` 693dbab442623ca3
  - `app-cli/src/main.rs` 2d65352e2216ae8b
  - `vault.rs` ce5e0be22eb63823
  - `term.rs` 515d7268307792ba
  - `shell.rs` 0426e4b2f2265e94
- **Release builds (shipped code), in the snapshot:**
  - `CARGO_TARGET_DIR=/tmp/e13s4-target cargo build --release -p app-cli`: `Finished release ... in 6m 26s`.
  - `scripts/build-core.sh --release`: `build-core (release): target/app-core/AppFFI.xcframework ...`.
  - `xcodebuild -project macos/App.xcodeproj -scheme App -configuration Release -destination platform=macOS -derivedDataPath /tmp/e13s4-dd build`: `** BUILD SUCCEEDED **`.
  - `app --debug-info`: `Build type: release`.
- **Release test host, in the snapshot only.** `crates/app-ffi/examples/e13s4_host.rs` exists only in my copies, never in the project tree. It calls `app_platform::hardening::harden()` first, as `start::start` does. Then it drives `Session::new()` (private pasteboard): `open`, `unlock`, `list`, `show_field`, drop (Hide), `entry` of the other entry, `copy_field`, `clear_clipboard`, `lock`, `close`, and `panic!` on request.
  - It reads the master password from a file into a heap `String`, as Swift hands one over.
  - Built with `cargo build --release -p app-ffi --example e13s4_host`: release profile, LTO, `panic = "abort"`, symbols stripped.
- **Attach-allowed copy (AT-C01, AT-C02).** `/tmp/e13s4-copy` is an rsync of the snapshot, with its own target `/tmp/e13s4-copy-target`. It has exactly one change: in `hardening.rs`, `apply(macos::core_dumps_off, macos::deny_debugger)` became `apply(macos::core_dumps_off, || Ok(()))`. `diff -r` of the crates shows only that line.
  - Same release profile.
  - `nm -u`: the shipped `app` and host import `_mlock _munlock _ptrace _setrlimit`. The copy's import `_mlock _munlock _setrlimit`, so only the deny call is gone.
- **Demo vault.** `v13.appvault` was made with the shipped release tool: `db-create -p -t 200`, then `add -u … --url … --notes … -p` for `Vfy13Bank` and `add -p` for `Vfy13Other`.
  - Every value carries the marker `e13s4-`: master password, two entry passwords, user name, notes, URL.
  - The values were given only through stdin or files under `/tmp/e13s4-work/v` (mode 600), never as program arguments of a dumped process.
- **Derived keys.** A scratch test in the snapshot's `app-format/tests` (`e13s4_keys.rs`, deleted with the copy) ran in its own process. It printed `P`, `C`, `T` (32 bytes each), `K_enc` (32), `K_mac` (64) and the stream key (64).
  - It used `read_header`, `password_part`, `composite_key`, `kdf::assess`/`derive`, `final_keys` and `open_payload`.
  - Cross-check: `sha256(master password) == P` printed `True`.
- **Needles.** 12 in all: 6 text values as UTF-8 and UTF-16LE, and 6 keys as raw bytes, first 16 bytes, and hex in lower and upper case. For logs and reports there were 3 more texts from the QA run (new entry password, new master password, estimate input) and the testdata demo passwords.
- **Probes,** written in `/tmp/e13s4-work/probe`. Product code was not changed.
  - **`dumper.dylib`,** loaded with `DYLD_INSERT_LIBRARIES`. The release tool and host are linker-signed without the runtime flag, so it loads. A thread waits for a request file. It walks `mach_vm_region_recurse` on its own task and writes every page that `mincore` reports, of every readable region that is writable or not file-backed. It also writes an index (region, VM tag, `user_wired_count`, process wired bytes).
  - **`search.py`** searches each dump outside the read-only pages of the arm64 shared library cache (0x180000000 to 0x300000000, not writable). Those pages are the same in every process. It searched 42 to 131 MB per dump, of 1.6 to 1.8 GB.
  - **`attach`** (ptrace `PT_ATTACHEXC`, SIGSEGV handler), **`wired`** (`proc_pid_rusage`), **`corelimit.dylib`** (`getrlimit` at load and 1.5 s later).
  - **`regcheck.py`** compares every register value in a crash report with the needles: little-endian bytes, trailing zeros cut, at least 4 bytes.
  - **Self-tests.** A planted file gave `HITS T/first16=1 T/raw=1 entry_pw/utf16=1 master_pw/utf8=1`. A synthetic two-region dump gave the hit with its address in the kept region only. A planted register gave `HITS T:0x9cf66465bcc524f9`.
- **Mac settings:**
  - `sysctl`: `kern.coredump: 1`, `kern.corefile: /cores/core.%P`.
  - `launchctl limit core`: `core 0 unlimited`.
  - Shell: `ulimit -c` 0, `ulimit -Hc` unlimited.
  - `DevToolsSecurity -status`: `Developer mode is currently disabled.`
  - `/cores` held 0 files before and after.
  - Tools: macOS 26.6 (25G5057c), rustc 1.99.1, Python 3.9.6.
- **Owner's session (rule 10).** No window, no screen capture, no general pasteboard.
  - The release tool was never given `clip`. The host's `copy_field` goes to `Session::new()`'s private pasteboard.
  - App was started only with `open -g -j -n` and stopped at its standard-input read, before any window.
  - Nothing was attached with lldb (developer mode is off, so it would show the authorization prompt).
  - App was never crashed (crash dialog).
- **Rule 11.** Every process was started by my scripts and ended by `exit` on stdin, by its own crash, or by `kill` of its PID. Afterwards, `pgrep -f e13s4` printed nothing.

## 1. AT-C01: secrets after lock

**Tool,** the attach-allowed copy. `driver.py cli`: `app open v13.appvault`, then the password on stdin, `show -s Vfy13Bank`, `show Vfy13Bank`, a dump, `close`, a dump, `exit`. The attach probe ran while unlocked: `attach -1 1 false` (EPERM, no deny, as intended).

```
start wired 0
after unlock wired 16384
dumped unlocked pid 7150 wired 32768
after close wired 0
dumped locked pid 7150 wired 0
start-7150.bin:    45,072,384 searched, no needle
unlocked-7150.bin: 116,916,224 searched, HITS T/first16=1 T/raw=1 entry_pw/utf8=1 master_pw/utf8=1 notes/utf8=1 other_pw/utf8=1 url/utf8=1 username/utf8=1
  master_pw 0x1052cfb00 in 1052cc000-1052d0000 prot=3 tag=7 user_wired=1
  T         0x9a7002d60 in 9a7000000-9a7004000 prot=3 tag=2 user_wired=1
  field values in 1052d0000-1056b4000 tag=7 user_wired=0 (the decrypted vault)
locked-7150.bin:   116,932,608 searched, no needle
```

**Host,** the attach-allowed copy. `driver.py host`: the `locked` dump after `lock`.

```
unlocked-8090.bin: HITS T/raw=1 entry_pw/utf8=1 master_pw/utf8=1 notes=1 other_pw=1 url=1 username=1
  master_pw 0x1026d3e00 and T 0x1026d3f90 in 1026d0000-1026d4000 tag=7 user_wired=2
locked-8090.bin: 131,563,520 searched, no needle
```

- **Never present in any dump:** `P`, `C`, `K_enc`, `K_mac` and the stream key, in any form, even while unlocked. `T` and the kept master password appear only while unlocked, and only in wired pages.
- **F-059, still present (known Low, open, accepted by the lead 2026-10-28).** `driver.py cli2` ran `show -a Password Vfy13Bank`, then `close`. The `locked2` dump holds the entry password once, at `0x1058dfba0` (MALLOC_TINY). It is preceded by 32 zero bytes and followed by `0a 00…`: the value plus newline at the start of Rust's stdout line buffer, exactly as F-059 describes.
  - It is a value the user asked the tool to print. The Mac app's host has no such copy.
  - Not a new finding. The F-059 fix in E13-S6 should be re-checked with this run.

## 2. AT-C02: secret after Hide

Host (pid 8090), dumps after each step. The counts are hits for the Bank entry password (UTF-8). Every other form gave 0.

```
unlocked: entry_pw=1   (0x1026d81b0, the decrypted vault)
shown:    entry_pw=2   (+ 0x1026d4050, the String returned by show_field)
hidden:   entry_pw=1   (after drop and entry(Vfy13Other): the shown copy is gone)
copied:   entry_pw=2   (+ 0x1026dc3f0, the Copy path)
cleared:  entry_pw=1   (after clear_clipboard: the copy-path block is gone)
locked:   no needle
```

Pass at the Rust and FFI level. The Swift view layer (the shown text field, the secure unlock field) needs a visible window, so it goes to Mac QA.

## 3. AT-C03: debugger and core dumps

**Attach to release builds.** The probe binary is unentitled and ad hoc signed.

```
shipped release app, vault open (pid 10657):        attach -1 16 true | alive after attach: True
shipped-hardening host, vault unlocked (pid 91570): attach -1 16 true | alive after: True
Release App.app, open -g -j -n --stdin <fifo> ... --args --password-stdin v13.appvault (pid 90545):
  ps: S /private/tmp/e13s4-dd/Build/Products/Release/App.app/Contents/MacOS/App --password-stdin ...
  stdout so far: 'Vault password: '
  attach: attach -1 16 true | alive after attach: True S | stderr: '' | ended by kill -KILL 90545
control, attach-allowed copy (pids 7150, 8090):      attach -1 1 false
```

- **Release `App.app`:** `flags=0x10002(adhoc,runtime)`, no entitlements, imports `_mlock _ptrace _setrlimit`, 0 `APP_TEST` strings.
- **stderr empty:** no M11-01, so both hardening steps succeeded.

**Core limit.** The `corelimit.dylib` probe, in the shipped release `app` started with RLIMIT_CORE unlimited/unlimited:

```
loaded core soft=9223372036854775807 hard=9223372036854775807
after-start core soft=0 hard=0
```

**Forced crash in its own folder** (`crash_watch.py`). The binaries were copied into `/tmp/e13s4-crash`, which is also the cwd. Core limit unlimited. `kill -SEGV` by PID.

- **The release tool needs two signals.** The first `kill -SEGV` is taken by Rust's stack-overflow handler, which resets to the default action and returns, because there is no faulting instruction. The process stays alive (a 240 s watch confirmed it; it was then ended with `kill -KILL`). So the run sends a second one.

```
e13s4cli (cmp-identical to the shipped release app), vault open, pid 39383: exit -11 | /cores/core.39383 exists: False | core files in crash folder: []
e13s4cli-gta (same, re-signed with get-task-allow), pid 39683:             exit -11 | /cores/core.39683 exists: False | []
control e13s4ctrl (C, no limit change, no entitlement), pid 18602:          exit -11 | /cores/core.18602 exists: False
control e13s4ctrl-gta (same C, get-task-allow), pid 18777:                   exit -11 | /cores/core.18777 exists: True size 5839863824
```

- **What the controls show.** On this Mac a core is written only for a process with `get-task-allow`. Even with that entitlement, App's release tool writes none, because of its 0/0 limit.
- The control core was deleted at once (`rm /cores/core.18777`). `/cores` is empty again.

## 4. AT-C04: crash reports

- **Release tool, a real panic with a vault open** (pid 40910). The run unlocks, prints `show -s Vfy13Bank`, then the reader of stdout is closed, and the shell command `help` (`print!`) panics:

```
thread 'main' panicked at .../std/src/io/stdio.rs:1168:9:
failed printing to stdout: Broken pipe (os error 32)
exit -6 pid 40910
```

- **Release host** (shipped hardening), `panic!` with the vault unlocked (pid 92362), and with the shown value held in a live variable (pid 92524): `exit -6` each. stderr: `E13-S4 forced panic with a vault open` and `... with a shown value held: 21` (the length only).
- **Reports read.** Only `~/Library/Logs/DiagnosticReports/e13s4*` (the names are unique to my binaries), each checked by its `pid`. They were written 2 to 5 minutes after the crash.

```
e13s4cli-2026-10-29-205823.ips      pid 40910 EXC_CRASH SIGABRT asi "abort() called"
e13s4host-2026-10-29-210746.ips     pid 92362 EXC_CRASH SIGABRT asi "abort() called"
e13s4host-2026-10-29-210743.ips     pid 92524 EXC_CRASH SIGABRT asi "abort() called"
e13s4cli-2026-10-29-205823.000.ips  pid 39383 EXC_CRASH SIGSEGV
e13s4cli-gta-2026-10-29-205830.ips  pid 39683 EXC_CRASH SIGSEGV
search.py (all needles, all forms): no needle in each of the 5
regcheck.py: 37 or 38 register values per report, no needle bytes in any
stderr of the three panics: no needle
```

- **App.app not tested here.** A forced crash of `App.app` would show the system crash dialog. It goes to Mac QA.

## 5. AT-C05: key pages locked

| Process | Start | Unlocked | After lock or close |
|---|---|---|---|
| Shipped release `app` (pid 47041) | 0 | 16,384 | 0 |
| Shipped-hardening host (pid 91570) | 0 | 16,384 | 0 (lock), 0 (close) |
| Copy `app` (pid 7150): dump index | 0 | 32,768; 2 regions `user_wired=1` (master password page, `T` page) | 0; 0 wired regions |
| Copy host (pid 8090): dump index | 0 | 16,384; 1 region `user_wired=2` (master password and `T` in one page) | 0; 0 wired regions |
| Release `App.app` at its password read (pid 90545) | 0 | Mac QA | n/a |

`CARGO_TARGET_DIR=/tmp/e13s4-target cargo test --release -p app-ffi --test key_pages --test memory -- --nocapture --test-threads=1` printed:

```
test app11_9_b_key_pages_are_wired_while_the_vault_is_unlocked ... unlocked, password only: 32768 bytes wired (page 16384)
unlocked, password and key file: 32768 bytes wired
test app11_9_refused_locks_still_unlock_with_one_warning ... ok
test result: ok. 2 passed; 0 failed; 1 ignored
test the_linked_core_zeroes_freed_blocks ... ok
test result: ok. 1 passed; 0 failed
```

## 6. AT-C06: logs

- **Stream.** `log stream --level debug --style ndjson --predicate 'processImagePath CONTAINS "/e13s4-"'` ran from 20:47:24 until after the last run. Only my binaries live under those paths.
  - 119 events in all: 60 Debug, 48 Info, 8 Default, 3 activities.
  - They came from 3 processes, all mine: host 91570 and host 8090 (pasteboard, defaults, launch services; one CFBundle line naming the binary's folder) and `App` 90545 (one activity, "Membership API: translate identifier").
  - The release tool processes log nothing to the system log.
- **Persisted.** `log show --info --debug --style ndjson` over the same window, with `processID IN {33 PIDs of mine} AND (processImagePath CONTAINS "/e13s4-" OR (processID == 90545 AND processImagePath ENDSWITH "/xpcproxy"))`. The image-path part is needed because the PID list alone matched other processes that later reused those numbers; those lines were deleted unread. Result: 15 events from 90545 (App and its launch through xpcproxy), 91570 and 8090.
- **QA run of the release tool,** all at `RUST_LOG=trace RUST_BACKTRACE=full`: `db-info`, `search`, `ls`, `show`, `edit -p` (new entry password), `show -s --all`, `mkdir`, `mv`, `rm`, `generate -L 24`, `estimate` (password on stdin), `db-edit -p` (new master password), `ls` with the new password, `ls` with the old one (`exit=1`, "Wrong password, key file or security key."), `db-info`. That covers 15 processes.
  - Before that, the shell and host flows of sections 1 to 5, and the Release App start-up.
- **Search.** `logstream.ndjson` (117,344 bytes), `logshow.ndjson` (12,678 bytes) and 28 stderr, driver and build logs all gave `no needle`, for all 15 demo values and 6 keys in every form. The testdata demo passwords (`demo-pass-1`, `demo-pass-2`, `demo-pass`, `demo-bank-1`, `demo-entry-pass`, `demo-pw-0`) were not found in the logs, the test log or the build logs either.
  - Only expected files hold demo values: the stdout of `show -s`, which prints on purpose, and the scratch key log that made the needles.

## Tree changes during the check

At 21:30 the project tree had moved on from my snapshot:

- `app-ffi/src/edit.rs` (rustfmt of tests only)
- `app-cli/src/vault.rs` and `commands.rs` (title masking, F-066)
- `app-platform` (`folder.rs`, `signals.rs`)
- `app-crypto/tests/ssh_wipe.rs`, `app-core`
- `macos/App/Platform/ShownPasswordField.swift`

These are E13-S6 and E5-S11 work. `hardening.rs`, `macos/process.rs`, `macos/memory.rs`, `memory.rs` and `app-ffi/src/lib.rs` were unchanged, as was the whole of `app-format`. No result here depends on the changed lines, so I did not rerun.

## Mac QA (with the owner's go)

1. **lldb on the real Release `App.app`.** Attach and dump after typing in the secure unlock field, Show, Hide, an entry change and lock (AT-C01 and AT-C02 at the view level). Developer mode is off, so lldb would show the authorization prompt.
2. **lldb attach form of AT-C03** on the Release App and the release tool. Expect it to be refused.
3. **Forced crash or panic of the Release `App.app` with a vault open** (AT-C03 crash half, AT-C04). Check no `/cores/core.<pid>` and read its report. This shows the crash dialog.
4. **Wired bytes of the unlocked Release `App.app`** (AT-C05 in the real app). Unlock needs the window.
5. **The window flows of `App.app` at debug log level** (AT-C06 for the screens).

## Clean-up and CPU

- **Deleted:**
  - `/tmp/e13s4-src`, `/tmp/e13s4-copy`, `/tmp/e13s4-target`, `/tmp/e13s4-copy-target`, `/tmp/e13s4-dd`, `/tmp/e13s4-crash` and `/tmp/e13s4-work` (dumps, vault, needles, probes);
  - the control core;
  - my 7 `e13s4*` crash reports.
- **Unregistered:** the Release bundle from Launch Services (`lsregister -u`) before deleting it.
- **Left alone:** the per-user instance lock and socket files of the release App name. App's next start takes them over.
- **Processes:** none of mine left. The log stream (pid 8618) and the first search (pid 9286, stopped for its CPU cost and rerun on the non-shared pages) were ended by PID.
- **CPU:** about 25 minutes in total. The largest single run was the release tool and core build: 424 s user over 16 min wall. No run was over 30 minutes.
