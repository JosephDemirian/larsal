# E6-S6 Memory hygiene (SR-07; AT-C01, AT-C02, AT-C04, AT-C05, AT-C06)

Story: E6-S6 Memory hygiene. Card: [APP-11](../../spec/app/APP-11-hardening.md) (APP-11.9). Decisions: LD-133, LD-193 (and LD-199 (3), which came in during this check).
Date: 2026-10-28.
Role: Verify. I did not build or review this story. I opened the reference source once, read only, to see how it keeps the password part (section 3).
Result: **signed** (rerun at 08:56 on the tree with the F-058 fix; see Rerun below). The first pass at 08:30 found F-058 (Medium): the master password that a session keeps for saving was not held in page-locked memory. Both holders now lock it, and the rerun proves it. F-059 (Low) stays open, and the lead accepts it.

- **After lock: nothing is left.** I dumped the memory of the debug `app` shell and of a Swift session after lock. Neither dump held the master password, a field value, `P`, `C`, `T`, `K_enc`, `K_mac` or the stream key. One case is the exception: the command line keeps the last line it printed (F-059, Low, section 1.3).
- **After Hide (AT-C02):** the Swift copy of the Show value is gone. While the vault stays unlocked, the decrypted vault in Rust still holds the value, as it should. A 23-byte copy from the Copy path stays until the 10-second clipboard clear.
- **Crash (AT-C04):** the release `app` has a core limit of 0/0 after start-up.
- **Key pages (AT-C05):** while a vault is unlocked, 16,384 bytes are wired: one page, the one that holds `T`. After lock or close, the wired count goes back to 0, in the tests and in my own check on the running `app`. Under `ulimit -l 0`, unlock still works, writes one M11-01 and wires 0 bytes.
- **Logs (AT-C06):** I read 101,272 lines of system log (144 of them from `com.app.desktop`) and every test log. None held a demo secret.
- **Allocator (F-034, F-042, F-048, F-053):** all five scenarios pass. With the zeroing allocator removed in a scratch copy, all five fail. **Verified.**
- **Swift view state:** after Hide it holds no protected value, and after lock it holds no string with a demo value.
- **Tests:** `cargo test -p app-platform -p app-format -p app-ffi -p app-cli` gave 1047 passed, 0 failed, 24 ignored.

## Setup

- **Isolated copy.** Another agent was working in the project tree (an E8-S2 run with its own target). So I made a copy at 08:30:02 with `rsync -a --exclude /target --exclude /fuzz/target --exclude /app-shots` to `/tmp/v-e6s6-src`. Its `target` links to `/tmp/v-e6s6-target`. I set `CARGO_TARGET_DIR=/tmp/v-e6s6-target` and used `-derivedDataPath /tmp/v-e6s6-dd`.
  - Right after the copy, `diff -rq` printed `identical` for `crates`, `vendor`, `macos`, `scripts` and `testdata`. `cmp` matched `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml`.
- **Tree changes during the check.** At 08:47, these were still identical to my copy: `app-platform`, `app-format`, `app-cli`, `app-core`, `app-model`, `vendor`, `scripts` and `testdata`.
  - `app-ffi` (`edit.rs`, `session.rs`, `views.rs`, `start.rs`, `API.md`), `app-crypto` (`ssh.rs`) and some Swift screens had changed. That is E5-S5 work (LD-199).
  - `app-ffi/src/lib.rs`, which installs the allocator, was unchanged.
  - The `edit.rs` change matters here: it adds `password_pages` to `Saver` (section 3).
- **SHA-256 (first 16 hex digits) of the files I verified:**
  - `app-platform/src/memory.rs` 7b3b6f0ac5ae0e0a
  - `app-platform/src/macos/memory.rs` ec6b504d580e0ce9
  - `app-format/src/keys.rs` f46a20c4e0510504
  - `app-ffi/src/lib.rs` 9c20fd7c90d8e23a
  - `app-ffi/src/edit.rs` 2084551053933ef4 (the copy, before LD-199 (3))
  - `app-cli/src/main.rs` 88e914776f743270
  - `app-cli/src/term.rs` 515d7268307792ba
  - `app-cli/tests/memory_hygiene.rs` d21ed7f79e283645
  - `app-ffi/tests/key_pages.rs` 1fb1342dd31859cb
- **Builds, all in the copy:**
  - `cargo build -p app-cli`
  - `cargo build --release -p app-cli`
  - `scripts/build-core.sh`, which printed `build-core (debug): target/app-core/AppFFI.xcframework ...`
  - `xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/v-e6s6-dd build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`, which printed `** TEST BUILD SUCCEEDED **`
- **Tools:** cargo and rustc 1.99.1, Xcode 27.0, macOS 26.6, Python 3.9.6. `sysctl` showed `kern.coredump: 1` and `kern.corefile: /cores/core.%P`, and `/cores` held 0 files before and after.
- **Demo vaults.** I made two, with the debug `app`, using unique demo values:
  - `v6.appvault` was made with `db-create -p -t 200` and `add -u … --url … --notes … -p … Vfy6Bank`. Its master password, entry password, user name, notes and URL all start with `vfy6-`.
  - `v6b.appvault` is a copy of `v6.appvault` plus a second entry, `Vfy6Other`, with its own `vfy6-` password.
  - The master password is the same in both. It was only ever typed in through stdin pipes. The vaults live in `/tmp/v-e6s6-work`.
- **Derived keys.** A scratch integration test in the copy's `app-format/tests` printed `P`, `C`, `T`, `K_enc`, `K_mac` and the stream key of each vault. It used `read_header`, `password_part`, `composite_key`, `kdf::assess`/`derive`, `final_keys` and `open_payload`. I deleted it after each run.
  - Cross-check: `P` begins `6dc839bad6a2656f1ff01ad0`, and `shasum -a 256` of the password gives the same digits.
- **No windows, no general pasteboard (AGENTS.md rule 10).**
  - The command line ran with `APP_TEST_PASTEBOARD=1`, which means the private named pasteboard.
  - The Swift checks ran as model-level tests in the xctest runner. AppTests has no host app, so there was no window. They used `Session()`, which copies to a private pasteboard.
  - Every `app` process was started by my scripts and ended by `exit` on its stdin, or by `kill -KILL <its pid>` (rule 11). Afterwards, `pgrep -fl v-e6s6` printed nothing.

### How the dumps were made

- **Not lldb.** `DevToolsSecurity -status` printed `Developer mode is currently disabled.` So an lldb attach would put the system's developer-tools authorization prompt on the owner's screen. I skipped it, and also `gcore` (debugger entitlement). The lldb run of the real `App.app` goes to Mac QA.
- **What I used instead: a test-only dumper.** `dumper.c`, about 100 lines, built into `/tmp/v-e6s6-work/dumper.dylib`. Product code was not changed.
  - **What it dumps.** It walks the process's own map with `mach_vm_region_recurse` on `mach_task_self()`, so it needs no permission. It takes every readable region that is writable or not file-backed (heaps, stacks, data, anonymous maps). Within those, it writes every page `mincore` reports as resident, paged out or modified. That gives 40 to 210 MB per dump.
  - **Index file.** One line per region, with the VM tag and the region's wired count (`user_wired_count`), and the process's wired bytes (`proc_pid_rusage`).
  - **Loading it.** The debug `app` loaded it with `DYLD_INSERT_LIBRARIES`. A thread waits for a request file, so the dump is taken from inside the process at the moment I choose. The xctest runner `dlopen`ed it and called `v_dump`. The runner is ad hoc signed without the runtime flag (`flags=0x2(adhoc)`).
- **The search ran in another process.** `search.py` searched each dump for these needles:
  - the five or six text values, as UTF-8 and UTF-16LE;
  - the six keys, as raw bytes, as their first 16 bytes, and as hex text.

  The process being dumped never held a needle. The command line got its values over stdin. The Swift test builds the master password at run time, as typing does, and compares its model strings with needles that are reversed and masked.
- **Wired bytes from outside the process.** `wired`, a 10-line C tool, calls `proc_pid_rusage` on the `app` pid. It works for a process of the same user without any prompt.
- **`vmmap`.** It has the read-only task-port entitlement, so it attaches without a prompt. It mapped the regions of the locked `app` (`locked.vmmap`). It has no `-wired` option on macOS 26, so wired counts come from the region info and `proc_pid_rusage`.

## 1. AT-C01: the debug `app` shell after lock

### 1.1 Run

`run_cli.sh`: `app open v6.appvault`, then the password, `show -s Vfy6Bank`, `clip Vfy6Bank 1` (private pasteboard), a dump (`unlocked`), `close`, a dump (`locked`), and `exit`. There was also a dump (`start`) before the password.

```
pid 90148
dumped start: pid 90148 rc 0 wired 0
after unlock: pid 90148 rc 0 wired 16384
dumped unlocked: pid 90148 rc 0 wired 16384
after close: pid 90148 rc 0 wired 0
dumped locked: pid 90148 rc 0 wired 0
app exit 0
```

Each line is the count of hits for that needle (UTF-8 text, or the raw 32 or more key bytes). The UTF-16, first-16-bytes and hex forms gave 0 hits in every dump except the two hits listed in 1.2.

```
start:    39,796,736 bytes, 30 regions, wired 0      master_pw=0 entry_pw=0 username=0 notes=0 url=0 P=0 C=0 T=0 K_enc=0 K_mac=0 stream_key=0
unlocked: 126,943,232 bytes, 43 regions, wired 16384 master_pw=1 entry_pw=1 username=1 notes=1 url=1 P=0 C=0 T=1 K_enc=0 K_mac=0 stream_key=0
locked:   126,943,232 bytes, 41 regions, wired 0     master_pw=0 entry_pw=0 username=0 notes=0 url=0 P=0 C=0 T=0 K_enc=0 K_mac=0 stream_key=0
```

### 1.2 What the unlocked dump holds, and where (the control)

- **`T` and the master password.** `T` (raw and first 16 bytes) is at `0x10608fad0`. The master password is at `0x10608fab0`. Both are in `10608c000-106090000`, a region of exactly one page (MALLOC_TINY), split off and `user_wired=1`. So this is the page `memory::lock` wired.
  - The password is there because the shell's session keeps it (`vault.rs` `Session.creds`) for saving. It sits in the page with `T` only because the allocator put it next to `T` (section 3).
- **The field values.** They are in MALLOC_SMALL, next to each other: the decrypted vault in Rust.
- **Never present, even while unlocked:** `P`, `C`, `K_enc`, `K_mac` and the stream key. They live only during the key work and the document read.

### 1.3 The remnant: the last printed line (F-059)

- **Run 2:** `show -a Password Vfy6Bank`, then `close`. The `locked` dump had `entry_pw=1` at `0x101707a70` (MALLOC_TINY). It is followed by `0a` and preceded by zeros: the value plus newline at the start of a buffer.
- **Run 3:** the same, with `help` printed in between. The value was still there, at `0x105a67c20`. `print!` of whole lines goes straight to the file and skips the buffer.
- **Run 4:** the same, with `show Vfy6Bank` in between. That prints `URL: …`, 33 bytes, through the buffer. The `locked` dump then had 0 hits.
- **Conclusion.** The copy is Rust's own stdout line buffer, which `term::out_parts` writes through. It keeps the bytes of the last line written through it until a longer line overwrites them.
- **Run 1** (`show -s`, then `clip`) leaves nothing, because later lines overwrote the value.
- **It is a value the user asked the tool to print,** and the terminal holds it too. So I count it as an explained remnant, the command line's version of a Show value, and not as a blocker. It is logged as F-059 (Low) with its smallest fix.

## 2. AT-C02 and the Swift view state: Show, Copy, Hide, entry change, lock

My test, `VerifyE6S6Tests.swift`, existed only in the copy. Run alone with `xcodebuild … test-without-building -only-testing:AppTests/VerifyE6S6Tests`, its steps are:

1. `Session()` and `MainWindowModel`, then open `v6b.appvault`.
2. Set `unlock.password` to a password built at run time, then `unlock()`.
3. `select(Vfy6Bank)`, `toggleShow("Password")` and `copy("Password")`, then dump `shown`.
4. `toggleShow` (Hide) and `select(Vfy6Other)`, then dump `hidden`.
5. Wait 11 s, still unlocked, then dump `cleared`.
6. `window.lock(id)`, then dump `locked`.

It also walks every stored property of the window, vault and unlock models with `Mirror`.

```
VERIFY-E6S6 after Hide: ["username in window._opened._.value._placeRows._.subtitle", … 8 entries, all username in row subtitles …]
VERIFY-E6S6 walked 13 strings
VERIFY-E6S6 after lock: []
✔ Test "Verify E6-S6: no demo value in the models or in memory after Hide and lock" passed after 13.173 seconds.
** TEST EXECUTE SUCCEEDED **
```

```
shown:   137,265,152 bytes, wired 16384  master_pw=1 entry_pw=3 username=3 notes=2 url=4 other_pw=1 P=0 C=0 T=1 K_enc=0 K_mac=0 stream_key=0
hidden:  137,265,152 bytes, wired 16384  master_pw=1 entry_pw=2 username=2 notes=1 url=2 other_pw=1 P=0 C=0 T=1 K_enc=0 K_mac=0 stream_key=0
cleared: 136,986,624 bytes, wired 16384  master_pw=1 entry_pw=1 username=2 notes=1 url=2 other_pw=1 P=0 C=0 T=1 K_enc=0 K_mac=0 stream_key=0
locked:  137,052,160 bytes, wired 0      master_pw=0 entry_pw=0 username=0 notes=0 url=0 other_pw=0 P=0 C=0 T=0 K_enc=0 K_mac=0 stream_key=0
```

The three copies of the entry password while unlocked:

- **The Swift string behind `shown["Password"]`.** It has the header of a native Swift string just before the bytes (count `0x17`, flags `f0`). It is in `shown`, and gone in `hidden`: Hide released it.
- **A 23-byte block from the Copy path** (`0x…08090`, `17 00 …` before the bytes). It is in `shown` and `hidden`, and gone in `cleared`: the clipboard clear 10 s after the copy released it.
- **The decrypted vault in Rust** (no Swift header, next to the other entry's password). It stays while the vault is unlocked. That is expected: App does not encrypt field values in memory, and neither does the reference (SR-07).

The other results:

- **After lock:** 0 hits for every needle, and 0 wired bytes. The model walk found 13 strings and none held a demo value.
- **After Hide (still unlocked):** the walk found the user name only, in row subtitles, which is not a protected field. No model string held the entry password or the master password.
- **The project's own `ScreenTests` pass.** Run with my suite as `-only-testing:AppTests/ScreenTests -only-testing:AppTests/VerifyE6S6Tests`, the result was `✔ Test run with 9 tests in 2 suites passed`. Among them:
  - "APP-06.11, AT-E07: the password field clears when an unlock starts; Hide, entry change, lock drop shown values"
  - "APP-03.7, APP-03.15, APP-03.21: Edit > Copy copies the password; …; quit locks every vault"
  - "APP-06: a wrong password shows M06-06 and leaves the field empty"

  In that first combined run, the `locked` dump held the user name and URL once each. They were the `EntryRow` my test still kept in a local variable. After I scoped it to the id lookup, the runs above show 0.
- **Limit of this check.** It runs the models, not the AppKit views. Text field buffers of a real window (the secure unlock field, the Show field) need a visible window, so the lldb dump of the running `App.app` goes to Mac QA.

## 3. AT-C05: key pages locked

- **`key_pages` test.** `cargo test -p app-ffi --test key_pages --test memory -- --nocapture --test-threads=1`:

```
unlocked, password only: 16384 bytes wired (page 16384)
unlocked, password and key file: 32768 bytes wired
test result: ok. 2 passed; 0 failed; 1 ignored
```

  The test asserts that wired bytes return to the baseline after `lock` and after `close`.
- **`ulimit -l 0`.** I ran the child by hand:

```
ulimit -l: 0
test refused_lock_child ... child true 0
stderr:
Process protection could not be fully applied.
```

  So unlock works, 0 bytes are wired, and M11-01 is written exactly once.
- **app-platform tests.** `cargo test -p app-platform memory` gave 5 passed (1 ignored, the child). Among them:
  - `app11_9_b_locked_pages_are_wired_until_the_last_guard_drops`
  - `app11_9_refused_lock_goes_on_with_one_warning`
  - `freed_blocks_are_zero`
  - `realloc_wipes_the_old_block_when_it_grows_or_shrinks`
  - `the_system_allocator_keeps_freed_bytes`
- **My own check on the running `app`** (section 1.1): `wired` reported 0, then 16384 after unlock, then 0 after `close`.
  - The dump index shows the wired page itself. It is a one-page region with `user_wired=1` that holds `T`.
  - In the locked dump, no region has `user_wired=1` (`grep -c uw=1` gave 0).
  - The Swift session showed the same: the `T` page `c8a4d4000-c8a4d8000` had `uw=1` while unlocked, and the process was back to 0 wired after lock.
- **The open item: the kept password is not locked (F-058).**
  - **Mac app run alone** (the `shown` dump): the master password is at `0xc8a0f1120` in `c8a000000-c8a400000`, with `user_wired=0`, while `T` is in the wired page `c8a4d4000`. So it can be swapped out.
  - **Other runs.** In one run it happened to fall in `T`'s page. In the command line it fell 0x20 bytes before `T` both times. That is luck of the allocator, not a guarantee.
  - **The code.** `app-ffi/src/edit.rs` `Saver` (as copied) and `app-cli/src/vault.rs` `Session.creds` keep the password as a plain `SecretString` while the vault is unlocked.
  - **Why it matters.** APP-11.9 locks `P`, and the kept password gives `P` at once (`P` = SHA-256 of it). The reference source keeps the password part in the crypto library's wiping vector from its page-locked pool, for as long as the database is open (SR-07 "as in the reference").
  - **Already partly fixed.** LD-199 (3) says the same for the Mac app. The project's `edit.rs` got `password_pages` at 08:32, after my copy, so I did not verify it. `app-cli` is unchanged.

## 4. AT-C04: crash reports

- **Release `app`.** `cargo build --release -p app-cli` printed `Finished release`. `app --debug-info` printed `Build type: release`.
- **The run.** `run_rl.sh` started `app open v6.appvault` under `ulimit -c unlimited`, with stdin on a FIFO that was never written, so it waits at its password prompt. A probe library reads `getrlimit(RLIMIT_CORE)` at load and again 1.5 s later:

```
shell core limit: soft=unlimited hard=unlimited
stderr: Vault password for /tmp/v-e6s6-work/v6.appvault:
loaded core soft=9223372036854775807 hard=9223372036854775807
after start-up core soft=0 hard=0
stopped 84820 (SIGKILL), alive: no
```

- **Result:** a release `app` can write no core dump, and `/cores` held 0 files.
- **Not forced here.** As asked, I did not force a crash or panic, because it would show a dialog. The crash report contents wait for Mac QA. The App bundle's own core limit and deny-attach were proven in E6-S4.

## 5. AT-C06: logs

- **System log.** `/usr/bin/log show --start "2026-10-28 08:42:00" --info --debug --predicate 'subsystem == "com.app.desktop"'` covered the window of both Swift runs. It gave 144 lines, all of three kinds:
  - `Main window opened: App 0.1.0`
  - `Search updated the list in N µs`
  - the header line
- **Whole system log.** The same command without the predicate gave 101,272 lines, 15,319,338 bytes.
- **Search.** `grep_needles.py` searched both for every demo text value and every key, as hex in either case and as raw bytes. Result: `no needle`. There were also 0 hits for the testdata demo passwords (`demo-pass-`, `demo-bank-1`, `demo-entry-pass`, `demo-pw-0`).
- **Test and build logs**, also `no needle`:
  - `test-all.log`, `release.log`
  - `xcode-build.log`, `xcode-build2.log`, `xcode-test1.log`, `xcode-test2.log`
  - the stderr of every `app` run (`cli*.err`, `rl.stderr`)

  `test-all.log` also had 0 hits for the testdata demo passwords.
- **Command line stdout.** The only hits were in `cli.out`, the stdout of `show -s`, which prints the entry on purpose.

## 6. The allocator: F-034, F-042, F-048, F-053

`cargo test -p app-cli --test memory_hygiene -- --nocapture`:

```
F-034 open: 2 freed blocks held the value before the wipe (largest 43296 bytes); after it 143 blocks freed, 0 with the value, 0 not all zero
F-042 save: 1 freed blocks held the value before the wipe (largest 33026 bytes); after it 543 blocks freed, 0 with the value, 0 not all zero
F-048 strength: 12 freed blocks held the value before the wipe (largest 6336 bytes); after it 2139 blocks freed, 0 with the value, 0 not all zero
F-053 JSON import: 2 freed blocks held the value before the wipe (largest 448 bytes); after it 72 blocks freed, 0 with the value, 0 not all zero
APP-11.9-c growth: 8 freed blocks held the value before the wipe (largest 2048 bytes); after it 9 blocks freed, 0 with the value, 0 not all zero
test result: ok. 1 passed; 0 failed
```

**Allocator removed, in the scratch copy.** I changed the test's global allocator from `Probe(Zeroing(Probe(System, &AFTER)), &BEFORE)` to `Probe(Probe(System, &AFTER), &BEFORE)`. I also made each scenario's check count a failure instead of stopping, so that all five run.

```
F-034 open: 3 freed blocks held the value before the wipe (largest 1802240 bytes); after it 143 blocks freed, 3 with the value, 114 not all zero
F-034 open: FAIL, a block reached the system unwiped
F-042 save: … 3 with the value, 590 not all zero … FAIL
F-048 strength: … 6 with the value, 2067 not all zero … FAIL
F-053 JSON import: … 2 with the value, 42 not all zero … FAIL
APP-11.9-c growth: … 8 with the value, 8 not all zero … FAIL
assertion `left == right` failed: scenarios failed  left: 5  right: 0
test result: FAILED. 0 passed; 1 failed
```

After the run I restored the file. `cmp` against the project file printed `restored-identical`.

**Second mutant.** I deleted the `#[global_allocator]` in `app-ffi/src/lib.rs`. `cargo test -p app-ffi --test memory` then failed with `assertion failed: !app_platform::memory::marker_survives_free(true)`. Restored, and `cmp` printed `restored-identical`. With the allocator in place, the test passes.

F-034, F-042, F-048 and F-053 are set to **verified** in security/findings.md.

## 7. Tests

`cargo test -p app-platform -p app-format -p app-ffi -p app-cli` (debug, in the copy) gave `total passed 1047 failed 0 ignored 24`, summed over all 36 result lines. Exit 0, in 165.65 s real, 844.07 s user and 49.71 s sys.

## Open items at the first pass

1. **F-058 (Medium), fixed and verified in the rerun.** The master password kept for saving is outside page-locked memory while the vault is unlocked.
   - **Mac app:** fixed in the tree by LD-199 (3) (`edit.rs` `password_pages`) after my copy. It needs a rerun of section 2 on that tree.
   - **Command line:** `app-cli/src/vault.rs` `Session.creds` is still a plain `SecretString`.
   - **Smallest fix:** in `Creds`, hold `app_platform::memory::lock(password.expose().as_bytes())` in a field declared after the password, so the password is wiped first and then unlocked, as `LockedKey` and the new `Saver` do. Add one test that the guard is `Some`.
   - **Re-verify:** rerun `run_cli.sh` and the Swift suite. The scripts are kept in `/tmp/v-e6s6-work`, and the master password must show `user_wired=1`.
2. **F-059 (Low), not blocking; accepted by the lead.** Rust's stdout line buffer keeps the last line `term::out_parts` wrote, for example the value of `show -a Password`, after `close`. It stays until a longer buffered line overwrites it.
   - **Smallest fix:** in `out_parts`, flush `io::stdout()`, then write a line that carries a value through an unbuffered handle on fd 1 (a `File` from `try_clone_to_owned`, as `term.rs` `input()` does for stdin). The escaped copy stays wiped.

## Rerun on the fixed tree (08:56)

- **Fresh copy.** I made it at 08:55:54 with the same `rsync` into `/tmp/v-e6s6-src`, using the same target and derived-data folders.
- **The fix.** Each holder now keeps a page lock on the kept password, declared after the password, so the password is wiped first and then unlocked:
  - the command line: `app-cli/src/vault.rs` `Session.password_pages`, set by `keep_password()` at open and again after `db-edit` changes the password;
  - the Mac app: `app-ffi/src/edit.rs` `Saver.password_pages` (LD-199 (3)).
- **SHA-256 (first 16 hex digits) of the files in this rerun:**
  - `vault.rs` ce5e0be22eb63823
  - `commands.rs` 747e683745f60330
  - `edit.rs` a7f928e0fea8a1c5
  - `session.rs` e253e57b590abefd
  - `key_pages.rs` 434625baad3536ed
  - `app-ffi/src/lib.rs` 9c20fd7c90d8e23a (unchanged)
  - `app-cli/src/main.rs` 2d65352e2216ae8b
  - `macos/memory.rs` ec6b504d580e0ce9 (unchanged)
- **Tests.** `cargo test -p app-platform -p app-format -p app-ffi -p app-cli` gave `total passed 1053 failed 0 ignored 24`, exit 0, in 178.73 s real and 843.37 s user. It includes:
  - `vault::kept_password_tests::f_058_kept_password_pages_are_locked`
  - `ld_199_3_kept_password_is_page_locked`
  - `app11_9_b_key_pages_are_wired_while_the_vault_is_unlocked`
  - `app11_9_refused_locks_still_unlock_with_one_warning`
  - `findings_leave_no_plain_value_in_freed_memory`
  - `the_linked_core_zeroes_freed_blocks`
- **Command line, `run_cli.sh` with the fixed debug `app`:**

```
after unlock: pid 7134 rc 0 wired 16384
after close: pid 7134 rc 0 wired 0
unlocked: master_pw=1 entry_pw=1 username=1 notes=1 url=1 P=0 C=0 T=1 K_enc=0 K_mac=0 stream_key=0
locked:   master_pw=0 entry_pw=0 username=0 notes=0 url=0 P=0 C=0 T=0 K_enc=0 K_mac=0 stream_key=0
  master_pw 0x105cffb50 in 105cfc000-105d00000 prot=3 tag=7(MALLOC_TINY) user_wired=2
  T         0x105cffb70 in 105cfc000-105d00000 prot=3 tag=7(MALLOC_TINY) user_wired=2
locked: 0 regions with user_wired > 0
```

  - **Why `user_wired=2` proves the fix.** The password and `T` share one page here, and that page now carries two nested locks: the password's own and `T`'s. Before the fix it was `user_wired=1` (`T` only).
- **Mac app, the Swift suite** (`toggleShow` is now `async`, so my test awaits it), run alone:

```
✔ Test run with 1 test in 1 suite passed after 12.789 seconds.
VERIFY-E6S6 after lock: []
shown:   wired 32768  master_pw=1 entry_pw=3 username=3 notes=2 url=4 other_pw=1 P=0 C=0 T=1 K_enc=0 K_mac=0 stream_key=0
hidden:  wired 32768  master_pw=1 entry_pw=2 … T=1
cleared: wired 32768  master_pw=1 entry_pw=1 … T=1
locked:  wired 0      master_pw=0 entry_pw=0 username=0 notes=0 url=0 other_pw=0 P=0 C=0 T=0 K_enc=0 K_mac=0 stream_key=0
  master_pw 0xbea198440 in bea198000-bea19c000 prot=3 tag=2(MALLOC_SMALL) user_wired=1
  T         0xbea089b00 in bea088000-bea08c000 prot=3 tag=2(MALLOC_SMALL) user_wired=1
locked: 0 regions with user_wired > 0
```

  - **Result.** The kept password now has a wired page of its own, so the process wires two pages while unlocked and 0 after lock.
  - **ScreenTests** on this tree: `✔ Test run with 8 tests in 1 suite passed`.
- **Logs from the rerun:** `no needle` in the test, build and test-run logs, in the `app` output, and in the 18 `com.app.desktop` log lines of the rerun window.
- **Clean-up.** I deleted the copy, target, derived data and dumps again. No process of mine was left.
- **CPU for the rerun:** about 20 minutes (tests 893 s, core and Xcode builds about 300 s, the rest small). The whole check used about 55 minutes of CPU, and no single run was over 30 minutes.

## Mac QA (with the owner's go)

- **lldb dump of the real `App.app`.** Run it after typing in the secure unlock field, Show, Hide and lock. It needs developer mode or the authorization prompt (AT-C01 and AT-C02 at the view level).
- **AT-C04 with a forced panic in a Release App,** to read the crash report.

## Clean-up and CPU

- **Deleted:** the copy `/tmp/v-e6s6-src` (including my Swift test and the scratch key test), `/tmp/v-e6s6-target`, `/tmp/v-e6s6-dd`, and all memory dumps.
- **Kept in `/tmp/v-e6s6-work`:** the scripts, probes, demo vaults, needles and logs.
- **No process of mine left:** `pgrep -fl v-e6s6` printed nothing.
- **CPU:** about 34 minutes of CPU time in total, over about 40 minutes of wall time. The largest single run was the four-crate test run, 166 s wall (894 s CPU). No single run was over 30 minutes.
