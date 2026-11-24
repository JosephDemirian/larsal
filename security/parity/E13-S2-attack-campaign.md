# E13-S2 attack campaign: results

Story: E13-S2. Catalog: [plan/attacks-and-checks.md](../../plan/attacks-and-checks.md) "Attack catalog". Severities: its Findings section.
Date: 2026-10-29. Role: filer. I did not run the attacks and fixed nothing. I read each group's report, checked each failed row against its evidence and the code it names, and filed the new findings in [security/findings.md](../findings.md).

Groups run today: A, B, E, H, I, J. Group C ran in E13-S4 (Done). Groups D, F, G, K were not run: D after E6-S1 and E6-S5, F after E7 and D4, G after E8-S2 and E8-S3, K after E5-S11, E5-S12 and E6-S3.

**Count.** Run today, 45 rows: 34 passed, 6 failed, 0 Mac QA, 5 wait. Whole catalog, 73 rows: 40 passed (34 today, 6 AT-C in E13-S4), 6 failed, 27 wait (5 today, 22 in groups D, F, G and K). New findings: 21, F-098 to F-118 (1 High, 8 Medium, 12 Low). Existing rows cited, not filed again: F-047, F-068, F-092, F-077.

## Every catalog row

| Row | Attack | Result | Report | Findings |
|---|---|---|---|---|
| AT-A01 | Wrong credentials | passed (a real hardware key: Mac QA, after F-107) | [E13-S2-AT-A.md](E13-S2-AT-A.md) | |
| AT-A02 | Header tampering | passed | [E13-S2-AT-A.md](E13-S2-AT-A.md) | |
| AT-A03 | Payload tampering | passed | [E13-S2-AT-A.md](E13-S2-AT-A.md) | |
| AT-A04 | Truncation | passed | [E13-S2-AT-A.md](E13-S2-AT-A.md) | |
| AT-A05 | KDF cost bomb | passed | [E13-S2-AT-A.md](E13-S2-AT-A.md) | |
| AT-A06 | Decompression bomb | passed | [E13-S2-AT-A.md](E13-S2-AT-A.md) | |
| AT-A07 | XML attacks | passed | [E13-S2-AT-A.md](E13-S2-AT-A.md) | |
| AT-A08 | Hostile document inside valid encryption | passed | [E13-S2-AT-A.md](E13-S2-AT-A.md) | |
| AT-A09 | Downgrade | passed | [E13-S2-AT-A.md](E13-S2-AT-A.md) | |
| AT-A10 | Fuzzing | passed as a smoke run (22 targets, 20-60 s each, 0 crashes); the 24-hour runs are E13-S3 | [E13-S2-AT-A.md](E13-S2-AT-A.md) | |
| AT-A11 | Differential fuzzing | passed (420 files, 0 differences) | [E13-S2-AT-A.md](E13-S2-AT-A.md) | |
| AT-A12 | Key file attacks | passed | [E13-S2-AT-A.md](E13-S2-AT-A.md) | |
| AT-B01 | Known answers for primitives | passed | [E13-S2-AT-B.md](E13-S2-AT-B.md) | |
| AT-B02 | Known answers for whole files | passed (one reference test vault that needs a hardware key not run) | [E13-S2-AT-B.md](E13-S2-AT-B.md) | |
| AT-B03 | Fresh randomness | passed | [E13-S2-AT-B.md](E13-S2-AT-B.md) | |
| AT-B04 | One random source | passed | [E13-S2-AT-B.md](E13-S2-AT-B.md) | F-100 |
| AT-B05 | Constant time | passed | [E13-S2-AT-B.md](E13-S2-AT-B.md) | F-099 |
| AT-B06 | KDF cost is real | **failed** | [E13-S2-AT-B.md](E13-S2-AT-B.md) | F-098 |
| AT-B07 | No padding oracle | passed | [E13-S2-AT-B.md](E13-S2-AT-B.md) | |
| AT-C01 | Secrets after lock | passed in E13-S4 (Mac QA part: lldb dump of Larsal.app) | [E13-S4-memory-process-checks.md](E13-S4-memory-process-checks.md) | |
| AT-C02 | Secret after Hide | passed in E13-S4 on the main window's Show; the editor's Show leaves a copy (AT-E07) | [E13-S4-memory-process-checks.md](E13-S4-memory-process-checks.md) | F-102 |
| AT-C03 | Debugger and core dumps | passed in E13-S4 (Mac QA part: lldb attach of Larsal.app) | [E13-S4-memory-process-checks.md](E13-S4-memory-process-checks.md) | |
| AT-C04 | Crash reports | passed in E13-S4 (Mac QA part: a forced Larsal.app crash and its report) | [E13-S4-memory-process-checks.md](E13-S4-memory-process-checks.md) | |
| AT-C05 | Swap | passed in E13-S4 (Mac QA part: wired count of an unlocked Larsal.app) | [E13-S4-memory-process-checks.md](E13-S4-memory-process-checks.md) | |
| AT-C06 | Logs | passed in E13-S4 (Mac QA part: window flows at debug log level) | [E13-S4-memory-process-checks.md](E13-S4-memory-process-checks.md) | |
| AT-D01 | Clipboard manager | waits (group D; E6-S1) | not run | |
| AT-D02 | Timed clear | waits (group D; E6-S1) | not run | |
| AT-D03 | Clear on lock and quit | waits (group D; E6-S1) | not run | |
| AT-D04 | Screen capture | waits (group D; E6-S5) | not run | |
| AT-D05 | Keystroke tap | waits (group D; E6-S5) | not run | |
| AT-E01 | Text injection | passed (the stored vault name in Vault Settings checked by code reading only) | [E13-S2-AT-E.md](E13-S2-AT-E.md) | |
| AT-E02 | Dangerous links | passed | [E13-S2-AT-E.md](E13-S2-AT-E.md) | |
| AT-E03 | Boundary abuse | **failed** | [E13-S2-AT-E.md](E13-S2-AT-E.md) | F-101, F-104 |
| AT-E04 | Retired: no web engine (replacement checks) | passed on the Debug app (the Release build check is E14-S3) | [E13-S2-AT-E.md](E13-S2-AT-E.md) | |
| AT-E05 | Retired: no developer tools (replacement checks) | waits: AT-C03 passed in E13-S4; AT-J05 waits for D7 (E14-S3) | [E13-S2-AT-E.md](E13-S2-AT-E.md) | |
| AT-E06 | Drag and drop | passed | [E13-S2-AT-E.md](E13-S2-AT-E.md) | F-103 |
| AT-E07 | Secrets in the screen | **failed** | [E13-S2-AT-E.md](E13-S2-AT-E.md) | F-102 |
| AT-E08 | Local listeners | passed (a Release app with its window: Mac QA) | [E13-S2-AT-E.md](E13-S2-AT-E.md) | F-105 |
| AT-F01 | No association | waits (group F; E7, D4) | not run | |
| AT-F02 | Replay | waits (group F; E7, D4) | not run | |
| AT-F03 | Wrong keys | waits (group F; E7, D4) | not run | |
| AT-F04 | Silent association | waits (group F; E7, D4) | not run | |
| AT-F05 | Lookalike sites | waits (group F; E7-S3, D4) | not run | |
| AT-F06 | Foreign frames | waits (group F; E7, D4) | not run | |
| AT-F07 | Flood | waits (group F; E7, D4) | not run | |
| AT-F08 | Wrong passkey | waits (group F; E7-S5, D4) | not run | |
| AT-G01 | Lookalike window | waits (group G; E8-S2) | not run | |
| AT-G02 | Focus change | waits (group G; E8-S2, E8-S3) | not run | |
| AT-G03 | Hostile sequence | waits (group G; E8-S3; E8-S1's run is history) | not run | |
| AT-H01 | Keys after lock | **failed** (one sequence: socket changed while unlocked) | [E13-S2-AT-H.md](E13-S2-AT-H.md) | F-106, F-108, F-109 |
| AT-H02 | Key limits | passed | [E13-S2-AT-H.md](E13-S2-AT-H.md) | |
| AT-H03 | Key pulled out | passed on a simulated key (OD-01); a real key: Mac QA, after F-107 | [E13-S2-AT-H.md](E13-S2-AT-H.md) | F-107 |
| AT-H04 | Wrong hardware key | passed on a simulated key (OD-01); another real key: Mac QA, after F-107 | [E13-S2-AT-H.md](E13-S2-AT-H.md) | F-107 |
| AT-I01 | Crash during save | passed (1,000 kills, 0 broken) | [E13-S2-AT-I.md](E13-S2-AT-I.md) | |
| AT-I02 | Disk full | passed | [E13-S2-AT-I.md](E13-S2-AT-I.md) | |
| AT-I03 | No permission | passed | [E13-S2-AT-I.md](E13-S2-AT-I.md) | |
| AT-I04 | Link tricks | **failed** | [E13-S2-AT-I.md](E13-S2-AT-I.md) | F-111; F-047 (re-test pending) |
| AT-I05 | Two writers | **failed** | [E13-S2-AT-I.md](E13-S2-AT-I.md) | F-110 |
| AT-I06 | File permissions | passed (the planted temp file case is F-111) | [E13-S2-AT-I.md](E13-S2-AT-I.md) | F-111 |
| AT-I07 | Planted sync commands | waits for W-15 (today's part passed: nothing ran) | [E13-S2-AT-I.md](E13-S2-AT-I.md) | F-112 |
| AT-I08 | Hostile sync commands and downloads | waits for W-15 (no sync runner exists) | [E13-S2-AT-I.md](E13-S2-AT-I.md) | |
| AT-J01 | Known vulnerabilities | passed | [E13-S2-AT-J.md](E13-S2-AT-J.md) | F-113, F-114 |
| AT-J02 | Policy | passed | [E13-S2-AT-J.md](E13-S2-AT-J.md) | F-113, F-114 |
| AT-J03 | New dependency review | passed | [E13-S2-AT-J.md](E13-S2-AT-J.md) | F-117 (F-068 for the architecture.md cells) |
| AT-J04 | Reproducible build | pass (E14-S4 Verify 2026-10-29: two clean builds identical; LD-251 (3)) | [E13-S2-AT-J.md](E13-S2-AT-J.md), [E14-S4-reproducible-build.md](E14-S4-reproducible-build.md) | |
| AT-J05 | Signing | waits for D7 (E14-S3) | [E13-S2-AT-J.md](E13-S2-AT-J.md) | |
| AT-J06 | Names and secrets | passed | [E13-S2-AT-J.md](E13-S2-AT-J.md) | F-115, F-116, F-118 |
| AT-K01 | Lock events | waits (group K; E6-S2's run is history, its Mac QA open) | not run | |
| AT-K02 | Biometry change | waits (group K; E6-S3) | not run | |
| AT-K03 | Quick unlock off | waits (group K; E6-S3) | not run | |
| AT-K04 | Expired warning | waits (group K); the notice is not wired | not run | F-077 (open) |
| AT-K05 | Looks like the mockup | waits (group K; E5-S12) | not run | |
| AT-K06 | VoiceOver | waits (group K; E5-S11) | not run | |

## New findings

| ID | Severity | Row | Group label | One line |
|---|---|---|---|---|
| F-098 | Medium | AT-B06 | RT-B1 | `larsal db-create` and `import` tune the KDF with a wall clock (LD-72); under load one vault got 11 Argon2id iterations, 0.33 x the target |
| F-099 | Low | AT-B05 | RT-B2 | The bare 32-byte `ct_eq` shows a 0.2 ns step; no MAC check shows it |
| F-100 | Low | AT-B04 | RT-B3 | The one-random-source guards miss arc4random, getentropy, SecRandomCopyBytes, RandomState and Swift code |
| F-101 | High | AT-E03 | RT-E-1 | A FIFO at the vault path or the Save As target blocks save for good, and every lock waits on that save on the main thread |
| F-102 | Medium | AT-E07 | RT-E-2 | The editor's Show and Hide leaves one copy of the entry password in memory after lock and close |
| F-103 | Medium | AT-E01, AT-E06 | RT-E-3 | The attachment ask-first list misses types macOS runs or acts on (.term, .xhtml, .jnlp, .afploc, .webarchive and more) |
| F-104 | Low | AT-E03 | RT-E-4 | `open_attachment` answers AskFirst before it checks the vault id |
| F-105 | Low | AT-E08 | RT-E-5 | The AT-E08 row omits Larsal's own SSH agent socket |
| F-106 | Medium | AT-H01 | F-H1 | A socket change while unlocked leaves the key in the old agent at lock, with no message |
| F-107 | Medium | AT-H03, AT-H04 | F-H3 | Hardware keys are not wired into the app or the CLI, and no open story owns it |
| F-108 | Low | AT-H01 | F-H2 | A silent system agent blocks the lock 2 s per marked key on the main thread |
| F-109 | Low | AT-H01 | F-H4 | `Throwaway::start` is flaky under load (int06_22 part is F-092) |
| F-110 | Medium | AT-I05 | F-I1 | Two separate writers saving at once both say saved and one save is lost |
| F-111 | Medium | AT-I04, AT-I06 | F-I2 | The settings export writes through a link planted at its fixed temp name |
| F-112 | Low | AT-I07 | F-I4 | larsal-core still lists the remote import kind |
| F-113 | Medium | AT-J01, AT-J02 | F-J1 | cargo audit and cargo deny never check the vendored ssh-key and zxcvbn |
| F-114 | Low | AT-J01, AT-J02 | F-J2 | The fuzz workspace is outside the audit and deny gates |
| F-115 | Low | AT-J06 | F-J3 | The name guard passes base64, Brotli (WOFF2) and zstd content unread |
| F-116 | Low | AT-J06 | F-J4 | Encrypted demo vaults hold the reference app's name, readable with the published demo passwords |
| F-117 | Low | AT-J03 | F-J5 | LD-115, LD-138 and LD-157 lack an explicit lead co-sign |
| F-118 | Low | AT-J06 | F-J6 | Three .DS_Store files and the owner's home path in one proof file |

## Checks of the failed rows

Each claimed failure was checked against its report and the code it names on today's tree:

- AT-B06: crates/larsal-cli/src/commands.rs `clock()` (line 1027) is a wall-clock `Instant`, passed to `settings::tune` in `write_vault`.
- AT-E03: crates/larsal-core/src/storage.rs:80 opens the vault path with a plain `File::open` (no O_NONBLOCK); the FIFO runs were repeated by the group on the tree re-synced at 21:40.
- AT-E07: in-process scan evidence only (not re-run by me); reproduced by the group in a fresh process and on today's ShownPasswordField.swift.
- AT-H01: crates/larsal-sshagent/src/keyring.rs `remove_from_system` takes `self.system_agent()` at lock time.
- AT-I04: crates/larsal-ffi/src/larsal_settings.rs:583 `write_json` opens `.<name>.tmp` with create and truncate.
- AT-I05: race counts from the group's runs (4 of 150 process pairs, 7 of 120 session races); storage has no lock across the re-check and the rename.

Duplicates dropped:

- AT-I04's racing temp swap (the group's F-I3) is **F-047**, fixed in E13-S6b with a re-test pending. crates/larsal-core/src/storage.rs changed at 20:55 with that fix. The AT-I report does not say whether its case 6 ran before or after it, so the F-047 re-test must repeat case 6 (rename each new temp file away, put a link at its name, 300 adds through `larsal open`). If `larsal` still prints "saved" while the vault path becomes the link, F-047 goes back to open.
- The int06_22 failures in AT-H (4 of 4 under load) add to **F-092**.
- The two stale architecture.md cells in AT-J03 are **F-068** (fixed in text in E13-S6a). Today's architecture.md no longer has "lead co-sign open".

## Mac QA and the owner's go

These rows passed, but each still has a part that needs Mac QA:

- AT-A01, AT-H03, AT-H04: a real hardware key. These also wait for F-107.
- AT-E08: a Release app with its window.
- AT-C01, AT-C03 to AT-C06: the Larsal.app parts listed in E13-S4.

The 24-hour fuzz runs of AT-A10 are E13-S3 and wait for the owner (OD-05).

## Notes for the lead from the groups (not filed)

**AT-A**
- N1: one strength_estimate slow unit took 10 s wall. Run alone it takes 3.8 s CPU, so it is not a hang.
- N2: a text node just under the 1 GiB limit peaks at about 1 GB before it is refused. This is inside the ceilings LD-22 to LD-90 already accept.
- N3: `fuzz/Cargo.lock` gained one line, cargo's sync for another agent's larsal-core change.
- N4: KDF settings outside the format's range get the "A Larsal update may open it" text, as the spec says.

**AT-B**
- N1: the decided differences LD-01 and LD-03 are not in LD-84's list for AT-A11.
- N2: the ignored Argon2id benchmark test fails its upper bound under load, because it uses a wall clock.
- N3: there are no Twofish or Argon2id vaults made by the reference.

**AT-E**
- The CPU budget was spent, so no Release build was made and Vault Settings was not rendered.

**Re-runs and side effects**
- Builds in AT-A (fuzz), AT-H and AT-J failed once during other agents' edits and built cleanly on re-run.
- AT-I had a stray saver (PID 23352) that ran for 28 minutes in its own /tmp folder before it was stopped by its PID.

## Exit state

E13's exit needs every attack passed and no open Critical or High finding. Open from this campaign:

- 6 failed rows: AT-B06, AT-E03, AT-E07, AT-H01, AT-I04, AT-I05.
- 1 High finding: F-101.
- 27 rows waiting for their stories.

E13-S2 stays todo.

## Re-run after E13-S6 (2026-10-30)

Role: Red team. Re-run of the 6 failed rows (their findings F-098 to F-118 fixed and re-tested in E13-S6, LD-225) and of groups D, G and K, whose stories are now Done (E6-S1, E6-S5, E8-S2, E8-S3, E5-S11, E6-S2). AT-K02, AT-K03 (E6-S3) and AT-K05 (E5-S12) still wait; group F still waits (E7, D4).

- **Copy and build.** Private copy taken at 11:26:41 (`rsync -a --exclude target --exclude larsal-shots` to /tmp/e13rr-red-copy), with its own CARGO_TARGET_DIR and derived data. `scripts/build-core.sh` (debug), `cargo build --release -p larsal-cli`, then `xcodebuild … test -skip-testing:LarsalUITests`: 342 tests in 49 suites, 3 failed in that run and are explained in AT-G02 and the notes below. `SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` did not compile, because of AutoTypeRelockTests.swift, which another agent was rewriting at 11:24 and 11:47.
- **Harnesses.** They lived only in the copy and were deleted with it: crates/larsal-ffi/tests/red_rr.rs (13 tests), 4 AT-H01 tests appended to the copy's tests/ssh.rs, macos/LarsalTests/RedATE07Tests.swift, and two Python drivers.
- **Run conditions.** The Rust runs used HOME in /tmp, no SSH_AUTH_SOCK, and `sandbox-exec` with the network denied. Nothing was shown on the owner's screen: launches were hidden and views offscreen. The general pasteboard was never used, and no real key event was sent. Every process was stopped by its PID.

**Count.** 20 rows: 10 pass, 0 fail, 7 Mac QA, 3 wait. The F-101 High is closed in this run: no call blocks on a FIFO.

| Row | Result | Proof |
|---|---|---|
| AT-B06 | pass (F-098) | `larsal db-create -p` (default target 1,000 ms) ran under 28 `yes` processes, stopped by PID: 44, 45 and 45 Argon2id iterations (11 on 2026-10-29). Unlocks took 1.34 to 1.41 s of user CPU. At normal load: 42 iterations, 1.25 to 1.47 s. Larsal's `db-info` and the reference tool's `db-info` read the same stored settings: 42, 44, 45 and 45 rounds, 64 MiB. `f_098_kdf_tuning_clock_is_the_threads_cpu_time` ok. |
| AT-E03 | pass (F-101, F-104) | **Every export** (`red_e03_every_export`): 180 exports; 1,675 calls unlocked, 1,499 after lock, 1,499 after close. 0 panics, 0 secrets in any result, error or panic, 0 calls over 5 s. The 26 secrets searched were both master passwords, every protected value and a typed marker. After lock only status, unlock failures and wizard or generator answers come back. Unlock again: "The editor is not open." **Two threads** (`red_e03_two_threads`): 2,998 calls on two threads, while a third thread locked, unlocked and asked Show every 20 ms (12 cycles): 0 panics, 0 secrets, no deadlock. **FIFOs** (`red_e03_fifo`): a FIFO at every path argument (21 exports), and the open vault's own file swapped for a FIFO (check_disk, save, resolve_disk Reload and Merge, write_recovery_copy, lock, unlock, check_header, close). Every call returned, the slowest in 1.63 s, most under 1 ms; save answered "This vault's path is not a file Larsal can write." A FIFO key file on a locked vault: M06-14 at once. **Attachments:** `open_attachment` with vault 0, 999999 or u64::MAX and "x.command" now gives UnknownVault (was AskFirst). **Start-up:** `start()` on the hidden Debug Larsal with 9 hostile argument sets gave typed exits in 100 to 400 ms; a FIFO as the vault or as `--config` returned at once. **Swift:** the F-101 lock tests and F-125 pass. |
| AT-E07 | pass (F-102) | `RedATE07Tests`: the secrets were made in a separate Rust process, and the test holds them only masked. It scans every resident page that is private or writable. Counts are [password UTF-8, field UTF-8, password UTF-16, field UTF-16]: unlocked [1,1,0,0]; main Show [4,4,0,0]; Hide [1,1,0,0]; editor Show [6,4,0,0]; editor Hide [3,3,0,0]; Show again [4,1,0,0]; **after lock [0,0,0,0]; after close [0,0,0,0]** (2026-10-29: [1,0,0,0]). The editor's Show, Hide, Cancel and lock with the accessibility flag off: [0,0,0,0]. The builder's tests "F-102, AT-E07", "APP-06.11, AT-E07", "AT-E07: a Show that finishes …" and "FEA-06.12, AT-E07" pass. |
| AT-H01 | pass (F-106, F-108, F-109) | Throwaway `ssh-agent`s, listed with `ssh-add -l` every 2 ms. **Lock, Lock Everything, close:** each call returned in 33 to 70 µs. The remove-on-lock key left the system agent at 4.6 to 4.8 ms, and the ask-first key left Larsal's socket at 52 to 55 ms. The unmarked key stays (INT-06.24). **Socket changed while unlocked** (`set_ssh_agent` to B; B and off in one OK; `save_settings`): the key left the old agent A at 4.5 to 7.4 ms and never reached B (on 2026-10-29 it stayed in A with no message). **An agent that holds removals:** the lock returned in 72 µs, Larsal's own key was gone at 55 ms, one 2 s wait covered both keys, and MI06-19 names both. **Builder tests:** `cargo test -p larsal-sshagent`: 84 passed, plus `t53_t57`, which passes outside my sandbox (the sandbox also blocks its sshd on 127.0.0.1). The 19 builder tests of `larsal-ffi --test ssh` pass. |
| AT-I04 | pass (F-111, F-047) | **`larsal` tool:** a link at the vault path stays a link, and the real file gets the entry. A hard link at the vault path is left unchanged. A dangling link is refused and nothing is made. A link at an attachment export target is refused without `-f`; with `-f` Larsal writes a new 0600 file and the victim is unchanged. A path swapped after unlock: to a dangling link, saved as a 0600 file; to a link to the victim, "changed on disk … Nothing was saved". **Window app's save** (Session, backup on): with a link at the vault path the backup is a 0600 file next to the real file. Links planted at the backup name are replaced by a 0600 file, never followed. **Racing attacker** (each new temp file renamed away and a link to the victim put at its name), 3 rounds of 300 adds, 139, 12 and 14 swaps: the link reached the vault path in each round, which F-047 accepts (anyone who can write the folder can replace the vault). Each add that landed it printed "changed on disk … Nothing was saved", never "saved", and the victim was unchanged. **Settings files:** the export and the store's own file, with links at the old fixed temp names and at the target, and a 0666 file planted at a temp name: the victim was unchanged, and each result is a 0600 file with one link. |
| AT-I05 | pass (F-110) | **Two sessions on one vault:** the turn flow asks OnSave, merges and reloads. 100 races of add-and-save on two threads: 200 saves done, 225 entries on file, 0 lost (2026-10-29: 7 lost). **Processes:** 20 pairs of `larsal add` processes: 40 saved, 0 lost. 150 trials of two `larsal open` shells adding at the same instant: each time one saved and the other was told "changed on disk", 0 lost (2026-10-29: 4 lost). **Conflict copy:** our `merge -s` and the reference tool's `merge -s`, each run both ways, give the same 7 rows. |
| AT-D01 | Mac QA | Needs a real clipboard history app on the general pasteboard. On a private pasteboard, the copy carries `org.nspasteboard.ConcealedType` and `TransientType` (`red_d02_d03_clipboard`). |
| AT-D02 | pass (private named pasteboard; the general pasteboard in the real app stays with Mac QA, E6-S1) | `red_d02_d03_clipboard`, with another process (osascript JXA) reading and writing the pasteboard: our value was gone at 1.19 s for a 1 s timeout, and the other process's newer text was left alone. `larsal-platform`: 31 passed (`clear_only_while_still_ours`); `larsal-ffi --test clipboard`: 9 passed. |
| AT-D03 | pass (same) | Copy, then lock: gone. Copy, then the quit path (`lock_all`, `clear_clipboard`): gone. `app_03_15_lock_close_and_quit_clear` ok. |
| AT-D04 | Mac QA | The capture paths need a visible window. Recorded from 7 hidden `open -n -g -j` launches (LARSAL_TEST_HIDDEN): the main view window reads 0 from its first listing, and 1 with `--allow-screen-capture`. The 500×500 window AppKit makes listed 1 for one poll (0×0, off screen) in 3 of 5 locked launches, then 0; this is passed to the lead as a new observation. `ScreenProtectionTests` (10) and `ScreenProtectionListTests` pass. |
| AT-D05 | Mac QA | An event-tap logger needs Input Monitoring and real keystrokes. `SecureInputTests` (9, through the seam) pass. |
| AT-G01 | Mac QA | Needs another program's real window. With the fake window list, "AT-G01: a lookalike window gets the picker, never typing, while Always ask is on" passes, and the larsal-autotype `int05_match` hostile titles pass. |
| AT-G02 | Mac QA | Needs real typing into a real window. With the fake sink, "AT-G02 T90, T91" and "LD-234 (1), AT-G02 T103" pass, and `larsal-ffi --test autotype_typing` passes 4 of 4. T74 failed in the full run because another agent was rewriting its test file; its 11:47 version passes. |
| AT-G03 | pass | `red_g03_hostile_sequences`, through the session's Auto-Type path (nothing typed): repeat counts up to 30 digits gave MI05-12; long delays gave MI05-13 and MI05-14; self references (the user name, 1,000 references, a 4^9 expansion) gave MI05-27; 40 nested braces gave the nesting error; 60 KiB of keys gave MI05-21; 5,000 unknown placeholders gave MI05-19. The slowest took 1.07 ms. The editor refuses rules over 64 KiB (TooLong). `larsal-autotype`: 106 passed. |
| AT-K01 | Mac QA | Needs a real screen lock, sleep and user switch. `LockSignalsTests` (22, through the seams) pass. |
| AT-K02 | waits | E6-S3 is todo. |
| AT-K03 | waits | E6-S3 is todo. |
| AT-K04 | pass (F-077) | `red_k04_expired_warning` on option-a-personal (1 expired entry): the first after-unlock gives `expiry_search` "is:expired-3", titled "Expired or due to expire in 3 days"; the second gives none. The Swift test "F-077, APP-01.18 a, b" passes through the real views offscreen. |
| AT-K05 | waits | E5-S12 is todo. |
| AT-K06 | Mac QA | Needs real VoiceOver. "AT-K06: every control on every built screen is named and reachable" (24 screens) and "AT-K06: the walk finds a password on screen once Show was chosen, and never before" pass. |

**Notes (not filed; the lead files and numbers any new finding).**

- Two full-run failures passed when re-run alone: FEA-01.34 (search under 50 ms, load 36) and the editor's Expires "now" check.
- In a fully silent agent, a list through Larsal's socket waits the 2 s upstream timeout. Larsal's own keys are already gone by then. My first AT-H01 probe measured that wait, and the holding proxy above is the valid measurement.
- In the copy, a failed sshd start in own_agent.rs `Sshd::start` left one sshd running (PID 78076). I stopped it by its PID; it is reported to the lead.
