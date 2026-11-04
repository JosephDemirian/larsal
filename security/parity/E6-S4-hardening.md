# E6-S4 Process hardening (SR-05, AT-C03)

Story: E6-S4 Process hardening. Card: [APP-11](../../spec/app/APP-11-hardening.md). Decision: LD-174.
Date: 2026-10-28.
Role: Verify. I did not build or review this story. No reference access was needed, and none was used.
Result: **signed.**

- **Release builds:** the core limit is 0/0, and attach is refused with EBUSY plus SIGSEGV. The control without the call gets EPERM. Proven in the larsal-platform tests under `--release`, in the real Release `Larsal.app` started hidden, and in the release `larsal` tool.
- **Debug builds:** they skip both steps. The core limit is left as inherited, no deny flag is set, and the Debug bundle carries `get-task-allow`.
- **Self-test:** it passes. All nine expected values match libgcrypt 1.12.1. Three match the RFC texts byte for byte, and six also match a second implementation.
- **Signature:** the Release bundle shows `flags=0x10002(adhoc,runtime)` and has no entitlements at all. `DYLD_INSERT_LIBRARIES` is ignored.
- **Not run here:**
  - **lldb checks and the forced crash** wait for Mac QA (AGENTS.md rule 10, LD-174).
  - **APP-11.10-b** needs a test build (section 5).

## Setup

- **Sources.** Rust tests ran in the project with `CARGO_TARGET_DIR=/tmp/v-e6s4-target`.
- **Isolated copy for the app builds.** Another agent was running `scripts/check.sh`, which writes `target/larsal-core` and `macos/LarsalCore/Generated`. So the app builds ran in a copy, made with `rsync -a --exclude target` to `/tmp/v-e6s4-src`, whose `target` links to `/tmp/v-e6s4-target`. `diff -rq` printed `crates identical`, `vendor identical`, `macos identical` and `scripts identical`, and `cmp` printed `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml identical`.
- **Builds.**
  - In the copy, with `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`: `scripts/build-core.sh --release` (`build-core (release): target/larsal-core/LarsalFFI.xcframework ...`), then `xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -configuration Release -destination platform=macOS -derivedDataPath /tmp/v-e6s4-xcode build` (`** BUILD SUCCEEDED **`).
  - For the debug checks: `scripts/build-core.sh`, then the same command with `-configuration Debug`.
  - `cargo build --release -p larsal-cli` and `cargo build -p larsal-cli`.
- **Tools.** cargo and rustc 1.99.1, macOS 26.6, libgcrypt 1.12.1, OpenSSL 4.0.3, Python 3.9.6 `hashlib` (LibreSSL 2.8.3).
- **Mac settings.** The shell defaults are soft core limit `0` and hard limit `unlimited`. `sysctl` shows `kern.coredump: 1` and `kern.corefile: /cores/core.%P`, so a process with a core limit above 0 can dump. Correction (E1-S5 Verify, V-A11-8, 2026-10-28): on this Mac no process wrote a core dump without the debug entitlement, with or without the hardened runtime, so the core limit 0 of step 2 is defence in depth here, not the only guard.
- **Hidden runs (AGENTS.md rule 10).**
  - Larsal was started with `--password-stdin a.larsalvault` and stdin on a FIFO that was never written. It stops at `Vault password:`, after hardening (step 1) and the self-test (step 9), before any window. It never reached AppKit's run loop.
  - Each run was ended with `kill -KILL <pid>`, by the PID it was started with (rule 11). SIGKILL makes no crash report.
  - Demo vault: a copy of `testdata/password-only.larsalvault`.
  - Afterwards: no Larsal process was left, `/cores` held 0 files, and none of my runs made a crash report.
- **Probes**, written in `/tmp/v-e6s4-work` (product code unchanged):
  - `attach.c` installs a SIGSEGV handler, calls `ptrace(PT_ATTACHEXC, pid, 0, 0)`, and prints `attach <rc> <errno> <SIGSEGV seen>`. It would detach at once if an attach ever succeeded.
  - `inject.dylib` is a demo library. When loaded, it writes `/tmp/v-e6s4-work/injected-<pid>.txt` with `getrlimit(RLIMIT_CORE)` at load time and again 1.5 s later, after start-up.

## 1. Release Rust builds: core limit 0/0, attach refused

`cargo test --release -p larsal-platform` printed `test result: ok. 15 passed; 0 failed; 3 ignored`. Among them:

```
test hardening::tests::app11_4_a_failed_core_limit_still_denies_attach ... ok
test macos::process::tests::app11_2_core_limit_is_zero_and_cannot_be_raised ... ok
test macos::process::tests::app11_3_deny_attach_refuses_ptrace_attach ... ok
test macos::process::tests::app11_5_harden_follows_the_build_kind ... ok
```

The raw values come from the child-process cases. The release test binary's `hardening_target_child` was started per role, and `hardening_attacher_child` attached to it. The shell was set to `ulimit -c unlimited` (soft and hard), and `9223372036854775807` is unlimited.

```
role=plain  core_limit(soft hard)=9223372036854775807 9223372036854775807 attach(rc errno sigsegv)=-1 1 false
role=deny   core_limit(soft hard)=9223372036854775807 9223372036854775807 attach(rc errno sigsegv)=-1 16 true
role=core   core_limit(soft hard)=0 0 attach(rc errno sigsegv)=-1 1 false
role=harden core_limit(soft hard)=0 0 attach(rc errno sigsegv)=-1 16 true
```

- **Control (`plain`):** EPERM (1), no SIGSEGV.
- **Deny-attach (`deny`):** EBUSY (16) plus SIGSEGV.
- **`harden()` in a release build:** both effects. The core limit is 0/0, and the `core` child also failed to raise it again (the `setrlimit` to 1 returned -1).

## 2. Debug builds stay debuggable

`cargo test -p larsal-platform` (debug) printed `test result: ok. 15 passed; 0 failed; 3 ignored`, with the same four tests ok. In the debug build, `app11_5_harden_follows_the_build_kind` asserts the debug branch: the limit is unchanged and attach is not refused.

The same roles with the debug test binary:

```
shell: soft=unlimited hard=unlimited
role=plain  core_limit=9223372036854775807 9223372036854775807 attach=-1 1 false
role=harden core_limit=9223372036854775807 9223372036854775807 attach=-1 1 false
shell: soft=0 hard=unlimited
role=harden core_limit=0 9223372036854775807 attach=-1 1 false
```

The Debug `Larsal.app` built for this check:

- **Signature:** `Identifier=app.larsal.desktop.debug`, `flags=0x10002(adhoc,runtime)`, and the entitlement `com.apple.security.get-task-allow` set to `true`.
- **Hidden run** (`LARSAL_TEST_HIDDEN=1`, `LARSAL_TEST_INSTANCE_DIR` set to a private folder): `attach -1 1 false`, the same EPERM as the control. So no deny flag is set. The unentitled probe gets EPERM from the system's code-signing policy. lldb, which has the debugger entitlement, can attach thanks to `get-task-allow`; an lldb run is for Mac QA.
- **Core limit inside the debug Larsal.** I used a copy re-signed ad hoc without the runtime flag, so that the probe library can load:

```
loaded core soft=9223372036854775807 hard=9223372036854775807
after-start core soft=9223372036854775807 hard=9223372036854775807
```

Debug builds leave the core limit alone (APP-11.2-b, without the crash).

## 3. Crypto self-test (APP-11.10)

`cargo test -p larsal-crypto --lib selftest`, in both debug and `--release`, printed `test result: ok. 3 passed` each time:

```
test selftest::tests::app11_10_d_every_check_passes ... ok
test selftest::tests::app11_10_each_wrong_answer_stops_the_run_at_that_check ... ok
test selftest::tests::app11_10_the_whole_test_takes_under_10_ms ... ok
```

The last test asserts that the fastest of five runs takes under 10 ms. In the copy, `cargo test -p larsal-ffi --lib app11_10` printed `test start::tests::app11_10_self_test_passes_and_m11_02_names_the_check ... ok`.

**The nine expected values.** Each value was taken from `crates/larsal-crypto/src/selftest.rs` by script and compared with:

1. A C program on libgcrypt 1.12.1. It ran the same inputs, then decrypted each cipher result back to the plaintext; all came back as plaintext.
2. A second implementation where one exists: Python `hashlib`/`hmac`, and the OpenSSL 4.0.3 command line (`enc -aes-256-cbc -nopad`, `-aes-256-ecb -nopad`, `-chacha20`).
3. The published text, for three of them. RFC 7539, RFC 4231 and RFC 9106 were downloaded from rfc-editor.org (read only). Each value was cut out of the RFC by script and compared as a string.

| Check | Value in code | libgcrypt | 2nd impl. | Published source |
|---|---|---|---|---|
| SHA-256 | `248d6a61…19db06c1` | MATCH | Python: same | FIPS 180-2 B.2 (value as published; document not downloaded) |
| SHA-512 | `204a8fc6…38ca3445` | MATCH | Python: same | (see note 1) |
| AES-256-CBC | `f58c4c04…bc6702c7d` | MATCH, decrypts back | OpenSSL: same | SP 800-38A F.2.5 blocks 1 and 2 (value as published; document not downloaded) |
| AES-KDF, 1 round | `8ea2b7ca516745bfeafc49904b496089` | MATCH, decrypts back | OpenSSL ECB: same | FIPS-197 C.3 (value as published; document not downloaded) |
| Twofish-256-CBC | `e0227c3c…ae37c3a0` | MATCH, decrypts back | none | the reference's value; confirmed by libgcrypt |
| Salsa20 | `b4c0afa503be7fc29a62058166d56f8f` | MATCH, decrypts back | none | the reference's value; confirmed by libgcrypt |
| ChaCha20 | `76b8e0ad…b2ee6586` (64 bytes) | MATCH, decrypts back | OpenSSL: same | **RFC 7539 A.1 vector 1: MATCH** |
| HMAC-SHA-256 | `b0344c61…2e32cff7` | MATCH | Python: same | **RFC 4231 4.2 test case 1: MATCH** |
| Argon2id | `0d640df5…6b01e659` | MATCH | none | **RFC 9106 5.3 tag: MATCH** |

The RFC comparison printed:

```
ChaCha20 RFC7539-A.1-TV1  rfc=76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586  code=<same>  MATCH
HMAC-SHA-256 RFC4231-TC1  rfc=b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7  code=<same>  MATCH
Argon2id RFC9106-5.3  rfc=0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659  code=<same>  MATCH
```

The inputs in the code also match the RFCs:

- **ChaCha20:** key and nonce all zero, counter 0, 64 bytes.
- **HMAC-SHA-256:** key 20 × `0b`, data `Hi There`.
- **Argon2id:** m = 32 KiB, t = 3, p = 4, version 0x13, password 32 × `01`, salt 16 × `02`, secret 8 × `03`, associated data 12 × `04`, tag 32 bytes.

Note 1 (wording only, not a failure): the SHA-512 comment in `selftest.rs:24` calls its value a "FIPS 180-2 example", but FIPS 180-2's own SHA-512 examples use `abc` and an 896-bit message. The value for this 56-byte message is right: libgcrypt and Python agree.

## 4. Larsal level: Release Larsal.app

**Signature (APP-11.6-a; the E6-S4 check "`codesign -dv` shows the hardened runtime flag"):**

```
$ codesign -dv --verbose=4 /tmp/v-e6s4-xcode/Build/Products/Release/Larsal.app
Identifier=app.larsal.desktop
Format=app bundle with Mach-O thin (arm64)
CodeDirectory v=20500 size=14992 flags=0x10002(adhoc,runtime) hashes=462+3 location=embedded
Signature=adhoc
Runtime Version=27.0.0
$ codesign -d --entitlements - .../Larsal.app
Executable=/private/tmp/v-e6s4-xcode/Build/Products/Release/Larsal.app/Contents/MacOS/Larsal
$ codesign --verify --strict --verbose=2 .../Larsal.app
.../Larsal.app: valid on disk
.../Larsal.app: satisfies its Designated Requirement
```

- The entitlements are empty. So there is no `get-task-allow` and none of the six never-present entitlements.
- The bundle holds one executable, `Contents/MacOS/Larsal` (Mach-O arm64).
- `nm -u` lists `_ptrace` and `_setrlimit`, and no `_getrlimit`: the test-only call is not in the release build.
- `strings` finds 0 `LARSAL_TEST` strings, so the release binary carries no test switch (APP-11.5). It does hold the texts of M11-01 and M11-02.

**Hidden runs of the real Release binary.** The shell had `ulimit -c unlimited`.

```
$ Larsal --version
Larsal 0.1.0
exit=0

[release-hardened] shell core limit: soft=unlimited hard=unlimited
[release-hardened] pid=80484 stdout=Vault password:
80484 S    .../Release/Larsal.app/Contents/MacOS/Larsal --password-stdin /tmp/v-e6s4-work/a.larsalvault
attach -1 16 true
[release-hardened] Larsal still running after the attach attempt
[release-hardened] ended by PID 80484 (SIGKILL), status 137
[release-hardened] stderr: []
[release-hardened] marker file not created
```

- **Attach is refused (APP-11.3-a at the ptrace level, AT-C03).** The running Release Larsal answers EBUSY plus SIGSEGV and keeps running.
- **Both steps succeeded.** stderr is empty, so M11-01 was not written: `setrlimit` and `ptrace` both returned 0 (`hardening.rs` writes M11-01 when either step fails).
- **The self-test passed in the real Release Larsal (APP-11.10-a).** It runs at step 9, before the password prompt, and the prompt was reached.
- **The injection was blocked (APP-11.6-b).** This run had `DYLD_INSERT_LIBRARIES=inject.dylib` set. The hardened runtime ignored it, and no marker file was made.

**The core limit inside the Release Larsal** (APP-11.2-a without the crash). The probe cannot load into the hardened bundle, so I ran a copy re-signed ad hoc without the runtime flag (`flags=0x2(adhoc)`). Its code is the same: `otool -tv` of both binaries compared equal (`text section identical to the hardened Release binary`).

```
[release-noruntime] pid=81644 stdout=Vault password:
attach -1 16 true
[release-noruntime] stderr: []
marker injected-81644.txt:
loaded core soft=9223372036854775807 hard=9223372036854775807
after-start core soft=0 hard=0
```

**Every flag and the test variables set (APP-11.5-a):**

- Variables: `LARSAL_TEST_HIDDEN=1`, `LARSAL_TEST_INSTANCE_DIR`, `LARSAL_TEST_SELF_TEST_FAIL=1`, `LARSAL_TEST_PASTEBOARD=1`, `RUST_LOG=trace`, `RUST_BACKTRACE=1`.
- Flags: `--allow-screen-capture --minimized --config … --local-config … --password-stdin a.larsalvault`.
- Result: `attach -1 16 true`, Larsal still running, stderr empty.

**The release command line tool** (SR-05 covers it too; APP-11.1-b at the ptrace level). `larsal ls a.larsalvault` was left waiting at its prompt:

```
[cli-release] stderr-so-far=[Vault password for /tmp/v-e6s4-work/a.larsalvault: ]
attach -1 16 true
[cli-release] Larsal still running after the attach attempt
marker injected-87596.txt:
loaded core soft=9223372036854775807 hard=9223372036854775807
after-start core soft=0 hard=0
```

The tool is linker-signed without the runtime flag, so the probe loads in it and reads the limit from inside the real release binary.

**Not done: forcing a crash of Larsal.** It would show the macOS crash dialog (rule 10). The core limit 0/0 is measured inside the release process instead. With `RLIMIT_CORE` at 0 the kernel writes no core file, whatever `kern.coredump` says.

**Not done: lldb.** It can raise the developer-tools prompt (LD-174). The probe uses the raw `ptrace` call, which the kernel answers without any prompt.

## 5. Not provable now: APP-11.10-b and APP-11.10-c

- **APP-11.10-b (window app, wrong self-test answer): not provable.**
  - `larsal-ffi` has no fault hook: `crypto_self_test()` (`crates/larsal-ffi/src/start.rs:234`) always runs the real check. `selftest::run_with` (`crates/larsal-crypto/src/selftest.rs:82`) is private.
  - **What is needed:** a debug-only hook in `larsal-ffi`, like the command line tool's `LARSAL_TEST_SELF_TEST_FAIL` (`crates/larsal-cli/src/main.rs:100`). Then a hidden debug Larsal run with `LARSAL_TEST_INSTANCE_DIR` set, which skips the alert, should show M11-02 naming SHA-256 on stderr, exit 1, no window and no vault read.
  - Today the unit test `app11_10_self_test_passes_and_m11_02_names_the_check` covers only the M11-02 text.
- **APP-11.10-c (command line tool): not provable as the card states it**, because no release test build exists. Release builds have no hook, by design (APP-11.5). The existing debug hook shows the behaviour:

```
debug   larsal ls a.larsalvault, LARSAL_TEST_SELF_TEST_FAIL=1: exit=1 stdout=[] stderr=[Larsal cannot start: a self-check of its encryption code failed. SHA-256 gave a wrong answer.]
release larsal ls a.larsalvault, LARSAL_TEST_SELF_TEST_FAIL=1: exit=1 stdout=[] stderr=[Vault password for /tmp/v-e6s4-work/a.larsalvault: app: Wrong password, key file or security key. ...]
```

In the debug build: M11-02, exit 1, no password prompt. The release build ignores the variable: it passes the self-test, shows the prompt, and gets an empty password from `/dev/null`.

## Card cases

| Case | Status here |
|---|---|
| APP-11.1-a | Not run: needs a release test build that logs the start steps. Code read: `harden()` comes first in `larsal-ffi` `start()` (`start.rs:79`) and in the tool (`larsal-cli/src/main.rs:25`); before it, Swift calls only `coreIsDebug()` |
| APP-11.1-b | Proven at the ptrace level (release tool at its prompt: EBUSY plus SIGSEGV). The lldb form is for Mac QA |
| APP-11.2-a | Limit 0/0 measured inside the release Larsal and the release tool, started from a shell with `ulimit -c unlimited`. `kill -SEGV` not done (rule 10) |
| APP-11.2-b | Proven without a crash: the debug Larsal keeps unlimited/unlimited |
| APP-11.3-a | Proven at the ptrace level on the running Release Larsal; Larsal keeps running. The lldb form is for Mac QA |
| APP-11.3-b | For Mac QA (lldb) |
| APP-11.3-c | No deny flag in debug (EPERM like the control, not EBUSY), and `get-task-allow` is present. A successful lldb attach is for Mac QA |
| APP-11.4-a | Proven: `app11_4_a_failed_core_limit_still_denies_attach`, debug and release |
| APP-11.5-a | Proven at the ptrace level with every flag and all test variables set; 0 `LARSAL_TEST` strings in the release binary |
| APP-11.6-a | Proven: `flags=0x10002(adhoc,runtime)`, no entitlements |
| APP-11.6-b | Proven: `DYLD_INSERT_LIBRARIES` ignored, no marker |
| APP-11.10-a | Proven: the Release Larsal and the release tool pass the self-test and reach their prompts; under 10 ms by test |
| APP-11.10-b | Not provable now (section 5) |
| APP-11.10-c | Not provable as stated; the debug hook shows the behaviour (section 5) |
| APP-11.10-d | Proven: `app11_10_d_every_check_passes`; values confirmed in section 3 |
| APP-11.7-a, .8-a, .9-a to .9-c, .11-a | Not part of E6-S4 (E6-S6 and E14-S3 cover them) |

## For Mac QA (with the owner's go, LD-174)

- **APP-11.1-b and APP-11.3-a:** `lldb -p <pid>` on the release tool and on the Release Larsal.
- **APP-11.3-b:** `lldb Larsal`, then `run`, on a copy signed without the runtime flag; expect exit status 45.
- **APP-11.3-c:** `lldb -p <pid>` on the Debug Larsal.
- **AT-C03 crash half (optional):** `kill -SEGV` on the Release Larsal, then `ls /cores` shows no `core.<pid>`. This shows the crash dialog.

## Notes (do not block signing)

- **Note 1 above:** the citation for the SHA-512 value.
- **For the APP-11.7-a check, not this story:** besides the debug-only test variables, the code reads `HOME` (`crates/larsal-ffi/src/session.rs:831`) and the tool reads `TZ` (`crates/larsal-cli/src/zone.rs:23`). Neither touches hardening.
- **Crash reports from another test:** during this work, `~/Library/Logs/DiagnosticReports` got a SIGQUIT crash report from the debug test binary's `macos::terminal::tests::prompt_child` (the app09_16 test). It came from the other agent's check run in the project, not from my runs. That test leaves one report file per run. There is no dialog, because it is not a window app.

## Cleanup and cost

- **Removed:** `/tmp/v-e6s4-target`, `/tmp/v-e6s4-xcode`, `/tmp/v-e6s4-src`, `/tmp/v-e6s4-work` and `/tmp/v-e6s4-dl`.
- **Left alone:** the stale release instance files in the per-user temp folder (`app.larsal.desktop.lock` and `.sock`) existed before this run. Larsal's next start takes them over.
- **CPU time:** about 21 minutes in total (user plus system), most of it the release core build (10.4 min). Wall time was about 15 minutes.
