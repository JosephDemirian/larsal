# APP-11 Process hardening

Status: reviewed
Epics: E6-S4, E6-S6, E14-S3
Parity rows: SR-05, SR-07, SB-01

## What it does

At start, before it touches any secret, a release build of Larsal turns off core dumps and tells the macOS kernel to refuse debugger attach. It then runs a quick self-test of its crypto code against known answers and refuses to start if one fails. While it runs, key material sits in memory that is wiped when released and locked so it never goes to swap. The signed bundle uses the macOS hardened runtime, which blocks library injection through environment variables and the loading of foreign libraries. Debug builds skip the start-up steps so developers can debug and the memory attacks of E6-S6 can be run.

What runs first in the window app is APP-09.1. Which values are secret is FMT-04.19. Clearing secrets on lock is APP-02. Signing and notarization are E14 (SB-01, AT-J05).

## Inputs and outputs

- In: build kind (release or debug); the OS calls below; the public test vectors of APP-11.10.
- Out: process limits and flags set; a warning line when a step fails (M11-01); a fatal error and exit 1 when the self-test fails (M11-02); locked, wiped memory for key material.

### What is applied, macOS

| Step | macOS call (public API) | Effect | Release | Debug |
|---|---|---|---|---|
| No core dumps | `setrlimit(RLIMIT_CORE)` with soft and hard limit 0 | No core file, even when the launching shell allowed them; child processes inherit 0; the process cannot raise it again | yes | no |
| Deny debugger attach | `ptrace(PT_DENY_ATTACH, 0, 0, 0)`, request number 31 | Later attach by ptrace-based tools (lldb, gdb) is refused; if the process is being traced when it makes the call, the kernel ends it with exit status 45 (ENOTSUP) | yes | no |
| Hardened runtime | Code signing option `runtime`, minimal entitlements (APP-11.6) | dyld ignores `DYLD_*` variables; only Apple-signed or same-team libraries load; other non-root processes cannot get the task port | yes (signed builds) | no |
| Crypto self-test | Larsal code (APP-11.10) | Start refused when a primitive gives a wrong answer | yes | yes |
| Locked key memory | `mlock` and `munlock` on pages that hold key material (APP-11.9) | Key pages never written to swap | yes | yes |

### Messages

| ID | Where | When | Text (Larsal) |
|---|---|---|---|
| M11-01 | stderr and the debug log | A step of APP-11.2 or APP-11.3 failed; or `mlock` refused to lock key pages (APP-11.9; once per process; Decided: spec/decisions.md LD-193 (4)) | Process protection could not be fully applied. |
| M11-02 | Window app: modal error, title "Larsal - Error". Command line tool: stderr | A self-test answer is wrong | Larsal cannot start: a self-check of its encryption code failed. Then the name of the failed check, for example "SHA-256 gave a wrong answer." |

## Rules

APP-11.1 **Which binaries, and when.** Release builds of the window app and of the `larsal` command line tool (INT-10) apply APP-11.2 and APP-11.3 as the first action of the process, before reading flags, standard input, settings or files. The browser bridge host (INT-01) does the same (D-APP11-1). Reference: the window app applies them after flag parsing, the single-instance check and its self-test, but before any password is read or vault opened; its command line tool applies them after its self-test and before its command runs; its browser bridge helper applies none.

APP-11.2 **No core dumps.** Set the core file size limit, soft and hard, to 0. Same as the reference on macOS.

APP-11.3 **Deny debugger attach.** Call `ptrace` with `PT_DENY_ATTACH` (31) and zero for the other arguments. Same as the reference on macOS.

APP-11.4 **A failed step is not fatal.** When APP-11.2 or APP-11.3 reports an error, write M11-01 once and go on starting. The steps run in the order APP-11.2, APP-11.3; a failure of the first does not skip the second. Reference: one warning line for any failure, then it goes on (D-APP11-2); its steps are chained so that a failed core-limit call skips the deny-attach call (a reference weakness Larsal does not copy).

APP-11.5 **Debug builds skip it; nothing else can.** A build with debug assertions on skips APP-11.2 and APP-11.3, so a debugger can attach and AT-C01 can dump memory. A release build has no flag, environment variable, setting or file that skips them. Debug builds never ship. Reference: the same split between debug and release builds.

APP-11.6 **Hardened runtime and entitlements.** Every executable in the release bundle is signed with the hardened runtime option. Entitlements are only those a feature needs, today the Keychain access group for quick unlock (APP-04). Never present: `com.apple.security.get-task-allow`, `com.apple.security.cs.allow-dyld-environment-variables`, `com.apple.security.cs.disable-library-validation`, `com.apple.security.cs.allow-unsigned-executable-memory`, `com.apple.security.cs.allow-jit`, `com.apple.security.cs.debugger`. Larsal has no web engine and no script engine (native Swift screens over the Rust core, LD-155) and makes no executable memory at run time, so it needs no JIT entitlement (Verified 2026-10-28, V-A11-1: the built app links neither WebKit nor JavaScriptCore and no Swift file imports them, and the E6-S4 Release bundle runs under the hardened runtime with no entitlements, which refuses memory that is both writable and executable). Until the developer account exists (decision D7), builds are signed ad hoc with the same option so these checks can run (Verified 2026-10-28, V-A11-2: the Xcode project signs with the ad hoc identity `-` and the hardened runtime on; the debug build on disk shows `flags=0x10002(adhoc,runtime)`, as E6-S4 showed for the Release bundle). Reference: signed with the runtime option; its entitlements are only its application id and a Keychain access group (observed on the installed 2.7.11 with `codesign`).

APP-11.7 **No outside code, no protection switch in the environment.** Larsal loads no plug-in and no library from a path given by the user, a setting or the environment. The screens are native views compiled into the app; Larsal shows no web content and loads no remote code (LD-155). What a release build reads from the environment, and why: the window app reads `HOME` only, to expand a typed key file path that starts with `~/` and to show the home folder as `~` in UL-PATH (APP-06); `HOME` is the home folder the login session sets, the one Finder and the shell mean by `~`, and a changed `HOME` can only change which file a `~/` path names, never a protection (that file must still be the right key). The command line tool's local times follow `TZ` through the system's time zone functions (INT-10, LD-178). Debug builds also read the test and Mac QA variables (`LARSAL_TEST_…` in Rust, `LARSAL_DEBUG_…` in the Swift debug code), each behind a debug-only guard; a release binary holds none of them (APP-11.5; E6-S4 proof: no `LARSAL_TEST` text in the release binary). Settings paths come only from flags (APP-09.5; Decided: spec/decisions.md LD-48). No environment variable can turn off a step of this card or of APP-10, raise a limit of LD-22, or make logs carry vault content. Larsal reads the per-user temporary folder from the OS, not from `TMPDIR` (APP-09.7). Reference on macOS: relies on the hardened runtime; its other environment measures are Windows-only (Not on Mac).

APP-11.8 **What the reference keeps in protected memory.** For parity proof, the reference's coverage:

| Value | How the reference holds it |
|---|---|
| Password component (the SHA-256 of the password, FMT-04.1) | Its crypto library's secure container: wiped on release, taken from a locked memory pool when one is available |
| Key file component (FMT-18), and the raw key file bytes | The component in a secure container; raw file bytes and temporary buffers wiped right after hashing |
| Hardware key response (FMT-04.10) | Secure container |
| Master seed and transformed key of an open vault (FMT-04.11) | Secure containers, kept while the vault is open so it can save |
| Cipher working buffers | Secure containers |
| Quick unlock random key and IV (APP-04) | Wiped right after use |
| Every other block freed through the language's delete operator | Wiped before release (the whole process replaces that operator) |
| Typed passwords and entry field values in its UI toolkit's text type | Not wiped: that type releases with a plain free (Verified 2026-10-28, V-A11-3: in the installed toolkit library the text buffer's release routine is a single direct call to `free`, outside the reference's replaced delete operator) |

The locked pool of its crypto library: the installed library imports `mlock`, `munlock` and `mmap`; the pool is small (at most 512 KiB by that library's default) and an environment variable of that library can shrink or turn it off (Verified 2026-10-28, V-A11-4: the installed library imports `mlock`, `munlock` and `mmap`; its pool-size routine reads that variable with a default of 512 KiB, keeps the smaller of the value and 512, turns the pool off at 0, raises the soft memory lock limit to the hard one, and uses the smaller of the two).

APP-11.9 **Larsal: every secret wiped, key pages locked.** Every secret (FMT-04.19, protected entry fields, typed passwords, generator output, one-time password secrets, passkey and SSH private keys, the quick unlock key) lives only in `SecretBytes` or `SecretString` (architecture, `larsal-crypto/secret.rs`): bytes are zeroed before the memory is released, and a buffer never grows by moving (capacity reserved up front, or the old buffer zeroed before release), so no stale copy is left behind. Key material (`P`, `F`, `R`, `C`, `T`, `K_enc`, `K_mac` of FMT-04, the field stream key of FMT-09, the quick unlock key with E6-S3) is also kept in pages locked with `mlock`; those pages are zeroed and unlocked when released. Not locked, by decision: the field stream's working state (alive only while a document is read or written), the decompressed payload that also holds the stream key (large; this rule asks for key material only), and the version 3 stream key copy in the plain header (it is in the file unencrypted) (Decided: spec/decisions.md LD-193 (6)). Every Rust allocation is also zeroed when freed, by Larsal's zeroing allocator, which covers buffers a library frees on its own (LD-193 (1) to (3)). When `mlock` fails, Larsal goes on with the memory unlocked and writes M11-01 once, without any secret (LD-193 (4)). The memory lock limit on this Mac is unlimited (observed with `ulimit -l`). This goes beyond the reference (SR-07; AT-C01, AT-C02, AT-C05).

APP-11.10 **Crypto self-test at start.** Before any vault is read (window app: APP-09.1 step 9; command line tool: before its command; bridge host: before its first message), Larsal checks these known answers through `larsal-crypto`, in this order:

| Check | Input | Expected |
|---|---|---|
| SHA-256 | the 56 ASCII bytes `abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq` (FIPS 180-2 example) | `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1` |
| SHA-512 | the same 56 bytes | `204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445` |
| AES-256-CBC, encrypt then decrypt, no padding | key `603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4`, IV `000102030405060708090a0b0c0d0e0f`, plaintext `6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51` (NIST SP 800-38A F.2.5, blocks 1 and 2) | ciphertext `f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d`; decrypting gives the plaintext back |
| AES-KDF, 1 round (CRY-02) | seed (AES key) `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`, block `00112233445566778899aabbccddeeff` (FIPS-197 C.3) | `8ea2b7ca516745bfeafc49904b496089` |
| Twofish-256-CBC, encrypt then decrypt, no padding | key, IV and plaintext as for AES-256-CBC | ciphertext `e0227c3cc80f3cb1b2ed847cc6f57d3c657b1e7960b30fb7c8d62e72ae37c3a0` (the reference's value; Verified 2026-10-28, V-A11-5: the same 32 bytes stand in the reference's self-test source, E6-S4 matched them with libgcrypt, which also decrypted them back, and Larsal's self-test with the approved Twofish crate passes, `app11_10_d_every_check_passes`); decrypting gives the plaintext back |
| Salsa20 (20 rounds), encrypt then decrypt | key `f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112`, nonce 8 zero bytes, 16 zero bytes | `b4c0afa503be7fc29a62058166d56f8f`; decrypting gives 16 zero bytes |
| ChaCha20, encrypt then decrypt | key 32 zero bytes, nonce zero, counter 0, 64 zero bytes (RFC 7539 A.1, vector 1) | `76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586`; decrypting gives 64 zero bytes |

On the first wrong answer: the window app shows M11-02 and exits with code 1 before any window other than the error appears; the command line tool and the bridge host write M11-02 to stderr and exit 1. The test uses only these public values, holds no secret and must finish in under 10 ms on this Mac (Verified 2026-10-28, V-A11-6: `app11_10_the_whole_test_takes_under_10_ms` passed, fastest of five runs, in a debug build). Reference: the same seven checks in the same order (plus a minimum-version check of its crypto library), the same fatal outcome. Larsal also checks HMAC-SHA-256 (RFC 4231 test case 1: key 20 bytes of `0b`, data `Hi There`, expected `b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7`) and one Argon2id vector from CRY-02.29 (D-APP11-3).

APP-11.11 **Crash output holds no secret.** Release builds abort on panic (architecture, release profile). With core dumps off (APP-11.2) the only crash output is the macOS crash report (thread stacks, registers, loaded images), which Larsal cannot turn off. Panic messages, crash report text and logs never contain a secret value (Rust rules 3 and 9; AT-C04, AT-C06). Reference: nothing beyond core dumps.

## Edge cases and errors

- **Started under a debugger** (release build without hardened runtime, launched from lldb): the kernel ends the process at APP-11.3 with exit status 45. With the hardened runtime the debugger cannot launch it at all. Both are expected.
- **Attach attempt later:** `lldb -p <pid>` fails; Larsal keeps running. An administrator can still get around both steps (out of scope, plan/security.md).
- **System tracing tools:** the deny-attach flag is also reported to block DTrace on the process (needs Mac QA (owner's go), V-A11-7: DTrace needs administrator rights, which agents do not use).
- **Shell with `ulimit -c unlimited`:** Larsal still sets 0 (APP-11.2); a forced crash writes no file to `/cores`.
- **macOS defaults on this Mac (26.6):** soft core limit 0, hard limit unlimited, core dumps on in the kernel with files in `/cores`. Without APP-11.2 any process could raise its own soft limit and dump. Whether macOS dumps a hardened-runtime process without the debug entitlement at all: it does not (Verified 2026-10-28, V-A11-8: three demo probes raised their soft core limit to the hard limit and crashed with SIGSEGV, signed ad hoc without the runtime, with the runtime, and with the runtime plus `com.apple.security.get-task-allow`; only the last wrote a file to `/cores`, 5.8 GB, deleted at once). So on this Mac a process without the debug entitlement wrote no core file; APP-11.2 stays as a second guard.
- **`mlock` limit reached or refused:** go on unlocked, one warning (APP-11.9).
- **Self-test failure in a debug build:** same outcome as release (APP-11.10).
- **The command line tool waiting at a password prompt:** already hardened (APP-11.1).

### Lead decisions

All decided as recommended in spec/decisions.md LD-174 (`libc` for D-APP11-4 signed in LD-157).

- **D-APP11-1 The browser bridge host.** (a) Harden it like the app; (b) leave it bare, as the reference does. Recommend (a): two system calls, and it handles encrypted traffic.
- **D-APP11-2 A failed hardening step.** (a) Warn and go on, as the reference does; (b) refuse to start. Recommend (a): both calls fail only in odd setups, and refusing would lock the user out of their vault.
- **D-APP11-3 Self-test additions.** (a) The reference's seven checks only; (b) also HMAC-SHA-256 and one Argon2id vector. Recommend (b): both are cheap and cover primitives Larsal relies on.
- **D-APP11-4 The C library calls.** `setrlimit`, `ptrace`, `mlock` and `munlock` need the `libc` crate in `larsal-platform/macos/` (the only place `unsafe` is allowed there). `libc` is not in the approved crates table; adding it needs an AT-J03 review and a new line (architecture, Approved crates).

### Not on Mac

- Linux: the process is also marked not dumpable, which also stops same-user ptrace and memory reads through the proc file system; skipped in snap packages because it breaks desktop portals.
- Windows: the process access list lets the user only wait on, query limited information of and end the process, and gives owner rights read access only (plus limited query and handle duplication for the system account when the SSH agent is built); this blocks memory reads and crash dumps by other non-admin processes.
- Windows: DLL search hardening (no DLLs from the current folder, safe search mode).
- Windows: three OpenSSL environment variables are set to an invalid location at start to block configuration and module injection (source only; not in the 2.7.11 tag, differs in installed version).
- Windows and Linux: the zero-on-release of freed memory uses each platform's way to learn a block's size; where none exists, memory is freed unwiped.

## Security notes

- **SR-05, AT-C03:** debugger attach denied and no core dumps in release builds. Must never happen: a release build that a same-user debugger can attach to, or that writes a core file.
- **SR-07, AT-C01, AT-C02, AT-C05:** key material in locked memory and every secret wiped. Must never happen: a demo master password, entry password or derived key found in a memory dump after lock or after Hide.
- **SB-01, AT-J05:** hardened runtime with no debug, dyld-environment, library-validation or JIT exceptions. Must never happen: a release bundle with `get-task-allow`.
- **The order matters** (APP-11.1): a password read before hardening could land in a core file or be read by a debugger.
- **No switch** (APP-11.5, APP-11.7): a hidden flag or environment variable that turns hardening off would be the first thing an attacker uses.
- **Self-test** (APP-11.10): a broken or miscompiled primitive must stop Larsal before it writes a vault nobody can open, or one that is weakly encrypted.
- **Out of scope:** an administrator, kernel extensions, a disabled System Integrity Protection.

## Test cases

`APP` stands for the window binary `Larsal.app/Contents/MacOS/Larsal`; `CLI` for the `larsal` tool. Demo vault `/tmp/spec-app11/a.larsalvault`, password `demo-pass-a`, entry "Demo Bank" with password `demo-bank-1`.

| Case | Given | When | Then |
|---|---|---|---|
| APP-11.1-a | A release test build that logs the time of each start step | Start `APP a.larsalvault` | Hardening logged before flag reading and before any file read |
| APP-11.1-b | Release build | `CLI` waiting at its password prompt; `lldb -p <pid>` | Attach refused |
| APP-11.2-a | Release build launched from a shell with `ulimit -c unlimited`, `a` unlocked | `kill -SEGV <pid>`; `ls /cores` | No `core.<pid>` file |
| APP-11.2-b | Debug build, same shell | Same | Core limit not changed by Larsal (a core file may appear; delete it, demo data only) |
| APP-11.3-a | Release build running | `lldb -p <pid>` | Attach fails; Larsal still running and usable |
| APP-11.3-b | Release build signed ad hoc without the runtime option | `lldb APP`, then `run` | Process exits with status 45 |
| APP-11.3-c | Debug build running | `lldb -p <pid>` | Attach succeeds |
| APP-11.4-a | Unit test with a fake platform whose core-limit call fails | Run the hardening step | M11-01 written once; deny-attach still called; start goes on |
| APP-11.5-a | Release build | Start with every Larsal flag and any environment variables set; then `lldb -p <pid>` | Attach always refused |
| APP-11.6-a | Release bundle | `codesign -dv --verbose=4 Larsal.app` and `codesign -d --entitlements - Larsal.app` | Flags include `runtime`; no entitlement from the never-present list |
| APP-11.6-b | Release bundle; a demo library that writes `/tmp/spec-app11/injected` when loaded | `DYLD_INSERT_LIBRARIES=<demo library> APP` | Larsal starts; the marker file is not created |
| APP-11.7-a | Code search | Search for environment reads and dynamic library loading | Release code reads only `HOME` (window app, for `~/` key file paths and UL-PATH) and `TZ` through the system's time functions (tool); every other read (`LARSAL_TEST_…`, `LARSAL_DEBUG_…`) is behind a debug-only guard or in test code; no library loading by path |
| APP-11.8-a | The reference source (Verify role) | Re-read its memory handling for each table row | Every row confirmed or corrected in the parity evidence for SR-07; the toolkit text row confirmed (Verified 2026-10-28, V-A11-9: every row matches the source: the password, key file and hardware key parts and the master seed and transformed key in the crypto library's secure containers, raw key file bytes wiped after hashing, cipher buffers in secure containers, the quick unlock key and IV wiped after use, the replaced delete operator wiping before it frees, and the toolkit text row as in V-A11-3) |
| APP-11.9-a | Debug build | Unlock `a`, show `demo-bank-1`, hide it, lock; dump memory; search for `demo-pass-a`, `demo-bank-1` and the derived key | None found (AT-C01, AT-C02) |
| APP-11.9-b | Debug build with a test hook that reports page lock results | Unlock `a` | Pages holding `T`, `K_enc` and `K_mac` report locked (AT-C05) |
| APP-11.9-c | Unit test: a `SecretBytes` grown from 16 to 4,096 bytes through a tracking allocator | Release it | Every block handed back to the allocator was all zero |
| APP-11.9-d | Debug build, memory lock limit 0 (`RLIMIT_MEMLOCK` 0) | Unlock `a` | `a` unlocks; M11-01 written once on stderr; no secret in it (LD-193 (4); test `app11_9_refused_locks_still_unlock_with_one_warning`) |
| APP-11.10-a | Release build | Start `APP` | All checks pass; start time added by the test under 10 ms |
| APP-11.10-b | Test build whose SHA-256 check is fed a wrong expected value | Start `APP` | M11-02 naming SHA-256; exit 1; no main window; no vault read |
| APP-11.10-c | Same test build | `CLI ls a.larsalvault` | M11-02 on stderr; exit 1; no password prompt |
| APP-11.10-d | Unit test | Run each table row through `larsal-crypto` | Every expected value matches (Twofish row confirmed against the `twofish` crate) |
| APP-11.11-a | Release build, `a` unlocked | Force a panic through a test hook; read the crash report and the log | Neither contains `demo-pass-a`, `demo-bank-1` or key bytes (AT-C04) |

## How this was learned

- The reference's early start-up routine shared by its window app and command line tool: core dump limit, the Linux not-dumpable flag, macOS deny-attach, the Windows process access list and DLL search settings, the single warning line, and the release-only switch.
- The window app's and the command line tool's start-up order, and the browser bridge helper's start-up (no hardening).
- The build configuration checks that enable each call per platform, and the macOS signing script (runtime option, entitlements file); the entitlements file itself.
- The crypto self-test routine and its seven checks; the version check of its crypto library.
- The process-wide replacement of the delete operator (wipe before release), the key classes (password, key file, hardware key response) and the open vault's key data, the key file reader's buffer wiping, and the quick unlock key wiping.
- On this Mac: `codesign -dv` and `codesign -d --entitlements -` on the installed 2.7.11 (runtime flag; entitlements application id and Keychain group only); `nm -u` on the installed window binary and command line tool (both import `ptrace` and `setrlimit`) and on its crypto library (imports `mlock`, `munlock`, `mmap`); `ulimit -l`, `ulimit -c`, `ulimit -Hc`, `sysctl kern.coredump kern.corefile`; python3 for the SHA-256, SHA-512 and HMAC-SHA-256 values. The 2.7.11 tag compared with the source commit (only Windows items differ).
