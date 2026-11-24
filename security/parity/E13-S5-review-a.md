# E13-S5 Review A: unsafe blocks, crypto calls, secret conversions

Story: E13-S5, two-person review (plan/epics.md; plan/team.md: two Checkers for crypto, file format, unsafe and secret handling; plan/architecture.md Rust rules 2, 3, 6, 7 and the approved crates table; plan/security.md; plan/attacks-and-checks.md AT-C*, AT-J*).
Reviewer: Checker A. I did not read any other Checker's review file.
Date: 2026-10-29. Tree read from 00:03 to 00:24.
Scope: every id of security/parity/E13-S5-inventory.md (171 items: U-01 to U-60, C-01 to C-71, S-01 to S-69), plus my own search for missed items.
Clean room: Larsal's own code only, plus Larsal's marked changes in `vendor/ssh-key` (LD-209, the one length check in `private/ecdsa.rs`) and `vendor/zxcvbn` (LD-136, `forbid(unsafe_code)`). I did not open the reference source.
Edits: this file only. No product code changed. Probes ran in a private copy (`/tmp/e13s5-a-copy`, own target `/tmp/e13s5-a-target`), deleted at the end.

## Verdict in one paragraph

No Critical or High finding. Every SAFETY note of the 57 hand-written unsafe items is true, and no caller of a safe wrapper can cause undefined behaviour. Every crypto call uses the right primitive and checks lengths first. Every MAC and key compare is constant time. Every random value comes from the OS source through `larsal_crypto::random`, and the crypto crates are reached only through `larsal-crypto`. The one Medium finding is a paperwork gap: AGENTS.md rule 4 and API.md line 5 say only Show returns a secret, but nine exports return secrets. The deliberate exceptions need one lead decision that names them all (F1). The Low findings: Debug derives on records that carry a secret; the unenforced "one quit guard at a time" (proven by a probe); one `format!` of the Wi-Fi password; the opened-attachment folder taken from `TMPDIR`; CLI messages that print a protected title; and std's stdout buffer, which keeps a printed secret.

## How I checked

- Read each item's code in context: every file of `larsal-platform/src/macos/`, `larsal-platform/src/{memory,clipboard,lib,net}.rs`, `larsal-hwkey/src/usb/{mod,watch}.rs` and `protocol.rs`, all of `larsal-crypto/src/`, `larsal-format/src/{keys,integrity,payload,lib,buffer,keyfile}.rs` and the protected paths of `document/{read,write,encode}.rs`, the larsal-core sites (totp, breach, url, storage, text, health, generator, imports), the larsal-ffi exports (views, edit, generator, wizard, vault_settings, session, autotype, start, lib, cli), larsal-cli (commands, term, vault), larsal-sshagent agent, and the Swift holders.
- Checked these upstream contracts against the SAFETY notes from memory of the published APIs (no network): `GlobalAlloc` (default `realloc` = alloc, copy, `self.dealloc`), C11 `memset_s` (macOS `RSIZE_MAX` = `SIZE_MAX >> 1` = `isize::MAX`, so `Layout` sizes never fail), `mlock`/`munlock`, `sigaction` (`sa_mask` 0 = empty set on macOS, no `SA_SIGINFO`, so a one-argument handler is right), `confstr`, `getpeereid`, `uname`, `localtime_r`, `tcgetattr`/`tcsetattr`, `poll`, `proc_pid_rusage` (the `rusage_info_t *` cast is Apple's own usage), and the IOKit and CoreFoundation calls (Create/Copy/Get rules, `_Nullable` callback and context, callbacks run only from the scheduled run loop).
- Commands (all `. "$HOME/.cargo/env"`, `CARGO_TARGET_DIR=/tmp/e13s5-a-target`, in the private copy unless noted):
  - `cargo clippy --offline --locked -p larsal-platform --features appkit,memory,test-memory,test-signals --all-targets -- -D clippy::undocumented_unsafe_blocks -D clippy::missing_safety_doc -D clippy::unnecessary_safety_comment`: no issues, exit 0. The same for `-p larsal-hwkey --all-targets`: exit 0.
  - The same with `-W clippy::multiple_unsafe_ops_per_block` (a restriction lint, not required): 5 blocks, see F9.
  - `cargo test --offline --locked -p larsal-platform --features appkit,memory,test-memory,test-signals --lib`: 27 passed, 0 failed, 7 ignored (the child roles). It includes `freed_blocks_are_zero`, `realloc_wipes_the_old_block_when_it_grows_or_shrinks`, `app11_9_b_locked_pages_are_wired_until_the_last_guard_drops`, `app11_3_deny_attach_refuses_ptrace_attach`, `int10_29_quit_signal_is_noted_then_ends_the_process`, `app09_16_quit_signal_at_the_prompt_restores_the_terminal`, and `clipboard::tests::*` (private named pasteboard only; the tests never call `Clipboard::general()`).
  - Probe P1 (nested quit guards, test added in the copy's `signals.rs`): two `catch_quit()` guards, dropped first-in first-out. Output: `PROBE after FIFO drop: SIGTERM action is note = true, SIG_DFL = false`. See F3.
  - Probe P2 (stack, test added in the copy's `larsal-crypto`): `kdf::derive` (Argon2id 1 MiB, `scrubbed_deep`) on a thread with a set stack size, one child process per size: ok at 512, 400, 352, 320, 304, 288, 280, 272, 264, 262, 260, 258, 256 and 248 KiB, overflow at 200 and 128 KiB. Control, a 300 KiB array: overflow on 256 KiB, ok on 320 KiB. `scrubbed_deep` alone: ok at 256 KiB, overflow at 240 KiB and below. So the deep scrub really writes about 240 to 256 KiB of stack, and `derive` fits in a 256 KiB thread, half of a 512 KiB secondary-thread stack (the Swift unlock runs in `Task.detached`).
  - From the shared root (read-only): `cargo tree --offline -e normal,build -i <crate> --depth 1 --all-features` for aes, cbc, chacha20, salsa20, twofish, argon2, pbkdf2, hkdf, sha2, sha1, hmac, subtle, rand_core, zeroize, p256, ed25519-dalek, ssh-key, bcrypt-pbkdf and getrandom@0.4.3. larsal-crypto is the only Larsal crate in each. `rustls`: only larsal-platform. `ring`, `getrandom@0.2.17`: no Larsal crate directly; `cargo tree -p larsal-ffi -i ring` and `-p larsal-cli -i ring`: not in the tree. `cargo tree -p larsal-ffi -p larsal-cli -e normal -d`: no duplicated crypto crate.
  - `grep` for crypto crate paths (`sha2::`, `aes::`, `hmac::`, `subtle::`, `zeroize::`, `getrandom`, `rand_core`, and so on) in `crates` and `fuzz` outside `larsal-crypto`: none. Other random sources (`RandomState`, `rand::`, `fastrand`): none. Swift (`CryptoKit|CommonCrypto|SecRandomCopyBytes|arc4random|.random(|UUID()|SecItem|LAContext`, LarsalTests excluded): none.
  - `grep` for `unsafe|extern "C|no_mangle|export_name|static mut|transmute|#[link` in `crates` and `fuzz` outside `larsal-platform/src/macos` and `larsal-hwkey/src/usb`: only comments and the crate gates. Gates: `forbid(unsafe_code)` in every lib.rs and main.rs except larsal-platform and larsal-hwkey (`deny`, with `allow` only in `macos/mod.rs` and `usb/mod.rs`); `pasteboard.rs` carries its own `forbid`.
  - `grep` for `{:?}`, `dbg!`, `println!`, `eprintln!`, `tracing::` in product Rust: no secret is printed (hits are tests, start-up messages and an error type with a path). Swift `Logger` and `print(`: three notices, none with vault data.

### Files read, with their state

Hashes (SHA-256, first 16 hex) taken at 00:24. All match the inventory's table except the two marked as changed. The other agents' edits did not touch any item's code that I relied on.

| File | Modified | SHA-256 (16) |
|---|---|---|
| crates/larsal-platform/src/macos/memory.rs | 10-28 07:44:50 | ec6b504d580e0ce9 |
| crates/larsal-platform/src/macos/process.rs | 10-28 03:49:38 | 7f6f61efe24282dd |
| crates/larsal-platform/src/macos/pipe.rs | 10-28 05:28:55 | ba16a58e985739e4 |
| crates/larsal-platform/src/macos/signals.rs | 10-28 05:28:55 | 8fadf27d0193b4ae |
| crates/larsal-platform/src/macos/instance.rs | 10-27 15:13:05 | 4d5c4c387f39ca26 |
| crates/larsal-platform/src/macos/system.rs | 10-28 14:52:39 | 7207855c65af423e |
| crates/larsal-platform/src/macos/terminal.rs | 10-28 05:17:40 | 886586e435f223d4 |
| crates/larsal-platform/src/macos/pasteboard.rs | 10-28 04:38:58 | 8721f0801785f74f |
| crates/larsal-platform/src/memory.rs | 10-28 07:45:28 | 7b3b6f0ac5ae0e0a |
| crates/larsal-platform/src/clipboard.rs | 10-28 04:38:58 | 430197c4fa8bcb4a |
| crates/larsal-hwkey/src/usb/mod.rs | 10-28 07:25:03 | dec9a56a7a48c4ca |
| crates/larsal-hwkey/src/usb/watch.rs | 10-28 07:40:07 | 67d8a043a5f66243 |
| crates/larsal-hwkey/src/protocol.rs | 10-28 06:36:33 | 2577f680bbf4452c |
| crates/larsal-crypto/src/{secret,random,hash,mac,cipher,stream,kdf,ssh,selftest}.rs | as in the inventory | all match |
| crates/larsal-format/src/keys.rs | 10-28 07:46:00 | f46a20c4e0510504 |
| crates/larsal-ffi/src/{lib,views,edit,generator,wizard,vault_settings,session,autotype}.rs, API.md | as in the inventory | all match (hashed at 00:08) |
| crates/larsal-cli/src/commands.rs | 10-28 09:21:39 | ee52b8dd6873e346 |
| crates/larsal-cli/src/term.rs | 10-28 04:28:41 | 515d7268307792ba |
| macos/Larsal/Dialogs.swift | **10-29 00:02:48 (changed after the inventory, was c1ca0e90...)** | 40fd2b2c0f050c40 |
| macos/Larsal/MainWindowModel.swift | **10-29 00:01:53 (changed after the inventory)** | 53d73cd73d80b68a |
| macos/Larsal/{UnlockModel,UnlockView,VaultModel,EditorModel,Generator,DialogSheets,EditorPasswordField,SecretFields}.swift, Platform/ShownPasswordField.swift | as in the inventory | all match |

I read Dialogs.swift at about 00:10 and MainWindowModel.swift at about 00:12, after both changes. The version sheet (S-67) is now at Dialogs.swift:298-365.

## Findings

| # | Item | Severity | Finding | Smallest fix |
|---|---|---|---|---|
| F1 | S-33, S-35, S-36, S-37, S-38, S-39, S-40 (and S-30, S-31, S-32, S-34) | Medium | AGENTS.md rule 4 allows one exception: "the single value the user asked for with Show". API.md:5 and architecture.md:189 repeat it ("Show returns one `String`, the only secret that crosses to Swift"). In code, these also cross: the live one-time codes, once a second and with no Show (`TotpView.code`: views.rs:1156-1158 `totp_of`, `codes` up to 200 per call, `totp`, edit.rs:2092 `draft_code`); the setup screen's one-time secret (`TotpSetup.secret`, edit.rs:1988-1992); the QR module matrix (edit.rs:1190-1218, `totp_qr`, `wifi_qr`), a lossless encoding of the one-time link or the Wi-Fi password, while API.md:95 says "the text stays in Rust"; the generator's value (`Generated.value`, generator.rs:283-287); and the new or changed master password through `password()`, `repeat()` and `generate()` (wizard.rs:991-1018, vault_settings.rs:476-484). API.md:243 lists codes, `totp_setup` and `generate`, but not the QR matrix or the wizard and vault settings passwords. Each one is user-started or on screen by design, as proven apps do, so the exposure is as intended. But the "never broken" rule and its two restatements do not match the code. | One lead decision that names every allowed crossing (Show values, live codes, one-time setup secret, QR matrix, generator value, master password Show and dice), then align AGENTS.md rule 4 wording (owner's file: lead asks), API.md:5, API.md:95, API.md:243 and architecture.md:189 with it. No code change. |
| F2 | S-33, S-35, S-36, S-37 | Low | The UniFFI records that carry a secret derive `Debug` (and `Clone`, `PartialEq`): `TotpView` (views.rs:360), `TotpSetup` (edit.rs:268), `VersionView` (edit.rs:458), `Qr` (edit.rs:504). One `{:?}` would print the code, the one-time secret, an old password or the QR matrix. Rust rule 3 says no `Debug` of a secret. `Generated` already has a hand-written `Debug` that hides the value (generator.rs). Today only tests format them: edit.rs:2851 and 2935 print a `VersionView` with `{:?}` to prove that protected title, user name and URL values are absent, so those tests need the other fields to stay visible. | A hand-written `Debug` that prints `[hidden]` for `code`, `secret`, `password` and `modules` only, as `Generated` does, and keeps the other fields visible for those tests. |
| F3 | U-13, U-14, U-15 (signals.rs) | Low | `QuitGuard` says "Only one may live at a time", but nothing enforces it. A second `catch_quit()` while one lives saves `note` as the "earlier" action. Dropped first-in first-out, the guards leave `note` installed for good, so SIGINT, SIGTERM, SIGQUIT and SIGHUP are noted and never acted on for the rest of the process. No memory unsafety. Not reachable today: the callers (larsal-cli `clip` commands.rs:712, the echo-off prompt in term.rs:176 and larsal-ffi cli.rs:235) run one after another on one thread. Probe P1: `SIGTERM action is note = true, SIG_DFL = false`. | In `catch_quit`, refuse a second guard with a static `AtomicBool` swapped on entry and cleared in `Drop`, and return `Err` (callers already treat `Err` as "no guard"). |
| F4 | S-37 (edit.rs:1222-1243 `wifi_text`) | Low | The Wi-Fi password goes through plain `String`s (`esc` builds one per field and can grow) and a `format!`, then into a `SecretString`. Rust rule 3 says no `format!` with a secret. The heap copies are wiped only because the zeroing allocator (LD-133, LD-193) is installed. | Build the text with exact capacity in one `String` and wrap it at once, or record in LD-193 that `wifi_text`, like the `qrcode` crate, relies on the zeroing allocator. |
| F5 | S-53 (edit.rs:1104-1117, 1146 `open_folder`) | Low | The folder for opened attachments comes from `std::env::temp_dir()`, which reads `TMPDIR`, and the check is `mode & 077 == 0` with no owner check. `larsal_platform::macos::user_temp_dir()` exists to avoid `TMPDIR` (instance.rs:10-13). Launched by `launchd` the app gets the per-user folder, so the risk is small. With `TMPDIR` unset or shared (`/tmp`), another local user who owns `/tmp/Larsal` can swap the checked folder before the file is created. The 0600 `create_new` file stays unreadable to that user, but the default app could be handed another file. | Use `larsal_platform::macos::user_temp_dir()` and also require `meta.uid() == effective_uid()`. |
| F6 | S-21 (larsal-cli commands.rs:283, 317, 796, 813) | Low | CLI success messages and the tree listing print the entry's Title with `e.value("Title")` (for example "Changes to {title} saved." at :285), also when the Title is protected by its own flag or the vault's flags. `show` prints `(hidden)` for the same field unless asked (commands.rs:425-427). The masking is not the same everywhere (LD-207, F-060). | Use the same masked title helper as `show` (or `(hidden)`) when the Title is protected. |
| F7 | S-55 (larsal-cli term.rs:62-86 `out_pair`, `out_parts`) | Low | Values printed by `show` and attachment text go through `io::stdout()`, whose `LineWriter` buffer (a static, never freed) keeps the last line's bytes after the flush, until later output overwrites them or the process ends. The zeroing allocator never sees that block. This matters for the long-running shell mode (INT-10.47), not for one-shot commands. Reads are already unbuffered (term.rs:140-150). | Write secret values through an unbuffered `File` made from the stdout descriptor, as `input()` does for stdin. |
| F8 | U-39, U-40 (watch.rs:134, 149) | Info | The two `unsafe extern "C-unwind" fn` callbacks have no `# Safety` section. The lint does not fire because they are private. Their contract ("`context` is the `&Watching` registered in `run`") sits only in the block notes. | Add a two-line `# Safety` doc to each. |
| F9 | U-04, U-21, U-24, U-35, U-38 | Info | Five blocks hold two unsafe operations each (`clippy::multiple_unsafe_ops_per_block`): memory.rs:36, system.rs:21, terminal.rs:35, watch.rs:110, watch.rs:127. Each note covers both operations, so they are sound. | Optional: one operation per block. |
| F10 | C-02, docs | Info | architecture.md's approved table still says "lead co-sign open" for rustls (LD-197) and qrcode (LD-198), and the inventory repeats it for C-02. spec/decisions.md:220-221 records both as co-signed by the lead on 2026-10-28. API.md:243's last sentence ("Rust frees without wiping until the zeroing allocator (LD-133, E6-S6)") is stale: E6-S6 installed it (larsal-ffi lib.rs:30-32). | Update both texts. |
| F11 | C-60, S-23 (url.rs:617-620 `remember_key`) | Info | Unsalted SHA-256 of the "exact command" for a remembered Yes. No caller yet. If it is ever wired with the resolved command (placeholders expanded, maybe a password), the stored hash can be guessed offline from the settings file. | When wired: hash the unresolved command text, or use HMAC with a per-install key from `larsal_crypto::random`. |

## Every item

Verdict "sound" means the SAFETY note, the crypto use or the secret handling is right as written. Findings refer to the table above.

### Unsafe (U)

| Id | Verdict |
|---|---|
| U-01 | Sound. `Zeroing<A>` passes pointer and layout unchanged. `realloc` stays the trait default (alloc, copy, `self.dealloc`), so the old block is wiped (test `realloc_wipes_the_old_block_when_it_grows_or_shrinks`). It never allocates, panics or unwinds. `Sync` because `System` is. |
| U-02 | Sound. Pass-through. |
| U-03 | Sound. Pass-through; zeroed blocks need no wipe. |
| U-04 | Sound. `layout.size()` bytes are the caller's live block until `A::dealloc`. A zero size never reaches `memset_s` (guard in `wipe`). Two operations in one block (F9). |
| U-05 | Sound. `memset_s(ptr, len, 0, len)`: `smax == n`, and `n <= isize::MAX` = macOS `RSIZE_MAX`, so it cannot return an error; the compiler may not drop it. |
| U-06 | Sound. `sysconf` touches none of our memory; a non-power-of-two answer falls back to 16 KiB. |
| U-07 | Sound. `mlock` changes no bytes. The safe front `memory::lock` rounds to whole pages (`addr & !(page-1)`, `next_multiple_of`); no overflow for a real slice; empty slice returns `None`. Locks nest per page (test `app11_9_b_...`). |
| U-08 | Sound. `munlock` in `Locked::drop`; an error is ignored, which is right (nothing left locked). Drop order at every holder (keys.rs:28-31 `LockedKey`, edit.rs:62-66 `Saver`, edit.rs:191-196, larsal-cli vault.rs:72-76) wipes and frees before unlocking. |
| U-09 | Sound. `setrlimit(RLIMIT_CORE, {0,0})`; test `app11_2_core_limit_is_zero_and_cannot_be_raised`. |
| U-10 | Sound. `PT_DENY_ATTACH` ignores the other arguments; test `app11_3_deny_attach_refuses_ptrace_attach`. |
| U-11 | Sound. `signal(SIGPIPE, SIG_IGN)`, `SIG_ERR` checked; test `a_write_to_a_closed_socket_is_an_error_not_a_signal`. |
| U-12 | Sound. `note` does one `AtomicI32` store (lock-free on arm64 and x86_64): async-signal-safe, no errno change. |
| U-13 | Sound as memory; single-guard rule not enforced (F3). |
| U-14 | Sound. Complete `sigaction` values, empty mask, flags 0 (no `SA_SIGINFO`, so the one-argument handler is right; no `SA_RESTART`, and the readers retry `Interrupted`). Error path puts back what was changed and raises a noted signal. F3 applies. |
| U-15 | Sound. Puts back what the system returned. F3 applies. |
| U-16 | Sound. `raise` after `put_back`; the swap clears the note first. |
| U-17 | Sound. Test feature only (`test-signals`), `SIG_DFL`. |
| U-18 | Sound. `confstr` writes at most `buf.len()`; 0, 1 and too-long answers are errors; the NUL is cut. |
| U-19 | Sound. `getpeereid` on a borrowed open fd; `uid`/`gid` infer `uid_t`/`gid_t`. |
| U-20 | Sound. `geteuid`. |
| U-21 | Sound. Zeroed `utsname`; `assume_init` after 0; `text` stops at the NUL or gives empty (F9: two operations). |
| U-22 | Sound. `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` into an initialised `timespec`; the assert fails closed (LD-156 (9)). |
| U-23 | Sound. `localtime_r` writes only `tm`; `tm_zone` is never read. No Larsal code calls `setenv` (forbidden in the safe crates; none in Swift), so no data race on the zone data. |
| U-24 | Sound. `tcgetattr`, then `assume_init` after 0 (F9). |
| U-25 | Sound. `TCSAFLUSH` with a complete `termios`; on error the guard drops and a noted signal is raised. |
| U-26 | Sound. One valid `pollfd`, 100 ms; `Interrupted` retried. |
| U-27 | Sound. `BorrowedFd<'fd>` outlives `self`. Field order drops `quit` after the terminal is restored. |
| U-28 | Sound. `CFSetGetValues` into exactly `count` slots of our own immutable copy. |
| U-29 | Sound. `set_device_matching(None)`. |
| U-30 | Sound. `CFRetained::retain` of a member the set keeps alive; `set` outlives the `collect`. |
| U-31 | Sound. 8 writable bytes from `scratch` (SecretBytes), `len` 8, synchronous; a short report is `Failed`. |
| U-32 | Sound. Reads exactly 8 bytes through a const pointer. |
| U-33 | Sound. Read of an immutable extern static. |
| U-34 | Sound. Array of `CFDictionary<CFString, CFNumber>`. |
| U-35 | Sound. Callbacks are registered before scheduling and run only inside `run_in_mode` on this thread; unscheduled and cleared before `watching` drops (locals drop in reverse: `watching` goes before `manager`). The context is only read as `&Watching`. A sink panic aborts in release (`panic = "abort"`). F9 applies. |
| U-36 | Sound. This thread's run loop and mode. |
| U-37 | Sound. Same run loop and mode; no callback after it. |
| U-38 | Sound. `None` callbacks and null context are `_Nullable` (F9). |
| U-39 | Sound (block). The context really is the registered `&Watching`; `known` addresses cannot be reused while `present` holds them. Missing `# Safety` doc (F8). |
| U-40 | Sound (block); as U-39 (F8). |
| U-41 | Sound. Test feature only. Reads only through `memmem`/`memcmp` within the block; the same pointer and layout are passed on. |
| U-42 | Sound. `proc_pid_rusage(getpid(), RUSAGE_INFO_V2, &zeroed)`, Apple's documented cast. |
| U-43 | Sound. A freed block's address is only compared; new blocks are read only while ours. |
| U-44 | Sound. Contract passed on. |
| U-45 | Sound. Contract passed on. |
| U-46 | Sound. Test. |
| U-47 | Sound. Test (does not check `shrunk` for null before reading; harmless in a test). |
| U-48 | Sound. Test, in a child process. |
| U-49 | Sound. Test. |
| U-50 | Sound. Test. |
| U-51 | Sound. Test; atomic store only. |
| U-52 | Sound. Test. |
| U-53 | Sound. Test; target is the test's own child, ended by its PID. |
| U-54 | Sound. Test, in a child. |
| U-55 | Sound. Test. |
| U-56 | Sound. Test; fresh descriptors from `openpty`. |
| U-57 | Sound. Test. |
| U-58 | Sound as far as Larsal controls it. Generated UniFFI 0.32.2 scaffolding (LD-157); `forbid(unsafe_code)` refuses hand-written unsafe in larsal-ffi; every object handle is an `Arc` the generated Swift owns. |
| U-59 | Sound. `LarsalEvents` and `AutoTypeFocus` are `Send + Sync` on the Rust side. The Swift sides (`WindowEvents`, Front.swift:13; `FocusCheck`, AutoType.swift:52) are `nonisolated`, hold only immutable `let`s, and hop to the main actor for UI work. |
| U-60 | Sound. Safe statics installing `Zeroing(System)` in larsal-ffi (lib.rs:30-32) and larsal-cli (main.rs:25-27); rest on U-01 to U-05. |

### Crypto (C)

| Id | Verdict |
|---|---|
| C-01 | Sound. larsal-crypto/Cargo.toml is the only manifest naming them; versions pinned with `=` in the workspace as the approved table says; `zeroize` features on for every state type, with compile-time `ZeroizeOnDrop` checks (hash.rs:64-69, kdf.rs, mac.rs). `cargo tree -i`: larsal-crypto only. |
| C-02 | Sound. rustls on ring, TLS 1.3 and 1.2 only, platform verifier with an empty extra-root list in product (`with_anchors` is `#[cfg(test)]`); feature `net` is on in no product crate. LD-197 is co-signed (F10: stale text says open). |
| C-03 | Sound. Dev-dependency, tests only. |
| C-04 | Sound. Fuzz targets name no crypto crate. |
| C-05 | Info. getrandom 0.4.3 also sits under larsal-ffi through `uniffi_pipeline -> tempfile`; Larsal never calls it. Same version as larsal-crypto's. |
| C-10 | Sound. `subtle` slice `ct_eq`; lengths are public. |
| C-11 | Sound. `==` on SecretBytes and SecretString goes through `subtle`. |
| C-12 | Sound. `wipe` grows to capacity (no reallocation), then `zeroize`. `SecretString` takes the buffer with `mem::take`. |
| C-13 | Sound (best effort, as documented). Probe P2: the 256 KiB scrub is real (overflows below about 240 KiB), and `derive` fits in a 256 KiB thread. Registers and other threads are not covered, as stated. |
| C-14 | Sound. `SysRng::try_fill_bytes` (getentropy); error gives no value. |
| C-15 | Sound. Into `SecretBytes::zeroed`, filled in place. |
| C-16 | Sound. `2^32 mod n` = `n.wrapping_neg() % n`; rejection gives exact uniformity; 64 draws then fail closed. |
| C-17 | Sound. Version and variant bits right (RFC 9562). |
| C-18 | Sound. Boxed state wiped on drop; `finalize_reset` in place; output copied into SecretBytes and the crate's array zeroized. |
| C-19 | Sound. Parts are hashed in turn, no joined copy. |
| C-20 | Sound. `new_from_slice` (any key length), tag into SecretBytes, scrubbed stack. |
| C-21 | Sound. Verify computes then `ct_eq`; never returns the computed tag. |
| C-22 | Sound. Key 32 and IV 16/12 checked before `new_from_slices`; ChaCha20 is the IETF variant with counter 0 (CRY-01.6). |
| C-23 | Sound. CBC encrypts in place in the output (no plaintext copy left); pending bytes in `Zeroizing`; ChaCha20 `try_apply_keystream_b2b` stops at the counter limit. |
| C-24 | Sound. Every failure is `Decrypt`; output only in SecretBytes; `finish_unpadded` only for version 3. |
| C-25 | Sound. All 16 bytes looked at with `ct_gt`/`ct_eq`. |
| C-26 | Sound. Lengths checked; boxed state. |
| C-27 | Sound. SHA-512 split 32 + 12 (version 4), SHA-256 with the fixed nonce (version 3, read only; save uses ChaCha20 with a fresh stream key). |
| C-28 | Sound. `try_apply_keystream`, `StreamLimit` leaves data unchanged. |
| C-29 | Sound. `derive` takes only a `Cleared` from `assess`; AES-KDF blocks in SecretBytes; SHA-256 finalised into the output. |
| C-30 | Sound. AES-256 ECB on each block, `rounds` times; key schedule zeroized; rounds capped by `check_ranges` and the cost check. |
| C-31 | Sound. Our own `Zeroizing<Vec<Block>>` work memory, `try_reserve_exact` before use; secret and associated data empty in product. |
| C-32 | Sound. Zero password and zero salt or seed; no secret. |
| C-33 | Sound. Iterations 1 to 10,000,000 and length 1 to 1,024 checked first. |
| C-34 | Sound. `from_prk` refuses a short key; length 1 to 8,160. |
| C-35 | Sound. Ranges checked before any allocation; `checked_mul`. |
| C-36 | Sound. Parse under `scrubbed`; every failure is `None`; public parts only. |
| C-37 | Sound. Empty passphrase, cipher, KDF, salt, zero rounds and the round ceiling are checked before any bcrypt-pbkdf work; decrypt under `scrubbed_deep`. LD-209's change (vendor/ssh-key/src/private/ecdsa.rs:63-67) only widens the accepted scalar length to 1 to SIZE with the existing zero padding. |
| C-38 | Sound. Seed and scalar in `Zeroizing`; the public half must match before signing; Ed25519 (RFC 8709), P-256 ECDSA with RFC 6979 over SHA-256. |
| C-39 | Sound. `verify_strict` for Ed25519; P-256 `verify` hashes with SHA-256; algorithm and trailing bytes checked. |
| C-40 | Sound. Known answers only. |
| C-50 | Sound. P, R, C, K_enc, K_mac, version 3 key as FMT-04 says; results in SecretBytes or `LockedKey`; `same_as` uses `ct_eq`. |
| C-51 | Sound. Header hash and every HMAC compared in constant time; per-block keys; whole stream verified before any byte is handed on. |
| C-52 | Sound. Cost check, then key work; version 4 integrity before decrypt; version 3 start bytes compared with `ct_eq`. |
| C-53 | Sound. Fresh salt, seed, IV, stream key and padding from the OS source on every save; the new T must differ (`ct_eq`); the written document is read back. |
| C-54 | Sound. Field stream from the inner header's key; `read_plain`'s zero-key stream is never applied (protected values refused first). |
| C-55 | Sound. Constant-time compares. |
| C-56 | Sound. Key file hashed in 16 KiB pieces from a SecretBytes buffer; new key file from 32 random bytes; check value `ct_eq`. |
| C-57 | Sound. Not secret. |
| C-58 | Sound. RFC 4226/6238 dynamic truncation; code returned as SecretString. |
| C-59 | Sound. SHA-1 for the range query (k-anonymity); only the 5-hex prefix is plain. |
| C-60 | Info (F11). No caller. |
| C-61 | Sound. SHA-256 of the vault file's first 1,024 bytes (public); random temp suffix from `random::below`. |
| C-62 | Sound. Cost check before the KDF; decrypt, then content hash `ct_eq`; key parts in SecretBytes. The format has no MAC, and a local import gives no oracle. |
| C-63 | Sound. MAC verified before every CBC decrypt (opdata, item keys, overview); PBKDF2-SHA512 range-checked. |
| C-64 | Sound. PBKDF2 or Argon2id, HKDF-Expand to separate enc and mac keys, MAC verified (iv, ct) before decrypt. |
| C-65 | Sound. OS source; generator picks with unbiased `below` and a Fisher-Yates shuffle (password.rs:300-337). |
| C-66 | Sound. Constant-time repeat compare; benchmark on dummy input. |
| C-67 | Sound. Hashes of public data (SSH public blob, a path for the backup name); random overwrite in `wipe_file`. |
| C-68 | Sound. |
| C-69 | Sound. `random::fill` of one byte. |
| C-70 | Sound. Every call goes through larsal-crypto ssh.rs. |
| C-71 | Sound. grep finds no crypto, random or Keychain call in product Swift. |

### Secrets (S)

| Id | Verdict |
|---|---|
| S-01 | Sound. No `Clone`, `Debug` prints `[hidden]`, wiped over full capacity; doc tests prove `Clone` and `Display` do not compile. |
| S-02 | Sound. `LockedKey` drops the key, then unlocks; `FinalKeys` and `TransformedKey` hold `LockedKey`; `Debug` hidden. |
| S-03 | Sound. Every field value is a SecretString; `duplicate` copies straight into a new SecretString. `Entry::value()` is a hidden `expose()` (Info; 117 call sites to keep in mind for grep-based checks). |
| S-04 | Sound. `Arc<SecretBytes>`: wiped when the last holder drops. |
| S-05 | Sound. Grow: new SecretBytes, copy, old one dropped (wiped). `Text::push` encodes one char in a 4-byte stack array (Info: stack, unscrubbed). |
| S-06 | Sound for Rust heap; the documented limits (Swift, CoreFoundation, IOKit, stack) hold. |
| S-10 | Sound. Values cross only when not protected by field or vault flag. |
| S-11 | Sound. Exact-size copies straight into SecretBytes; crate outputs wipe themselves. |
| S-12 | Sound. |
| S-13 | Sound. The 20-byte answer is read through `scratch` into `reply` (SecretBytes) and copied into SecretBytes; R = SHA-256 of it. IOKit's own buffers are system memory, as noted. |
| S-14 | Sound. `text_value` is used only for values the model holds as plain text (names, colours, sequences); a crafted file that marks them protected still gets the keystream applied in order. Wiped by the allocator on free. |
| S-15 | Sound. `concat` straight into SecretBytes, XOR in place, base64 of the XORed bytes only. |
| S-16 | Sound. Sampled every listed site: copies go into SecretBytes or Text. |
| S-17 | Sound. `Chars` and `Text` are wiping; one SecretString at the end. |
| S-18 | Sound. Moved into `set_password`, which wraps it at once; a too-long value is dropped on the heap (zeroing allocator). |
| S-19 | Sound. New SecretStrings; repeat compare `ct_eq`. |
| S-20 | Sound. Lower-cased in Text; map keys moved into SecretString on drop and on duplicate (F-052). |
| S-21 | Sound for memory (heap copies wiped by S-06). F6: CLI messages print a protected title. |
| S-22 | Sound. |
| S-23 | Info (F11). |
| S-24 | Sound. Plan values stay SecretString; `autotype_type` only counts; the picker masks protected title and user. |
| S-30 | Sound. Show; F1 for the rule wording. |
| S-31 | Sound. Show; Swift drops it on Hide, pause and close (EditorModel.swift:130-140, 182-202). |
| S-32 | Sound. Show; `showable` refuses the password, one-time and passkey fields. |
| S-33 | Sound as behaviour (the "Show" button opens the sheet, Dialogs.swift:298-365, EditorMorePages.swift:379). F1 (rule wording) and F2 (`Debug`). |
| S-34 | Sound. Show. |
| S-35 | Sound as behaviour (setup sheet only; cleared after `setTotp`, DialogSheets.swift:48, 85). F1, F2. |
| S-36 | Deliberate crossing without Show (F1); `Debug` (F2). Swift drops codes on leave, lock and close (VaultModel.swift:239-254, 304-319). |
| S-37 | Deliberate crossing (F1); API.md:95 says the text stays in Rust although the matrix encodes it; `wifi_text` (F4); `Qr` derives `Debug` (F2). |
| S-38 | Sound. Hand-written `Debug` hides the value; F1 for the rule wording. |
| S-39 | Sound as behaviour (Show of typed text); not in API.md:243 (F1). |
| S-40 | Sound as behaviour; not in API.md:243 (F1). |
| S-45 | Sound. `password.map(SecretString::new)` first, then the length check. |
| S-46 | Sound. Each value wrapped at once; too-long values dropped on the heap (zeroing allocator). |
| S-47 | Sound. |
| S-48 | Sound. |
| S-50 | Sound. One item with the concealed and transient markers, `CurrentHostOnly`, written in one call; cleared only while the change count is still ours. The NSString is system memory (documented). |
| S-51 | Sound. The value is dropped right after the copy; the clear runs on every path (timer, quit signal through the guard); the private pasteboard only in debug builds with `LARSAL_TEST_PASTEBOARD`. |
| S-52 | Sound. Exclusive-create 0600 temp file, sync, rename. |
| S-53 | Sound as file handling (0700 folder, 0600 `create_new`, random name, wiped and removed on close and lock). F5 for the folder source. Overwriting before delete does not reach old blocks on APFS or SSDs (Info; MOD-05.12 asks only for the overwrite). |
| S-54 | Sound. `create_new`, mode 0400, read back. |
| S-55 | Sound for reads (unbuffered, SecretBytes, escaped copies in SecretString). F7 for the stdout buffer. |
| S-56 | Sound. Add message built in a SecretBytes of exact size; peer checked before any write. |
| S-60 | Sound with the known Swift limit: `password` set to empty before the call and on `clear()`; Swift `String`s are not wiped. |
| S-61 | Sound. No copy, cut, drag, Services, Look Up, speech or Writing Tools; secure input while focused. |
| S-62 | Sound. |
| S-63 | Sound. `shown` dropped on Hide, select, leave and lock (`clear()` releases the model, MainWindowModel.swift:69-76); a late Show is dropped by `showTurn`. |
| S-64 | Sound. |
| S-65 | Sound. Value cleared on close and refusal (Generator.swift:87, 123). |
| S-66 | Sound. |
| S-67 | Sound. Shown field in `@State`, gone with the sheet; `VersionView` in `model.dialog`, cleared by `leave()` and `clear()`. |
| S-68 | Sound. No-copy field; emptied after `setTotp`. |
| S-69 | Sound. Accessibility values equal what is drawn; dots while hidden. |

## Items the inventory missed

1. Swift code that relies on unchecked contracts, not in the inventory: `WindowID: @unchecked Sendable` (AutoType.swift:18; wraps an `AXUIElement`, a thread-safe CF object); `DiskWatch: @unchecked Sendable` (Platform/DiskWatch.swift:12; state touched only on its own queue, and `deinit` runs only when no block holds `self`); `unsafeDowncast(value, to: AXUIElement.self)` (AutoType.swift, guarded by `CFGetTypeID == AXUIElementGetTypeID()`); the Carbon C callback `carbonHotKeyPressed` with `MainActor.assumeIsolated` (AutoType.swift:105-110; application-target hot key events arrive on the main thread, and `assumeIsolated` traps otherwise). Reviewed: sound.
2. `wifi_text` (larsal-ffi edit.rs:1222-1243): plain `String` escapes and a `format!` of the Wi-Fi password (F4).
3. larsal-ffi `open_folder` (edit.rs:1104-1117, 1146) reads `TMPDIR` through `std::env::temp_dir()` (F5).
4. std's stdout buffer in larsal-cli `term::out_parts` (term.rs:68) keeps printed secrets (F7).
5. Records with a secret that derive `Debug`/`Clone`: `TotpView`, `TotpSetup`, `VersionView`, `Qr` (F2). The inventory notes `Debug` for three of them but not `Qr`.
6. Non-constant-time `==` or `cmp` on secret values used for search and de-duplication, not for any authentication decision: larsal-core refs.rs:864, 890, 1049; attachments.rs:152; breach.rs:205-209, 572; import/v1.rs:183; larsal-autotype lib.rs:811, matching.rs:598, 703; larsal-ffi edit.rs:1624. Info: no attacker-timed oracle.
7. Stale texts: architecture.md "lead co-sign open" for LD-197 and LD-198; API.md:243 on the zeroing allocator (F10).
8. Process-wide single `QuitGuard` rule not enforced (F3); listed as a doc remark only.

## Report

- Story: E13-S5 (Checker A step).
- Files changed: security/parity/E13-S5-review-a.md (new). No product code.
- Proof: the clippy, test, probe, cargo tree and grep runs above, with their output.
- Open issues: F1 (Medium) needs a lead decision; F2 to F7 (Low) are small code or doc changes for a Builder; F8 to F11 (Info).
- Next step: the merge step compares this review with Checker B's, files agreed findings in security/findings.md, and sets the E13-S5 status line.
