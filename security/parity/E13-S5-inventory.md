# E13-S5 Inventory: unsafe code, crypto calls, secret conversions

Story: E13-S5, two-person review of every `unsafe` block, crypto call and secret conversion (plan/epics.md; plan/team.md, two Checkers; plan/architecture.md Rust rules 2 and 3 and the approved crates table; plan/security.md; plan/attacks-and-checks.md AT-C*, AT-J*).
Step: inventory only. It lists what the two Checkers review. It gives no verdicts. The observations at the end of each part are candidates for the merge step.
Date: 2026-10-28. Tree read from 23:39 to 23:55.
Clean room: I read only App's own code and App's marked changes in `vendor/`. I did not open the reference source.
Edits: this file only. No product code was edited. One slip: at 23:51 a `touch -c crates/app-platform/src/lib.rs` changed that file's modification time, not its bytes (SHA-256 below). It may make another agent's next build recompile `app-platform`.

## How it was made

Every list below comes from these commands. They ran from the project root unless noted.

- **Unsafe:** ripgrep `rg -n -t rust '\bunsafe\b|extern\s+"C"|extern\s*\{|extern crate|#\[link|no_mangle|export_name|static mut|transmute' crates`, the same over `fuzz`, `vendor` and the `tests/` and `examples/` folders, and `rg -c '\bunsafe\s*\{'`, `rg '\bunsafe (extern "C-unwind" )?fn '`, `rg '\bunsafe impl'` and `rg -c '// SAFETY:'` per file. The crate gates: `grep 'forbid(unsafe_code)|deny(unsafe|allow(unsafe'` on every `lib.rs` and `main.rs`, and the `[lints]` tables of every `Cargo.toml`.
- **Unsafe proof:** `cargo clippy --offline -p app-platform --features appkit,memory,test-memory,test-signals --all-targets -- -D clippy::undocumented_unsafe_blocks -D clippy::missing_safety_doc -D clippy::unnecessary_safety_comment` exited 0. The same for `-p app-hwkey --all-targets` exited 0. Both ran with `CARGO_TARGET_DIR=/tmp/e13s5-inventory-target`.
- **Control:** in a private copy (`rsync` of `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `clippy.toml`, `crates`, `vendor` to `/tmp/e13s5-inventory-copy`), I deleted one line of the SAFETY note at `process.rs:14`. The same clippy run then exited 101 with `error: unsafe block missing a safety comment --> crates/app-platform/src/macos/process.rs:15:8`. So the lint really guards these blocks.
- **Crypto:** `grep` of every crate's `[dependencies]` for the approved crypto crates, and `cargo tree --offline -e normal,build -i <crate> --depth 1 --all-features` for `aes cbc chacha20 salsa20 twofish argon2 pbkdf2 hkdf sha2 sha1 hmac subtle getrandom@0.4.3 getrandom@0.2.17 rand_core zeroize p256 ed25519-dalek ssh-key bcrypt-pbkdf ring rustls blake2 aes-gcm`. Then `cargo tree -p app-ffi` and `-p app-cli -e normal -i getrandom@0.4.3 / tempfile / ring` under the real features. `rg` for crate paths (`aes::`, `sha2::` and so on) outside `crates/app-crypto`, and for every call into App's own crypto API (`random::`, `hash::`, `mac::`, `kdf::`, `cipher::`, `stream::`, `ssh::`, `ct_eq(`, `Encryptor::new`, `Decryptor::new`, `Hasher::new`) in product sources (tests excluded). Swift: `rg -t swift 'CryptoKit|CommonCrypto|CC_SHA|SecRandomCopyBytes|arc4random|\.random\(|UUID\(\)|SecItem|LAContext' macos`.
- **Secrets:** `rg -c '\.expose(_mut)?\(\)'` per file (357 in product code outside app-crypto), then `rg` for exposures that copy (`to_owned|to_string|to_vec|String::from|format!|push_str|extend_from_slice|collect|from_utf8|lossy`), for `Entry::value(...)` copies, for `expose() ==` and `cmp` compares, for file, socket and terminal writes (`fs::write|File::create|OpenOptions|write_all|rename`), for UniFFI exports that take or return a `String`, and for the Swift holders (`showField|draftPassword|showDraftField|showVersion|totpSetup|generate|unlock|setPassword|setRepeat|codes|SecureField|ShownPasswordField|NoCopyTextField|shown`). Each hit was read in context.
- I did not use `cargo metadata`; `cargo tree` gave the dependency answers. I did not run `scripts/check.sh` or any test suite.

### Files read, with their state

All of them were last changed before 23:39, when this step started, except `app-platform/src/lib.rs` (my touch at 23:51; bytes unchanged). None changed while I read them; re-checked at 23:54.

| File | Modified | SHA-256 (first 16) |
|---|---|---|
| crates/app-platform/src/macos/memory.rs | 07:44:50 | ec6b504d580e0ce9 |
| crates/app-platform/src/macos/process.rs | 03:49:38 | 7f6f61efe24282dd |
| crates/app-platform/src/macos/pipe.rs | 05:28:55 | ba16a58e985739e4 |
| crates/app-platform/src/macos/signals.rs | 05:28:55 | 8fadf27d0193b4ae |
| crates/app-platform/src/macos/instance.rs | 15:13:05 | 4d5c4c387f39ca26 |
| crates/app-platform/src/macos/system.rs | 14:52:39 | 7207855c65af423e |
| crates/app-platform/src/macos/terminal.rs | 05:17:40 | 886586e435f223d4 |
| crates/app-platform/src/macos/pasteboard.rs | 04:38:58 | 8721f0801785f74f |
| crates/app-platform/src/macos/mod.rs | 14:52:31 | 7f956e76e37dec18 |
| crates/app-platform/src/clipboard.rs | 04:38:58 | 430197c4fa8bcb4a |
| crates/app-platform/src/memory.rs | 07:45:28 | 7b3b6f0ac5ae0e0a |
| crates/app-platform/src/lib.rs | 23:51:20 (my touch) | 87304fe26c7ab275 |
| crates/app-hwkey/src/usb/mod.rs | 07:25:03 | dec9a56a7a48c4ca |
| crates/app-hwkey/src/usb/watch.rs | 07:40:07 | 67d8a043a5f66243 |
| crates/app-hwkey/src/lib.rs | 07:33:23 | 75f02815091c5489 |
| crates/app-hwkey/src/protocol.rs | 06:36:33 | 2577f680bbf4452c |
| crates/app-crypto/src/secret.rs | 09:11:54 | 7649f16f504a2366 |
| crates/app-crypto/src/random.rs | 16:23:50 (10-27) | b7396e59a71691b0 |
| crates/app-crypto/src/hash.rs | 09:11:54 (10-25) | d9951c4b66e4edc5 |
| crates/app-crypto/src/mac.rs | 03:30:45 (10-26) | 3abb1eb0051a2ceb |
| crates/app-crypto/src/cipher.rs | 10:50:39 (10-25) | 3004f9c9816cafb5 |
| crates/app-crypto/src/stream.rs | 09:15:33 (10-25) | 07c919680e715117 |
| crates/app-crypto/src/kdf.rs | 03:37:36 | 4188f8b3f4593e20 |
| crates/app-crypto/src/ssh.rs | 09:03:24 | 8aef08046b3a8986 |
| crates/app-crypto/src/selftest.rs | 04:45:12 | 505701b17eb5c24e |
| crates/app-format/src/keys.rs | 07:46:00 | f46a20c4e0510504 |
| crates/app-ffi/src/lib.rs | 21:02:48 | 4c5a3729b365163a |
| crates/app-ffi/src/views.rs | 15:41:28 | 0b3f3922a4c579b7 |
| crates/app-ffi/src/edit.rs | 19:18:39 | fec93139f05e3289 |
| crates/app-ffi/src/generator.rs | 15:25:31 | d6b05cc21c204f3f |
| crates/app-ffi/src/wizard.rs | 16:08:38 | 93d8c91f4c841b5b |
| crates/app-ffi/src/vault_settings.rs | 19:33:35 | 52742759b79a88f1 |
| crates/app-ffi/src/session.rs | 21:02:48 | 1bda6de4ae34692f |
| crates/app-ffi/src/autotype.rs | 22:46:47 | 9b31119e7ec706ee |
| crates/app-ffi/API.md | 21:22:16 | 06b7dd40a569ee58 |
| crates/app-model/src/entry.rs | 21:40:26 | c2ebad16624e60df |
| crates/app-core/src/breach.rs | 14:02:53 | 7d779310e3846ef4 |
| crates/app-core/src/url.rs | 08:21:12 | c15331ee3821fdf0 |
| crates/app-core/src/text.rs | 22:52:38 | b4ff648402b48641 |
| crates/app-core/src/totp.rs | 22:40:13 | c14bd2d3ae195280 |
| macos/App/Platform/ShownPasswordField.swift | 21:26:26 | a2d094563a019e0c |
| macos/App/UnlockModel.swift | 00:46:08 | 9dd798cd78283644 |
| macos/App/UnlockView.swift | 23:32:05 | 7397713ae6c5bfc8 |
| macos/App/VaultModel.swift | 18:27:42 | db3fce23556a135f |
| macos/App/EditorModel.swift | 13:28:32 | 82caa4895af96208 |
| macos/App/Generator.swift | 09:56:05 | 53d39f2400764da0 |
| macos/App/NewVaultCredentials.swift | 14:20:25 | 690bc66f65275b82 |
| macos/App/VaultSettingsActions.swift | 14:20:25 | e65feae69a00302b |
| macos/App/Dialogs.swift | 18:20:29 | c1ca0e90edefe1d2 |
| macos/App/DialogSheets.swift | 21:17:37 | ed984f10c5b7b681 |
| macos/App/EditorPasswordField.swift | 21:17:43 | 271b80afc359cd09 |
| macos/App/SecretFields.swift | 14:18:56 | d61a24a42ac6c760 |

Dates are 2026-10-28 unless marked. Other files named in the tables were read the same way, between 23:42 and 23:53 (app-format, app-core, app-cli, app-sshagent sources and other Swift files). Other agents are building E5-S11, E6-S5 and E8-S2 now. The Checkers should re-hash any file they review.

## Part 1: unsafe code

### 1.1 The crate gates

| Crate | Gate in the crate root | `[lints]` in Cargo.toml |
|---|---|---|
| app-autotype | `lib.rs:30 #![forbid(unsafe_code)]` | `workspace = true` (Cargo.toml:19 `unsafe_code = "forbid"`) |
| app-cli | `main.rs:11 #![forbid(unsafe_code)]` | `workspace = true` |
| app-core | `lib.rs:15 #![forbid(unsafe_code)]` | `workspace = true` |
| app-crypto | `lib.rs:2 #![forbid(unsafe_code)]` | `workspace = true` |
| app-ffi | `lib.rs:4 #![forbid(unsafe_code)]` | `workspace = true` |
| app-format | `lib.rs:2 #![forbid(unsafe_code)]` | `workspace = true` |
| app-model | `lib.rs:4 #![forbid(unsafe_code)]` | `workspace = true` |
| app-sshagent | `lib.rs:18 #![forbid(unsafe_code)]` | `workspace = true` |
| uniffi-bindgen | `main.rs:3 #![forbid(unsafe_code)]` | `workspace = true` |
| app-platform | `lib.rs:4 #![deny(unsafe_code)]`; `macos/mod.rs:5 #![allow(unsafe_code)]`, `:6 #![deny(clippy::undocumented_unsafe_blocks)]`; `macos/pasteboard.rs:12 #![forbid(unsafe_code)]` | `[lints.rust] unsafe_code = "deny"` (Cargo.toml:36-37) |
| app-hwkey | `lib.rs:17 #![deny(unsafe_code)]`; `usb/mod.rs:9 #![allow(unsafe_code)]`, `:10 #![deny(clippy::undocumented_unsafe_blocks)]` (covers `usb/watch.rs`) | `[lints.rust] unsafe_code = "deny"` (Cargo.toml:11-12) |

Result: hand-written `unsafe` is only in `app-platform/src/macos/` and `app-hwkey/src/usb/`. No crate has an `extern` block, `#[no_mangle]`, `#[link]`, `static mut` or `transmute`. The other `unsafe` hits in `crates/` are text: the CSP string `'unsafe-inline'` (app-core `export/html.rs:30`, `tests/fea09.rs:337`) and comments (`storage.rs:42`, `tests/app05.rs:361`, `tests/no_plain_copies.rs:3`). That makes 0 unsafe outside the two allowed folders, so no finding.

Counts by script: 56 `unsafe {` blocks (`process.rs` 6, `memory.rs` 17, `signals.rs` 5, `terminal.rs` 7, `instance.rs` 3, `system.rs` 3, `pipe.rs` 2, `usb/mod.rs` 5, `usb/watch.rs` 8), 11 `unsafe fn`, 2 `unsafe impl`. 37 of the blocks are in product builds, 8 are in test tools behind a feature, and 11 are in unit tests. Every block has a `// SAFETY:` note; the clippy run proves it.

### 1.2 Every unsafe item

"Build" says where the code is compiled: **product** ships; **tool** is behind `test-memory` or `test-signals` (never on in a product build); **test** is `#[cfg(test)]`.

| ID | Location | Kind | Purpose | SAFETY note (short) | Build |
|---|---|---|---|---|---|
| U-01 | crates/app-platform/src/macos/memory.rs:20 | unsafe impl | `GlobalAlloc for Zeroing<A>`: the zeroing allocator (LD-133) | 16-19: pointer and layout passed unchanged to `A`; `dealloc` only writes zeros into the block given up; no alloc, panic or unwind | product |
| U-02 | memory.rs:21, block :23 | unsafe fn (trait) + block | `alloc` passes through | 22: caller's contract passed on unchanged | product |
| U-03 | memory.rs:26, block :28 | unsafe fn (trait) + block | `alloc_zeroed` passes through | 27: as for `alloc` | product |
| U-04 | memory.rs:31, block :36-39 | unsafe fn (trait) + block | `dealloc`: wipe, then free | 32-35: `layout.size()` bytes at `ptr` are ours until `A::dealloc`; same pointer and layout to `A` | product |
| U-05 | memory.rs:50, block :56 | unsafe fn + block | `wipe`: `memset_s` (not dropped by the compiler) | `# Safety` 48-49 (ptr valid for len writes); 52-55: smax == n, len ≤ isize::MAX = RSIZE_MAX, cannot fail | product |
| U-06 | memory.rs:64 | block | `sysconf(_SC_PAGESIZE)` | 63: reads and writes no memory of ours | product |
| U-07 | memory.rs:78 | block | `mlock` of key pages (APP-11.9) | 76-77: wires pages only; bad range fails ENOMEM/EINVAL | product |
| U-08 | memory.rs:88 | block | `munlock` | 87: as for mlock | product |
| U-09 | crates/app-platform/src/macos/process.rs:16 | block | `setrlimit(RLIMIT_CORE, 0)`: core dumps off (APP-11.2) | 14-15: `zero` valid and alive; only read | product |
| U-10 | process.rs:33 | block | `ptrace(PT_DENY_ATTACH)` (APP-11.3) | 30-32: ignores pid/addr/data; ending a traced process is wanted | product |
| U-11 | crates/app-platform/src/macos/pipe.rs:15 | block | `signal(SIGPIPE, SIG_IGN)` (LD-179) | 13-14: SIG_IGN is a system constant; no handler of ours | product |
| U-12 | crates/app-platform/src/macos/signals.rs:22 | `extern "C" fn` (safe) | `note`: quit-signal handler, one atomic store | doc 20-21: atomic store is async-signal-safe (no unsafe block) | product |
| U-13 | signals.rs:55 | block | `sigaction` read of the current action | 52-54: null new action, `current` complete and alive | product |
| U-14 | signals.rs:62 | block | `sigaction` install of `note` | 59-61: complete values; `note` async-signal-safe | product |
| U-15 | signals.rs:114 | block | `sigaction` put back | 112-113: the action the system returned | product |
| U-16 | signals.rs:127 | block | `raise` of the noted quit signal | 124-126: one of the quit signals, original action restored | product |
| U-17 | signals.rs:148 | block | `sigaction` to SIG_DFL for tests (LD-180) | 145-147: SIG_DFL installs no handler of ours | tool (`test-signals`) |
| U-18 | crates/app-platform/src/macos/instance.rs:18 | block | `confstr(_CS_DARWIN_USER_TEMP_DIR)` | 16-17: `buf` writable for `buf.len()`; confstr writes at most that | product |
| U-19 | instance.rs:45 | block | `getpeereid` on the instance socket | 43-44: fd open while borrowed; uid/gid writable | product |
| U-20 | instance.rs:57 | block | `geteuid` | 56: no args, cannot fail, touches no memory | product |
| U-21 | crates/app-platform/src/macos/system.rs:21 | block | `uname` + `assume_init` | 17-20: zeroed utsname valid whatever is written; assume_init only after 0 | product |
| U-22 | system.rs:70 | block | `clock_gettime(CLOCK_THREAD_CPUTIME_ID)`: KDF benchmark clock (LD-72) | 68-69: `ts` valid, initialised, alive | product |
| U-23 | system.rs:89 | block | `localtime_r`: UTC offset (LD-178) | 87-88: `t`, `tm` valid and alive; null on failure | product |
| U-24 | crates/app-platform/src/macos/terminal.rs:35 | block | `tcgetattr` + `assume_init` (echo-off prompt) | 32-34: fd open; `saved` writable; assume_init after 0 | product |
| U-25 | terminal.rs:46 | block | `tcsetattr(TCSAFLUSH)` echo off | 45: fd open; `quiet` complete | product |
| U-26 | terminal.rs:72 | block | `poll` for input or quit | 70-71: one valid pollfd; fd open | product |
| U-27 | terminal.rs:90 | block | `tcsetattr(TCSANOW)` restore in `Drop` | 88-89: borrow outlives self; `saved` complete | product |
| U-28 | crates/app-hwkey/src/usb/mod.rs:79 | block | `CFSetGetValues` into a sized Vec | 76-78: room for exactly `count`; own copy, count fixed | product |
| U-29 | usb/mod.rs:91 | block | `IOHIDManagerSetDeviceMatching(None)` | 89-90: None matches all; no dictionary of wrong types | product |
| U-30 | usb/mod.rs:101 | block | `CFRetained::retain` of a set member | 98-100: set holds IOHIDDevice refs and keeps each alive; our own retain | product |
| U-31 | usb/mod.rs:211 | block | `IOHIDDeviceGetReport`: 8-byte feature report read (carries hardware key response bytes) | 208-210: 8 writable bytes, len 8, synchronous | product |
| U-32 | usb/mod.rs:231 | block | `IOHIDDeviceSetReport`: 8-byte feature report write (challenge) | 227-230: reads exactly 8 bytes, `const uint8_t *`, synchronous | product |
| U-33 | crates/app-hwkey/src/usb/watch.rs:74 | block | read `kCFRunLoopDefaultMode` | 72-73: constant set before our code, never changes | product |
| U-34 | watch.rs:92 | block | `IOHIDManagerSetDeviceMatchingMultiple` | 90-91: array of CFString→CFNumber dictionaries | product |
| U-35 | watch.rs:110-113 | block | register matching and removal callbacks with a `&Watching` context pointer | 105-109: callbacks only inside `run_in_mode` on this thread; unscheduled and cleared before `watching` drops | product |
| U-36 | watch.rs:116 | block | `IOHIDManagerScheduleWithRunLoop` | 114-115: this thread's run loop and default mode, alive until unscheduled | product |
| U-37 | watch.rs:123 | block | `IOHIDManagerUnscheduleFromRunLoop` | 121-122: same run loop and mode; no callback after | product |
| U-38 | watch.rs:127-130 | block | register `None` callbacks, null context | 124-126: both `_Nullable`; manager holds no pointer to `watching` after | product |
| U-39 | watch.rs:134, block :142 | `unsafe extern "C-unwind" fn` + block | `arrived`: IOKit matching callback | fn: **missing** a `# Safety` section (private fn; clippy's `missing_safety_doc` covers pub only); block 140-141: context is the registered `&Watching` | product |
| U-40 | watch.rs:149, block :156 | `unsafe extern "C-unwind" fn` + block | `removed`: IOKit removal callback | fn: **missing** a `# Safety` section; block 155: as in `arrived` | product |
| U-41 | memory.rs:167; blocks :170, :175, :191 | unsafe impl + 3 trait fns + 3 blocks | `GlobalAlloc for Probe<A>`: the test probe that inspects freed blocks | 164-166 (impl); 169, 174; 183-190: read via memmem/memcmp as unsigned char, no Rust reference to uninitialised bytes | tool (`test-memory`) |
| U-42 | memory.rs:223 | block | `proc_pid_rusage` wired bytes (AT-C05 hook) | 220-222: zeroed struct valid; assume_init after 0 | tool |
| U-43 | memory.rs:259 | block | `marker_survives_free`: proves which allocator a binary uses | 252-258: block read only while ours; freed once by its allocator | tool |
| U-44 | memory.rs:281, block :283 | unsafe fn + block | `take`: alloc through global or System | `# Safety` 279-280; 282 | tool |
| U-45 | memory.rs:295, block :297 | unsafe fn + block | `give`: dealloc through the same allocator | `# Safety` 292-294; 296 | tool |
| U-46 | memory.rs:321 | block | `fill_and_free` test helper | 319-320 | test |
| U-47 | memory.rs:374 | block | realloc wipe test | 371-373 | test |
| U-48 | memory.rs:445 | block | `setrlimit(RLIMIT_MEMLOCK, 0)` in a child | 444 | test |
| U-49 | process.rs:57 | block | `getrlimit` | 56 | test |
| U-50 | process.rs:85 | block | `setrlimit` raise attempt (must fail) | 84 | test |
| U-51 | process.rs:98 | `extern "C" fn` (safe) | `on_segv` handler in the attacher child | atomic store only (no unsafe block) | test |
| U-52 | process.rs:116 | block | `signal(SIGSEGV, on_segv)` | 114-115 | test |
| U-53 | process.rs:119 | block | `ptrace(PT_ATTACHEXC)` against the test child | 117-118 | test |
| U-54 | pipe.rs:43 | block | `signal(SIGPIPE, SIG_DFL)` | 41-42 | test |
| U-55 | terminal.rs:111 | block | `openpty` | 109-110 | test |
| U-56 | terminal.rs:123 | block | `OwnedFd::from_raw_fd` | 121-122 | test |
| U-57 | terminal.rs:135 | block | `tcgetattr` | 133-134 | test |
| U-58 | crates/app-ffi/src/lib.rs:23 | generated | `uniffi::setup_scaffolding!()` plus 25 `#[uniffi::export]` attributes in app-ffi: generated `extern "C"` scaffolding. rustc's forbid at lib.rs:4 does not see it (Rust rule 2; reviewed in LD-157) | generated, no note | product |
| U-59 | crates/app-ffi/src/start.rs:39; crates/app-ffi/src/autotype.rs:160 | generated | `#[uniffi::export(with_foreign)]` traits `AppEvents` and `AutoTypeFocus`: generated foreign callback vtables | generated, no note | product |
| U-60 | crates/app-ffi/src/lib.rs:30-32; crates/app-cli/src/main.rs:25-27; app-cli tests/bench_zeroing.rs:5, tests/memory_hygiene.rs:21 | safe use | `#[global_allocator]` statics that install U-01 (and the probe in the hygiene test) | safe code; correctness rests on U-01 to U-05 | product (first two) |

Outside the crates:

- `vendor/zxcvbn`: `src/lib.rs:35 #![forbid(unsafe_code)] // App change (LD-136) 3`; its 3 wasm-only blocks are removed (lib.rs:17-18). `rg` finds no `unsafe` code.
- `vendor/ssh-key`: no `unsafe` (`rg` 0 hits). App's changes: `src/private/ecdsa.rs:63-71` (LD-209 1: a scalar of 1 to SIZE bytes, left-padded with zeros) and `src/lib.rs:21` (LD-209 2: README include removed). The crate has no forbid of its own; upstream did not have one.
- `fuzz/`: no `unsafe` in the 22 targets. `libfuzzer_sys::fuzz_target!` generates the C entry. The fuzz workspace has no `forbid(unsafe_code)` and no `[lints]`.

### 1.3 Observations for the merge step

1. **U-39, U-40:** the two IOKit callbacks are `extern "C-unwind"` and call App's sink. In debug and test builds, a panic in the sink would unwind through IOKit's C frames. Release builds abort on panic (`panic = "abort"`). Neither callback has a `# Safety` doc section.
2. **Gates:** `app-platform` and `app-hwkey` use `deny`, not `forbid`, as Rust rule 2 says. A second `#[allow(unsafe_code)]` anywhere in those two crates would compile. Today the only allows are `macos/mod.rs:5` and `usb/mod.rs:9`.
3. **Fuzz:** the fuzz workspace carries no `forbid(unsafe_code)`. It ships nothing.

## Part 2: crypto calls

### 2.1 Rule 3 boundary: who names a crypto crate

| ID | Location | What | Note |
|---|---|---|---|
| C-01 | crates/app-crypto/Cargo.toml:12-39 | The only manifest that names the approved crypto crates: `zeroize`, `subtle`, `getrandom` (`sys_rng`), `rand_core`, `sha2`, `sha1`, `hmac`, `aes`, `cbc`, `twofish`, `chacha20`, `salsa20`, `argon2`, `pbkdf2`, `hkdf`, `ssh-key` (App's copy), `bcrypt-pbkdf`, `ed25519-dalek`, `p256` | `cargo tree -i` for each: the only App crate above them is app-crypto. Below it, only other crypto crates (for example `aes` ← `aes-gcm`, `ssh-cipher`). `blake2` only ← `argon2`. No `crypto_box` in the tree yet. |
| C-02 | crates/app-platform/Cargo.toml:29; crates/app-platform/src/net.rs:30-31, 248, 250, 253 | `rustls` (optional, feature `net`) with `rustls::crypto::ring::default_provider()`, `rustls_platform_verifier::Verifier::new_with_extra_roots`, TLS 1.3 and 1.2 only | Crypto outside app-crypto. The approved table allows it ("app-platform `net.rs` only", LD-194; AT-J03 LD-197, lead co-sign open). `cargo tree -p app-ffi` and `-p app-cli -i ring` find no `ring`: it is in no product build today. |
| C-03 | crates/app-platform/Cargo.toml:34; crates/app-platform/src/net/tests.rs:15-20, 47 | `rcgen` (dev-dependency) and `rustls` server types for test certificates | Tests only. |
| C-04 | fuzz/Cargo.toml:33; fuzz/fuzz_targets/vault_open.rs:18, v1_import.rs:19, opvault_import.rs:20 | the `ssh-key` patch line; the targets use App's `app_crypto::cipher` API only | No crypto crate is named directly. |
| C-05 | `cargo tree -p app-ffi -e normal -i getrandom@0.4.3` | `getrandom` 0.4.3 also reaches app-ffi through `uniffi` → `uniffi_pipeline` → `tempfile`; `getrandom` 0.2.17 only ← `ring` (feature `net`) | A third-party path to the OS random source outside app-crypto. App never calls it. |

No product source outside app-crypto has a `use` of a crypto crate, except C-02 and C-03. Outside app-crypto, code calls only App's own API (`app_crypto::{cipher, hash, mac, kdf, stream, random, ssh, secret::ct_eq}`).

### 2.2 Inside app-crypto

| ID | Location | Crate call | Purpose |
|---|---|---|---|
| C-10 | crates/app-crypto/src/secret.rs:52-54 | `subtle` slice `ct_eq` | `ct_eq`: the one constant-time compare for bytes not in a secret type (Rust rule 6) |
| C-11 | secret.rs:153-160, 218-225 (PartialEq :162-167, :227-232) | `subtle::ConstantTimeEq` | `==` on SecretBytes and SecretString is constant time |
| C-12 | secret.rs:239-245 (Drop :141-145, :205-210) | `zeroize` | Wipe over the full capacity before free |
| C-13 | secret.rs:60-87 | `zeroize` | `scrubbed` (32 KiB) and `scrubbed_deep` (256 KiB): stack wipe below every crypto call |
| C-14 | crates/app-crypto/src/random.rs:34-35, 81-83 | `getrandom::SysRng` `try_fill_bytes` | `fill`: the OS random source |
| C-15 | random.rs:52-53, 85-89 | `SysRng` | `bytes(n)` into `SecretBytes` |
| C-16 | random.rs:65-66, 91-114 | `SysRng` `try_next_u32` | `below(n)` without bias (rejection, at most 64 draws) |
| C-17 | random.rs:77-78, 116-122 | `SysRng` | `uuid_v4` |
| C-18 | crates/app-crypto/src/hash.rs:80-107, 137-142 | `sha1::Sha1`, `sha2::Sha256`, `sha2::Sha512` (`new`, `update`, `finalize_reset`, then `zeroize`) | Streaming `Hasher` |
| C-19 | hash.rs:111-134 | as C-18 | One-shot `sha256`, `sha512`, `sha1` over parts (no joined copy) |
| C-20 | crates/app-crypto/src/mac.rs:33-52, 72-83 | `hmac::Hmac<Sha256 \| Sha1 \| Sha512>` `new_from_slice`, `update`, `finalize` | HMAC tags into `SecretBytes` |
| C-21 | mac.rs:61-69, 85-96 | C-20, then `secret::ct_eq` | `verify_hmac_sha256` and `verify_hmac_sha1`: constant-time tag compare |
| C-22 | crates/app-crypto/src/cipher.rs:133-147, 205-219, 301-303 | `cbc::Encryptor/Decryptor<aes::Aes256>`, `<twofish::Twofish>`, `chacha20::ChaCha20` via `KeyIvInit::new_from_slices` | Payload cipher setup; key and IV lengths checked first (`check_lengths` :290) |
| C-23 | cipher.rs:76-88, 156-167, 340-367 | `encrypt_blocks`, `try_apply_keystream_b2b` | Encrypt: CBC with PKCS#7 padding; ChaCha20 |
| C-24 | cipher.rs:96-111, 228-288, 369-394 | `decrypt_blocks`, `try_apply_keystream_b2b` | Decrypt into `SecretBytes`; `finish_unpadded` for version 3 |
| C-25 | cipher.rs:398-406 | `subtle` `ct_gt`, `ct_eq` | Constant-time PKCS#7 padding check (AT-B07) |
| C-26 | crates/app-crypto/src/stream.rs:56-67, 113-121 | `chacha20::ChaCha20`, `salsa20::Salsa20` `new_from_slices` | Protected-field streams |
| C-27 | stream.rs:75-94 | C-19 | Stream keys: SHA-512 (version 4) and SHA-256 (version 3) of the stream key |
| C-28 | stream.rs:102-110 | `try_apply_keystream` | XOR of protected values |
| C-29 | crates/app-crypto/src/kdf.rs:398-400, 624-657 | AES-KDF or Argon2, then `Sha256::finalize_into` | `derive`: the transformed key, only after `assess` gave `Cleared` |
| C-30 | kdf.rs:661-669 | `aes::Aes256::new_from_slice`, `encrypt_blocks` × rounds | AES-KDF rounds |
| C-31 | kdf.rs:683-728, 732 | `argon2::Argon2::new` / `new_with_secret`, `hash_password_into_with_memory` with `Zeroizing<Vec<Block>>` | Argon2d and Argon2id (RFC 9106); wiped work memory (LD-39) |
| C-32 | kdf.rs:429, 507-561, 92-94 | C-29 on dummy inputs; `Instant` wall clock and the platform CPU clock | Benchmark and calibration |
| C-33 | kdf.rs:778-801 | `pbkdf2::pbkdf2::<Hmac<Sha256 \| Sha512>>` | PBKDF2 for encrypted imports (FEA-08, LD-142) |
| C-34 | kdf.rs:812-827 | `hkdf::Hkdf::<Sha256>::from_prk`, `expand` | HKDF-Expand for imports |
| C-35 | kdf.rs:843-870 | C-31 | `import_argon2id`, ranges checked first |
| C-36 | crates/app-crypto/src/ssh.rs:60-79 | `ssh_key::PrivateKey::from_openssh`, `public_key().to_bytes()/to_openssh()`, `fingerprint(HashAlg::Sha256)` | Parse an OpenSSH private key (INT-06) |
| C-37 | ssh.rs:162-187 | `ssh_key` `decrypt` (bcrypt-pbkdf plus AES or ChaCha20-Poly1305 inside the crate) | `agent_key`: the round ceiling is checked before any KDF |
| C-38 | ssh.rs:305-350 | `ed25519_dalek::SigningKey::from_bytes`, `sign`; `p256::ecdsa::SigningKey::from_bytes`, `sign` (RFC 6979) | Signing for App's own agent; the public half must match first |
| C-39 | ssh.rs:255-300 | `ed25519_dalek` `verify_strict`; `p256::ecdsa::VerifyingKey::verify` | Session-binding signature check |
| C-40 | crates/app-crypto/src/selftest.rs:78-99 | C-18 to C-31 with public test values | Start self-test (APP-11.10) |

### 2.3 Where App's crypto API is called (product code)

| ID | Location | Call | Purpose |
|---|---|---|---|
| C-50 | crates/app-format/src/keys.rs:157, 189, 205, 222-223, 237, 256 (and :120 test feature) | `sha256`, `sha512`, `ct_eq` (`hmac_sha1` for `SoftwareKey`) | Key flow FMT-04: P, R, C, K_enc, K_mac, version 3 key; check that T changed |
| C-51 | crates/app-format/src/integrity.rs:24, 29, 37, 45, 71, 108 | `sha256`+`ct_eq`, `sha512`, `hmac_sha256`, `verify_hmac_sha256` | Header hash, header HMAC, block HMACs |
| C-52 | crates/app-format/src/payload.rs:280, 301, 350, 374, 385, 633 | `kdf::assess`/`derive`, `Decryptor`, `ct_eq`, `Encryptor` | Open and save the payload; version 3 start bytes |
| C-53 | crates/app-format/src/lib.rs:207-208, 273, 299, 309, 313, 365-366 | `random::bytes`/`below`, `kdf`, `FieldStream`, `sha256`, header HMAC | Save: new seeds, IVs and stream key |
| C-54 | crates/app-format/src/inner.rs:60-61; crates/app-format/src/document/read.rs:203 | `FieldStream::*_from_stream_key` | Protected stream; a zero-key stream for `read_plain`, never applied |
| C-55 | crates/app-format/src/hashed_blocks.rs:44; document/read.rs:1857 | `sha256` + `ct_eq` | Version 3 hashed blocks; HeaderHash |
| C-56 | crates/app-format/src/keyfile.rs:106-115, 135, 174, 227, 1702-1703 | `Hasher`, `sha256`, `random::bytes(32)`, `ct_eq` | Key file read, create and check value |
| C-57 | crates/app-format/src/document/read.rs:719, 1934 | `uuid_v4`, `random::bytes(4)` | New ids; attachment rename prefix |
| C-58 | crates/app-core/src/totp.rs:210-212 | `hmac_sha1/256/512` | One-time codes (FEA-04) |
| C-59 | crates/app-core/src/breach.rs:48 | `sha1` of the password | Breach range check (FEA-06): 5-hex prefix out, suffix kept as `SecretString` |
| C-60 | crates/app-core/src/url.rs:617-620 | `sha256` of a command | Remembered "Yes" key (MOD-08.31); **no caller yet** |
| C-61 | crates/app-core/src/storage.rs:61, 84, 382 | `sha256` of a file head; `random::below` | File change check; temp file names |
| C-62 | crates/app-core/src/import/v1.rs:116-128, 161-171 | `kdf`, `cipher::decrypt`, `sha256`, `ct_eq` | Version 1 import |
| C-63 | crates/app-core/src/import/opvault.rs:170, 195, 274, 286, 289, 412, 439 | `verify_hmac_sha256`, `Decryptor`, `kdf::pbkdf2`, `sha512` | Encrypted import (FEA-08) |
| C-64 | crates/app-core/src/import/bitwarden.rs:124, 126-128, 137, 139, 142, 145 | `kdf::pbkdf2`, `sha256` + `import_argon2id`, `hkdf_expand_sha256`, `verify_hmac_sha256`, `cipher::decrypt` | Encrypted import (FEA-08) |
| C-65 | crates/app-core/src/tree.rs:119; settings.rs:873; attachments.rs:508; generator/mod.rs:34; import/mod.rs:976 | `uuid_v4`, `random::below` | Ids, names; **generated passwords and passphrases** (generator/mod.rs:34) |
| C-66 | crates/app-core/src/settings.rs:271, 352, 379 | `kdf::benchmark`, `assess`, `ct_eq` | Vault settings: KDF tuning; repeat check |
| C-67 | crates/app-ffi/src/start.rs:297; wizard.rs:250, 615; edit.rs:1129, 2400; views.rs:669; saving.rs:581, 1327 | `selftest::run`, `benchmark`, `ct_eq`, `random::bytes(128)`, `random::below(36)`, `sha256` | Self-test; wizard; overwrite before delete; temp names; SSH fingerprint; backup names |
| C-68 | crates/app-cli/src/main.rs:101; commands.rs:969 | `selftest::run`, `ct_eq` | Command line self-test; repeat check |
| C-69 | crates/app-hwkey/src/lib.rs:373 | `random::fill` (1 byte) | Hardware key slot test challenge (INT-07.15) |
| C-70 | crates/app-sshagent/src/key.rs:63, 144; server.rs:563, 691 | `OpenSshKey::parse`, `agent_key`, `AgentKey::sign`, `ssh::verify` | SSH agent |
| C-71 | macos/App (80 Swift files) | none | No CryptoKit, CommonCrypto, Security item calls, `SecRandomCopyBytes`, `arc4random` or `.random`. `UUID()` only in AppTests (pasteboard and folder names). |

### 2.4 Random number sources

| Source | Where | Used by App |
|---|---|---|
| `getrandom::SysRng` (OS) | app-crypto random.rs:14, 35, 53, 66, 78 | Yes: the only source App calls (Rust rule 7) |
| Deterministic nonces | p256 RFC 6979, Ed25519 | Signing needs no random (C-38) |
| `getrandom` 0.4.3 via `tempfile` | app-ffi link graph (C-05) | No |
| `getrandom` 0.2.17 via `ring` | feature `net` only | No (TLS inside rustls) |
| std `HashMap` `RandomState` | std, seeded by the OS | Hash flooding defence only; not App's random |
| Swift `UUID()` | AppTests only | Tests only |

### 2.5 Observations for the merge step

4. **Rule 3 wording:** Rule 3 says only app-crypto imports crypto crates. `app-platform/net.rs` imports rustls and its ring provider (C-02). The approved table allows this, but Rule 3 itself does not name the exception. It is off by default and in no product build.
5. **Second random path:** `getrandom` is linked into app-ffi through UniFFI's `tempfile` (C-05). App does not call it. Recorded for AT-B04.
6. **Plain `==` and `cmp` on secret values:** these compares are local logic, not MACs or keys, and nothing remote can time them. The cases: app-autotype lib.rs:811, matching.rs:598, 703; app-core refs.rs:864, 890, 1049; attachments.rs:152; breach.rs:205, 209, 572; import/v1.rs:183, 499-501; opvault.rs:469; onepux.rs:73; health.rs:351, 737-745; app-ffi edit.rs:1624; app-cli commands.rs:853.
7. **C-60:** `remember_key` would store an unsalted SHA-256 of a command in the settings store. If it is ever wired with a resolved command that holds a password, that hash can be guessed offline. It has no caller now.

## Part 3: secret conversions

Secret types and helpers:

| ID | Location | What | Note |
|---|---|---|---|
| S-01 | crates/app-crypto/src/secret.rs:93, 175; `expose` :118, :188; `expose_mut` :124 | `SecretBytes`, `SecretString` | No Clone or Copy; Debug prints `[hidden]`; wiped on drop |
| S-02 | crates/app-format/src/keys.rs:27-62, 211, 244 | `LockedKey` (mlock'd pages, Deref to SecretBytes), `FinalKeys`, `TransformedKey` | Wipe and free first, then unlock (field order) |
| S-03 | crates/app-model/src/entry.rs:22-28, 44-49, 129-131 | `Field.value: SecretString` for every field; `duplicate()`; **`Entry::value(name) -> &str`** | `value()` is an expose that a grep for `expose()` misses: 117 product call sites |
| S-04 | crates/app-model/src/attachment.rs:19 | `Arc<SecretBytes>` attachment data | Shared, not cloned |
| S-05 | crates/app-core/src/text.rs:11-115; crates/app-format/src/buffer.rs:11-40 | `Text`/`Buf` and `Grow`: wiping growable buffers | Growing copies into a new SecretBytes and wipes the old one |
| S-06 | crates/app-platform/src/memory.rs:4-11; app-ffi lib.rs:30; app-cli main.rs:25 | Zeroing global allocator | Every plain Rust copy (UniFFI buffers included) is zeroed when freed; Swift and system copies are not |

Inside Rust, from a secret type to another form:

| ID | Location | Conversion | Note |
|---|---|---|---|
| S-10 | crates/app-ffi/src/views.rs:791-805, 834, 1061-1068; edit.rs:733-738 | Field value → `String` only when not protected (`plain_in`, `plain`, `FieldView`, `CustomFieldView`) | Protected values come empty |
| S-11 | crates/app-crypto/src/mac.rs:82; hash.rs:138-141; cipher.rs:107-109, 391-393; stream.rs:85 | crate output → `to_vec`/`collect` straight into SecretBytes; crate copy zeroized | Exact-size allocations |
| S-12 | crates/app-crypto/src/ssh.rs:313-317, 331, 369-380, 404-416 | Ed25519 seed and P-256 scalar in `Zeroizing`; `mpint32` stack array (scrubbed); `agent_form` encodes into `Zeroizing<Vec>`, moved into SecretBytes | No unwiped copy by design |
| S-13 | crates/app-hwkey/src/protocol.rs:157-205; usb/mod.rs:206-224; app-format keys.rs:182-190 | Hardware key response: report read into `scratch` SecretBytes, assembled in `reply` SecretBytes, `body[..len].to_vec()` into SecretBytes; then R = SHA-256(answer) | IOKit's own buffers are system memory. app-ffi does not depend on app-hwkey yet. |
| S-14 | crates/app-format/src/document/read.rs:1045-1050; document/encode.rs:345-352 | `text_value`: a Protected text → plain `String` for non-field values (27 callers); `secret_value` (:1054-1061) wraps the same decode in SecretString for fields | The plain copies are wiped only when freed (S-06) |
| S-15 | crates/app-format/src/document/write.rs:542-544, 596-610 | Protected field: bytes concat → SecretBytes, XOR, base64 into `Grow` | |
| S-16 | crates/app-core/src/import/opvault.rs:273; bitwarden.rs:121; v1.rs:175; onepux.rs:180-183; json.rs:122; bitwarden.rs:364, 386-392; opvault.rs:580 | Import passwords and values copied into new SecretBytes or `Text` | Wiping |
| S-17 | crates/app-core/src/generator/password.rs:304-337; passphrase.rs:120-135; generator/mod.rs:39-66 | Generated value built in `Chars` (SecretBytes) and `Text`, then SecretString | Wiping |
| S-18 | crates/app-ffi/src/generator.rs:376-388 | `use_generated`: `expose().to_owned()` → plain `String`, moved into `set_password` (SecretString at edit.rs:1422) | Moved, not copied again |
| S-19 | crates/app-ffi/src/wizard.rs:632-635, 639-647; vault_settings.rs:213 | Password pair copied into new SecretStrings (fill, part, change) | |
| S-20 | crates/app-core/src/health.rs:80-99 | Lower-cased rating inputs as plain `String` map keys, moved into SecretString when dropped (F-052) | |
| S-21 | crates/app-cli/src/commands.rs:283, 317, 796, 813; vault.rs:588; crates/app-core/src/clone.rs:160; import/mod.rs:1187-1194; merge.rs:853; crates/app-ffi/src/edit.rs:2079-2080, 2981; crates/app-sshagent/src/entry.rs:166 | `Entry::value("Title"/"UserName"/"URL")` → plain `String` or `format!` | Title and UserName can be protected by vault flags (LD-207, F-060) |
| S-22 | crates/app-core/src/breach.rs:47-60 | Password → SHA-1 → 5-hex prefix (plain, goes to the network) + 35-hex suffix (SecretString) | k-anonymity |
| S-23 | crates/app-core/src/url.rs:617-620 | command → SHA-256 hex in a `String` | No caller yet (C-60) |
| S-24 | crates/app-autotype/src/lib.rs:741-760, 795-814; crates/app-ffi/src/autotype.rs:498-536; app-autotype matching.rs:815-833 | Auto-Type plan holds SecretStrings (`Action::Text`, `Pick`); `autotype_type` only counts characters and posts no key event yet (E8-S3); picker rows mask protected titles and user names | The value stays in Rust today |

From Rust to Swift (UniFFI copies the string through a RustBuffer that S-06 zeroes on the Rust side):

| ID | Location | Export → Swift value | Note |
|---|---|---|---|
| S-30 | crates/app-ffi/src/views.rs:1321-1328 | `show_field` → `String` | Show (AGENTS rule 4 exception) |
| S-31 | crates/app-ffi/src/edit.rs:1439-1441 | `draft_password` → `String` | Editor Show |
| S-32 | edit.rs:1561-1568 | `show_draft_field` → `String` | Editor Show of a field |
| S-33 | edit.rs:1897-1918 (password :1915) | `show_version` → `VersionView.password` | History Show |
| S-34 | edit.rs:1928-1944 | `show_version_field` → `String` | History Show of a field |
| S-35 | edit.rs:1988-1992 | `totp_setup` → `TotpSetup.secret` | The one-time secret in the setup screen |
| S-36 | views.rs:1156-1158 → `totp` :1388, `codes` :1290 (up to 200 per call); edit.rs:2092 `draft_code` | `TotpView.code` | **Live one-time codes, once a second, without a Show** |
| S-37 | edit.rs:1190-1218 via `totp_qr` :2105-2112 and `wifi_qr` :2132 | `Qr.modules` | The QR matrix encodes the one-time link (with its secret) or the Wi-Fi password. API.md says "the text stays in Rust", but the modules carry it. |
| S-38 | crates/app-ffi/src/generator.rs:270-289 (`generate` :326) | `Generated.value` | The generator's value |
| S-39 | crates/app-ffi/src/wizard.rs:621-628 (`password`/`repeat` :991-1000); vault_settings.rs:476-484 | `String` | Show of the new and changed master password |
| S-40 | wizard.rs:1013-1018 | wizard `generate` → `String` | Generated master password, shown |

From Swift to Rust (each goes into a SecretString at once):

| ID | Location | Export | Note |
|---|---|---|---|
| S-45 | crates/app-ffi/src/session.rs:831-844 (SecretString :837) | `unlock(password: Option<String>)` | Master password |
| S-46 | crates/app-ffi/src/edit.rs:1400-1413, 1421-1431, 1510-1528, 2014 | `set_text`, `set_password`, `set_field`, `set_totp(secret)` | Editor values |
| S-47 | crates/app-ffi/src/generator.rs:340-358 (SecretString :350) | `edit_generated(text)` | The value as typed over |
| S-48 | crates/app-ffi/src/wizard.rs:976-988; vault_settings.rs:456-467 | `set_password`, `set_repeat` | Master password pair |

Pasteboard, files, terminal and sockets:

| ID | Location | Where the secret goes | Note |
|---|---|---|---|
| S-50 | crates/app-ffi/src/views.rs:1340-1363, 398-417; generator.rs:365-369; edit.rs:2116-2122 → crates/app-platform/src/clipboard.rs:106-133 → macos/pasteboard.rs:50-83 | `copy_field`, `copy_code`, `copy_generated`, `copy_totp_link` → `copy_value` → `Clipboard::copy` → `NSString::from_str` in one `NSPasteboardItem` with the concealed and transient markers, `CurrentHostOnly` | The value never reaches Swift. The NSString in system memory cannot be wiped (clipboard.rs:22-23). |
| S-51 | crates/app-cli/src/commands.rs:640-650, 705-716 | `clip`: `Clipboard::general().copy(value.expose(), None)`, value dropped, cleared after the wait | Debug builds with `APP_TEST_PASTEBOARD` use a private pasteboard |
| S-52 | crates/app-core/src/storage.rs:575-580 (via `replace_file`, temp file 0600 then rename); used by crates/app-ffi/src/edit.rs:1841-1872 `save_attachment` and crates/app-cli/src/commands.rs:888 | Attachment and export bytes to a file | Exports (`export/csv.rs:20`, `html.rs:68`, `xml.rs:15`) return SecretBytes; only app-cli writes them (commands.rs:1294-1300) |
| S-53 | crates/app-ffi/src/edit.rs:2378-2420, 1119-1135 | `open_attachment`: plaintext into a 0600 temp file in App's open folder; `wipe_file` overwrites it with random bytes, then deletes it | Plaintext on disk while the user views it |
| S-54 | crates/app-ffi/src/wizard.rs:716-724; crates/app-format/src/keyfile.rs:132-180 | New key file written with mode 0400 | Key material on disk by design (FMT-18.22) |
| S-55 | crates/app-cli/src/term.rs:56-93, 173-232; commands.rs:436-453, 1306-1310; crates/app-ffi/src/cli.rs:240-297 | Command line: `show` prints field values (protected included) to stdout; attachments to stdout; escaped copies held in SecretString; passwords read with echo off into SecretBytes, then SecretString | By design (INT-10) |
| S-56 | crates/app-sshagent/src/agent.rs:129-165, 204-224, 352-; server.rs:405-451 | Decrypted private key fields → `add_message` (SecretBytes) → Unix socket to the system agent; incoming agent messages read into SecretBytes | By design (INT-06); the socket's peer is checked first (agent.rs:226-) |

Swift holders (Swift `String`s cannot be wiped; ARC frees them through `malloc`, which S-06 does not cover):

| ID | Location | Holder | Dropped |
|---|---|---|---|
| S-60 | macos/App/UnlockModel.swift:19, 73-74, 83, 149; UnlockView.swift:209, 211 | `password` bound to `SecureField` or `ShownPasswordField`; `typed` captured by a detached Task | Set to `""` before the unlock call (:74) and on drop (:149) |
| S-61 | macos/App/Platform/ShownPasswordField.swift:9-62, 67-105, 107-124, 130-188 | `ShownPasswordField` on `NoCopyTextField`/`NoCopyCell`/`NoCopyEditor`: the text sits in the field's `stringValue`; no copy, cut, drag, Services or Writing Tools; secure input while focused | When the view goes |
| S-62 | macos/App/EditorPasswordField.swift:9-20, 98-136, 141-155; SecretFields.swift:9-28, 33-, 80-100 | Shown fields are `NoCopyTextField`; masked fields are `FocusSecureField` (`NSSecureTextField`); masked typing goes straight to Rust | Swift keeps no copy while masked |
| S-63 | macos/App/VaultModel.swift:43, 46, 228-231, 239-254, 360-371, 390-398 | `shown[field]` (Show value), `codes[id]` (TotpView) | On Hide, selection change, leave, lock and close |
| S-64 | macos/App/EditorModel.swift:42, 46, 51, 105-149, 177, 183-202 | `shownPassword`, `shownFields` (also **a typed protected value**, :109, F-060), `code` | On Hide, `pause`, `close` |
| S-65 | macos/App/Generator.swift:16, 70-72, 82-88, 107-124 | Generator `value` | On close and refusal; Copy and Use go through Rust |
| S-66 | macos/App/NewVaultCredentials.swift:9-56; NewVaultModel.swift:64-65; VaultSettingsActions.swift:13-45; VaultSettingsModel.swift:72-73 | `shownPassword`, `shownRepeat` (Show, generate) | On Hide and close (:41-42, :36-37, :45) |
| S-67 | macos/App/Dialogs.swift:339-353; EditorMorePages.swift:379-380 | Version field Show in `@State shown` (also `accessibilityValue`, :347); `VersionView` (with password) in `model.dialog` | When the dialog closes |
| S-68 | macos/App/DialogSheets.swift:8, 48, 83-85 | `TotpSetupSheet` `@State secret`, filled from `setup.secret` | Set to `""` after `setTotp` |
| S-69 | macos/App/EditorPages.swift:62, 70-71; DetailFields.swift:89-90, 211-216, 314; EntryListView.swift:173; EditorEntryPage.swift:339 | Drawn Show values and live codes; accessibility values match what is drawn (dots while hidden) | With S-63 and S-64 |

### 3.1 Observations for the merge step

8. **Crossings versus the rule:** architecture.md:189 says Show "returns one `String`, the only secret that crosses to Swift". AGENTS rule 4 allows "the single value the user asked for with Show". The code sends more out: S-30 to S-40. Live one-time codes (S-36, up to 200 per call, once a second) and the QR matrix (S-37) cross with no Show at all. API.md:243 lists most of these crossings, but leaves out the wizard and vault-settings `password()`, `repeat()` and `generate()` (S-39, S-40). It also says of QR that "the text stays in Rust".
9. **Debug on secret strings:** `VersionView` (edit.rs:458), `TotpSetup` (edit.rs:268) and `TotpView` (views.rs:360) derive `Debug` over a password, a one-time secret and a code. `Generated` hides its value in a hand-written `Debug` (generator.rs:107-114). Rust rule 3 says secrets never get `Debug` output.
10. **`Entry::value()`:** this accessor (S-03) is an expose that does not say so: 117 call sites a grep for `expose()` misses. Checkers should count it as an exposure.
11. **Plain Title and UserName copies:** S-21 copies `Entry::value("Title")` and `"UserName"` into plain strings whether or not a vault flag protects them. The command line prints them. Compare with LD-207 and F-060.
12. **Protected non-field text:** `text_value` (S-14) decodes a Protected value into a plain `String`; only the allocator wipes it.
13. **Swift copies:** the Swift copies (S-60 to S-69) are not wiped. This is the documented limit (LD-133, SR-07). The editor keeps a typed protected value outside a Show (S-64, F-060, LD-207).
14. **Auto-Type:** when E8-S3 posts key events, the plan's secrets go into the system event stream (S-24). Review it there.

## Counts

- Unsafe: 60 items (U-01 to U-60). 56 blocks (37 product, 8 test tools, 11 unit tests), 11 `unsafe fn`, 2 `unsafe impl`, 2 safe `extern "C"` handlers, the generated UniFFI scaffolding and 2 foreign traits. Every block has a SAFETY note (clippy exit 0; control exit 101). 2 `unsafe fn`s lack a `# Safety` section (U-39, U-40). 0 unsafe outside the two allowed folders.
- Crypto: 58 items. 5 at the Rule 3 boundary (C-01 to C-05), 31 inside app-crypto (C-10 to C-40), 22 caller groups (C-50 to C-71). 1 approved exception outside app-crypto (C-02, feature `net`). 0 Swift crypto.
- Secrets: 53 items. 6 types and helpers, 15 Rust conversions, 11 Rust-to-Swift crossings, 4 Swift-to-Rust crossings, 7 sinks (pasteboard, files, terminal, socket), 10 Swift holders.
- Observations for the merge step: 14.
