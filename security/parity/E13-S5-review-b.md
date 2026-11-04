# E13-S5 Review B: unsafe code, crypto calls, secret conversions

Story: E13-S5, two-person review of every `unsafe` block, crypto call and secret conversion. Role: Checker B. I did not read the other Checker's file.
Date: 2026-10-29. Tree read from 00:29 to 00:50 (CET).
Clean room: App's own code only, plus App's marked changes in `vendor/ssh-key` (LD-209) and how App calls the vendored crates. No reference source opened, no reference app run.
Edits: this file only. No product code changed in the shared tree. Probes ran in a private copy.

## Files read, with their state

All reviewed Rust files were last changed before 00:29 (newest: `app-platform/src/lib.rs` 23:51:20 on 10-28, a touch with unchanged bytes per the inventory; `app-ffi/src/autotype.rs` 22:46:47). Swift files changed after the inventory was made: `macos/App/AutoType.swift` (23:33:08), `macos/App/Dialogs.swift` (00:02:48). I read both at about 00:36. While I worked, `spec/decisions.md` changed at 00:41:57. I read its LD-197 and LD-207 rows after that change. A new test file, `crates/app-ffi/tests/autotype.rs` (00:45:22), appeared. It has 0 `unsafe` and I did not review it. No other reviewed file changed between 00:29 and 00:47 (`find -newer`).

## Proof run

All runs used my own target (`CARGO_TARGET_DIR=/tmp/e13s5-b-target`), offline.

- `cargo clippy --offline -p app-platform --features appkit,memory,test-memory,test-signals --all-targets -- -D clippy::undocumented_unsafe_blocks -D clippy::missing_safety_doc -D clippy::unnecessary_safety_comment`: exit 0.
- The same for `-p app-hwkey --all-targets`: exit 0.
- `cargo test --offline -p app-platform --features appkit,memory,test-memory,test-signals --lib -- macos::memory macos::signals macos::terminal macos::pipe`: `test result: ok. 10 passed; 0 failed; 4 ignored` (the 4 ignored are the child halves). Among them: `freed_blocks_are_zero`, `realloc_wipes_the_old_block_when_it_grows_or_shrinks`, `the_system_allocator_keeps_freed_bytes`, `app11_9_b_locked_pages_are_wired_until_the_last_guard_drops`, `app11_9_refused_lock_goes_on_with_one_warning`, `int10_29_quit_signal_is_noted_then_ends_the_process`, `ld178_ignored_sigint_stays_ignored`, `app09_16_quit_signal_at_the_prompt_restores_the_terminal`, `a_write_to_a_closed_socket_is_an_error_not_a_signal`.
- Probe, run in a private copy (`/tmp/e13s5-b-copy`, target `/tmp/e13s5-b-copy-target`). I added one test, `probe_b::two_guards_dropped_in_creation_order_leave_note_installed`, to the copy's `signals.rs`. It starts two `catch_quit()` guards, drops the first, then the second, and reads the SIGTERM action. Output: `SIGTERM handler after both guards: note=true dfl=false` and `1 passed` (finding B-6).
- `cargo tree --offline -p app-ffi --features net -e normal -i ring` and `-i getrandom@0.2.17`: both reach `app-ffi` through `app-platform` and `rustls` (finding B-1). `scripts/build-core.sh:36` is `cargo build ... -p app-ffi --features net`.
- `Cargo.lock`: one version of each approved crypto crate. The two exceptions are `getrandom`, with 0.2.17 (ring) and 0.4.3, and `rand` 0.10.3, which proptest brings in for tests only (`cargo tree -i rand@0.10.3`).
- `grep` of Swift (`macos/App`, 80 files) for CryptoKit, CommonCrypto, `SecRandomCopyBytes`, `arc4random`, `.random(`, `SecItem`, `LAContext`, `UUID()`: no hits.
- `grep -c unsafe` over `fuzz/`, `vendor/zxcvbn/src`, `vendor/ssh-key/src`: no `unsafe` code (only the comment in `vendor/zxcvbn/src/lib.rs:17`).

## Findings (most severe first)

None is Critical, High or Medium. I found no memory unsafety and no reachable secret exposure.

| ID | Severity | Items | Finding | Smallest fix |
|---|---|---|---|---|
| B-1 | Low | C-02, C-05 | The inventory says rustls on ring is "off by default and in no product build" (observation 4, C-02) and that getrandom 0.2.17 reaches App "only via ring (net)". But `scripts/build-core.sh:36` builds the Mac app's core with `--features net`, so ring (C and assembly), rustls and getrandom 0.2.17 ship in the Mac app. rustls draws its TLS randoms through ring's own OS source, so a second random path really runs. The use is allowed: LD-194 and LD-197, which the lead co-signed on 2026-10-28. But `plan/architecture.md` (approved table, HTTPS row) and the inventory still say "lead co-sign open", and AGENTS rule 3 ("Only `app-crypto` imports them") names no exception. | Correct C-02 and C-05 in the merge step: in the product build through `build-core.sh`, co-signed. Name the LD-194/LD-197 transport exception in Rust rule 3 or rule 7 of architecture.md. |
| B-2 | Low | S-33, S-35, S-36, S-37, S-38 | Rust rule 3 says secrets get no `Clone` and no `Debug` output. Four FFI records derive `Debug, Clone` over secret strings: `VersionView` (`edit.rs:458-475`, `password`), `TotpSetup` (`edit.rs:268-283`, `secret`), `TotpView` (`views.rs:360-370`, `code`) and `Qr` (`edit.rs:504-510`, `modules`). `Generated` (`generator.rs:96-97`) hides `value` in a hand-written Debug but still derives `Clone`. Product code formats none of them today: the only `{:?}` uses are the tests at `edit.rs:2781`, `2851` and `2935`, which assert that protected values are absent. | Hand-write `Debug` for these four records as `Generated` does, hiding the secret field. Drop `Clone` where UniFFI does not need it. |
| B-3 | Low | S-36, S-37 | Two crossings happen without a Show. Live one-time codes (`codes`, up to 200 per call, once a second; `totp`; `draft_code`) and the QR module matrices (`totp_qr`, `wifi_qr`) go to Swift. The matrix encodes the whole one-time link or Wi-Fi password and decodes trivially. `plan/architecture.md` (app-ffi Must) says Show's value is "the only secret that crosses to Swift". `API.md:5` repeats it. `API.md:95` labels the QR export "Secret: none". The codes are on screen by design (FEA-04.24), and the QR export is user-initiated, so this is a missing rule and documentation, not a leak. | Record a decision for the two exceptions, citing proven apps. Change `API.md:95` to name the matrix as a secret crossing. Extend the Must line in architecture.md. |
| B-4 | Low | missed item M-4 (with S-37) | `wifi_text` (`edit.rs:1222-1243`) builds the Wi-Fi password and network name in plain `String`s (the `esc` closure, which can grow) and joins them with `format!`. Only then does the result go into a `SecretString`. Rust rule 3 says "no `format!` with a secret". The zeroing allocator (S-06, LD-133) wipes the plain copies when they are freed or grow, so the impact is the rule's letter. | Push the escaped parts straight into one `String` sized exactly once, then wrap it, as `decode_protected_text` does. |
| B-5 | Low | S-21 | The command line composes Titles into its messages. `commands.rs:283-285` prints "Changes to {title} saved.", `:796-806` prints "{title} moved to {gname}.", `:813` (rm), `:317` (`ls`) and `vault.rs:588` (paths). Merge change records carry Titles too (`merge.rs:853`, printed by `merge_cmd`). None of these checks the vault's Title flag. LD-207 says a protected standard field "is never part of any text App composes for the screen, logs or errors". The window app follows it (`plain_in`, and the SSH agent's `shown_title` in `entry.rs:161`). The command line does not, and no decision says LD-207 leaves the command line out. | Either mask a flag-protected Title in command line messages (as `refs` `masked` does), or add one line to LD-207 that leaves the command line out (INT-10 prints values on request). |
| B-6 | Low | U-13 to U-16 | The `QuitGuard` doc says "Only one may live at a time" (`signals.rs:28-29`, `terminal.rs:15-16`), but nothing enforces it. Say two guards exist and the older drops first. It restores the original actions. Then the younger drops and restores the `note` handler it saved, so from then on SIGINT, SIGTERM, SIGQUIT and SIGHUP are only noted and never end the process. Proven by the probe above. This is not reachable today: the three callers (`app-ffi/src/cli.rs:235`, `app-cli/src/term.rs:176`, `app-cli/src/commands.rs:712`) run one after another on one thread. It is not undefined behaviour. | A static `AtomicBool` taken in `catch_quit` (a second call returns `Err`) and released in `Drop`. |
| B-7 | Info | U-39, U-40 | The IOKit callbacks are `unsafe extern "C-unwind"`, the callback type `objc2-io-kit` declares. They call the sink without `catch_unwind`, and they have no `# Safety` doc section. Clippy does not ask for one on private fns. In a debug or test build, a panic in the sink would unwind through IOKit and CoreFoundation frames. Release builds abort on panic. Today's only sink (`app-hwkey/src/watch.rs:51`) is `let _ = events.send(...)`, which cannot panic. `app-hwkey` is not yet a dependency of any product crate. | Add the `# Safety` lines. Wrap the sink call in `std::panic::catch_unwind` and drop the event (or abort) on a panic. |
| B-8 | Info | S-39, S-40, S-06 | `API.md:243` leaves out the wizard's and vault settings' `password()`, `repeat()` and `generate()` crossings (`wizard.rs:991-1018`, `vault_settings.rs:476-484`). It also still says UniFFI buffers are freed unwiped "until the zeroing allocator (LD-133, E6-S6)", which is now installed (`app-ffi/src/lib.rs:30-32`). | Two edits to `API.md:243`. |
| B-9 | Info (plausible, not proven) | S-61, S-62, S-68 | Neither `NoCopyEditor.harden()` nor `NoCopyCell` turns off undo (no `allowsUndo` anywhere in `macos/App`). `NSTextFieldCell` allows undo by default, so the shown-password editor may register its earlier texts with the window's undo manager. That would be a Swift holder the inventory does not list. I did not probe it: that needs a visible window (rule 10). | `allowsUndo = false` on `NoCopyCell` (and on the editor in `harden()`). |
| B-10 | Info | C-36, C-37, S-56 | In the vendored `ssh-key`, the private bytes of a key type the crate does not know (`OpaquePrivateKeyBytes`, `vendor/ssh-key/src/private/opaque.rs:142`) derive `Clone` and are not wiped on drop. App parses such keys (`OpenSshKey::parse`) and can send them to the system agent (`agent_form`). Only the zeroing allocator wipes them. That holds in app-ffi and app-cli, not in app-sshagent's own test binaries. Upstream behaviour, not an LD-209 change. | Note it in LD-182's conditions, or refuse unknown key types in `OpenSshKey::parse`. |

## Verdicts, item by item

"Sound" means the SAFETY note, crypto use or secret handling holds as the inventory describes it, read in context.

### Unsafe

| ID | Verdict | Note |
|---|---|---|
| U-01 | Sound | Pointer and layout go to `A` unchanged. `dealloc` writes only inside the freed block. No allocation, panic or unwind (memset_s does not allocate). `realloc` uses the trait default, which calls `self.dealloc`, so the old block is wiped (test `realloc_wipes_...`). |
| U-02 | Sound | Passes the caller's contract on. |
| U-03 | Sound | As U-02. |
| U-04 | Sound | `wipe(ptr, layout.size())` comes before `A::dealloc` with the same pointer and layout. |
| U-05 | Sound | `memset_s(ptr, len, 0, len)`: smax equals n, and a Layout size is at most isize::MAX, which is the macOS RSIZE_MAX. A zero size is skipped. |
| U-06 | Sound | `sysconf` touches no memory of ours. A non-power-of-two answer falls back to 16384, so `page - 1` cannot underflow in `memory::lock`. |
| U-07 | Sound | `mlock` only wires pages. `pub(crate)`: the one caller, `memory::lock`, derives page-aligned bounds from a live slice. |
| U-08 | Sound | As U-07. In `LockedKey` the key drops first (`keys.rs:28-31`), then the pages unlock. Nested locks are proven by the `app11_9_b` test. |
| U-09 | Sound | `rlimit` is valid and only read. Release builds only (`hardening.rs`). |
| U-10 | Sound | PT_DENY_ATTACH ignores its other arguments. The `libc` signature matches (`*mut c_char` address). |
| U-11 | Sound | SIG_IGN is a constant, so no handler of ours runs. Rust's `Command` resets SIGPIPE in its children. |
| U-12 | Sound | One `SeqCst` store to a lock-free `AtomicI32`, which is async-signal-safe. `sa_flags` is 0, so the one-argument handler form is right. |
| U-13 | Sound | Null new action, and `current` is complete. See B-6 for the single-guard rule. |
| U-14 | Sound | `catch` and `current` are complete and alive. An error puts back what was replaced, then raises a noted signal. |
| U-15 | Sound | Puts back the action the system returned. Errors are ignored, which is harmless. |
| U-16 | Sound | `raise` runs only after `put_back`, so the original action handles the signal. Tests `int10_29_...` and `app09_16_...` pass. |
| U-17 | Sound | Test feature only. SIG_DFL. |
| U-18 | Sound | `confstr` writes at most `buf.len()` bytes, the NUL included. A return of 0, 1 or more than the length is refused. |
| U-19 | Sound | The fd lives while `stream` is borrowed. `uid` and `gid` are writable. Used by the instance channel and both SSH agent paths. |
| U-20 | Sound | `geteuid` takes no pointers. |
| U-21 | Sound | A zeroed `utsname` is valid, and `assume_init` runs only after `uname` returns 0. Fields are read up to their NUL. |
| U-22 | Sound | `ts` is initialised. A failure panics on purpose (LD-156 (9)). |
| U-23 | Sound | `localtime_r` writes only `tm`. Only `tm_gmtoff` is read, never the `tm_zone` pointer. |
| U-24 | Sound | `assume_init` runs after `tcgetattr` returns 0. termios is plain integers, so uninitialised padding does not matter. |
| U-25 | Sound | `quiet` is a complete termios. On failure the guard drops. |
| U-26 | Sound | One pollfd, alive for the call. EINTR loops. |
| U-27 | Sound | The `BorrowedFd<'fd>` lifetime ties the fd to the guard. The terminal is restored before `quit` drops (field order). |
| U-28 | Sound | `Vec` sized to `count()`. The CFSet from `IOHIDManagerCopyDevices` is our own immutable copy. A negative count gives 0 slots, which cannot happen for a set. |
| U-29 | Sound | None matches all devices. |
| U-30 | Sound | The set keeps each device alive. `retain` adds our reference, and `CFRetained` releases it. |
| U-31 | Sound | 8 writable bytes, the length says 8, synchronous. Reply bytes land in the caller's `scratch` SecretBytes (S-13). |
| U-32 | Sound | A `NonNull` taken from `&[u8; 8]` is only read through, as `IOHIDDeviceSetReport`'s const pointer allows. |
| U-33 | Sound | An immutable CF constant. |
| U-34 | Sound | An array of CFString-to-CFNumber dictionaries. |
| U-35 | Sound | Callbacks run only inside `run_in_mode` on this thread. The context is used as a shared `&Watching`. `watching` drops before `manager`, but only after the unschedule and the None registration. |
| U-36 | Sound | This thread's run loop and mode. |
| U-37 | Sound | The same run loop and mode. |
| U-38 | Sound | Both parameters are nullable in the header, so the manager keeps no pointer to `watching`. |
| U-39 | Sound, Info B-7 | Context is valid while callbacks can run. The device is nonnull by the header's assume-nonnull region. No `# Safety` section, no `catch_unwind`. |
| U-40 | Sound, Info B-7 | As U-39. |
| U-41 | Sound (tool) | Freed blocks are read only through `memmem` and `memcmp`, within the block. Feature `test-memory` and tests only. |
| U-42 | Sound (tool) | `rusage_info_v2` matches RUSAGE_INFO_V2. Zeroed before the call. |
| U-43 | Sound (tool) | A block is read only while it is ours. The dangling `first` pointer is only compared as an address. |
| U-44 | Sound (tool) | Passes the contract on. |
| U-45 | Sound (tool) | As U-44. |
| U-46 | Sound (test) | Writes inside the block, frees it once. |
| U-47 | Sound (test) | Each pointer is used with its own layout. Only copied bytes are read. |
| U-48 | Sound (test) | Child process only. |
| U-49 | Sound (test) | `now` is writable. |
| U-50 | Sound (test) | Child process only. Must fail. |
| U-51 | Sound (test) | Atomic store only. The SIGSEGV comes from the kernel, not a fault, so returning from the handler is fine. |
| U-52 | Sound (test) | Handler as in U-51. |
| U-53 | Sound (test) | Targets the test's own child only. |
| U-54 | Sound (test) | SIG_DFL in a child. |
| U-55 | Sound (test) | Null name, settings and size are allowed. |
| U-56 | Sound (test) | New fds that nothing else owns. |
| U-57 | Sound (test) | As U-24. |
| U-58 | Sound (generated) | rustc's `unsafe_code` lint does not report code from external proc-macro expansions. That is why the forbid at `lib.rs:4` holds while refusing hand-written `unsafe`, as Rust rule 2 says. UniFFI's correctness rests on LD-157. |
| U-59 | Sound | The traits require `Send + Sync`. The Swift implementers (`Platform/Front.swift:13`, `AutoType.swift:52`) are `nonisolated final class`. `WindowEvents` hops to the main actor for UI work. Note for E8-S3: `FocusCheck.sameWindow()` runs AX and NSWorkspace reads on the Rust thread that calls it. That is not Rust memory unsafety, but check it when typing goes live. |
| U-60 | Sound | Safe statics. They rest on U-01 to U-05. |

Gates: `app-platform` and `app-hwkey` use `deny` (`lib.rs` and `[lints.rust]`), and their only `#![allow(unsafe_code)]` lines are `macos/mod.rs:5` and `usb/mod.rs:9`. That fits Rust rule 2. Every other crate has `#![forbid(unsafe_code)]` and the workspace lint `forbid`. The `fuzz/` workspace has no forbid and no `unsafe`.

### Crypto

| ID | Verdict | Note |
|---|---|---|
| C-01 | Sound | Only `app-crypto/Cargo.toml` names the approved crypto crates. Exact pins in `[workspace.dependencies]` match the approved table and `Cargo.lock`. `zeroize` features are on, and compile-time `ZeroizeOnDrop` checks are in `hash.rs`, `mac.rs` and `kdf.rs`. `crypto_box` is pinned but unused. |
| C-02 | Sound use, Low B-1 | TLS 1.3 and 1.2 only, ring provider, the platform verifier (`net.rs:244-258`). It ships in the Mac app (`build-core.sh:36`), contrary to the inventory. LD-197 is co-signed. |
| C-03 | Sound | `rcgen` is a dev-dependency only. |
| C-04 | Sound | The fuzz workspace only patches `ssh-key` to the vendored copy. Targets use `app_crypto::cipher`. |
| C-05 | Sound, see B-1 | getrandom 0.4.3 comes through UniFFI's `tempfile` (bindgen side), and App never calls it. getrandom 0.2.17 comes through ring, and ring does call it for rustls in the product build. |
| C-10 | Sound | `subtle` slice `ct_eq`. Lengths are public. |
| C-11 | Sound | `==` goes through `ct_eq` (test `equality_goes_through_ct_eq`). |
| C-12 | Sound | Resize to capacity, then `zeroize`, before the free. `SecretString` takes the buffer out without copying. |
| C-13 | Sound (best effort) | `#[inline(never)]` frames, `zeroize` and `black_box`. Registers and other threads are not covered, as documented. |
| C-14 | Sound | `SysRng::try_fill_bytes` (getentropy). No fallback. |
| C-15 | Sound | Filled in place in a `SecretBytes`. |
| C-16 | Sound | Rejection below `2^32 mod n`, which is exactly uniform. 64 draws, then fail closed. n = 0 is refused. |
| C-17 | Sound | Version and variant bits set over OS random bytes. |
| C-18 | Sound | Boxed state, `finalize_reset` in place, the output array zeroized. |
| C-19 | Sound | Parts are fed in turn, with no joined copy. |
| C-20 | Sound | Keys of any length. The tag goes into `SecretBytes`, and the crate output wipes itself. |
| C-21 | Sound | Full-length tag only, `subtle` compare. The computed tag is never returned. |
| C-22 | Sound | Key and IV lengths are checked before `new_from_slices`. States are boxed and zeroize. |
| C-23 | Sound | CBC output holds only ciphertext after the in-place encrypt. Pending plaintext is `Zeroizing`. The ChaCha20 limit is checked. |
| C-24 | Sound | One `Decrypt` error for every failure. Exact-size collects. `finish_unpadded` is only for version 3. |
| C-25 | Sound | Looks at all 16 bytes with `subtle` (`ct_gt`, `ct_eq`). Integrity is checked before decryption in version 4 and in the imports that have a MAC. |
| C-26 | Sound | Lengths checked, states boxed, `ZeroizeOnDrop` proven at compile time in the tests. |
| C-27 | Sound | SHA-512 bytes 0-31 and 32-43 (version 4), SHA-256 with a fixed nonce (version 3, read only). |
| C-28 | Sound | `try_apply_keystream`, StreamLimit at the end, data unchanged on error. |
| C-29 | Sound | Runs only with `Cleared` from `assess`. AES-KDF in a `SecretBytes`, then a SHA-256 `finalize_into`. `scrubbed_deep`. |
| C-30 | Sound | The key schedule zeroizes. ECB over the two 16-byte blocks, as CRY-02.1 says. |
| C-31 | Sound | Work memory is `Zeroizing<Vec<Block>>`, reserved fallibly. Settings go through `u32::try_from`. No parallel feature. |
| C-32 | Sound | Zero password and template salt. Clamped count, and zero time gives the maximum (fails safe). |
| C-33 | Sound | Iterations 1 to 10,000,000 and length 1 to 1,024 are checked first. |
| C-34 | Sound | `from_prk` needs a PRK of at least 32 bytes. Length 1 to 8,160. |
| C-35 | Sound | Ranges are checked before any allocation, plus `checked_mul`. |
| C-36 | Sound, Info B-10 | Parse failures are `None`, and parsing is inside `scrubbed`. |
| C-37 | Sound | Empty passphrase, cipher, KDF, salt and rounds are checked before any bcrypt-pbkdf work. The AEAD tag or checkint is verified by `ssh-key`. |
| C-38 | Sound | Ed25519 seed in `Zeroizing`, and the public half must match. The P-256 scalar goes through `mpint32` into `Zeroizing`, then `SigningKey::from_bytes`, and the public key must match. RFC 6979 deterministic nonce. Inside `scrubbed`. |
| C-39 | Sound | Ed25519 `verify_strict`. P-256 `from_sec1_bytes` and `from_scalars` (range checked). The algorithm must match, with no trailing bytes. |
| C-40 | Sound | Known answers with public values only. |
| C-50 | Sound | The answer's length (20) is checked before R. Parts are joined in order with no copy. The T-changed check uses `ct_eq`. Keys are in `LockedKey`. |
| C-51 | Sound | Header hash and HMAC are compared in constant time. Each block's key is `SHA-512(LE64(i) || K)`. Sizes are checked before reading. The whole stream is verified before decryption (`payload.rs:152-156`). |
| C-52 | Sound | Version 4: header HMAC, then blocks, then decrypt. Version 3: the start bytes are compared with `ct_eq` before the rest is decrypted. |
| C-53 | Sound | Fresh salt or seed, master seed, IV and stream key every save, all drawn before key work (`lib.rs:258-266`). A new master seed gives a new K_enc, so IVs never repeat under one key. |
| C-54 | Sound | The zero-key stream in `read_plain` is never applied: protected values are refused first. |
| C-55 | Sound | Constant-time compares. |
| C-56 | Sound | Streamed SHA-256 into `LockedKey`. A new key file takes 32 OS random bytes and a written check value. The check value compare uses `ct_eq`. |
| C-57 | Sound | Not secret. |
| C-58 | Sound | HMAC as RFC 4226/6238. The code comes back as `SecretString`. |
| C-59 | Sound | SHA-1 for the k-anonymity prefix. The full hex is built in a wiping `Text`. |
| C-60 | Sound | No caller (`grep remember_key`: tests only). The unsalted digest risk is recorded by the inventory (observation 7). |
| C-61 | Sound | Not secret. |
| C-62 | Sound | KDF through `assess`. The content hash is compared with `ct_eq` after the CBC decrypt (the format has no MAC). Keys are in `SecretBytes`. |
| C-63 | Sound | The MAC is checked before every decrypt (`opvault.rs:170`, `:439`). PBKDF2-SHA512, then the split. |
| C-64 | Sound | PBKDF2 or Argon2id, then HKDF-Expand to separate enc and mac keys. Both MACs are checked before the decrypt. |
| C-65 | Sound | Generator picks use `below` with Fisher-Yates. UUIDs come from the OS source. |
| C-66 | Sound | Benchmark with the CPU-time clock. The repeat compare uses `ct_eq`. |
| C-67 | Sound | Hashes of public data (paths, the SSH public blob). The wipe overwrite uses OS random bytes. |
| C-68 | Sound | Self-test at start. The repeat compare uses `ct_eq`. |
| C-69 | Sound | A 1-byte OS random challenge for the slot test. |
| C-70 | Sound | Goes through `app-crypto/ssh.rs` (C-36 to C-39). |
| C-71 | Sound | No crypto or random API in product Swift (grep above). |

### Secrets

| ID | Verdict | Note |
|---|---|---|
| S-01 | Sound | No Clone or Copy. Debug prints `[hidden]`. Wiped on drop over the full capacity (tests in `secret.rs`). |
| S-02 | Sound | Field order means wipe and free, then unlock. Debug is hidden on all three. |
| S-03 | Sound | Every field value is a `SecretString`. `duplicate()` copies straight into a new one. `Entry::value()` is an unmarked expose, as the inventory says. |
| S-04 | Sound | `Arc<SecretBytes>`, wiped when the last holder drops. |
| S-05 | Sound | Growth copies into a new `SecretBytes`, and the old one drops wiped. |
| S-06 | Sound | Proven by the tests above. It covers Rust heap only, as documented. |
| S-10 | Sound | `plain_in` checks the field flag or the vault flag. `plain` is only for fields the vault flags never cover. The row subtitle skips protected custom fields. |
| S-11 | Sound | Exact-size copies into `SecretBytes`. The crate outputs zeroize. |
| S-12 | Sound | Stack copies (`mpint32`'s array, `FieldBytes`) are covered by `scrubbed`. `agent_form` uses exact capacity, so the buffer never grows. |
| S-13 | Sound | Reports land in `scratch`, the answer in `reply`, and the body goes into an exact-size `SecretBytes`. `app-hwkey` is not linked into any product crate yet. |
| S-14 | Sound (limit) | `text_value` plain copies of Meta, Group and custom-data text are wiped only by S-06. |
| S-15 | Sound | `concat` of exact size into `SecretBytes`, XOR in place, base64 into `Grow`. Unprotected values go into the same wiping `Grow` (`write.rs:225`). |
| S-16 | Sound | Copies into new `SecretBytes`, dropped right after the KDF. |
| S-17 | Sound | `Chars` (SecretBytes), then `Text`, then `into_secret`. |
| S-18 | Sound | A plain `String` moves into `set_password`, which wraps it at once. A `TooLong` path drops it through S-06. |
| S-19 | Sound | New `SecretString`s. `matches()` uses `ct_eq`. |
| S-20 | Sound | Map keys move into `SecretString` on duplicates and on drain (F-052). |
| S-21 | Low B-5 | The window app and the SSH agent mask protected Titles. Command line messages and merge records do not. Heap copies are wiped by S-06. |
| S-22 | Sound | Only the 5-hex prefix is plain. The suffix is a `SecretString`. |
| S-23 | Sound | No caller (C-60). |
| S-24 | Sound (for now) | `autotype_type` counts keys and posts nothing. Review again in E8-S3, when the values reach the system event stream. |
| S-30 | Sound | Show. Refuses one-time password and passkey fields (`check_field`). Resolved through the reference meter. |
| S-31 | Sound | Editor Show of the password. |
| S-32 | Sound | `showable` refuses the password, one-time password and passkey fields. |
| S-33 | Sound flow, Low B-2 | Fetched only by the sheet's Show button (`EditorMorePages.swift:379`). The record derives Debug and Clone. |
| S-34 | Sound | As S-32. |
| S-35 | Sound flow, Low B-2 | Only for the setup screen the user opened. The Swift `@State` copy is cleared after `setTotp`. The `model.dialog` copy goes with the dialog. |
| S-36 | Low B-3, B-2 | No Show. Codes expire. They are dropped on leave, lock and close (`VaultModel.swift:242-258`, `EditorModel.swift:185-202`). |
| S-37 | Low B-3, B-4 | The module matrix carries the secret. User-initiated. It lives in `model.dialog` until the dialog closes. |
| S-38 | Sound, B-2 (Clone) | Debug hides the value. Dropped on lock and close (D-02-5). |
| S-39 | Sound flow, Info B-8 | Show of the typed master password. Not listed in API.md. |
| S-40 | Sound flow, Info B-8 | The generated master password, shown on purpose. Not listed in API.md. |
| S-45 | Sound | Wrapped before the length check, so a `TooLong` error drops a `SecretString`. |
| S-46 | Sound | Length checked, then wrapped. Error paths drop a plain `String` through S-06. |
| S-47 | Sound | As S-46, and the value is dropped on `TooLong`. |
| S-48 | Sound | Into `SecretString`. |
| S-50 | Sound (limit) | One item with the concealed and transient markers, CurrentHostOnly. The change count is recorded and the content never read back. The clear empties only App's own copy. The NSString copy cannot be wiped, as documented. |
| S-51 | Sound | The vault is dropped before the wait and the value right after the copy. The quit guard cuts the wait short. Debug builds use a private pasteboard. |
| S-52 | Sound | 0600 temp file, sync, rename. A link at the path is replaced, never followed. |
| S-53 | Sound (limit) | 0700 folder checked with `symlink_metadata`, 0600 `create_new` file, random name. The overwrite is best effort on APFS and SSDs, as documented in MOD-05. |
| S-54 | Sound | Mode 0400, `create_new`, read back. Removed on failure. |
| S-55 | Sound | Echo-off prompt that reads one byte at a time into `SecretBytes`. A quit signal restores the terminal first. |
| S-56 | Sound | The peer uid is checked on both sockets. The add message and incoming messages sit in `SecretBytes`. |
| S-60 | Sound (Swift limit) | Set to `""` before the call and in `clear()`. |
| S-61 | Sound, Info B-9 | No Copy, Cut, drag, Services, Look Up or Writing Tools, and secure input while focused. Undo is not turned off. |
| S-62 | Sound, Info B-9 | Masked typing goes straight to Rust, and the shown field is the no-copy field. |
| S-63 | Sound | `showTurn` drops late Show answers. Values go on select, leave and clear (lock or close). |
| S-64 | Sound (documented) | The typed protected value is kept in `shownFields` (F-060). Dropped on `pause` and `close`. |
| S-65 | Sound | Value cleared on close and refusal. Copy and Use run in Rust. |
| S-66 | Sound | Dropped on Hide and in `clearPassword`. |
| S-67 | Sound | The version sheet's values go with the dialog. `leave()` sets `dialog = nil`. |
| S-68 | Sound | As S-35. |
| S-69 | Sound | Values drawn only from S-63 and S-64. |

## Missed items (not in the inventory)

- **M-1** `scripts/build-core.sh:36`: `-p app-ffi --features net` is the switch that puts C-02 (ring, rustls, getrandom 0.2.17) into the Mac app (B-1).
- **M-2** `macos/App/AutoType.swift:40`: Swift `unsafeDowncast(value, to: AXUIElement.self)`. Sound: guarded by the `CFGetTypeID == AXUIElementGetTypeID()` check on line 39. The file changed at 23:33 (E8-S2 in progress).
- **M-3** `macos/App/AutoType.swift:105-110`: the Carbon C callback `carbonHotKeyPressed` with `MainActor.assumeIsolated`. Sound: Carbon calls application-target hot key handlers on the main thread.
- **M-4** `crates/app-ffi/src/edit.rs:1222-1243`: `wifi_text` builds the Wi-Fi password into plain `String`s with `format!` (B-4).
- **M-5** `crates/app-platform/src/hardening.rs:23-37`: the safe front of U-09 and U-10. Release only, each step whatever the other did.
- **M-6** `vendor/ssh-key/src/private/opaque.rs:142`: unknown key types' private bytes are not wiped on drop (B-10).
- **M-7** `macos/App/Platform/ShownPasswordField.swift:107-150`: the undo stack of the no-copy field editor as a possible Swift holder (B-9).

## Open issues

- B-9 needs a probe with a visible window, which waits for the owner (rule 10). It could also be closed by just setting `allowsUndo = false`.
- B-1 and B-3 need a decision row or doc edits (architecture.md, API.md, LD-207 for B-5) at the merge step.

## Next step

Merge with Checker A's review. Rows for B-1 to B-6 in `security/findings.md` (Low). B-7 to B-10 are Info. None blocks E13-S5's acceptance on safety grounds.
