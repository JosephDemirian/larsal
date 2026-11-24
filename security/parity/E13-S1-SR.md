# E13-S1 parity sign-off: Runtime (SR)

Rows: SR-01 to SR-16 in [plan/security.md](../../plan/security.md). Story: E13-S1.
Date: 2026-10-29. Verify agent, group SR.

| Row | Result |
|---|---|
| SR-01 | **Verified** on today's tree; real idle and other-app input (T05) still wait for Mac QA (owner's go) |
| SR-02 | **Verified** on today's tree; real screen lock, sleep and user switch on this Mac still wait for Mac QA |
| SR-03 | **Failed (finding SR-A, Medium):** the app never passes the clipboard countdown to the minimize lock, so the delay is always 1 s. Everything else passes. |
| SR-04 | Waits for E6-S3 (quick unlock is not built; it needs a signing team, D7) |
| SR-05 | **Verified** |
| SR-06 | **Failed (finding SR-B, High):** secure input passes, but the Caps Lock warning is only on the unlock form. The new vault, change password and entry editor password fields have none. The reference warns on all of them. |
| SR-07 | **Verified** on today's tree (key checks re-run); the lldb dump of the real Larsal.app still waits for Mac QA |
| SR-08 | **Failed (finding SR-C, High):** the notice of expired and expiring entries after unlock is not wired into the app. |
| SR-09 | **Verified** |
| SR-10 | **Failed (finding SR-D, Medium):** auto-open is not built, and no story owns it |
| SR-11 | **Verified** (Larsal is stricter: no command URL ever runs, and only http and https open). Finding SR-E (Low): the rest of MOD-08.31 is not wired. |
| SR-12 | **Verified** |
| SR-13 | **Verified** |
| SR-14 | **Verified** |
| SR-15 | **Verified** for today's Larsal and `larsal`. The browser bridge sockets come with E7 and are checked there (AT-E08). |
| SR-16 | **Verified** for every dialog that exists today. The browser dialogs come with E7. |

How it was run:
- **Reference.**
  - The reference source (REF_SOURCE) was read only.
  - The reference command line tool (REF_CLI) ran on a copy of one of its own demo test vaults (REF_TESTDATA), with `HOME=/tmp/e13s1-SR-home`.
  - The reference window app was never launched.
- **Our side, private copy.**
  - Built in `/tmp/e13s1-SR-copy`: `rsync -a --exclude target --exclude larsal-shots`, with its own `target` and derived data `/tmp/e13s1-SR-dd`.
  - The copy was made at 20:36. At the end, the SHA-256 (first 16 hex digits) of every file this report relies on matched the shared tree: `LockSignals.swift` 8a35a268a248e9ee, `AppDelegate.swift` 6be44d1aa1b50bd1, `SecureInput.swift` ebd40eada81ed87b, `UnlockView.swift` 10179bb377614c51, `SecretFields.swift` d61a24a42ac6c760, `EditorPasswordField.swift` 271b80afc359cd09, `URLOpener.swift` 0a16a9243ca76d36, `hardening.rs` 3d66e42cda450a1c, `instance.rs` 286687cff000a1db, `larsal_settings.rs` 44e2f852f4a32799, `session.rs` 1bda6de4ae34692f, `expiry.rs` 1271f3f9f5225a5f, `larsal-cli/src/main.rs` 2d65352e2216ae8b.
- **Builds.**
  - `scripts/build-core.sh` gave `build-core (debug): target/larsal-core/LarsalFFI.xcframework`.
  - `xcodebuild … -derivedDataPath /tmp/e13s1-SR-dd build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` gave `** TEST BUILD SUCCEEDED **`.
  - The command line checks used the shared debug `larsal` in `/tmp/e13s1-target` (built at 20:45 from today's tree).
- **No windows (rule 10).**
  - LarsalTests has no host app, so the Swift tests ran in the xctest runner, which opens no window.
  - The Larsal probe ran the debug `Larsal` with `LARSAL_TEST_HIDDEN=1`: activation policy `.prohibited`, no window, no menu bar icon, no global shortcut. It also had its own instance folder (`LARSAL_TEST_INSTANCE_DIR`), so it never touched the owner's settings.
  - I stopped it by its own PID with `kill -TERM`. After that, `pgrep -f e13s1-SR-dd` was empty.
  - Nothing touched the general pasteboard, the owner's ssh-agent, `~/.ssh` or the Keychain. The ssh tests use their own agents in `/tmp`.
- **Load.** The Mac had a load average of 300 on 14 cores (other agents were building). Timings below are slow for that reason.

## SR-01 Idle lock

**Reference.**
- **Defaults** (settings table): idle lock is on, 900 s.
- **Timer.** The idle timer never runs shorter than 10,000 ms.
- **What counts as activity.** An application-wide event filter counts mouse press to key release, hover enter to hover move, and wheel events, all inside the app. After each counted event it ignores events for 500 ms.
- **When the timer fires,** every vault is locked.
- **The settings spin box** has no upper bound in the source's code. Our 12-hour cap is Larsal's own rule (APP-02.3).

**Ours.**
- **Defaults.** `LockSettings` is built from the store: `lock.idle.enabled` defaults to on and `lock.idle.seconds` to 300 (`larsal_settings.rs`: `d("S-TIME-04", "lock.idle.seconds", P, Number(10, 43_200, 300))`).
- **Bounds.** `idle` is clamped to 10 s through 43,200 s, and the throttle is 0.5 s.
- **What counts as activity.** Only an AppKit local event monitor counts input (keys, mouse buttons, moves, drags, wheel), so only input to Larsal's own windows counts.
- **A late timer** locks before it restarts the countdown.

**Run.** `xcodebuild … test-without-building -only-testing:LarsalTests/LockSignalsTests …`:
```
✔ Test "APP-02 T02: applied settings restart the countdown from the new period" passed
✔ Test "APP-02 T03: each key restarts the countdown" passed
✔ Test "APP-02 T04: events within 0.5 s of a restart are ignored" passed
✔ Test "APP-02 T07, T08: the period is used within 10 s and 12 h" passed
✔ Test "APP-02 T09: idle lock off never locks" passed
✔ Test "APP-02 T10: the countdown runs with nothing unlocked, does nothing, and starts again" passed
✔ Test "APP-02 idle: input after the period locks first and never restarts the countdown" passed
✔ Suite LockSignalsTests passed
```
`LarsalSettingsTests` "APP-01.3 OK stores every page and the parts read the new values" passed. It shows that the stored lock settings reach `LockSignals`.

**Result: verified** for everything that can be checked without the owner's screen. Real idle time and typing in another app (T05) wait for Mac QA, as before.

## SR-02 Screen lock, user switch, sleep

**Reference.**
- **Screen lock.** It listens for the distributed notification `com.apple.screenIsLocked` and locks all vaults when the screen lock setting is on (default on).
- **User switch.** It listens for the workspace notification that the session resigned active, and locks all vaults when the user switch setting is on (default on).
- **Sleep.** It has no sleep listener on macOS.

**Ours.**
- **Screen lock.** `LockSignals` observes `com.apple.screenIsLocked` on the system distributed center with `.deliverImmediately`.
- **User switch.** It observes `NSWorkspace.sessionDidResignActiveNotification`.
- **Sleep.** It observes `NSWorkspace.willSleepNotification` (Larsal goes further). The lock runs on the main thread before the handler returns.

**Run (same run):**
```
✔ Test "APP-02 T01: a screen lock locks every vault" passed
✔ Test "APP-02 T12, T13: com.apple.screenIsLocked locks when the setting is on" passed
✔ Test "APP-02 T12: the system distributed center delivers the screen lock at once, also in the background" passed
✔ Test "APP-02 T14: on will-sleep the vault is locked before the handler returns" passed
✔ Test "APP-02 T15: the session resigning active locks when the setting is on" passed
✔ Test "APP-02 T52, APP-03.15: a lock signal clears the clipboard in Rust, shown values and live codes" passed
```

**Result: verified.** Real events on this Mac wait for Mac QA, as before.

## SR-03 Lock on minimize, lock before quit

**Reference.**
- **Minimize.** With lock on minimize on (default off), a minimize or a hide to the tray starts a delayed lock. The delay is `qBound(1, seconds left on the clipboard countdown, 20)` seconds, so a value just copied can still be pasted. A running delay timer is not restarted.
- **Minimize after unlock.** Turning it on unticks and disables lock on minimize.
- **Quit.** It closes all vault tabs before it quits, which locks them.

**Ours.**
- **Minimize.** `LockSignals.minimized()` sets `minimizeDue = now + clamp(secondsLeft(), 1, 20)`. It is called on `NSWindow.didMiniaturizeNotification`, on `NSApplication.didHideNotification` and from `WindowRules.hideToIcon()` (the menu bar hide, E5-S11).
- **Minimize after unlock** sets `locksOnMinimize` to false.
- **Quit** saves and then locks (`applicationShouldTerminate`, `window.quit()`).
- **But the app never passes `secondsLeft`.** `AppDelegate.applicationDidFinishLaunching` builds `LockSignals(settings:unlocked:lock:)`, so the default `secondsLeft: { 0 }` is used. The ponytail note in `LockSignals.init` still says "`r` is 0 until Rust exports the clipboard countdown's time left". Rust exports no such value: `crates/larsal-platform/src/clipboard.rs` has `copy`, `clear`, `peek` and nothing for the time left, and `Session` has `clipboard()` and `clear_clipboard()` only.
- **So in the running app** a minimize always locks after 1 s, and the lock clears Larsal's clipboard copy (APP-03.15). With lock on minimize turned on, a password copied just before minimizing is gone after 1 s instead of staying until its countdown ends (up to 20 s).

**Run:**
```
✔ Test "APP-02 T16: minimize with nothing copied locks after 1 s" passed
✔ Test "APP-02 T17: minimize waits for the clipboard countdown" passed      <- with an injected secondsLeft only
✔ Test "APP-02 T18: the minimize delay is at most 20 s" passed
✔ Test "APP-02 T19: a restore does not stop the minimize lock" passed
✔ Test "APP-02 T20: a new minimize starts the delay again" passed
✔ Test "APP-02 T24: minimize after unlock turns lock on minimize off" passed
✔ Test "APP-02 T25: Hide Larsal counts as minimize (D-A02-2)" passed
✔ Test "APP-01.7 and .8 forgetting, and minimize after unlock excludes lock on minimize" passed
✔ Test "APP-02.15 step 8 (quit): a changed vault saves first; one that cannot be saved asks and the quit waits" passed
$ grep -n "LockSignals(" -A4 macos/Larsal/AppDelegate.swift
36:        lockSignals = LockSignals(
37-            settings: LockSettings(store: settings),
38-            unlocked: { session.vaults().contains { !$0.locked } },
39-            lock: { [window] in window.lockAll() }
40-        )
```

**Result: failed (finding SR-A, Medium).** We are not weaker on security, since we lock sooner. But the row's "as long as the clipboard countdown" and APP-02.8 `r` are not met. The part that waited for E5-S9 is still open now that E5-S9 is Done.

## SR-04 Quick unlock with Touch ID

**Reference.**
- **Key.** It makes a random AES-256 key and IV and encrypts the key parts with AES-256-GCM.
- **Keychain item.** The key goes into a Keychain item with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Access control is the current biometric set, or'ed with the watch and, when asked, the device passcode.
- **Encrypted key parts** stay in app memory only.

**Ours.**
- No quick unlock code exists. A search for `quick_unlock|QuickUnlock|LAContext|biometr` over `crates` and `macos` finds only the S-LOCK-01 settings key and its drawn, disabled switch (LD-211 (2)).
- E6-S3 is `todo`. It needs a signing team (the owner's Apple ID) and D7.

**Result: waits for E6-S3** (and D7). The row is left as `todo`.

## SR-05 Process hardening

**Reference.** In release builds (`QT_NO_DEBUG`), start-up sets `RLIMIT_CORE` to 0 and calls `ptrace(PT_DENY_ATTACH)`. It does this in both the window app and the command line tool, and a failure logs one warning. Its two steps are joined with `&&`, so a failed `setrlimit` skips the deny.

**Ours.**
- **Order.** `larsal_platform::hardening::harden()` is the first statement of `larsal-cli`'s `main` (`main.rs:31`) and step (1) of `larsal-ffi` `start` (`start.rs:87`).
- **Debug builds** skip both steps.
- **Release builds** run both steps, each one whatever the other did, and print M11-01 once on stderr if either fails. Larsal goes further: the reference skips the deny after a failed core limit.

**Run** (copy, release):
```
$ cargo test --release -p larsal-platform --lib -- hardening process
test hardening::tests::app11_4_a_failed_core_limit_still_denies_attach ... ok
test macos::process::tests::app11_5_harden_follows_the_build_kind ... ok      (release child: core limit 0/0, attach EBUSY + SIGSEGV)
test macos::process::tests::app11_2_core_limit_is_zero_and_cannot_be_raised ... ok
test macos::process::tests::app11_3_deny_attach_refuses_ptrace_attach ... ok   (control without the call: not EBUSY)
test result: ok. 5 passed; 0 failed; 2 ignored
```

**Result: verified.** The lldb and forced-crash runs on the signed Release Larsal stay with Mac QA, as in E6-S4.

## SR-06 Secure input and Caps Lock

**Reference.**
- **Secure input.** The shared password field turns on secure keyboard input on focus-in and off on focus-out and hide (`EnableSecureEventInput`/`DisableSecureEventInput`, never above one level).
- **Caps Lock.** The same field checks Caps Lock on focus-in, key press and key release. It shows a warning icon in the field plus a tooltip, "Warning: Caps Lock enabled!". The check is skipped only for a field that is the repeat partner of another one.
- **Where it is used.** The unlock form, the entry editor's password, the new vault and change-key password editor, the import wizard's password, the shared-group password and the generator.

**Ours.**
- **Secure input.**
  - Masked fields are `NSSecureTextField` (`SecureField`, `FocusSecureField`), so AppKit turns secure input on while they edit.
  - Every shown secret is a `NoCopyTextField`, which drives `SecureInput`: on while it has focus in the key window of the active app, and off on blur, hide, removal, resign-active, window close, lock and quit.
- **Caps Lock.**
  - Only `UnlockView` has the note: `capsLock = NSEvent.modifierFlags.contains(.capsLock)`, then "Caps Lock is turned on." The Auto-Type unlock panel reuses `UnlockView`, so it has the note too.
  - `grep -rn -E "Caps Lock|capsLock|alphaShift" macos` finds nothing else.
  - The new vault wizard's "Password" (`NewVaultView.swift:208`, `SecretField`), the vault settings password change (`VaultSettingsPages.swift:220`, `SecretField`) and the entry editor's password (`EditorPasswordField.swift`, `FocusSecureField` and `NoCopyTextField`) show no Caps Lock warning.
  - APP-06.6 says the note applies to every password-kind field of APP-10.9 except the repeat fields. APP-07.11 says it shows for the wizard's "Password".

**Run:**
```
✔ Test "Rule 10: a test run never makes the real secure input calls" passed
✔ Test "APP-10.8-e, APP-10.11: a shown password field turns Larsal's secure input on with the focus, off as it leaves" passed
✔ Test "APP-10.8-b, APP-10.13-a, -b: off when Larsal resigns active; on again when active with the field still focused" passed
✔ Test "APP-10.13: after a window close's release, on again when Larsal or the window is active, the field focused" passed
✔ Test "APP-10.11, APP-10.11-a: a stale focus report for a field with no editor turns nothing on" passed
✔ Test "APP-10.8: off while another window is key; on again when the field's window is key" passed
✔ Test "APP-10.8: off when the field is hidden, removed or its text replaced while typing; off as its window closes" passed
✔ Test "APP-10.8, APP-10.11, APP-10.12-b: a lock (the main window's path) keeps Larsal's call only while the field edits" passed
✔ Test "APP-10.10-a, APP-10.12: calls alternate, starting with enable; never two enables; none left on after quit" passed
✔ Suite SecureInputTests passed
$ grep -rn -E "Caps Lock|capsLock|alphaShift|CapsLock" macos
macos/Larsal/UnlockView.swift:21:    @State private var capsLock = false
macos/Larsal/UnlockView.swift:55:            capsLock = NSEvent.modifierFlags.contains(.capsLock)
macos/Larsal/UnlockView.swift:221:            capsLock = NSEvent.modifierFlags.contains(.capsLock)
macos/Larsal/UnlockView.swift:265:        } else if capsLock && passwordFocused {
macos/Larsal/UnlockView.swift:266:            Text(verbatim: "Caps Lock is turned on.")
```

**Result: failed (finding SR-B, High).** Secure input matches the reference. The Caps Lock warning is weaker: a user can set or change a master password, or type an entry password, with Caps Lock on and get no warning, where the reference warns. Real secure input (the ioreg holder, the event tap) still waits for Mac QA.

## SR-07 Memory hygiene

**Reference.**
- **Freed heap blocks.** Its global `operator delete` scrubs the block with the crypto library's scrub before `free`.
- **What is not wiped.** UI toolkit strings and byte arrays, which hold field values, are freed with plain `free` and are not wiped.
- **Key material** (password, key file and hardware-key response bytes) sits in the crypto library's secure buffers. In the installed build those come from a page-locked pool.

**Ours.** Unchanged since E6-S6:
- The zeroing global allocator (LD-133) is in Larsal and `larsal`.
- Every secret type wipes itself on drop.
- The key pages are locked while a vault is unlocked.

**Run** (copy, debug):
```
$ cargo test -p larsal-ffi --test key_pages
test app11_9_refused_locks_still_unlock_with_one_warning ... ok
test app11_9_b_key_pages_are_wired_while_the_vault_is_unlocked ... ok
test result: ok. 2 passed; 0 failed; 1 ignored
$ cargo test -p larsal-cli --test memory_hygiene
test findings_leave_no_plain_value_in_freed_memory ... ok
$ cargo test -p larsal-platform --lib
test macos::memory::tests::freed_blocks_are_zero ... ok
test macos::memory::tests::realloc_wipes_the_old_block_when_it_grows_or_shrinks ... ok
test macos::memory::tests::the_system_allocator_keeps_freed_bytes ... ok          (control)
test macos::memory::tests::app11_9_b_locked_pages_are_wired_until_the_last_guard_drops ... ok
test macos::memory::tests::app11_9_refused_lock_goes_on_with_one_warning ... ok
test result: ok. 26 passed; 0 failed; 7 ignored
$ cargo test -p larsal-ffi --test session --test clipboard
test e5_s2_views_carry_no_protected_value ... ok
test app_03_15_lock_close_and_quit_clear ... ok
test result: ok. 11 passed … ok. 9 passed
```

**Result: verified.** The lldb dump of the running Larsal.app stays with Mac QA, as in E6-S6.

## SR-08 Expired and expiring entries after unlock

**Reference.** After the first unlock of a vault in a run (not after a lock), with "show expired entries on unlock" on (default on, 3 days), it runs the search `is:expired-N`. It labels the result "Expired entries" (N ≤ 0) or "Entries expiring within N day(s)".

**Ours.**
- **The logic is in larsal-core.** `larsal_core::expiry::notice` (MOD-09.7) implements it, and `crates/larsal-core/tests/mod09.rs` covers it (`mod_09_7_notice_after_unlock`, `mod_09_7_notice_days_capped`; `cargo test -p larsal-core --test mod09`: 19 passed today).
- **The settings are stored.** `expiry.notice_on_unlock` (default on) and `expiry.notice_days` (default 3) are stored, and the settings page draws the "Expiry" switch.
- **Nothing calls the notice.** No code in `larsal-ffi` or `macos/` calls `notice` or reads either setting:
```
$ grep -rn "first_unlock\|NoticeSettings" crates/larsal-ffi/src crates/larsal-core/src macos/Larsal | grep -v "^crates/larsal-core/src/expiry.rs"
(nothing)
$ grep -rn "expiry.notice" crates macos/Larsal
crates/larsal-ffi/src/larsal_settings.rs:102:    d("S-START-11", "expiry.notice_on_unlock", P, Flag(true)),
crates/larsal-ffi/src/larsal_settings.rs:103:    d("S-START-12", "expiry.notice_days", P, Number(0, 90, 3)),
crates/larsal-core/src/expiry.rs:108:    /// `expiry.notice_on_unlock`, default on.
crates/larsal-core/src/expiry.rs:110:    /// `expiry.notice_days`, default 3, 0 to 90.
macos/Larsal/LarsalSettingsModel.swift:123:  …
macos/Larsal/LarsalSettingsPages.swift:29-34: the settings page only
```
- **No story owns the wiring.** E5-S9's inventory (`E5-S9-settings-inventory.md`, S-START-11) calls it "a follow-up of FEA-01/MOD-09.3". No story or follow-up batch lists it.

**Result: failed (finding SR-C, High).** After unlock the reference shows the user which passwords have expired or will soon. Larsal shows nothing, while its own "Expiry" switch says it does.

## SR-09 Single instance

**Reference.**
- **Single instance** is on by default. It uses a lock file and a local server in the temp folder with `UserAccessOption` (owner only).
- **A second launch** sends its file names to the running instance, or `--lock` to lock all vaults, and ends.
- **Passwords at launch** come only from standard input with `--pw-stdin`. There is no password option.

**Ours** (APP-09, `larsal-ffi` `instance.rs`, `start.rs`):
- **Socket.** A Unix socket and a lock file, both 0600, in the per-user temp folder that `confstr(_CS_DARWIN_USER_TEMP_DIR)` reports (0700).
- **Peer check.** The peer's uid is checked with `getpeereid` before anything is read.
- **Other launches.** `--lock` locks all vaults. A second launch passes its paths on and brings the primary to the front. `--password-stdin` (alias `--pw-stdin`) reads one line per file from standard input, and there is no password flag.

**Runs:**
```
$ cargo test -p larsal-ffi --lib -- instance start:: …
test instance::tests::app09_14_socket_is_0600_and_replaces_a_leftover ... ok
test instance::tests::app09_14_a_other_user_is_refused_before_reading ... ok
test instance::tests::app09_8_one_lock_holder_until_it_is_released ... ok
test instance::tests::app09_13_a_line_over_the_limit_is_dropped ... ok
test instance::tests::app09_13_a_slow_sender_is_cut_off_at_the_deadline ... ok
test start::tests::app09_12_a_lock_request_goes_to_the_window_else_rust_locks ... ok
test result: ok. 19 passed; 0 failed
$ cargo test -p larsal-ffi --test app09        (the copy's target/xcode linked to /tmp/e13s1-SR-dd; every Larsal hidden)
test app09_10_ab_open_is_passed_on_and_stdin_is_not_read ... ok
test app09_10_c_second_launch_activates_the_primary ... ok
test app09_11_a_lock_without_an_instance ... ok
test app09_12_a_lock_request_is_delivered ... ok
test app09_13_abc_channel_limits ... ok
test app09_16_a_the_primary_reads_one_password_line_per_file ... ok
test app09_8_a_after_kill_9_the_next_launch_is_primary ... ok
test app09_27_a_int_term_quit_end_with_exit_code_0 ... ok
test result: ok. 18 passed; 0 failed
```
Hidden Larsal probe (debug Larsal from `/tmp/e13s1-SR-dd`, `LARSAL_TEST_HIDDEN=1`, `LARSAL_TEST_INSTANCE_DIR=/tmp/e13s1-SR-inst`, demo vault made with `larsal db-create`, password piped on stdin):
```
$ printf '<demo password>\n' | Larsal --password-stdin our.larsalvault &      (pid 32106)
stdout: "Vault password: "          (M09-08 only, the password is never printed)
$ stat -f "%Sp %Su %N" …sock …lock
srw------- <user> /tmp/e13s1-SR-inst/app.larsal.desktop-debug.sock
-rw------- <user> /tmp/e13s1-SR-inst/app.larsal.desktop-debug.lock
$ Larsal --lock
All open vaults were locked.           exit 0
$ Larsal our.larsalvault
Larsal is already running. The request was passed to it.      exit 0
$ kill -TERM 32106                     primary exit 0
```

**Result: verified.**

## SR-10 Auto-open

**Reference.**
- **Which entries.** After unlock it looks for the group at path `/AutoOpen`. For each entry with a URL and a password or user name, it reads the comma-separated `IfDevice` list. It matches the computer's host name with no case, and a leading `!` excludes a name.
- **Opening.** It then opens the vault at the entry's resolved URL, using the resolved user name as the key file and the resolved password.

**Ours.**
- **No code.** `grep -rlni "auto_open\|autoopen\|auto-open" crates/*/src macos/Larsal` finds only a doc comment in `larsal-core/src/url.rs:513`. No Rust or Swift code reads such a group.
- **No owner.** APP-06.25, M06-39 and LD-97 specify it, but no story in `plan/epics.md` builds it. E5-S3 is Done without it.

**Result: failed (finding SR-D, Medium).** We are not weaker on security, since a feature that is absent cannot be abused. But the parity row is not built and nothing owns it.

## SR-11 Opening an entry URL

**Reference.**
- **`cmd://` URLs.** It asks before running one. The question shows the command cut to 400 characters with a literal `{PASSWORD}` masked, and No is the default. Only a remembered Yes (the `_EXEC_CMD` field set to `1`) skips the question.
- **Every other URL** goes to the system opener, whatever its scheme.

**Ours.**
- **One opener.** Every URL open in the app goes through `URLOpener.open`: the menu, the rail, the editor, the context menu and View > Open URL. A search for `NSWorkspace.shared.open` finds only `URLOpener` and `FileOpener` (attachments, MOD-05.12, after its own risky-file question).
- **What it opens.** `URLOpener.allowed` accepts only `http` and `https` with a host. So a `cmd://` URL never runs a program, and `javascript:`, `file:`, `data:` and other schemes never open.
- **larsal-core has the full rules** of MOD-08.31 (`open_kind`, `command_words`, `question_text`, `remember_key`) with tests. The app does not use them yet (finding SR-E).

**Run:**
```
✔ Test "AT-E02: only http and https with a host are opened" passed   (refused: cmd://open, javascript:, file:, data:, mailto:, example.com, …)
$ cargo test -p larsal-core --test mod08      (mod_08_31_opening_urls: the core rules that the app does not call yet)
test result: ok. 47 passed; 0 failed
```

**Result: verified.** Larsal is stricter than the reference: no command can run, with or without a question. The missing MOD-08.31 parts (the confirm, the vault link, `mailto`, `http://` for a bare host, MSG-08-4) are a feature gap and do not weaken security (finding SR-E, Low).

## SR-12 Recent vaults and remembered key files

**Reference.**
- **Defaults.** "Remember last databases" is on, and so is "remember last key files" (which also covers the hardware-key slot).
- **Turning it off** clears the stored list.
- **What is stored.** Paths only, never a password.

**Ours.**
- **Defaults.** `recent.remember` is on. `recent.remember_keys` is **off** (LD-51, stricter).
- **Turning it off.** `recent.remember` off also turns off reopen-at-start and remember-keys, and removes `state.recent`, `state.last_active` and `state.last_folders`. `recent.remember_keys` off removes `state.key_files`, `state.hardware_keys` and `state.last_folders`.
- **No password key.** The settings table has no key for a password.

**Runs:**
```
test larsal_settings::tests::app01_2_app_defaults ... ok
test larsal_settings::tests::app01_7_forgetting ... ok
test larsal_settings::tests::app01_14_recent_vaults ... ok
✔ Test "APP-01.7 and .8 forgetting, and minimize after unlock excludes lock on minimize" passed
```
Hidden Larsal probe (SR-09 above): after an open and unlock by stdin password, then a quit by TERM, the instance's settings folder held:
```
drwx------  settings/
-rw-------  settings_debug.json   {}
-rw-------  state_debug.json      {"state.last_active": "/private/tmp/e13s1-SR-work/our.larsalvault",
                                   "state.open_at_quit": ["/private/tmp/e13s1-SR-work/our.larsalvault"],
                                   "state.recent": ["/private/tmp/e13s1-SR-work/our.larsalvault"]}
$ grep -rl "sr13" settings/   ->  no sr13 value in settings
```

**Result: verified.** Note: with `recent.remember_keys` turned on, nothing writes `state.key_files` yet, so the option stores nothing. That is a feature gap in the safe direction, recorded under SR-E.

## SR-13 Command line tool

**Reference** (REF_CLI, `HOME=/tmp/e13s1-SR-home`, a copy of a demo test vault, password piped):
```
$ printf 'a\n' | REF_CLI show ref.db "Sample Entry"
Enter password to unlock ref.db:
Password: PROTECTED
$ printf 'a\n' | REF_CLI show -s ref.db "Sample Entry" | grep -i password
Password: Password
$ REF_CLI ls --help      (options: -q, -k, --no-password, -y, -R, -f, -h; no password option)
```
Its source turns terminal echo off around the prompt (`ECHO` cleared) and reads standard input when it is not a terminal.

**Ours** (shared debug `larsal`, demo vault `our.larsalvault`):
```
$ printf '<pw>\n<pw>\n' | larsal db-create -p -t 200 our.larsalvault
Password for the new vault (Return for none): Same password again: … New vault our.larsalvault saved.     exit 0
$ printf '<pw>\n' | larsal show our.larsalvault Demo
Vault password for our.larsalvault: Title: Demo
UserName: demo-user
Password: (hidden)
$ printf '<pw>\n' | larsal show -s our.larsalvault Demo | grep -i password
Vault password for our.larsalvault: Password: sr13-entry-secret
$ larsal ls --password <pw> our.larsalvault
larsal ls: unknown option --password. Run larsal help ls to see its options.    exit 1
$ larsal ls -p <pw> our.larsalvault
larsal ls: unknown option -p. Run larsal help ls to see its options.          exit 1
```
```
$ cargo test -p larsal-cli --test int10       (copy)
test int10_12_a_no_echo_at_the_prompt_pty ... ok
test int10_12_b_signal_at_the_prompt_restores_echo_pty ... ok
test int10_12_b_sighup_at_the_prompt_restores_echo_pty ... ok
test int10_12_d_end_of_input_is_the_empty_password ... ok
test int10_16_a_no_secret_in_arguments_or_environment ... ok
test int10_16_b_generated_password_never_printed ... ok
test int10_28_c_show_protected ... ok
test result: ok. 114 passed; 0 failed
```
The text for a hidden value differs: the reference prints `PROTECTED` and Larsal prints `(hidden)`. The behaviour is the same.

**Result: verified.**

## SR-14 Logging

**Reference.**
- **Release builds** define `QT_NO_DEBUG_OUTPUT` and keep warnings.
- **Vault content in warnings.** Some warnings carry it: the merge conflict warnings print an entry title, and so do the importer and attachment warnings that the row lists.
- **Debug builds** also print titles during a merge.

**Ours.**
- **Rust** has no logging crate. `grep -rnE "\b(log::|tracing::|info!|warn!|debug!|error!|trace!)" crates/*/src` finds nothing. Outside tests, the only `eprintln!`/`println!` calls in the library crates print fixed start-up messages (M11-01, M09-xx, M11-02 naming a self-test, the version).
- **Swift** has three `Logger.app.notice` calls, the same in debug and release. They log the Larsal version, a search time in µs and a count of files opened from Finder. There is no `print`, `NSLog` or `os_log` elsewhere.
- **System log.** `/usr/bin/log show --predicate 'subsystem == "app.larsal.desktop"' --last 24h` gave 356 lines (test runs of the day by every agent):
```
 328 xctest [app.larsal.desktop:app] Main window opened: Larsal 0.1.0
  20 xctest [app.larsal.desktop:app] Search updated the list in N µs
   7 Larsal [app.larsal.desktop:app] Main window opened: Larsal 0.1.0
```

**Result: verified** (Larsal goes further, LD-67: no vault content in any log, debug builds included).

## SR-15 Listening sockets

**Reference.** Its listeners are the single-instance local server (owner only, user temp folder), the browser proxy's local socket and, on macOS, the Safari app-group socket. It opens no network port.

**Ours.**
- **No browser bridge yet.** It is not built (E7).
- **Larsal** listens on one Unix socket.
- **`larsal`** listens on nothing. `larsal-cli` has no listener code, and E6-S7's `lsof` on the release `larsal` saw none.

Hidden Larsal probe (pid 32106, after start-up and unlock):
```
$ lsof -nP -a -p 32106 -i        -> (nothing)   exit 1
$ lsof -nP -a -p 32106 -U
Larsal 32106 … 4u unix 0x23306b2dc23d58bd 0t0 /tmp/e13s1-SR-inst/app.larsal.desktop-debug.sock
```
This is the debug build's test-folder socket. The normal path is the 0700 per-user temp folder (`instance::tests::app09_7_names_follow_the_build_kind`, `macos::instance::tests::temp_folder_is_the_os_one_and_private`). The ssh client test `int06_21_feature_off_contacts_no_agent_and_opens_no_socket` passed.

**Result: verified** for today's Larsal. E7-S1 and E7-S6 add the browser sockets, and AT-E08 must run again then.

## SR-16 What happens on lock

**Reference.**
- **First** it closes any modal dialog that belongs to the vault widget and clears copied text.
- **Unsaved edits.** An entry being edited asks "Discard changes and lock anyway?" (Cancel stops the lock). A modified vault saves when auto-save is on; otherwise it asks to save, discard or cancel. Those questions hold the lock.
- **Locking** drops the vault and keeps the header. SSH keys marked for removal on lock are removed.

**Ours.**
- **Rust.** `Session::lock`/`lock_all` drop the generator value, clear Larsal's clipboard copy and drop the vault (`slot.vault.take()`, the pending unlock, ratings, edit state and breach state). They then call `ssh_locked` and `autotype_locked`.
- **Swift.** `MainWindowModel.lockAll(asks: false)` saves first. A save that cannot finish goes to a recovery copy, and the automatic lock never waits (LD-50). The Auto-Type picker and its unlock panel close on lock.

**Runs:**
```
✔ Test "APP-02.15 step 8, APP-02.16: Lock Everything and automatic locks save first; a failed save asks on the menu" passed
✔ Test "APP-02.16 T56, APP-05.28 T60: an automatic lock meeting a changed file keeps the change in a recovery copy" passed
✔ Test "APP-09.12, APP-02.16 (LD-217 (4), R-OFF): a lock request saves the change, or keeps it in a recovery copy" passed
✔ Test "SR-16, INT-05.29: a lock, another app or the target quitting closes the picker untyped" passed
✔ Test "INT-05.25 step 5, APP-06.27: Cancel, lock everything or the vault closing stops, nothing typed" passed
✔ Test "APP-06 T11: a lock signal clears the typed password" passed
test saving::tests::app_02_16_an_unattended_lock_keeps_the_change_in_a_recovery_copy ... ok
test app_03_15_lock_close_and_quit_clear ... ok
test app_03_15_lock_of_another_vault_clears ... ok
test app06_16_lock_during_unlock_drops_the_result ... ok
test int06_24_lock_removes_marked_keys_within_1_s_and_keeps_the_rest ... ok
test int06_24_close_and_lock_all_do_the_same ... ok
test int06_34_sr16_lock_closes_the_question_as_deny ... ok
test int06_24_at_h01_a_lock_during_decryption_adds_nothing_to_the_system_agent ... ok
test result (larsal-ffi --test ssh): ok. 16 passed; 0 failed
```

**Result: verified** for every dialog Larsal has today. The browser's site access and association dialogs come with E7-S2, and their close on lock is checked there.

## Findings (for the lead; not filed in security/findings.md)

- **SR-B (High), SR-06: the Caps Lock warning exists only on the unlock form.**
  - Where it is missing: the new vault wizard "Password" (`NewVaultView.swift:208`), the vault settings password change (`VaultSettingsPages.swift:220`) and the entry editor password (`EditorPasswordField.swift`). The reference warns on all of them.
  - Smallest fix: move the `NSEvent.modifierFlags.contains(.capsLock)` check and the M06-37 note out of `UnlockView` into one shared modifier, use it on those three fields (not on the repeat fields), and add one test per field.
- **SR-C (High), SR-08: no notice after unlock.**
  - What is missing: `larsal_core::expiry::notice` is never called, so after the first unlock Larsal shows no expired or expiring entries, though "Expiry" (S-START-11) is on by default.
  - Smallest fix: call `expiry::notice` from `larsal-ffi` at the first unlock of a slot (it already knows `locked_at`) and return its search text. In Swift, put that text in the vault's search field with MSG-09-1 or MSG-09-2. Add the APP-01.18 a to c cases as tests. Give it an owning story (E5 follow-up batch).
- **SR-A (Medium), SR-03: the minimize delay ignores the clipboard countdown.**
  - What is wrong: the app builds `LockSignals` without `secondsLeft`, so the delay is always 1 s. Rust has no export of the clipboard countdown's time left.
  - Smallest fix: add the time left to `larsal-platform` `Clipboard` (it holds the deadline), export it on `Session`, and pass `secondsLeft: { Int(session.clipboardSecondsLeft()) }` in `AppDelegate`. Add a test that the app's `LockSignals` gets it, and drop the stale ponytail note.
- **SR-D (Medium), SR-10: auto-open is not built and has no story.**
  - Smallest fix: give APP-06.25 (with LD-97) an owning story. It builds the `/AutoOpen` group logic in `larsal-core`, calls it after unlock in `larsal-ffi`, and adds M06-39. Or the lead records a decision to drop it.
- **SR-E (Low), SR-11 and SR-12: Swift bypasses parts of the spec.**
  - SR-11: the app opens URLs only through Swift's `URLOpener`, not through larsal-core's MOD-08.31 rules. A `cmd://` URL never asks and never runs, a vault link does nothing, `mailto:` and a bare host (`example.com`) do not open, and MSG-08-4 is never shown. This is safe, but it is not the spec.
  - SR-12: with `recent.remember_keys` on, nothing stores the key file or hardware-key slot.
  - Smallest fix: route `URLOpener` through `larsal_core::url::open_kind` (via `larsal-ffi`), and write `state.key_files` at unlock when the option is on. Both belong in the E5 follow-up batch.

## Cleanup

- **Processes.** Every Larsal and `larsal` I started has ended. The probe primary (pid 32106) ended by `kill -TERM` with exit 0, and the app09 tests stop their own children. Afterwards, `pgrep -f e13s1-SR` was empty.
- **Launch Services.** The copy's Larsal.app was unregistered with `lsregister -u` (dump count for the path went from 1 to 0).
- **Folders.** I deleted `/tmp/e13s1-SR-copy`, `-dd`, `-home`, `-work` and `-inst`, and the logs.
- **Name guard.** `scripts/check-names.sh` after writing this file gave `names: PASS (3134 files scanned, 15 vault files name-only)`.
