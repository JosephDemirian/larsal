# E5-S1 to E5-S4: native shell, session, unlock screen, main window

Stories: E5-S1 Native shell and Rust bridge, E5-S2 Session and Rust API, E5-S3 Unlock screen, E5-S4 Main window (one Verify run, LD-160).
Date: 2026-10-28.
Role: Verify (no reference access needed; none used).
Supersedes: security/parity/E5-S1-shell.md, which proved the withdrawn Tauri shell (LD-155, LD-156).

Result:
- **E5-S1: signed.** check.sh PASS with the Swift steps; AT-E08; no WebKit; cargo deny; 0 hand-written `unsafe` in larsal-ffi; 17 of 17 APP-09 cases, plus M09-01, 02, 04, 05, 09 by hand on the Release binary; Release signature has the hardened runtime and no `get-task-allow`. Needs a visible window: AT-E08 on a Release app after its window exists (N4).
- **E5-S2: signed.** AT-E03 over all 30 exports; AT-E07 on four demo vaults; Show gives one value; Copy is the stub; API.md lists every export. Notes N1 (F-057) and N3, not blocking.
- **E5-S3: signed.** APP-06 messages through the session (15 cases) and the screen model; AT-D05 as far as it can be proven without a window. Needs a visible window: AT-D05's keystroke-tap test (N4).
- **E5-S4: signed on re-check (2026-10-28).** The first run failed AT-E06 on F-056; the lead fixed it (LD-165), and the re-check at the end of this file proves the fix. Search, AT-E01, AT-E02, the key file drop and live codes all pass.
- Design parity ("matches the mockup") is not checked here. It comes from the parity fleet (design/option-a/BUILD-AND-VERIFY.md, E5-S12). Done needs that report too.

## Setup

- `. "$HOME/.cargo/env"`; Xcode tools with `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`.
- Debug: `scripts/check.sh` runs `scripts/build-core.sh` and builds `target/xcode/.../Debug/Larsal.app`.
- Release:
  - `scripts/build-core.sh --release`: prints `build-core (release)`.
  - Then `xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -configuration Release -destination platform=macOS -derivedDataPath /tmp/verify-e5/xcode-release build SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: `** BUILD SUCCEEDED **`.
  - Afterwards `scripts/build-core.sh` (debug) was run again, so `target/larsal-core` is the debug core, as check.sh leaves it.
- Screen rule (AGENTS.md rule 10): no window was shown.
  - Debug app runs used `LARSAL_TEST_HIDDEN` with their own instance folder.
  - Every Release run ended before step 10 (the window): flags, a lock request, a secondary, or a primary held at the F06 prompt.
  - The SwiftUI probe used a borderless window at -20000,-20000 that was never ordered front, with activation policy `.prohibited`.
- Processes: each one was started by a script and stopped by its PID. The final line of each script run: `all started processes ended: True`.
- Probe tests:
  - `/tmp/verify-e5/probe/verify_e5.rs` (7 tests) was copied into `crates/larsal-ffi/tests/` only for each run, then removed. `ls crates/larsal-ffi/tests` shows the 4 original files.
  - The scripts are `/tmp/verify-e5/scripts/runs.py` and `/tmp/verify-e5/probe/secure/main.swift`.
  - No product file was changed. Files written: this file, two rows in `security/findings.md`, the superseded note in `security/parity/E5-S1-shell.md`, and the status lines in `plan/epics.md`.
- Demo vaults only: testdata/ (passwords in testdata/README.md).

## E5-S1 Native shell and Rust bridge

### check.sh with the Swift steps

`scripts/check.sh` 2026-10-28 01:06 to 01:22 (951 s wall):

```
G1 static ......... PASS (unsafe count 52 in 8 crates)
G2 tests .......... PASS
deny .............. PASS
audit ............. PASS
fuzz smoke ........ PASS (18 targets, 30s each)
Overall ........... PASS
```

- The Swift steps are in G1 (`swift-format`, `swiftlint`: both logs empty, so they passed) and G2:
  - `build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift`;
  - `xcode-test`: `Test run with 13 tests in 6 suites passed`, `** TEST SUCCEEDED **`;
  - `app09`: `test result: ok. 17 passed; 0 failed`.
- `cargo audit`: one allowed warning, RUSTSEC-2026-0374 (`basic-toml`, generator only, LD-157 (3)).

### No hand-written unsafe in larsal-ffi (Rust rule 2)

- `target/check/unsafe.log` (cargo-geiger, one run per crate): `larsal-ffi: 0 unsafe`. The check accepts that line only with `forbids_unsafe` true.
- `crates/larsal-ffi/src/lib.rs` line 4: `#![forbid(unsafe_code)]`.
- Only `larsal-platform` has `unsafe` (52; reviewed by two Checkers, E5-S1 pass B).

### cargo deny

`target/check/deny.log`: `advisories ok, bans ok, licenses ok, sources ok`. The UniFFI MPL-2.0 exceptions are the ones LD-157 lists.

### No WebKit (`otool -L`)

- Release binary `/tmp/verify-e5/xcode-release/Build/Products/Release/Larsal.app/Contents/MacOS/Larsal`, linked libraries:
  - frameworks: Foundation, AppKit, Carbon, CoreFoundation, CoreGraphics, CoreText, CoreTransferable, SwiftUI, SwiftUICore;
  - libraries: libobjc, libSystem and the Swift runtime libraries.
  - `otool -L … | grep -ci webkit` gives `0`.
  - No other Mach-O file in the bundle links WebKit.
  - `strings` finds `WKWebView` or `WebKit` 0 times.
- Debug binary: the same list plus DeveloperToolsSupport; no WebKit.
- No Network or CFNetwork framework is linked.
- The socket calls the binary imports (`nm -u`) are `_socket _bind _listen _accept _connect`: the instance channel (Rust `UnixListener` and `UnixStream`).
- The Release `--debug-info` prints `Web engine: none`.

### Codesign of the Release build

```
Identifier=app.larsal.desktop
Format=app bundle with Mach-O thin (arm64)
CodeDirectory v=20500 size=14544 flags=0x10002(adhoc,runtime) hashes=448+3 location=embedded
Runtime Version=27.0.0
entitlements (xml): []            get-task-allow count: 0
codesign --verify --deep --strict: valid on disk; satisfies its Designated Requirement
```

- `runtime` is the hardened runtime.
- The project sets `ENABLE_HARDENED_RUNTIME = YES`, `ENABLE_APP_SANDBOX = NO`, `CODE_SIGN_INJECT_BASE_ENTITLEMENTS = NO` (Release), `SWIFT_VERSION = 6.0` and `MACOSX_DEPLOYMENT_TARGET = 14.0`.

### AT-E08 Local listeners

**Debug app, hidden, fully started.** The delegate has run and the channel answers. The vault `option-a-personal` was unlocked through F06 with its demo password.

```
-rw-------  app.larsal.desktop-debug.lock
srw-------  app.larsal.desktop-debug.sock      socket mode: srw------- josephilhan; folder: drwx------
lsof -nP -p 44289: fds=29 IPv4=0 IPv6=0 TCP=0 UDP=0 LISTEN=0 unix=1
  Larsal 44289 josephilhan 4u unix 0xa8c69fba54425307 0t0 /tmp/verify-e5/inst-debug/app.larsal.desktop-debug.sock
lsof -nP -a -i -p 44289 (any internet socket): (empty)
netstat tcp/udp lines naming pid 44289: (none)
netstat -anv -f unix: a8c69fba54425307 stream … Larsal:44289 … /tmp/verify-e5/inst-debug/app.larsal.desktop-debug.sock
```

**Release primary, held at the F06 prompt.** It runs from step 7 (lock and listener) and has not reached step 10 (window). It uses the real per-user folder from the OS.

```
socket: srw------- … /var/folders/95/…/T/app.larsal.desktop.sock; folder: drwx------ josephilhan
lsof -nP -p 85845: fds=9 IPv4=0 IPv6=0 TCP=0 UDP=0 LISTEN=0 unix=1
  Larsal 85845 josephilhan 4u unix 0x80e0dfe57a9efc85 0t0 /var/folders/95/…/T/app.larsal.desktop.sock
lsof -nP -a -i -p 85845: (empty)      netstat tcp/udp naming pid 85845: (none)
```

- Result: the only socket is the instance socket of APP-09.14 (Unix, 0600, in the 0700 per-user folder). There is no TCP or UDP socket and no open port.
- The same-user peer check is covered by the unit test of pass B (Checker 2026-10-27).
- A Release app after its window exists needs a visible window (N4).

### APP-09: the 17 cases, and by hand on the Release binary

- `cargo test -p larsal-ffi --test app09` (in check.sh): 17 passed. Each case runs the built Debug Larsal.app hidden:
  - 2_a, 2_b, 3_a, 3_b, 4_a, 8_a, 8_b;
  - 9_a, 10_ab, 10_c, 11_a, 11_b;
  - 12_a, 13_abc, 16_a, 27_a, 27_b.
- The same cases by hand on the hidden Debug app (runs.py debug):

```
M09-09 --bogus: exit 1, stderr 'Unknown flag: --bogus. Run Larsal --help for the list of flags.'
M09-04 --lock, no instance: exit 0, 'Larsal is not running. There is no open vault to lock.'
M09-01 activate (no args): exit 0, 'Larsal is already running. The request was passed to it.'
M09-01 open (a file): exit 0, 'Larsal is already running. The request was passed to it.'
M09-02 --lock: exit 0, 'All open vaults were locked.'
M09-05 activate, primary stopped (SIGSTOP): exit 1, 1.01 s, 'The running copy of Larsal does not answer. Quit it and try again.'
M09-05 --lock, primary stopped: exit 1, 1.01 s, same text
primary SIGTERM -> exit 0
```

On the Release binary (runs.py release).
- Release has no test variables (LD-48), so M09-01 and M09-02 run against a stand-in primary. It is a script that holds the Release instance lock (`flock`, checked held before each launch) and answers on the Release socket (0600).
- M09-05 also ran against the real Release primary held at the F06 prompt.

```
M09-09 --bogus: exit 1, 'Unknown flag: --bogus. Run Larsal --help for the list of flags.'
M09-09 --key-file without value: exit 1, 'The flag --key-file needs a value. Run Larsal --help for the list of flags.'
M09-04 --lock, no instance: exit 0, 'Larsal is not running. There is no open vault to lock.'
M09-04 --lock with LARSAL_TEST_* set: exit 0, same text (Release ignores the debug variables)
stand-in answers {"ok":true}:  activate exit 0 M09-01; open exit 0 M09-01; --lock exit 0 'All open vaults were locked.' (M09-02)
  requests: {"v":1,"cmd":"activate"}, {"v":1,"cmd":"open","paths":["/Users/…/testdata/rich-v4.larsalvault"]}, {"v":1,"cmd":"lock"}
stand-in answers {"ok":false}: activate 0 M09-01; open 0 M09-01; --lock exit 1 'The vaults could not be locked.' (M09-03)
stand-in never answers:        activate, open, --lock: exit 1 after 1.01 s, M09-05
real Release primary at the F06 prompt: activate exit 1 (1.02 s) M09-05; --lock exit 1 (1.01 s) M09-05
-v: 'Larsal 0.1.0'; --debug-info: 'Build type: release … Web engine: none … Debugging mode: off' (no path)
```

Hostile process arguments for `start()` (debug, hidden). No panic in any case:

| Arguments | Exit | Text |
|---|---|---|
| invalid UTF-8 flag | 1 | M09-09 |
| invalid UTF-8 file with `--lock` | 0 | M09-04 |
| 200 KB flag | 1 | M09-09 |
| 200 KB file with `--lock` | 0 | M09-04 |
| `--key-file` at the end | 1 | M09-09 |
| `--config=` | 1 | M09-09 |
| `--config=` with `--lock` | 1 | M09-09 |
| `--local-config` twice with `--lock` | 0 | M09-04 |
| `--lock -- --help -v` | 0 | M09-04 |
| `-` with `--lock` | 0 | M09-04 |
| 8,000 file arguments with `--lock` | 0 | M09-04 |
| F06 with 3 files and an empty stdin | ran as a hidden primary; SIGTERM gave exit 0 | none |

## E5-S2 Session and Rust API

### API.md lists every export

- The generated bindings (`target/larsal-core/Swift/LarsalCore.swift`) export these.
  - Free functions: `coreIsDebug coreVersion launchHidden vaultLook launchFinished openFiles start`.
  - `Session` methods: `init() shared() vaults open switchTo unlock approveUnlock cancelUnlock checkHeader takeMessage takeBanner lock lockAll close sidebar list entry showField copyField rate search codes totp`.
  - `LarsalEvents`: `bringToFront sessionChanged`.
- Every one is a row in `crates/larsal-ffi/API.md`, with inputs, output, errors and secret. A script over API.md found every function name.
- Every type has a row too: `Launch LarsalEvents Session LarsalError VaultInfo VaultLook UnlockResult UnlockMessage ListView Sidebar GroupRow TagRow EntryList EntryRow EntryKind Rating SearchHits PasskeyView SshKeyView EntryDetail FieldView AttachmentView TotpView`. The one exception is `FieldKind` (N3).
- In the Rust source, the `#[uniffi::export]` items are exactly these 30 functions:
  - lib.rs: 3;
  - start.rs: `start`, `launch_finished`, `open_files`;
  - session.rs: `vault_look` and 14 methods;
  - views.rs: 9 methods.

### AT-E03 Boundary abuse

- Existing test: `session.rs::at_e03_hostile_arguments` ok (check.sh).
- Probe `verify_at_e03_every_export` ok. It covers every export, in these groups:
  - `vault_look`: 18 hostile paths, each answered in under 2 s:
    - empty, NUL, `/`;
    - `/dev/zero`, `/dev/random`, a FIFO, a symlink loop, a folder;
    - `~`, a relative path, a 4,096-byte path, a 4,097-byte path, a 10 MiB path, 3,000 `é`;
    - a text file, the big vault.
  - `open_files`: the same 18 paths; 10,000 empty strings; an empty list. All returned in under 5 s with no panic.
  - Unknown vault ids `0`, an unused id, `999999` and `u64::MAX`: all 17 vault-taking methods give `UnknownVault`.
  - 13 malformed or foreign entry ids into `entry`, `totp`, `codes`, `show_field`, `copy_field` and `ListView::Group`. They give `UnknownEntry`, `UnknownGroup` or `TooLong`. The ids:
    - empty, `x`, 31 and 33 digits, 32 zeros, 32 `g`;
    - `+`, `-`, space or brace prefixes, 16 `é`;
    - an id of the other open vault, 1 MiB of text.
  - Field names: empty, NUL, unknown, wrong case, 10 MiB, `otp`, `TOTP Seed`, `TimeOtp-Secret`. Every one is an error for Show and Copy.
  - 13 hostile queries into `search`, `ListView::Search` and `ListView::Tag`. Each takes under 5 s; the only error is `TooLong`. The queries:
    - empty, 10 MiB, exactly 64 KiB, 64 KiB + 1;
    - nested and catastrophic regex patterns, `*[`;
    - 10,000 `-`, `is:weak` × 5,000, a lone `"`, `t:`, RTL override + BEL.
  - `codes`: 201 ids and 100,000 ids give `TooLong`; 200 give 200 results; a foreign id gives `UnknownEntry`; an empty list gives an empty list.
  - `rate`: `(0,0)`, `(u32::MAX, i32::MIN)`, `(1, i32::MAX)` and `(u32::MAX, 0)` all return `Ok`.
  - `unlock`: 14 hostile password and key file pairs. Each takes under 10 s and gives `TooLong` or `Failed`. The pairs:
    - a 10 MiB password, 64 KiB + 1, NUL;
    - a 10 MiB key path, a 4,097-byte key path, an empty key path;
    - `/dev/zero`, `/dev/random`, a FIFO, a symlink loop, a folder, `~`, NUL;
    - the big vault as key file.
  - Then `approve_unlock`, `cancel_unlock`, `check_header` and `take_message`.
  - Locked vault: all 9 view methods give `Locked`.
  - Hostile `open` paths give `CannotOpen` or `TooLong`.
  - 6 threads at once, 40 calls each: list, Show, codes, rate, lock with unlock, switch. They were joined with no panic.
  - Close twice gives `UnknownVault` the second time; `lock_all` twice.
- `AT-E03: 490 results checked, no panic, no secret in any error text`.
  - Every result and error text was searched for the vault's protected values of 5 or more characters (11 of 12).
  - The 4-digit demo PIN also matches ids and temp paths, so it was left out of this search. The AT-E07 view search below strips ids and includes it.

### AT-E07 Secrets in the screen

No protected value in any view (probes `verify_at_e07_*`, all ok). The search covers the whole `Debug` text of every view the screen can ask for:
- `sidebar`, `vaults`;
- every `ListView` (All, Expired, Weak, Favorites, Codes, Passkeys, Bin, two searches, every group, every tag);
- `entry` and `totp` of every listed entry, `codes` of every entry, `search`.

It was run before and after `rate` (rows, detail and sidebar then carry ratings). Ids are stripped. It looks for every protected value (entries and history) and every attachment line of 6 or more characters:

```
AT-E07 rich-v4.larsalvault before rating: 10 entries, 15813 view bytes, 12 protected values, 2 attachment lines, hits []
AT-E07 rich-v4.larsalvault after rating: 10 entries, 18558 view bytes, 12 protected values, 2 attachment lines, hits []
AT-E07 option-a-personal.larsalvault before rating: 25 entries, 57671 view bytes, 33 protected values, 4 attachment lines, hits []
AT-E07 option-a-personal.larsalvault after rating: 25 entries, 77179 view bytes, 33 protected values, 4 attachment lines, hits []
AT-E07 rich-v3.larsalvault before/after rating: 10 entries, 12 protected values, hits [] / hits []
AT-E07 big-10000.larsalvault before/after rating: 10000 entries, 13563180 / 19184366 view bytes, 10000 protected values, hits [] / hits []
```

- Existing test `session.rs::e5_s2_views_carry_no_protected_value` ok.
- **Show returns one value.** Probe `verify_show_returns_one_value`: `Show: 24 protected fields shown one by one; Copy NotAvailable for each`.
  - Each Show gave exactly that field's protected value and no other protected value.
  - `e5_s2_show_and_copy` ok.
  - Show and Copy refuse the one-time password fields (`otp`, `TOTP Seed`, `TOTP Settings`, `TimeOtp-*`): `at_e03_hostile_arguments`.
- **Copy is the stub.**
  - Rust `copy_field` checks its arguments and returns `NotAvailable` (views.rs `copy_field`; 24 of 24 above).
  - The Swift side never calls `copyField` and never touches `NSPasteboard` (grep over `macos/Larsal`: 0 hits).
  - Each Copy control is disabled with the hint "Copy comes with the clipboard (E6-S1): the value stays in the Rust core." (`Controls.swift` `Later.copy`).
- **Swift state is cleared.** `ScreenTests` "APP-06.11, AT-E07: the password field clears when an unlock starts; Hide, entry change, lock drop shown values" passed (check.sh xcode-test). It checks:
  - Hide: `shown` is empty;
  - entry change: `shown` is empty;
  - vault switch: `shown` and `codes` are empty, and after 1.3 s `codes` is still empty (the code timer stopped);
  - lock: `shown`, `codes`, `detail` and `rows` are empty, `window.main == nil`, and the unlock field is empty.
  - `MainWindowModel.refresh` calls `leave()` for every vault not shown and `clear()` for every locked one.
- Not checked: process memory after Hide and lock. UniFFI copies strings through buffers that Rust frees without wiping until the zeroing allocator (LD-133, E6-S6; API.md says so). This waits for E6-S6.

## E5-S3 Unlock screen

### APP-06 messages through the session

Probe `verify_app06_messages_through_the_session` ok. Each line is a real unlock on a demo vault:

```
M06-05 "Enter the password for this vault."                                  (no credentials)
M06-06 "Wrong password, key file or security key. Check them and try again." (wrong password; empty password; wrong key file)
M06-07 The key file "empty.larsalkey" is empty. Choose the right key file.
M06-09 The key file "mismatch.larsalkey" is damaged: its built-in check failed. …  (XML v2 key file, one hex digit of its check changed)
M06-11 The key file "missing.larsalkey" cannot be found. Choose it again.
M06-12 Larsal is not allowed to read the key file "noaccess.larsalkey". …           (mode 000)
M06-14 "…" is a folder or a special file. Choose a normal file as the key file. (a folder; a FIFO; /dev/zero)
M06-15 Larsal does not accept the key file "dtd.larsalkey" because it declares a document type. …
M06-30 This is the vault file itself, so it cannot also be its key file. …
M06-24 "gone.larsalvault" cannot be found. It may have been moved, renamed or deleted. …  (vault removed after it was opened)
M06-01 "README.md" is not a vault file. Open the file that holds your vault.   (before Unlock, APP-06.3)
right key file: Unlocked
```

- No message holds the password.
- Also passed: `session.rs::app06_unlock_messages`, `app06_3_header_look`, `app06_16_lock_during_unlock_drops_the_result`, and the 7 tests of `tests/messages.rs` (`t39` every kind, `t40` no secret and no file text, `m06_texts_match_the_table`, …).
- Through the screen model: `ScreenTests` "APP-06: a wrong password shows M06-06 and leaves the field empty" passed. It also checks that Lock everything clears a typed password (APP-06.5).
- Still open in APP-06, as the status line says: M06-31 to M06-33, M06-38 and the 30-second clear. With a key file alone, a wrong key file gives M06-06, not the M06-33 alert.

### AT-D05 Keystroke tap: proven without a window, live test waits

- The password field is a SwiftUI `SecureField` (`UnlockView.swift` line 186).
- When the user shows the password, it becomes a `TextField`, and Larsal turns on secure input itself while that field has focus. `UnlockView.swift` lines 49 to 51 call `SecureInput.set(focus == .password && model.reveal)`, and call it off on disappear.
- Offscreen probe (`/tmp/verify-e5/probe/secure/main.swift`, compiled with Larsal's own `Platform/SecureInput.swift`; Swift 6, main actor):

```
secure event input before (system-wide): false
after SecureInput.set(true): true
after SecureInput.set(false): false
SwiftUI SecureField is backed by: AppKitSecureTextField
is NSSecureTextField: true
window visible: false app active: false
makeFirstResponder(SecureField) in the offscreen window: true
secure event input with the SecureField first responder (window never key): false
```

- So Larsal's `SecureInput` turns secure event input on and off.
- A SwiftUI `SecureField` on macOS is an `NSSecureTextField`. AppKit turns on secure event input for it only while it is first responder in the key window, which is why the last line reads false in a window that is never key.
- **Not provable now:** the keystroke-tap test itself (a demo event-tap logger running while the master password is typed). It needs:
  - a visible, key Larsal window with the field focused;
  - Input Monitoring permission for the logger;
  - typed keys.
- That is for Mac QA with the owner's go (AGENTS.md rule 10).

## E5-S4 Main window

### Search under 50 ms on big-10000, before and after rating

- `ScreenTests` "FEA-01.34: a search on big-10000 updates the list in under 50 ms, before and after rating" passed: `FEA-01.34 search worst: 0.016496834 seconds before rating, 0.016937917 seconds after rating`.
- That is the worst of 6 queries: `Entry 0999`, `user01 -Entry`, `t:Entry u:user0 9 99 999`, `*t:^Entry 1`, `zzz`, `e`. Each is timed from the Rust call to the sorted sections. The Debug app runs with the optimized core (LD-161).
- Rust: `session.rs::fea01_34_search_speed_on_big_10000` and larsal-core `fea01_34_speed_10000_entries` ok. `option_a.rs::typed_is_weak_matches_the_weak_view` and `search_returns_ids_of_all_rows` ok.

### AT-E01 Vault text is plain text

- `PlainTextTests` "AT-E01: Markdown, links and control characters in vault text are shown as they are" passed.
  - It renders the row, the fields panel and the notes offscreen, and reads the drawn text back with on-device text recognition.
  - The input is `**bold** [link](https://example.com) <b>x</b>` + BEL + NUL. It is drawn literally, never as bold or a link.
- The lint rule `no_markdown_text` (macos/.swiftlint.yml, severity error). Probe file `/tmp/verify-e5/lint/Probe.swift` linted with the project config, `--strict`:
  - refused, exit 2: `Text("Title: \(title)")` at line 8, `AttributedString(markdown: title)` at line 9, `LocalizedStringKey(title)` at line 10;
  - accepted: `Text(verbatim: title)` and `Text(title)`.
- A grep of `macos/Larsal` finds no `AttributedString`, `markdown`, `LocalizedStringKey`, `Link(`, `NSAttributedString`, `openURL` or web view. It also finds no interpolated string key in `Button`, `Label`, `Toggle`, `Menu`, `help` or the accessibility modifiers.

### AT-E02 Only http and https open

- `URLOpenerTests` "AT-E02: only http and https with a host are opened" passed.
  - 4 links allowed.
  - 22 refused, among them `javascript:` (with case, leading space, tab), `file:///`, `file://localhost`, `data:`, `javascript://example.com/%0A…`, `data://`, `vbscript:`, `about:`, `ftp:`, `ssh:`, `cmd:`, `mailto:`, `larsal:`, `https://` with no host, `http:/`, a bare host and `//host`.
  - The test never calls the real opener.
- The only `NSWorkspace.shared.open` in the app is `URLOpener.swift` line 24, after `allowed`. Its callers: `Menus.swift` line 61 and `RailView.swift` lines 47 and 94; each control is disabled when `allowed` gives nil.

### AT-E06 Drops: fails (F-056)

- There are exactly 2 drop targets in `macos/Larsal` (grep `dropDestination|onDrop`).
  1. **Key file row** (`UnlockView.swift` lines 303 to 307). It takes the first dropped file URL as the key file; links are refused (`FileOpen.paths` keeps file URLs only). LD-163 (2) allows it. `ScreenTests` "LD-163 (2): the key file row takes a dropped file and clears with Remove Key File" passed.
  2. **Welcome card** (`WelcomeView.swift` lines 67 to 71). Links are refused. **Every dropped file is opened**: `FileOpen.paths(urls)`, then `window.open(path)`, with no extension check.
     - A `notes.txt` becomes a locked vault in the session with an unlock screen. `session.rs::app06_3_header_look` shows that `README.md` opens this way and reads M06-01.
     - APP-09.26 (D-APP09-7, LD-153) and AT-E06 say a window drop opens only `.larsalvault` and the reference's vault extension; every other drop is refused. The case is APP-09.26-a: "`notes.txt` refused, nothing opened".
     - Nothing runs; the file is read only for the header check. Severity Low.
- Also not built: a vault-file drop while a vault is shown (the first half of APP-09.26-a). No drop target exists there, so the drop is refused, which is safe. It is listed open in the E5-S4 status line; LD-153 places APP-09.26 with E5-S2.
- Text fields (search, password) take dropped text as typed text, the standard behaviour; nothing opens.

### Live codes only for rows on screen

- `ScreenTests` "Checker E5-S4 (3): codes are asked only for rows on screen and the entry shown" passed:
  - only the shown entry first;
  - a row that comes on screen is added;
  - a row that leaves the screen is dropped on the next tick.
- Rust caps `codes` at 200 ids: 201 gives `TooLong` (probe).
- `VaultModel.tick` asks only for `rows` with `hasTotp` in `onScreen`, plus the selection.
- `ScreenTests` "Checker E5-S4 (4): leaving the screen cancels the rating worker" passed.
- `session.rs::fea04_live_code` ok.

## Findings and notes

**F-056 (Low, fails AT-E06; blocks the E5-S4 sign-off): the welcome drop opens any file.**
- Where: `macos/Larsal/WelcomeView.swift` lines 67 to 70.
- Smallest fix: keep only paths whose extension, compared without letter case, is `larsalvault` or the reference's vault extension. Write that extension as bytes, for example `String(decoding: [0x6B, 0x64, 0x62, 0x78], as: UTF8.self)` (name rule). It fits as a small `FileOpen.vaultPaths(_:)` beside `FileOpen.paths`. Return false when nothing is left.
- Test: one `PlatformTests` case where a `.txt` URL gives no path and `.larsalvault` / `.LARSALVAULT` give theirs.

**N1 = F-057 (Low, not blocking): Show hands out the passkey fields when Swift asks for them by name.**
- The detail never lists the passkey fields (MOD-01.8), so no screen path asks for them.
- Probe `verify_show_passkey_fields` on option-a-personal: `Show of protected fields not in fields (passkey, otp): given 5, refused 1`. The 5 are passkey fields, the 1 is `otp`.
- Where: `crates/larsal-ffi/src/views.rs` `check_field` (lines 984 to 992) refuses only the one-time password fields.
- Smallest fix: also refuse `name.starts_with(PASSKEY)` (the prefix constant at line 37), as for the one-time password fields; add the case to `at_e03_hostile_arguments`.
- API.md describes today's behaviour exactly, so this is hardening, not a broken check.

**N2 (note for the card): SIGTERM at the F06 prompt.**
- The Release primary held at the prompt ended with `exit -15` (killed by the re-raised signal, the readpassphrase pattern the Checker accepted in pass B). stdout was `Vault password: `.
- The APP-09 exit table says "quit by SIGINT, SIGTERM, SIGQUIT → 0". That holds for the running app: the hidden Debug primary gave exit 0, and so does `app09_27_a`.
- The card has no line for the time before the window. Proposed: add an edge case "a signal at the F06 prompt ends Larsal by that signal after the terminal is restored".

**N3 (note): API.md has no row for `FieldKind`.**
- Its five values are listed in the `FieldView` row, so nothing is missing.
- A one-line type row would match the other types.

**N4 (needs a visible window, for Mac QA with the owner's go):**
- AT-E08 on a Release app after its window exists. The Debug app fully started and the Release app before its window are both proven above. The Release binary imports no network API beyond the Unix socket calls.
- The AT-D05 keystroke-tap test.

## Re-check 2026-10-28 (LD-165)

**F-056: verified.**
- `macos/Larsal/Platform/FileOpen.swift` `droppedVaults` keeps only file URLs whose extension, compared without letter case, is `larsalvault` or the reference's vault extension (built from bytes).
- `WelcomeView.swift` line 68 uses it.
- `xcodebuild … test -only-testing:LarsalTests/PlatformTests`, with the fix: `✔ Test "APP-09.26-a, AT-E06: a drop opens vault files only" passed`, `** TEST SUCCEEDED **`.
- Probe: `droppedVaults` reduced to `paths(urls)`. Result: `✘ … recorded an issue at PlatformTests.swift:28:9` and `:29:9` (`notes.txt` kept), `** TEST FAILED **`.
- The file was restored (`cmp` equal) and the test re-run passed, so `target/xcode` holds the fixed build.
- Drop targets (grep `dropDestination|onDrop|registerForDraggedTypes|NSDraggingDestination` over `macos/Larsal`): only `WelcomeView.swift` line 67 (vault files only) and `UnlockView.swift` line 303 (the key file row: any file as key file, links refused, as LD-163 (2) designs it).
- Note: the test covers `droppedVaults`, not the call in `WelcomeView`. That one line was checked by reading it.

**F-057: fix holds in code, not verified by its test.**
- `views.rs` `check_field` (line 989) now refuses `name.starts_with(PASSKEY)`.
- Probe `verify_show_passkey_fields` on option-a-personal, with the fix: `given 1, refused 5`. The one given is the standard `Password` field of the Mastodon entry, not a passkey field. Without the fix: `given 5, refused 1`.
- But `session.rs::at_e03_hostile_arguments` passes with the fix removed (`test at_e03_hostile_arguments ... ok` in the probe).
  - It asks the passkey names on rich-v4's "Full demo entry", which has no passkey field, so `UnknownField` comes back either way.
  - `views.rs` was restored (`cmp` equal).
- Smallest fix: ask the two passkey names on a Passkeys row of option-a-personal (for example in `option_a.rs`). There, Show returns the value without the fix.
- F-057 does not block a story: it is a note on E5-S2, which is signed.

**Card:** the APP-09 exit table now has a line for a quit signal at the F06 prompt ("ended by that signal, after the terminal is restored"). That matches the Release run above (`exit -15`), so N2 is closed.

## CPU used

About 36 minutes of CPU in total. The longest single run was check.sh at 15.9 minutes wall.
- `scripts/check.sh`: 1867.7 s user, 122.4 s sys, 951 s wall.
- Probe test runs: 3 × about 20 s user, plus their larsal-ffi test builds.
- Release core and Release app build: 16.2 s and 27.7 s user.
- Debug core rebuild: 0.6 s.
- SwiftUI probe: 2 small builds.
- Larsal runs: each under 1 s CPU.
