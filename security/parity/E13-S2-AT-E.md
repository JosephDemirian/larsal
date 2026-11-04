# E13-S2 attack campaign, group AT-E: screen layer and the Swift–Rust boundary

Story: E13-S2. Rows: AT-E01 to AT-E08 of [plan/attacks-and-checks.md](../../plan/attacks-and-checks.md). Severities: its Findings section.
Date: 2026-10-29. Role: Red team, group AT-E. I did not build any of this code. I did not open the reference source or run the reference tool for this group: no row of AT-E compares with the reference.

## Result

| Row | Result | One line |
|---|---|---|
| AT-E01 Text injection | **passed** | Ten hostile markers, one per text field, are drawn literally in every state; no link element anywhere; the lint rule refuses Markdown and interpolated keys. |
| AT-E02 Dangerous links | **passed** | 22 + 37 hostile URL texts refused; every vault URL opens only through `URLOpener`. |
| AT-E03 Boundary abuse | **failed** (RT-E-1, High; RT-E-4, Low) | 180 exports, 5,100+ calls, 0 panics, 0 secrets in any error. But five exports block for good on a FIFO instead of returning an error, and Lock Everything and every automatic lock wait on one of them on the main thread. |
| AT-E04 Retired, replacement | **passed** | `otool -L` and `nm -u` show no WebKit or JavaScriptCore. The running app maps no WebKit image. In its first 20 s it opens no internet socket. |
| AT-E05 Retired, replacement | **waits for its stories** | Its replacement checks are AT-C03 (group AT-C, E13-S4: debugger attach and crash on a release build, needs Mac QA) and AT-J05 (E14-S3). |
| AT-E06 Drag and drop | **passed** | Three drop targets. Links are refused, and only vault files open, each as an unlock screen. FIFO, `/dev/zero` and a folder named like a vault return at once. |
| AT-E07 Secrets in the screen | **failed** (RT-E-2, Medium) | The Swift view state is clean after Hide and after lock. But after the editor's Show and Hide, one copy of the entry password stays in process memory after lock and after close. |
| AT-E08 Local listeners | **passed** (RT-E-5, Low: the row omits a listener) | The only listener is the instance socket, Unix, `0600` in a `0700` folder. With the SSH agent on, Larsal's own agent socket is added, also `0600`/`0700`. No TCP, no UDP, no port. |

Findings: RT-E-1 High, RT-E-2 Medium, RT-E-3 Medium, RT-E-4 Low, RT-E-5 Low. The filer gives them F-numbers.

## Setup

- **Private copy.** At 20:35:33 I made it with `rsync -a --exclude target --exclude larsal-shots --exclude fuzz/target` into `/tmp/e13s2-ate/copy`. It had its own `target` and the DerivedData folder `/tmp/e13s2-ate/dd`. I changed no product code in the shared tree.
  - The harness files were added only in the copy:
    - `crates/larsal-ffi/tests/red_at_e03.rs`: 1,342 lines, SHA-256 `5d758e7b8229c66a…`;
    - `macos/LarsalTests/RedTeamATETests.swift`: 631 lines, `d78a3ea12e4ebd1e…`.
  - Both are deleted with the copy.
- **Tree changes during the run.** Other agents changed files during my run: `larsal-core/src/storage.rs` (F-047), `larsal-ffi/src/edit.rs` and `views.rs` (20:37 to 21:00), and `macos/Larsal/Platform/ShownPasswordField.swift` (F-069, 20:58).
  - At 21:40:31 I re-synced `crates/` and the Cargo files from the tree into the copy and re-ran the FIFO checks of RT-E-1.
  - I also copied today's `ShownPasswordField.swift` and its test and re-ran AT-E07 on them. After that copy, `diff -rq` showed `macos/Larsal` equal to the tree.
  - Both findings hold on the re-synced code.
- **Builds.** All builds ran in the copy:
  - `scripts/build-core.sh` printed `build-core (debug): target/larsal-core/LarsalFFI.xcframework …` (11 min);
  - `cargo test -p larsal-ffi --test red_at_e03 --no-run`;
  - `xcodebuild … -derivedDataPath /tmp/e13s2-ate/dd build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` printed `** TEST BUILD SUCCEEDED **`.
  - Tools: rustc 1.99.1, Xcode 27.0, macOS 26.6.
- **Demo data only.** I used copies of `testdata/rich-v4.larsalvault` (`demo-pass-5`) and `option-a-personal.larsalvault` (`demo-pass-7`) in `/tmp/e13s2-ate/run`. I also made three vaults from rich-v4 through larsal-ffi:
  - `e01.larsalvault`: hostile text in every field;
  - `e07.larsalvault`: one entry, "E07 entry", with a random 26-character password and a protected `PIN`, both made in the Rust step;
  - `hang.larsalvault`.
  - Nothing in `testdata/` was written.
- **Rule 10 and rule 11.**
  - The Rust harness ran under `env -u SSH_AUTH_SOCK HOME=/tmp/e13s2-ate/run/home sandbox-exec` with a profile that denies remote network. It used `Session()` and its private pasteboard; the one `Session.shared()` call only reads `vaults()`.
  - The Swift tests run in the host-less LarsalTests bundle with offscreen windows that are never ordered front. Attachment Open goes to the existing fake opener (`ParityDemo.setUp`).
  - Larsal launches ran the Debug binary directly, the way `tests/app09.rs` does: `LARSAL_TEST_HIDDEN=1`, `LARSAL_TEST_INSTANCE_DIR` in `/tmp`, no `SSH_AUTH_SOCK`. Each was stopped by its PID with SIGTERM.
  - No window, no focus, no general pasteboard, no `~/.ssh`, no keychain. `ps` at the end showed none of my processes.

## AT-E01 Text injection

**Method.** The Rust step wrote one hostile marker into every text field of `e01.larsalvault`. The pattern is `**T1** [lnk](https://example.com) <b>x</b> \`c\` _i_` + BEL. The markers and their fields:
- `T1` title, `U1` user name, `L1` URL, `N1` notes;
- `K1` tag, `A1` attribute name, `B1` attribute value;
- `F1` attachment name (the file `**F1** [lnk](https:example.com) <b>x.txt`);
- `G1` group name;
- `V1` the vault's file name, which Larsal shows as the vault name;
- `D1` the vault's stored name and description.

The Swift test `RedATE01` opens the vault with `Session()` and renders the real `MainWindow` offscreen (`Screen`). It reads every label, title, value, help and placeholder of the accessibility tree in these states:
- main and detail, with tags open;
- every editor page;
- the unlock screen;
- welcome with the vault in the recent list.

Static checks: SwiftLint over `macos/Larsal` with the project rule `no_markdown_text`, a probe file against that rule, and a grep for rich-text and link APIs.

**Output.**

```
RED AT-E01 seen: A1, B1, F1: detail, editor Advanced, main, tags open; G1, K1, T1, V1: every state;
  N1, U1: detail, editor Entry, main, tags open; L1: editor Entry
RED AT-E01 links: []
RED AT-E01 not literal: []
✘ … Expectation failed: seen[m]?.isEmpty == false      (D1 only: the stored name is not on any main-window frame)
swiftlint lint --strict --config .swiftlint.yml Larsal   -> exit 0, 0 lines
probe: Probe.swift:8 / :9 / :10 error "No Markdown or interpolated Text keys"
       (Text("Title: \(title)"), AttributedString(markdown:), LocalizedStringKey(title)); Text(verbatim:) and Text(title) pass
grep AttributedString(markdown | LocalizedStringKey( | NSAttributedString(html | WKWebView | import WebKit | openURL over macos/Larsal: 0
existing PlainTextTests "AT-E01: …shown as they are": passed
```

**Result: passed.**
- Every marker that is on screen is drawn with its asterisks, brackets and tags. No element has the link role, and no marker shows up in rendered form.
- `D1` appears only in Vault Settings, as the value of a `TextField` bound to `model.name` and `model.description` (`VaultSettingsView.swift`), which is plain text. I did not render that window; the CPU budget was spent.
- The `AttributedString` uses in `AutoTypePicker.swift` and `LarsalSettingsMorePages.swift` are `AttributedString(String)` (plain) or a fixed text of Larsal's own.

## AT-E02 Dangerous links

**Method.** Existing `URLOpenerTests` (22 refused, 4 allowed). New `RedATE02` adds 37 hostile texts, among them:
- `jav\0ascript:`, a zero-width space before `javascript:`, `javascript:/*https://…*/`;
- `file:/etc/hosts`, `file:etc/hosts`, `file:///Applications/Calculator.app`, base64 `data:`;
- `x-apple.systempreferences:`, `shortcuts://`, `applescript://…do shell script`, `x-man-page://`, `help:`;
- `smb:`, `afp:`, `vnc:`, `ftp:`, `itms-services:`, `tel:`, `facetime:`, `ssh:`, `telnet:`, `cmd://`;
- `https:example.com`, `https:\\example.com`, `http:///etc/hosts`, full-width `ｈｔｔｐｓ://`, `{REF:U@I:0}`;
- a text with line breaks that ends in `javascript:`.

Static check: every `NSWorkspace.shared.open` in `macos/Larsal`.

**Output.**

```
✔ Test "AT-E02: only http and https with a host are opened" passed
RED AT-E02 allowed of 37 hostile: ["https://%00"]
grep NSWorkspace|openURL|URLOpener: vault URLs open only in URLOpener.open (URLOpener.swift:24), called from RailView 48/94,
  Menus 67, LarsalCommandsVault 58, EditorEntryPage 83, ContextMenus 23; each control is disabled when allowed() is nil.
  The other open is FileOpener.open (VaultEdits.swift:305), for attachment copies (see RT-E-3).
```

**Result: passed.**
- `javascript:`, `file:`, `data:` and every unknown scheme are refused.
- The one text let through, `https://%00`, is an `https` URL with an odd host. It goes to the default browser like any web link, which the row allows; it is not a finding.

## AT-E03 Boundary abuse

**Method.** The Rust harness `red_at_e03.rs` calls every export of larsal-ffi. The script below counts 180 in the source, from `#[uniffi::export]` blocks.

In-process callers:
- `Session` methods;
- `LarsalSettingsStore`, `VaultSettings` and `Wizard` methods;
- the free functions.

`start()` reads the process arguments, so it ran on the Debug Larsal binary instead (below).

The calls, each wrapped in `catch_unwind` and timed:
- **Unknown vault ids:** `0`, `999999`, `u64::MAX`, and a closed id.
- **Malformed entry and group ids** (12 kinds): empty, `x`, 31 and 33 hex digits, 32 zeros, 32 `g`, a `+` sign, a leading space, braces, `é`×16, upper case, 1 MiB.
- **Foreign ids:** entry and group ids of the other open vault, a group id used as an entry id, and the reverse.
- **Texts:** empty, NUL, control characters with RTL override, ESC and BOM, format strings, Markdown, 64 KiB, 64 KiB + 1, `é` over 64 KiB, and 10 MiB.
- **Paths:** empty, NUL, `/`, `/dev/zero`, `/dev/random`, `/dev/null`, a FIFO, a symlink loop, a folder, `~`, a relative path, a missing file, a text file, 4,096 and 4,097 bytes, 10 MiB, `/etc/passwd`.
- **Number extremes and long lists:**
  - integers: `u32::MAX`, `i32::MIN`/`MAX`, `i64::MIN`/`MAX`;
  - lists: 100,000 ids, 100,000 tag chips, 1,000 × 64 KiB chips, 10,000 answers;
  - icons: PNGs of 0 bytes, 16 MiB, 16 MiB + 1, a bare signature, and a header claiming 60000 × 60000.
- **KDF choices:** `u64::MAX` memory, lanes and time; 4 TiB; zero; 2^24 lanes; AES with `u32::MAX` ms.
- **Generator options:** length 0 and `u32::MAX`, no character types, `u32::MAX` words, a 10 MiB separator, a 65-character separator.
- **Auto-Type:** plans 0, 1, 2 and `u64::MAX`, with a focus probe that always says false, so nothing could be typed.
- **SSH:** agent paths, with no `SSH_AUTH_SOCK`.

The secret search:
- It covers every Ok value except a Show's, every error's `Display` and `Debug` text, and every panic message.
- The 49 secrets searched: the protected values of 5 or more characters of both vaults (entries and history, read with larsal-format), the two master passwords, and four typed-in markers (password, field value, one-time secret, generator text).

The passes:
- **Pass 1:** with both vaults unlocked, then again on A after lock and after close. Before the lock, an editor draft with a typed password, a generator value and an Auto-Type plan were open. After that it unlocks A again to check that the draft is gone.
- **Pass 2:** two threads run the whole battery at once, while a third locks A, unlocks it and asks Show, every 20 ms.
- **FIFO checks:** each path-taking export with its own fresh FIFO; and a vault whose own file becomes a FIFO while it is open.

**Commands.**

```
cargo test -p larsal-ffi --test red_at_e03 --no-run            (in the copy)
env -u SSH_AUTH_SOCK HOME=… RED_TMP=/tmp/e13s2-ate/run sandbox-exec -f nonet.sb target/debug/deps/red_at_e03-… <test> --nocapture
  tests: red_at_e03_every_export, red_at_e03_two_threads, red_fifo_paths, red_fifo_swap, red_fifo_open_files, red_use_folder
```

**Output (pass 1 and pass 2).**

```
RED pass1: 1781 calls over 176 exports, panics 0, secret hits 0, over 5 s 0        (15.2 s)
  error kinds: UnknownVault 232, UnknownEntry 222, UnknownField 147, TooLong 120, Refused 102, UnknownGroup 69,
               Locked 66, CannotOpen 25, NotSettingsFile 16, Invalid 16, CannotWrite 11
  after lock: 65 data calls -> Locked; the rest carry no data: switch_to, check_header None, take_message None,
              approve_unlock Ignored, cancel_unlock, breach_stop, generator_options (options only),
              copy_generated -> Copied{empty:true} (the value was dropped on lock), autotype_rows [] , autotype_choose Gone
  after close: 71 -> UnknownVault;  unlock again: draft_password / editor -> Refused("The editor is not open.")
  private pasteboard after lock_all and clear_clipboard: 0 items
RED pass2: 3322 calls over 172 exports, panics 0, secret hits 0, over 5 s 0; 24 lock/unlock cycles during the run (9.6 s), no deadlock
red_use_folder (the 180th export): 18 hostile folders -> NotWritable or a write in that folder; panics 0
examples:
  codes 201 ids -> TooLong; 100000 bad ids -> TooLong (2 ms); set_tags 100000 chips -> TooLong
  add_custom_icon 60000x60000 header -> Refused("The icon could not be read.") 0 ms; 16 MiB + 1 -> TooLong
  search ((((a*)*)*…, r:(a+)+$, //(a+)+b// -> 0 ms; is:weak x5000 -> notice "This search is too long."
  Wizard.measure max / 4TiB / lanes 2^24 / zero -> Refused at once; check_encryption max -> M07-35 "This Mac has 48.0 GiB …"
  AES with u32::MAX ms -> M07-34 Ask "… about 30 seconds …" (needs the user's Use Anyway)
  autotype_type plan 0/1/2/u64::MAX -> Gone; breach_start in this build (no `net` feature) -> sends nothing
  attach_file /dev/zero, /dev/random, a folder, a loop -> CannotOpen at once
  open_attachment(vault 0 | 999999 | u64::MAX, "x.command", false) -> Ok(AskFirst)          (RT-E-4)
start() on the Debug Larsal, hidden (17 argument sets): --bogus exit 1 M09-09; invalid UTF-8 flag exit 1; 200 KB flag exit 1;
  200 KB file / 8000 files / invalid UTF-8 file with --lock exit 0 M09-04; --key-file at the end exit 1; --config= exit 1;
  --config=/dev/zero --lock exit 0; -v, --help, --debug-info exit 0 (no path, no secret); --pw-stdin with the password, --lock exit 0;
  no output held demo-pass-5
```

**Output (FIFO checks, re-run on the 21:40 Rust tree).**

```
RED FIFO vault_look / open / unlock key_file (M06-14) / attach_file / import_settings / VaultSettings.choose_key_file (M07-27) /
         Wizard.choose_key_file / ssh_agent_status / set_ssh_agent / export_to / new_key_file (M07-26) / Wizard.create: returned in 0-5 ms
RED FIFO save_as: BLOCKED until the other end opened (read end opened, write end opened); then Ok(None) [replaced by a file]
RED SWAP save_as(FIFO): BLOCKED over 3 s
RED SWAP lock(vault) while save_as blocks: returned in 0 ms: Ok(())     sidebar after that lock: Err(Locked)
RED SWAP own file is a FIFO: check_disk: BLOCKED over 3 s
RED SWAP own file is a FIFO: save: BLOCKED over 3 s
RED SWAP own file is a FIFO: resolve_disk(Reload): BLOCKED over 3 s
RED SWAP own file is a FIFO: lock: returned in 0 ms: Ok(())      close: Ok(())
open_files([FIFO]) and open_files([y.larsalvault FIFO]): returned in 0 ms
```

Then through the screen. `RedLockHang` sets up a vault with one unsaved change and swaps its file for a FIFO. It then calls `MainWindowModel.lockAll()`, which is what the lock signals and the instance channel's `lock` call, on the main actor. A watchdog thread checks the vault after 4 s and then opens both ends of the FIFO once, so the test can finish:

```
RED HANG changes before lock: 1
RED HANG lockAll on the main thread took 4.51 s; vault still unlocked 4 s after the lock began: true; locked at the end: true
```

Without the watchdog the call never returns. In my first pass 1 run the FIFO fixture was intact; the harness sat at 0 % CPU for 10 minutes in `save_as` until I opened the FIFO from outside.

**Result: failed.**
- No panic, no secret in any error, typed errors after lock and close, and no harm from two threads.
- But `save_as`, `save`, `check_disk` and `resolve_disk(Reload)` block for good on a FIFO, and the Swift lock path waits on `save` (RT-E-1).
- Low: `open_attachment` answers `AskFirst` before it checks the vault (RT-E-4).

Coverage, by a script over `crates/larsal-ffi/src/*.rs` (`#[uniffi::export]` blocks, minus the two foreign traits Swift implements):

```
180 exports in source; called: all but LarsalSettingsStore.use_folder in pass 1/2, and that one in red_use_folder; start() on the binary
```

## AT-E04 Retired: no web engine (replacement checks)

**Method.**
- `otool -L` and `nm -u` on today's Debug Larsal binary (built 21:32 in the copy), and for history on the Release binary in `target/xcode` (from 2026-10-27).
- `lsof` image list of the running hidden primary.
- The E6-S7 kind of network capture, done again:
  - `lsof -nP -a -i -p <pid>` every 0.25 s and `nettop -n -L 21 -s 1 -p <pid>`, both over the first 20 s from the launch;
  - a loopback positive control for `nettop`.

**Output.**

```
Debug Larsal (today): otool -L WebKit/JavaScriptCore: 0; nm -u WKWebView|WebView|JSContext|JavaScriptCore: 0
Release Larsal (2026-10-27, history): 0 and 0
NETCAP pid 69709: 64 lsof -i polls in 20 s from start, 0 with an internet socket; nettop -p: 0 rows
NETCAP mapped WebKit/JavaScriptCore/WebCore images in the running app: 0
NETCTL positive control (loopback TCP): 8 nettop rows, e.g. "tcp4 127.0.0.1:52225<->127.0.0.1:52224,lo0,Established,…"
```

**Result: passed.** A Release build of today's tree was not made: the CPU budget was spent. E14-S3 and AT-J05 check the release binary.

## AT-E05 Retired: no developer tools (replacement checks)

- The row says it is covered by AT-C03 and AT-J05.
- **AT-C03** is a debugger attach and a forced crash on a release build. It belongs to group AT-C (E13-S4). On this Mac a debugger attach can raise the developer-tools prompt, and a crash of a window app can raise the crash dialog, both on the owner's screen. So it needs Mac QA with the owner's go (rule 10).
- The code is in place: `larsal-platform/src/macos/process.rs` has `PT_DENY_ATTACH`, `RLIMIT_CORE` 0 and its own test, `app11_3_deny_attach_refuses_ptrace_attach`. I did not re-run that test (CPU budget).
- **AT-J05** is E14-S3.

**Result: waits for its stories.**

## AT-E06 Drag and drop

**Method.**
- **Drop targets.** A grep of `macos/Larsal` for `dropDestination|onDrop|registerForDraggedTypes|NSDraggingDestination|performDragOperation` found three:
  - `WelcomeView.swift:71`: vault files only, through `FileOpen.droppedVaults`;
  - `UnlockView.swift:340`: the key file row, which takes any file URL by LD-163 (2);
  - `EditorPages.swift:154`: the attachment zone, file URLs only.
- **`RedATE06`.** It feeds 13 hostile URLs to `FileOpen.droppedVaults` and `FileOpen.paths`:
  - links: `https:`, `javascript:`, `data:`, a remote-host `file:`;
  - non-vault files: `notes.txt`, `x.command`, `x.larsalvault.command`;
  - vault names: `x.LARSALVAULT`, a folder named `folder.larsalvault`, a FIFO `fifo.larsalvault`, a link `zero.larsalvault` → `/dev/zero`, a symlink loop, a real vault.
- Then it opens each accepted path the way the welcome drop does (`window.open`), timed.
- The attachment zone and the key file row hand their files to `attach_file` and `unlock`. AT-E03 shows those refuse FIFOs and devices at once.

**Output.**

```
RED AT-E06 dropped vault paths: x.larsalvault (remote file URL), x.LARSALVAULT, folder.larsalvault, fifo.larsalvault, zero.larsalvault, loop.larsalvault, real.larsalvault
RED AT-E06 key file row paths: 10 of 13 (file URLs only)
RED AT-E06 open <each>: 0.000 s; unlock screen true (or none for the missing remote path); main false; vaults 1, then 2 for real.larsalvault
✔ AT-E06 red … passed; ✔ "APP-09.26-a, AT-E06: a drop opens vault files only" passed; ✔ "LD-163 (2): the key file row …" passed
```

**Result: passed.**
- Links are refused, and nothing but a vault file opens from the window drop.
- A real vault opens only as an unlock screen (`main` stays nil). The folder, FIFO, device and loop return at once and stay unopened.

## AT-E07 Secrets in the screen

**Method.** `RedATE07` and its variants run in the xctest process.

Its own memory is scanned for the E07 entry's password and PIN, as UTF-8 and as UTF-16LE:
- It walks every readable private or writable region with `mach_vm_region_recurse`.
- It reads only the pages `mincore` reports resident or paged out, with `mach_vm_read_overwrite`.
- The needles are kept XOR-masked; the plain secret is never built by the test.

The Swift model state is searched by `Mirror` over `MainWindowModel` and everything it holds. The window is rendered offscreen throughout.

Variants:
- each in a fresh session, and the editor cases also in a fresh process each;
- with and without the accessibility flag;
- Rust-only call sequences (`beginEdit`, `rateDraft`, `draftPassword`, `cancelEdit`, `rate`, `showField`).

**Output** (counts are `[password utf8, PIN utf8, password utf16, PIN utf16]`).

```
1 unlocked, nothing shown: memory [1, 1, 0, 0] swift state []          (the decrypted vault in Rust)
2 Show password and PIN:   memory [4, 4, 0, 0] swift state [….shown.value ×2]
3 after Hide:              memory [1, 1, 0, 0] swift state []
4 editor Show:             memory [5, 4, 0, 0] swift state [editor.shownPassword, editor.shownFields]
5 editor Hide:             memory [4, 3, 0, 0] swift state []           (the draft in Rust)
6 Show again before lock:  memory [5, 1, 0, 0]
7 after lock:              memory [1, 0, 0, 0] swift state []           <- one password copy
8 after close:             memory [1, 0, 0, 0] swift state []
variants, each from [0,0,0,0]: main Show-lock, Show-Hide-lock, select-lock, Show-lock unrendered, unlock-lock -> after lock [0, 0, 0, 0]
  editor rendered, Show+Hide, Cancel, lock -> after lock [1, 0, 0, 0], after close [1, 0, 0, 0], after the host view is removed [1, 0, 0, 0]
  (same with the accessibility flag off, in a fresh process; same on today's ShownPasswordField.swift with the F-069 fix)
  editor unrendered with Show+Hide; editor rendered without Show; editor unrendered without Show -> after lock [0, 0, 0, 0]
  Rust only: begin_edit+cancel, +rate_draft, +draft_password, rate(all), show_field -> after lock [0, 0, 0, 0]
probe in the copy: EditorPasswordField.dismantleNSView clearing the field -> still [1, 0, 0, 0] (probe reverted; cmp equal to the tree)
existing: ✔ "APP-06.11, AT-E07: …", ✔ "AT-E07: a Show that finishes after …", ✔ "FEA-06.12, AT-E07: a lock closes the reports …"
```

**Result: failed (RT-E-2).**
- The Swift view state holds no secret after Hide and after lock, and the main window's Show path leaves no copy.
- But the editor's rendered Show leaves one copy of the entry password in the process after lock and after close.

## AT-E08 Local listeners

**Method.** Hidden Debug primary, started with a rich-v4 copy and `--pw-stdin` (unlocked through F06), then:
- `lsof -nP -p` and `lsof -nP -a -i -p`;
- `netstat -anv` for tcp, udp and unix, filtered on the PID;
- the socket's mode and folder;
- a `lock` request and a 1 MB request on the channel.

A second run had `ssh.enabled` true (S-SSH-01) and `HOME` in `/tmp`; it ran a same-user identities request to Larsal's agent socket. Both primaries were stopped with SIGTERM by their PID.

**Output.**

```
LISTEN socket: 0o140600 owner uid 501 me 501 folder 0o40700
lsof -nP -p 68193: 42 fds, types DIR 2, REG 36, PIPE 3, unix 1   (4u unix …/inst/app.larsal.desktop-debug.sock)
lsof -nP -a -i -p: 0 lines; netstat tcp: 0, udp: 0 lines naming the pid; netstat unix: 1 line (Larsal:68193)
channel lock answer: {"ok":true}; 1 MB request: connection closed (BrokenPipe); Larsal alive after: True; SIGTERM -> exit 0
SSH on: 2 socket fds: instance socket and …/larsalhome/Library/Application Support/Larsal/agent.sock
  agent socket mode 0o140600 uid 501, folder 0o40700; same-user identities answer type 12; internet sockets: none;
  after exit the agent socket is gone
```

**Result: passed.**
- No web server, no port. Every listener is Unix, owner-only and in an owner-only folder.
- The browser bridge sockets (INT-01) do not exist yet; that part waits for its story.
- The SSH agent socket is a listener the row does not name (RT-E-5).
- A Release app after its window exists needs a visible window: Mac QA with the owner's go.

## Findings

### RT-E-1 (High; AT-E03, area saving and lock): a FIFO at the vault path or the Save As target blocks for good, and every lock waits on it

- **What.**
  - `save_as` with a FIFO target blocks. So do `save`, `check_disk` and `resolve_disk(Reload)` once the open vault's own file is a FIFO. They never return a typed error.
  - Every other path export refuses a FIFO at once: `open`, the unlock key file, `attach_file`, `import_settings`, key files, `vault_look`, `open_files`.
  - `MainWindowModel.lockAll()` (Swift, main actor) calls `saveAll`. For each unlocked vault with unsaved changes, and `save.on_lock` on by default (S-FILE-02), `saveAll` calls `session.save(vault:)` synchronously on the main thread (`Saving.swift` line 282).
  - So Lock Everything, every automatic lock (idle, sleep, screen lock, user switch) and the channel's `lock` wait on the blocked save: the vault stays unlocked and Larsal freezes. `Session.lock` itself still works while a save blocks (`red_fifo_swap`).
- **Who can do it.**
  - Another app with normal user rights that can write the vault's folder: it replaces the vault file with a FIFO (the Tamperer and Other-apps rows of security.md). After that the next autosave blocks in its detached task, and the change stays unsaved.
  - A save that stalls on an unresponsive network volume delays every lock in the same way, until the volume times out.
- **Why High.** The automatic lock, a protection, does not happen: the window keeps showing the open vault. The lead may weigh that it needs a local writer in the vault's folder.
- **Steps (demo data).**
  1. Copy `testdata/rich-v4.larsalvault` to `/tmp/hang/hang.larsalvault`.
  2. In a Swift test, `MainWindowModel(session: Session())`, open the vault, unlock it with `demo-pass-5`.
  3. Make one change, for example `session.deleteEntry(vault:entry:)` on the first row; `saveStatus.changes` is 1.
  4. `rm` the file and `mkfifo` the same path.
  5. Call `window.lockAll()` on the main actor. It does not return, and `session.vaults()` from another thread shows the vault unlocked. Opening the FIFO's two ends once from outside lets it go on.
  - The Rust part alone: `two_vaults`; `save_as(a, "/tmp/x.fifo")`; or swap A's file for a FIFO, then `check_disk(a)` or `save(a)`. Each blocks over 3 s.
- **Smallest fix.**
  1. In Rust, open the vault file and the Save As target for every read the save, the pre-save check, the backup, `check_disk` and the reload do with `O_NONBLOCK`, `fstat` it, and refuse anything but a regular file with a typed error ("… is not a normal file"). The path exports above already refuse FIFOs; this makes the save path match.
  2. In Swift, an automatic lock (`asks == false`) must not wait without end on `save`: run it off the main thread with a deadline. On timeout, write the recovery copy (APP-02.16) and lock anyway.
- **Test.** The `RedLockHang` case: `lockAll()` returns in under 2 s and the vault is locked. And a Rust case: with the own file swapped for a FIFO, `save`, `check_disk`, `resolve_disk(Reload)` and `save_as` each return an error within 1 s.

### RT-E-2 (Medium; AT-E07, area editor password field): the editor's Show leaves a copy of the entry password in memory after lock and close

- **What.** After the editor is rendered with its password shown, then Hide, Cancel, lock and close, one UTF-8 copy of the entry password stays in Larsal's process. It stays after the hosting view is removed too. The Swift model state is clean (`Mirror`: none).
- **What leaves no copy:**
  - the main window's Show and Hide;
  - the editor without rendering;
  - the rendered editor without Show;
  - every Rust-only sequence.
- So the copy comes from AppKit drawing the shown value in `EditorPasswordField`: a `NoCopyTextField` whose `attributedStringValue` is `EditorPasswordField.coloured(text)`.
  - It holds with and without the accessibility flag, in a fresh process, and on today's `ShownPasswordField.swift` (with F-069's undo fix).
  - Clearing the field in `dismantleNSView` did not remove it (probe in the copy, reverted).
  - Medium, as F-058: a secret left in memory after lock, readable only by someone who can read Larsal's memory.
- **Steps (demo data).**
  1. Make a copy of rich-v4 with a new entry "E07 entry" whose password is a random value made in a separate process. The test knows it only XOR-masked.
  2. `MainWindowModel` with `Session()`, open and unlock that copy.
  3. Build an `NSHostingView(MainWindow)` in a borderless window at (-20000, -20000).
  4. Select the entry, `main.edit()`, `editor.toggleShowPassword()` twice, `main.cancelEditor()`, `window.lock(id)`, `window.close(id)`.
  5. Scan the process's own resident pages (`mach_vm_region_recurse` + `mincore` + `mach_vm_read_overwrite`). The result is 1 hit for the password; the same steps with the main window's Show give 0.
- **Smallest fix to try.** While the field is not being edited, draw the shown password the way the detail does: SwiftUI `Text(verbatim:)` in the coloured runs, which leaves no copy. Make the `NoCopyTextField` only when the user focuses the field to type. Then find any other cell that draws a secret.
- **Test.** The `RedATE07Editor` scan as a LarsalTests case: after lock, 0 hits.

### RT-E-3 (Medium; AT-E01 and AT-E06 "nothing runs", area attachments): Open asks first for 18 extensions, but macOS runs or acts on more

- **What.** `open_attachment` asks first only for the 18 extensions of MOD-05.12 rule 3 (`RISKY` in `edit.rs` and `larsal-core/src/attachments.rs`), and the card says "for example".
- **What else LaunchServices on this Mac hands out.** Asked without opening anything (`NSWorkspace.urlForApplication(toOpen:)` on files with each extension), it gives these default apps for types that are not on the list:

| Extension | Default app | Same kind as, on the list |
|---|---|---|
| `.term` | Terminal | `.terminal` |
| `.xhtml`, `.xht`, `.shtml` | the browser | `.html` |
| `.webarchive`, `.url`, `.xsl` | Safari | `.webloc` |
| `.jnlp`, `.class` | JavaLauncher | `.jar` |
| `.afploc`, `.ftploc`, `.atloc` | Finder | `.inetloc`, `.fileloc` |
| `.vncloc` | Screen Sharing | the location files |
| `.mailloc` | Mail | the location files |
| `.action` | Automator | `.workflow` |
| `.wflow`, `.shortcut` | Shortcuts | `.workflow` |
| `.scptd`, `.osax` | Script Editor | `.scpt` |
| `.svgz` | the SVG viewer | `.svg` |
| `.iso`, `.img`, `.cdr`, `.sparseimage`, `.toast` | DiskImageMounter | `.dmg` |

- **Why it matters.** Larsal writes the copy itself; its Info.plist sets no `LSFileQuarantineEnabled`, so the copy carries no quarantine mark and Gatekeeper does not ask either. A hostile vault (a shared group or a merge) can bring such an attachment.
- **Steps.** In the editor of any demo vault, attach a file named `x.term` or `x.xhtml`. `open_attachment(vault, "x.term", false)` returns `Opened { path }` with no `AskFirst`, while `x.terminal` and `x.html` return `AskFirst`.
- **Smallest fix.** Add these extensions to both `RISKY` lists, keeping the two in one place, and say on the card that the list is Larsal's. Better: ask for every extension whose default app is not a plain viewer. Test: `open_attachment` gives `AskFirst` for each added extension.

### RT-E-4 (Low; AT-E03, area attachments): `open_attachment` answers `AskFirst` before it checks the vault

- **What.** `open_attachment(vault, "x.command", false)` returns `Ok(AskFirst)` for vault `0`, `999999` and `u64::MAX`, for a locked vault, and when no such attachment exists. The extension check comes before `with_draft` (`edit.rs`, the `RISKY` test at the start of `open_attachment`).
- **Effect.** The screen would ask the risk question for an attachment that cannot be opened; then the confirmed call gives the typed error.
- **Steps.** `Session::new().open_attachment(u64::MAX, "x.command".into(), false)` returns `Ok(AskFirst)`; with `"x.txt"` it returns `Err(UnknownVault)`.
- **Smallest fix.** Look up the attachment in the draft first, then test the extension. Add the case to `at_e03_editor_refuses_hostile_arguments`.

### RT-E-5 (Low; AT-E08 row, area plan and spec): the row does not name Larsal's own SSH agent socket

- **What.** With S-SSH-01 on, Larsal listens on `~/Library/Application Support/Larsal/agent.sock` (INT-06.32). It is a Unix socket, `0600` in a `0700` folder, serving only peers of the same user (`larsal-sshagent/src/server.rs` `same_user`), and it is removed at exit.
- **The gap.** AT-E08's "Passes when" lists only the instance socket and the bridge sockets. A strict reading would fail a correct build.
- **Fix.** Add "with the SSH agent on (S-SSH-01), Larsal's own agent socket of INT-06.32" to the AT-E08 row and to security.md's listener list.

### Notes (not findings)

- An unknown flag is echoed with its control characters, so an ESC sequence in an argument reaches the terminal (`--\x1b[31m\x07` printed as typed). The argument comes from whoever starts Larsal.
- `LarsalSettingsStore.text`, `save_settings` and the Unknown-flag message echo the text they were given, unbounded: a 10 MiB key comes back in a 10 MiB error. No secret is involved, and Swift passes fixed keys.
- `open_files` with a path that is not a vault opens nothing, and in this harness left no M09-07 banner (`take_banner` was `None`). This is for the APP-09 Verify to look at.

## Open items

- AT-E05: AT-C03 on a release build (debugger attach, forced crash) needs Mac QA with the owner's go; AT-J05 is E14-S3.
- AT-E08: a Release app after its window exists, and the bridge sockets once INT-01 is built.
- AT-E01: Vault Settings with the hostile stored name, rendered (checked here by reading only).
- AT-E04: today's Release binary, at E14-S3.
- The `/tmp/e13s2-ate` folder (copy, DerivedData, demo vaults, harness) was deleted at the end; the harness files exist only as described above.
