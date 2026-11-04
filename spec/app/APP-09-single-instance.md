# APP-09 Single instance and the app's command line flags

Status: reviewed
Epics: E5-S1
Parity rows: SR-09, SC-05 (the start flag only; APP-10 owns screen protection)

## What it does

Larsal runs as one instance per macOS user. A second launch does not start a second window. It hands its request to the running instance and exits: open these files, lock every vault, or just come to the front. The window app also takes a small set of command line flags: settings file paths, a lock request, a key file and a password from standard input for the files it opens, a flag that allows screen capture, a start-minimized flag, debug info, help and version.

On macOS most opens do not use the command line at all. Finder, the Dock and the `open` command send open-document events, and clicking the Dock icon sends an activation event. This card covers those paths too, plus the file types Larsal declares, URL schemes (none), files dropped on the window, quitting by signal, and launch at login.

Who owns what: how a vault unlocks is APP-06; locking is APP-02; quick unlock is APP-04; saving and the recent-vaults list are APP-05 and APP-01; screen protection is APP-10; process hardening and the crypto self-test are APP-11; the `larsal` command line tool is INT-10.

## Inputs and outputs

### Flags of the window app

The window app is the binary inside the bundle (`Larsal.app/Contents/MacOS/Larsal`). Long flags take a value as `--flag value` or `--flag=value`. Flags may come before or after file arguments. `--` ends the flags; everything after it is a file argument.

| ID | Larsal flag | Reference spelling (accepted alias, D-APP09-1) | Value | Effect in a first launch | Effect in a second launch |
|---|---|---|---|---|---|
| F01 | `FILE ...` (positional) | same | paths | Open each file (APP-09.6, APP-09.15) | Passed to the running instance (APP-09.10) |
| F02 | `--config PATH` | `--config` | path | Settings file (APP-09.5) | Ignored |
| F03 | `--local-config PATH` | `--localconfig` | path | Local (per-machine) settings file (APP-09.5) | Ignored |
| F04 | `--lock` | `--lock` | none | Lock all vaults of the running instance, then exit (APP-09.11) | Sent as a lock request (APP-09.10) |
| F05 | `--key-file PATH` | `--keyfile` | path | Key file for every F01 file (APP-09.17) | Ignored, never passed on |
| F06 | `--password-stdin` | `--pw-stdin` | none | Read one password line per F01 file (APP-09.16) | Ignored; stdin is not read |
| F07 | `--allow-screen-capture` | `--allow-screencapture` | none | Start with screen capture allowed (APP-10.5) | Ignored |
| F08 | `--minimized` | `--minimized` | none | Start hidden or minimized (APP-09.21) | Ignored |
| F09 | `--debug-info` | `--debug-info` | none | Print build information, exit 0 (APP-09.4) | Same (no instance contact) |
| F10 | `-h`, `--help` | same | none | Print usage, exit 0 (APP-09.3) | Same |
| F11 | `-v`, `--version` | same | none | Print `Larsal <version>`, exit 0 (APP-09.3) | Same |

No flag takes a password or any other secret as its value (APP-09.18).

### Other inputs

- Open-document events from macOS: Finder double click, Open With, a file dropped on Larsal's Dock icon, `open FILE` (APP-09.23).
- Activation events: Dock icon click, the app switcher, Finder opening the app (APP-09.22).
- Requests on the instance channel (APP-09.12 to APP-09.14).
- Standard input, only with F06.
- Environment: none. No environment variable changes this card's behavior (Decided: spec/decisions.md LD-48).
- Files dropped on the main window (APP-09.26).
- Signals SIGINT, SIGTERM, SIGQUIT, SIGHUP (APP-09.27).

### Messages

Our IDs and our wording. "stderr" means a line on standard error of the launching process; "banner" means the error bar inside the main window.

| ID | Where | When | Text (Larsal) |
|---|---|---|---|
| M09-01 | stderr | A second launch passed its request on (open or activate) | Larsal is already running. The request was passed to it. |
| M09-02 | stderr | F04, lock delivered | All open vaults were locked. |
| M09-03 | stderr | F04, lock not delivered | The vaults could not be locked. |
| M09-04 | stderr | F04, no running instance | No copy of Larsal is running, so there is nothing to lock. |
| M09-05 | stderr | The instance lock is held but nobody answers | The running copy of Larsal does not answer. Quit it and try again. |
| M09-06 | stderr and a modal error alert | The instance lock cannot be created | Larsal cannot start: the instance lock PATH could not be created (REASON). |
| M09-07 | banner | A path to open does not exist or cannot be read | Could not open PATH. It does not exist or cannot be read. |
| M09-08 | stdout | F06, before each password line | `Vault password: ` (no newline, flushed) |
| M09-09 | stderr | Unknown flag, or a flag without its value | Names the flag, then: "Run Larsal --help for the list of flags." |

### Exit codes

| Situation | Exit code |
|---|---|
| Help, version, debug info | 0 |
| Unknown flag or missing value | 1 |
| Second launch passed open or activate on (also when delivery failed) | 0 |
| F04, lock delivered | 0 |
| F04, lock not delivered | 1 |
| F04, no running instance | 0 |
| The running copy does not answer (M09-05), with or without F04 | 1 |
| The instance lock cannot be created (M09-06) | 1 |
| Crypto self-test failed (APP-11.10) | 1 |
| Normal quit, or quit by SIGINT, SIGTERM, SIGQUIT | 0 |
| SIGINT, SIGTERM or SIGQUIT at the F06 password prompt, before the window exists | ended by that signal, after the terminal is restored (as readpassphrase does; LD-165) |

There is no single-instance setting: Larsal always runs one copy per macOS user and build kind (Decided: spec/decisions.md LD-47; APP-01 D-01-4).

## Rules

APP-09.1 **Start-up order.** The window app runs these steps in this order: (1) process hardening (APP-11.1); (2) read the flags (APP-09.2); (3) help and version (APP-09.3); (4) debug info (APP-09.4); (5) pick the settings files (APP-09.5); (6) collect the file arguments (APP-09.6); (7) single-instance check (APP-09.8 to APP-09.10); (8) a lock request with no instance running (APP-09.11); (9) crypto self-test (APP-11.10); (10) create the main window, screen protection already applied (APP-10.1); (11) reopen previous vaults (APP-09.20); (12) open the file arguments (APP-09.15 to APP-09.17); (13) start minimized or come to the front (APP-09.21). No window is shown, no password is read and no vault file is read before step 9 has passed. The reference runs the same steps, except that its hardening comes after step 8 and its self-test before hardening; both still run before any password or vault is touched.

APP-09.2 **Reading flags.** The flags are exactly F01 to F11. An unknown flag, or F02, F03 or F05 without a value, prints M09-09 and exits with code 1; no later step runs, so a running instance is not contacted. The reference spellings in the flag table are accepted as hidden aliases (not listed in help) (D-APP09-1). The reference's toolkit also accepts its own toolkit options (see Not on Mac); Larsal has none.

APP-09.3 **Help and version.** F10 prints a one-line description, the usage line, every flag of the table with a one-line meaning (aliases not shown) and the file argument, on stdout, then exits 0. F11 prints `Larsal <version>` on stdout and exits 0. If both are given, version wins (the reference's toolkit checks version first; Verified 2026-10-28, V-A09-1: in the installed 2.7.11 bundle the toolkit's parse-and-act routine tests the version option, then help, then the long help, and the version branch exits; its command line tool also tests version before help). Neither contacts a running instance, reads settings or shows a window.

APP-09.4 **Debug info.** F09 prints on stdout, then exits 0, before settings, the instance check or any window: product and version; build type (release or debug); source revision (first 7 hex digits of the commit, when known); the screen layer (`Shell: SwiftUI (native)`) and a line saying that no web engine is used (`Web engine: none`), as the native app has none (LD-155); whether debugging mode is on; OS name and version; CPU architecture; kernel name and version; the list of features built in (Auto-Type, Browser bridge, Passkeys, SSH agent, Shared groups, Hardware keys, Quick unlock); each crypto crate with its version. It never prints paths, settings values or anything from a vault. Reference: the same kinds of lines (it names its UI toolkit and its crypto library); its source also prints build type and distribution lines that the installed 2.7.11 does not print (differs in installed version).

APP-09.5 **Settings files.** F02 sets the path of the settings file; F03 sets the path of the local (per-machine) settings file. Each is independent: a missing one keeps its normal location (APP-01). Larsal reads no environment variable for these paths (Decided: spec/decisions.md LD-48). Debug builds use different default file names (suffix `_debug`), so they never read or write release settings. Reference: the same flags, plus two environment variables with its own prefix that override the paths, and a portable mode (a writable marker file next to the program moves settings next to it); Larsal has neither (LD-48, D-APP09-9).

APP-09.6 **File arguments.** Each positional argument that names an existing regular file (after following symbolic links) is kept, in the order given. Others (missing paths, folders) are dropped without a message. Each kept path is made absolute against the current working folder before it is used or passed on. Reference: keeps every existing path, folders included (a folder then fails at unlock), and keeps relative paths relative, so a relative path passed to a running instance is resolved against that instance's folder. That defect is not copied.

APP-09.7 **Instance identity.** There is at most one primary instance per macOS user and build kind. The lock file and the channel socket live in the per-user temporary folder that the OS reports (the Darwin user temp folder, mode 0700; read from the OS, not from `TMPDIR`). Names: `app.larsal.desktop.lock` and `app.larsal.desktop.sock`; debug builds use `app.larsal.desktop-debug.lock` and `app.larsal.desktop-debug.sock`. The socket path must stay under 104 bytes (the macOS socket path limit); on this Mac the debug socket path is 75 bytes. Reference: lock file and socket in the per-user temporary folder, named after the product plus the user name from the environment (characters not safe in file names replaced by `_`, trailing dots and spaces removed), plus a debug suffix in debug builds.

APP-09.8 **Becoming the primary.** At step 7 Larsal takes an exclusive advisory lock on the lock file without waiting. The OS releases this lock when the process ends, so a crash never leaves a stale lock. Lock taken: this process is the primary; it removes a leftover socket file if one exists, listens on the socket (APP-09.14) and goes on with start-up. Lock held by another process: APP-09.9. Lock file cannot be created or locked for any other reason (for example the path is a folder, or the folder is not writable): Larsal refuses to start: M09-06 on stderr and in a modal error alert, naming the lock path and the system's reason, then exit 1; no main window, no listener, no vault opened (Decided: spec/decisions.md LD-47). Reference: uses a lock file holding the process id, and decides "stale" by asking the socket (APP-09.9).

APP-09.9 **Asking the running instance.** When the lock is held, Larsal connects to the socket, up to 3 tries with 150 ms each. Connected: this process is a secondary (APP-09.10). Not connected after 3 tries: print M09-05 and exit 1, with no window, no vault opened and stdin not read; Larsal never starts a second copy (Decided: spec/decisions.md LD-47). This holds for F04 too. Reference: same tries and timeout, only while its single-instance setting is on; when nobody answers it deletes the old lock, takes it and becomes the primary itself; with the setting off it starts a second copy without asking.

APP-09.10 **What a secondary does.** It sends exactly one request: `lock` when F04 is given (file arguments are then ignored); otherwise `open` with the kept absolute paths when there are any; otherwise `activate`. For `open` and `activate` it prints M09-01 and exits 0, also when delivery failed. For `lock`: delivered prints M09-02 and exits 0; not delivered prints M09-03 and exits 1. A secondary never reads stdin, never shows a window, never applies F02, F03, F05, F06, F07 or F08, and never passes on a key file path or a password.

APP-09.11 **Lock with no instance.** F04 when no process holds the instance lock prints M09-04 and exits 0 (a screen-lock script treats "nothing open" as success). It never starts the window. When the lock is held but nobody answers, APP-09.9 applies (M09-05, exit 1), because an unlocked vault may still be open there. Reference: with its single-instance setting off it does not try the channel, and reports M09-04 even if another copy runs; Larsal has no such setting (LD-47).

APP-09.12 **What the primary does with a request.** `activate`: bring to front (APP-09.22). `open`: bring to front, then open each path in order (APP-09.15) with no password and no key file; a path that is not a regular file at that moment is skipped without a message. `lock`: lock all open vaults as the Lock all action does, as an automatic trigger (APP-02.12, APP-02.16); the window is not brought to front (D-APP09-2). Unknown or malformed request: no action. Reference: brings the window to front on every incoming connection, including lock; opens only paths whose extension, compared without letter case, is its own vault extension (stored encoded (name rule): `6B 64 62 78`); Larsal opens any regular file and lets format detection decide (D-APP09-3).

APP-09.13 **Channel format.** One request per connection: a UTF-8 JSON object on one line, at most 65,536 bytes including the newline. Fields: `"v": 1`, `"cmd"`: one of `"activate"`, `"open"`, `"lock"`, and for `open` only `"paths"`: 1 to 64 strings, each an absolute path of 1 to 1,024 bytes in UTF-8 (1,024 is the macOS path limit). The primary answers one line, `{"ok":true}` when it accepted the request or `{"ok":false}`, then closes. Anything else (longer line, bad JSON, other `v`, a relative path, too many paths) closes the connection with no action and no answer. The secondary waits at most 1 second for the answer; no answer counts as the running copy not answering (M09-05, exit 1; on macOS a connect to a stopped process succeeds, so this is how a hung primary is found; LD-159). Reference: a 4-byte big-endian length, then a 4-byte command number (1 = open, followed by a string list; 2 = lock), no answer, no limits. The format is Larsal-internal (D-APP09-5).

APP-09.14 **Channel access.** The socket file has mode 0600 inside the 0700 per-user folder. The primary also checks that the peer runs as the same user id and closes the connection otherwise. The channel carries only the requests of APP-09.13 and the one-line answer. No request can unlock, show, copy, export, change or delete anything. Reference: the socket is restricted to the owner; there is no peer check.

APP-09.15 **Opening a path.** One routine serves file arguments, Finder and Dock opens, channel requests and window drops. (a) Resolve the canonical path (symbolic links followed). If that fails (missing, or not readable), show M09-07 with the path as given and stop. (b) If a vault with the same canonical path is already in the session (compared without letter case on macOS, with letter case elsewhere), make it the shown vault; if a password or key file came with the request and that vault is locked, start its unlock (APP-06); stop. (c) Otherwise add the vault to the session, locked, showing its unlock screen (APP-06); make it the shown vault; put it at the top of the recent-vaults list (APP-01); if a password or key file came with the request, start the unlock at once, with quick unlock skipped for this attempt (APP-04). Whether the file is a vault is decided by format detection at unlock (FMT-01), never by its extension.

APP-09.16 **Password from standard input.** With F06, for each kept file argument in order: print M09-08 on stdout; if stdin is a terminal, turn its echo off; read one line; turn echo back on; print a newline on stderr. The line end (LF or CRLF) is removed; nothing else is trimmed. End of input gives an empty line. A line keeps at most its first 65,536 bytes (64 KiB): the rest of a longer line is read and dropped, so the next line still goes to the next file. A line that is not valid UTF-8 (also when the cut splits a character) is refused: its bytes are wiped and it counts as an empty line; a read error does the same (Decided: spec/decisions.md LD-200 (6); built in `larsal-ffi` `cli.rs`, `read_password_line`). The text goes straight into a secret type (APP-11.9) and is never echoed, logged or shown. An empty line means "no password component", as an empty unlock field does (FMT-04.2, APP-06): with F05 the unlock starts with the key file alone; without F05 the unlock screen is only shown. Without file arguments, stdin is not read. The lines are read in the primary only, after hardening (APP-09.1).

APP-09.17 **Key file flag.** The F05 path is used for every kept file argument, together with the F06 password when given. It is not checked until the unlock; a missing or unreadable key file gives the unlock screen's key file error (APP-06). Without file arguments F05 does nothing.

APP-09.18 **No secrets in arguments or environment.** Larsal never takes a password, key file content or any other secret as a flag value or an environment variable, because other processes can read both (process list). F06 is the only way to pass a password on start.

APP-09.19 **Same file more than once.** A file argument given twice, or a file that is already open, does not add a second session entry; APP-09.15 (b) applies. With F06, one password line is still read for each kept argument, duplicates included.

APP-09.20 **Reopen previous vaults.** When the reopen setting is on (APP-01; reference default on), the window first reopens the vaults that were open at the last quit that still exist, in the saved order, then the one that was shown last (so it becomes the shown one), all locked. Then the file arguments open (APP-09.15), so the last file argument is the shown vault.

APP-09.21 **Start minimized.** After step 12, when F08 is given or the minimize-at-start setting is on (APP-01; default off): with the menu bar icon on (APP-08) the window is hidden without the minimize animation; with it off the window is minimized into the Dock. Lock on minimize (APP-02) then applies as for any minimize. Otherwise the window is shown and brought to front.

APP-09.22 **Bring to front.** Un-minimize, show if hidden, raise, and make Larsal the active application with the main window as key window. Triggers: `activate` and `open` requests (APP-09.12), and Larsal becoming the active application by any means (Dock icon click, the app switcher, Finder opening the app). Reference: the same, on every activation.

APP-09.23 **Finder, Dock and the `open` command.** A file opened from Finder (double click, Open With), dropped on Larsal's Dock icon or opened with `open FILE` arrives as an open-documents event, not as an argument. If Larsal is not running, macOS starts it with no flags and then delivers the event; if Larsal is running, macOS delivers the event to it and the channel is not used. Each file opens through APP-09.15 with no password and no key file and no extension check, in the order given.

APP-09.24 **Declared file types.** Larsal's bundle declares two document types (D-APP09-6): (a) `.larsalvault`: role Editor, handler rank Owner, Larsal's own exported type `app.larsal.desktop.vault` conforming to `public.data`, with Larsal's vault document icon; (b) the reference's vault extension (stored encoded (name rule): `6B 64 62 78`): role Editor, handler rank Alternate (offered in Open With, never taking over the default), through an imported type with Larsal's own id `app.larsal.desktop.vault-compat`. Key files and every other kind are not declared. Reference: one document type only, its own vault extension, role Editor, its app icon as the document icon, an OS type code equal to the extension, no type id; key files not declared.

APP-09.25 **No URL schemes.** Larsal declares no URL scheme and ignores URL-open events. Reference: none. The browser talks to Larsal through native messaging (INT-01), never through URLs.

APP-09.26 **Files dropped on the window.** Reference: files dropped on the main window open through APP-09.15 when their extension, compared without letter case, is its vault extension; other files are refused (the drop shows "not allowed"). Larsal (D-APP09-7 (a), decided in spec/decisions.md LD-153; letter case ignored, LD-165): the same, accepting `.larsalvault` and the reference's vault extension; every other drop on the main window is refused; the attachment drop target (MOD-05) is separate and unchanged.

APP-09.27 **Quit by signal.** SIGINT, SIGTERM and SIGQUIT start an orderly quit, the same as the Quit action (APP-02 locks on quit, APP-05 handles unsaved changes). SIGHUP is ignored, so closing the Terminal that launched Larsal leaves Larsal running. Same as the reference.

APP-09.28 **Launch at login.** The launch-at-login setting (APP-01; default off) makes macOS start Larsal at login with no flags. Larsal registers the main app as a login item through the system service (SMAppService, macOS 13 and later), and the checkbox shows the system's actual registration (D-APP09-8). Reference (macOS): writes a per-user launch agent property list into `~/Library/LaunchAgents`, named after its reverse-domain id, with run-at-load on, its program path as the only argument and both outputs sent to `/dev/null`; turning it off deletes the file; the checkbox shows whether the file exists.

APP-09.29 **Debug builds.** A debug build follows the same one-copy rules (LD-47), with its own debug-named lock and socket (APP-09.7), so a debug copy and a release copy never contact each other. The settings files are the debug ones (APP-09.5), and the launch-at-login checkbox is shown disabled. Reference: in a debug build every launch is a full instance and never becomes a secondary; its single-instance and launch-at-login checkboxes are disabled.

## Edge cases and errors

- **Missing file argument** (`Larsal /tmp/none.larsalvault`): dropped silently in step 6 (no M09-07). M09-07 appears only when a path vanishes between step 6 and APP-09.15, or comes from Finder, the channel or a drop.
- **Folder as file argument:** dropped (APP-09.6). Reference: kept, opened as a session entry, and its unlock fails.
- **A non-vault file** (`Larsal notes.txt`): opened as a session entry; the unlock screen reports it is not a vault (APP-06, FMT-01). Same in the reference for arguments and Finder opens.
- **Fewer stdin lines than files:** the missing lines are empty (APP-09.16).
- **F04 together with files or F06:** only the lock request is handled; stdin is not read.
- **F05 or F06 without files:** no effect, stdin not read.
- **`open -a Larsal --args --lock` while Larsal runs:** macOS only activates the running instance and drops the arguments (OS behavior), so the lock is not sent. Scripts must call the binary inside the bundle, or use `open -n`. Verified 2026-10-28, V-A09-2: with a hidden background-only demo app, a second `open -g` with `--args --lock` while the first copy ran started nothing and passed no arguments; `open -n -g` with the same arguments started a second copy, which got `--lock`.
- **Two launches at the same moment:** the advisory lock lets exactly one become primary; the other becomes a secondary once the primary listens, or prints M09-05 and exits 1 if the primary is not listening within 3 tries. Reference: a race between deleting and re-taking its lock file is possible.
- **Primary hung** (stopped with SIGSTOP): a new launch prints M09-05 after about 1 second (the answer wait of APP-09.13) and exits 1. Only the hung copy runs; the user quits it (LD-47).
- **Primary killed** (SIGKILL): the OS released the lock; the next launch becomes primary with no message. Reference: prints its stale-lock message and takes over.
- **Request while a vault is unlocking or a dialog is open:** open requests add their vaults behind the dialog; a lock request follows APP-02 for an unlock in progress. Verified 2026-10-28 in part, V-A09-3: in the reference both requests are handled by its event loop, which also runs while a dialog is open, so opened vaults get tabs behind it, and a lock during an unlock counts that vault as locked (APP-02 V-A02-2); in Larsal a lock during an unlock drops the unlock's result (test `app06_16_lock_during_unlock_drops_the_result`). Vaults added behind an open sheet in Larsal need Mac QA (owner's go): it takes the window app with a sheet open.
- **Reference self-relaunch:** after some display settings the reference restarts itself with no arguments, so every flag (including F07) is dropped. Larsal has no setting that needs a restart; if one ever does, the new process starts protected (APP-10.5).

### Lead decisions

All decided in spec/decisions.md LD-153, each as recommended below.

- **D-APP09-1 Reference flag spellings.** (a) Accept them as hidden aliases; (b) Larsal names only. Recommend (a): scripts written for the reference keep working at no cost.
- **D-APP09-2 Lock request and the window.** (a) Bring to front, as the reference does; (b) do not. Recommend (b): lock requests come from screen-lock scripts, where raising a window is noise.
- **D-APP09-3 Which forwarded files open.** (a) Only the reference's vault extension, as the reference does; (b) `.larsalvault` and that extension; (c) any regular file, format detection decides. Recommend (c): matches Finder opens and the open dialog (architecture: the open dialog accepts any file).
- **D-APP09-4** Decided (spec/decisions.md LD-47): Larsal has no single-instance setting, so this question is gone.
- **D-APP09-5 Channel format and limits.** The Larsal-internal JSON format and the limits of APP-09.13 (proposed numbers). The reference format has no limits.
- **D-APP09-6 Declared types.** `.larsalvault` as Owner, the reference's extension as Alternate, type ids as in APP-09.24 (placeholders, renamed with the product name, D1).
- **D-APP09-7 Drop on the main window.** (a) Open vault-extension drops, as the reference does; (b) refuse every drop except the attachment target, as AT-E06 read before LD-153. Recommend (a): opening only shows an unlock screen; AT-E06 now holds this exception.
- **D-APP09-8 Launch at login.** (a) The system login item service; (b) a launch agent file, as the reference does. Recommend (a): the current macOS way, and the user sees and controls it in System Settings.
- **D-APP09-9 Portable mode.** Not in Larsal on macOS: a signed bundle must not be changed, and the settings folder is fixed (AGENTS.md Naming).

### Not on Mac

- Windows: file arguments get the letter case they have on disk; the installer sets the file association; portable mode next to the program.
- Linux: the desktop entry passes one file per launch and declares a MIME type for the vault extension; settings live in the XDG folders; the lock and socket names carry the user name because the temporary folder is shared.
- Windows and Linux: "hide to the tray" also minimizes the window.
- All platforms: the reference's UI toolkit adds its own options (a help variant that lists toolkit options, platform, style, session and similar); Larsal has none.

## Security notes

- **SR-09:** one instance, a second launch focuses the first, and the command line can ask it to lock. Proof: test cases APP-09.8-a to APP-09.12-c.
- **The channel must never become a remote control.** Any process of the same user can connect. It may only open an unlock screen or lock (APP-09.14). Never add a request that unlocks, reads, copies or changes data, and never pass a password or key file through it (APP-09.10). A flood of requests is bounded by APP-09.13.
- **No secrets in arguments or the environment** (APP-09.18). F06 reads the password from stdin, into a secret type, after hardening (APP-09.1, APP-09.16; Rule 4 of AGENTS.md).
- **Opened files are hostile input.** Every path from Finder, the channel or a drop reaches only the unlock screen; the parser limits and attacks AT-A01 to AT-A12 apply. A path is never written to before the user unlocks and saves (APP-05, AT-I04).
- **No URL scheme** (APP-09.25): a web page cannot launch or drive Larsal.
- **Drop on the window:** AT-E06 allows the vault-file drop, which only shows an unlock screen (D-APP09-7, LD-153).
- **F07 lowers protection** for the whole run (APP-10.5, SC-05, AT-D04). A secondary launch cannot change it.
- **Hardening comes first** (APP-09.1, APP-11.1, SR-05).

## Test cases

Demo files for all cases: folder `/tmp/spec-app09/`; `a.larsalvault` (password `demo-pass-a`), `b.larsalvault` (password `demo-pass-b`), `k.larsalvault` (key file `k.larsalkey` only, no password), `c.` + the reference's vault extension (password `demo-pass-c`, made with the reference command line tool), `notes.txt` (text). `Larsal` stands for `Larsal.app/Contents/MacOS/Larsal`.

| Case | Given | When | Then |
|---|---|---|---|
| APP-09.1-a | No instance; a test build that logs each start-up step | `Larsal a.larsalvault` | Log order: hardening, flags, settings, files, instance, self-test, window, reopen, open, front; no file read before self-test |
| APP-09.2-a | Primary running, window minimized | `Larsal --bogus` | stderr names `--bogus` and points to `--help`; exit 1; primary window stays minimized |
| APP-09.2-b | No instance | `Larsal --key-file` | M09-09 for `--key-file`; exit 1; no window |
| APP-09.2-c | No instance | `printf 'demo-pass-a\n' \| Larsal --pw-stdin a.larsalvault` | Same as `--password-stdin`: `a` unlocked |
| APP-09.2-d | No instance; reopen setting off | `Larsal -- --lock` | `--lock` treated as a file name; no such file, dropped; window starts normally |
| APP-09.3-a | Any state | `Larsal --help` | stdout lists F01 to F11 (no aliases); exit 0; no window; primary (if any) not raised |
| APP-09.3-b | Any state | `Larsal --version` and `Larsal -v --help` | Both print `Larsal <version>` only; exit 0 |
| APP-09.4-a | Any state | `Larsal --debug-info` | stdout has version, build type, OS, CPU, kernel, features, crypto crates; no path, no setting value; exit 0; no window |
| APP-09.5-a | No instance | `Larsal --config /tmp/spec-app09/s1`; change the theme; quit | Change written to `/tmp/spec-app09/s1`; the normal settings file unchanged |
| APP-09.5-b | No instance | `LARSAL_CONFIG=/tmp/spec-app09/s2 LARSAL_CONFIG_LOCAL=/tmp/spec-app09/s3 Larsal` | The normal settings files are used; `s2` and `s3` are not created (LD-48) |
| APP-09.6-a | Primary started from `/` | `cd /tmp/spec-app09 && Larsal b.larsalvault` | Primary opens `/tmp/spec-app09/b.larsalvault` |
| APP-09.6-b | No instance; reopen setting off | `Larsal /tmp/spec-app09 /tmp/none.larsalvault` | Window starts with no vault added; no M09-07 |
| APP-09.7-a | Release primary running | `ls -l "$(getconf DARWIN_USER_TEMP_DIR)"` | `app.larsal.desktop.lock` and `app.larsal.desktop.sock` exist; socket mode `srw-------` |
| APP-09.8-a | Primary killed with `kill -9` | `Larsal` | New process is primary; no M09-05; one Larsal process |
| APP-09.8-b | A folder created at the lock file path | `Larsal a.larsalvault` | M09-06 on stderr and in an alert, naming the lock path and the reason; exit 1; no main window; `a` not opened; no socket created |
| APP-09.9-a | Primary stopped with `kill -STOP` | `Larsal a.larsalvault` | After about 1 s M09-05; exit 1; no second window; `pgrep -x Larsal` counts 1 |
| APP-09.9-b | Primary running; its settings file edited by hand to hold the reference-style single-instance value "off" | `Larsal b.larsalvault` | Value ignored; M09-01; exit 0; the primary shows `b`; one Larsal process |
| APP-09.10-a | Primary running, vault `a` open and locked | `Larsal b.larsalvault` | M09-01; exit 0; primary shows `b` unlock screen in front |
| APP-09.10-b | Primary running | `printf 'demo-pass-b\n' \| Larsal --password-stdin b.larsalvault` | M09-01; exit 0; `b` shown locked (password not forwarded); stdin not read (no M09-08) |
| APP-09.10-c | Primary running, minimized | `Larsal` | M09-01; exit 0; window restored and in front |
| APP-09.11-a | No instance | `Larsal --lock` | M09-04; exit 0; no window, no Dock icon |
| APP-09.11-b | Primary with `a` unlocked, stopped with `kill -STOP` | `Larsal --lock` | M09-05; exit 1 (not M09-04) |
| APP-09.12-a | Primary with `a` unlocked, window behind another app | `Larsal --lock b.larsalvault` | M09-02; exit 0; `a` locked; `b` not opened; window stays behind |
| APP-09.12-b | Primary running | Channel `open` with path `/tmp/spec-app09/c.` + reference extension | `c` unlock screen shown |
| APP-09.12-c | Primary running | Channel `open` with paths of `notes.txt` and `/tmp/spec-app09` | `notes.txt` added (unlock screen says not a vault); folder skipped silently |
| APP-09.13-a | Primary running | Send a 70,000-byte line with `nc -U` | Connection closed, no answer, nothing opened |
| APP-09.13-b | Primary running | Send `{"v":1,"cmd":"open","paths":["a.larsalvault"]}` | Closed without answer (relative path); nothing opened |
| APP-09.13-c | Primary running | Send `{"v":1,"cmd":"activate"}` | Answer `{"ok":true}`; window in front |
| APP-09.14-a | Unit test with a fake peer user id 501 vs own 502 | Connect | Closed before reading; no action |
| APP-09.15-a | `a` open and locked | `open /tmp/spec-app09/a.larsalvault` | No second entry; `a` becomes the shown vault |
| APP-09.15-b | `a` open | `open /tmp/spec-app09/A.LARSALVAULT` (same file, case-insensitive volume) | No second entry |
| APP-09.15-c | Primary running | Channel `open` for `/tmp/spec-app09/x.larsalvault`, deleted just before | Banner M09-07 naming the path |
| APP-09.15-d | No instance; recent list empty | `Larsal a.larsalvault` | `a` at the top of the recent list even before unlock |
| APP-09.16-a | No instance | `printf 'demo-pass-a\n' \| Larsal --password-stdin a.larsalvault` | stdout `Vault password: `; `a` unlocked; quick unlock not tried |
| APP-09.16-b | No instance | `printf 'demo-pass-a\r\n' \| Larsal --password-stdin a.larsalvault` | `a` unlocked |
| APP-09.16-c | No instance | `printf 'demo-pass-a \n' \| Larsal --password-stdin a.larsalvault` | Wrong-key message on `a` unlock screen (trailing space kept) |
| APP-09.16-d | No instance | `printf '\n' \| Larsal --password-stdin --key-file k.larsalkey k.larsalvault` | `k` unlocked with the key file alone |
| APP-09.16-e | No instance | `printf '\n' \| Larsal --password-stdin a.larsalvault` | `a` unlock screen shown; no unlock attempt, no error |
| APP-09.16-f | No instance | `printf 'demo-pass-a\n' \| Larsal --password-stdin a.larsalvault b.larsalvault` | `a` unlocked; second line empty, `b` unlock screen with no attempt |
| APP-09.16-g | No instance | `printf '\xff\xfe\n' \| Larsal --password-stdin a.larsalvault` | `a` unlock screen shown; no unlock attempt, no error (line not UTF-8, read as empty; unit test `app09_16_line_ends_go_nothing_else_is_trimmed`) |
| APP-09.16-h | No instance | 65,546 `x` then a line end, then `demo-pass-b` and a line end, piped to `Larsal --password-stdin a.larsalvault b.larsalvault` | Wrong-key message on `a` (65,536 `x` tried); `b` unlocked (the rest of the long line dropped; unit test `app09_16_one_line_per_call_and_long_lines_are_cut`) |
| APP-09.17-a | No instance | `printf 'demo-pass-a\n' \| Larsal --password-stdin --key-file /tmp/none.larsalkey a.larsalvault` | `a` unlock screen shows the key file error (APP-06) |
| APP-09.18-a | Code review and `Larsal --password x` | Run | Unknown flag, exit 1; no flag or environment variable takes a secret |
| APP-09.19-a | No instance | `printf 'demo-pass-a\nwrong\n' \| Larsal --password-stdin a.larsalvault a.larsalvault` | Two lines read; one entry `a`; the second attempt shows the wrong-key message |
| APP-09.20-a | Reopen on; last quit with `a` then `b` open, `b` shown | `Larsal k.larsalvault` | Entries `a`, `b`, `k`, all locked; `k` shown |
| APP-09.21-a | Menu bar icon on | `Larsal --minimized a.larsalvault` | No window visible; Larsal in the menu bar; `a` in the session |
| APP-09.21-b | Menu bar icon off | `Larsal --minimized` | Window minimized in the Dock |
| APP-09.22-a | Window hidden to the menu bar | Switch to Larsal with Cmd-Tab | Window shown, raised, key |
| APP-09.23-a | No instance | `open /tmp/spec-app09/a.larsalvault` | Larsal starts; `a` unlock screen |
| APP-09.23-b | Larsal running | Drop `a.larsalvault` and `b.larsalvault` on the Dock icon | Both added in that order; `pgrep -x Larsal` counts 1 |
| APP-09.24-a | Built bundle | `plutil -p Larsal.app/Contents/Info.plist` | Two document types: `larsalvault` (Editor, Owner) and the encoded extension (Editor, Alternate); exported type `app.larsal.desktop.vault` |
| APP-09.25-a | Built bundle | `plutil -p Larsal.app/Contents/Info.plist` | No URL types entry |
| APP-09.26-a | Main window showing `a` | Drag `b.larsalvault` onto it; then drag `notes.txt` | `b` unlock screen; `notes.txt` refused, nothing opened |
| APP-09.27-a | `a` unlocked, launched from Terminal | `kill -TERM <pid>` | Orderly quit as Quit (APP-02, APP-05); exit 0 |
| APP-09.27-b | Larsal launched from Terminal | Close the Terminal window (SIGHUP) | Larsal still running |
| APP-09.28-a | Launch at login off | Turn it on | Larsal listed in System Settings, Login Items; turning off removes it; checkbox matches the list |
| APP-09.29-a | Debug build running; release build running | Start the debug `Larsal` again | The second debug launch is a secondary of the first (M09-01, exit 0); debug-named lock and socket; the release copy is not contacted; launch-at-login checkbox disabled |

## How this was learned

- The reference window app's start-up routine: the flag list, their help texts, the order of steps, the early exits, the password-from-stdin loop and the start-minimized choice.
- The reference's application object: the lock file and local socket names and folder, the three 150 ms tries, the stale and failed-lock branches, the message framing and the two command numbers, the receiver's extension filter, the open-file and activation events, the signal handling and the self-relaunch.
- The main window's open, bring-to-front, hide, drop and lock-all routines, and the tab routine that opens a path (canonical path, already-open check, recent list, unlock with the given key).
- The settings screen's general tab (single instance, launch at login, minimize at start, reopen previous vaults) and its debug-build disabling; the settings defaults table; the settings file location routine (environment overrides, portable mode, debug suffix).
- The macOS utilities' launch-at-login routine.
- The bundle property list template, the Linux desktop entry and MIME file; the installed 2.7.11 bundle read with `plutil -p` (one document type, no URL types); `strings` on the installed window binary (same flags and messages as the source); the 2.7.11 tag compared with the source commit (same behavior except the debug-info lines and Windows-only items).
- The reference command line tool's `--help` and `--version` (its UI toolkit shows the same option handling). The window app was not launched.
- `getconf DARWIN_USER_TEMP_DIR` on this Mac (folder mode 0700; socket path length computed with python3).
