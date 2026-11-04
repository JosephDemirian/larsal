# E13-S6 part h: re-test of F-106, F-108, F-109, F-102, F-103, F-104, F-099, F-100, F-105

Story: E13-S6 part h ([plan/epics.md](../../plan/epics.md)). Rows: [security/findings.md](../findings.md). Earlier proof: [E13-S2 AT-H](E13-S2-AT-H.md) (F-H1 = F-106, F-H2 = F-108, F-H4 = F-109), [E13-S2 AT-E](E13-S2-AT-E.md) (RT-E-2 = F-102, RT-E-3 = F-103, RT-E-4 = F-104, RT-E-5 = F-105), [E13-S2 AT-B](E13-S2-AT-B.md) (RT-B2 = F-099, RT-B3 = F-100). Ruling: LD-225 (1).

## Round 2 (Verify, after the F-103 fix)

Date: 2026-10-29 (the runs took place from 10:53 to 11:20 on 2026-10-30 by the Mac's clock). Role: Verify, round 2. I did not find, build or check these fixes.

| Finding | Result | One line |
|---|---|---|
| F-106 (Medium) | **fixed, re-tested** | The row's steps through the session again: after the switch to B, the lock and the turn-off leave A empty; with A stopped, MI06-19 names the key. Mutant M1 gives the red team's result back. |
| F-108 | **fixed, re-tested** | The 5 f_108 tests pass. Mutant M2 asks the silent agent 3 times; mutant M3 makes the lock wait 2.0 s. Both fail. |
| F-109 | **fixed, re-tested** | 5 runs of `agent` and 2 runs of `own_agent` at load average 17 to 18: 0 failures. Mutant M4 fails f_109. |
| F-102 (Medium) | **fixed, re-tested** | `f102EditorShowLeavesNoCopy` passes. The mutant (the field for every Show) leaves 3 UTF-8 copies and fails. Round 1's residual still stands. |
| F-103 (Medium) | **fixed, re-tested** | All 13 types that failed round 1 now ask first. Of the 1,369 extensions LaunchServices knows on this Mac, exactly the listed ones ask. No system app that runs, mounts, installs or opens a URL has an unlisted extension. |
| F-104 | **fixed, re-tested** | f_104 passes. Mutant M6 (the type test first) gives `Ok(AskFirst)` for vault id 0 and fails. |
| F-099 | **fixed, re-tested** | 3 release runs give cropped t 0.09, -1.92 and -0.35. Mutant M7 gives -18.18 and fails. |
| F-100 | **fixed, re-tested** | 4 probes (2 Rust, 2 Swift) each make `cry_03_t11` fail. Mutant M8b fails f_100. bans ok. |
| F-105 | **fixed, re-tested** | Both texts still name the agent socket. The socket is 0600 in a 0700 folder, with no internet socket, and it is gone after turn-off. |

All 9 rows are fixed and re-tested. Verdict: **signed (9 re-tested)**.

### Round 2 setup

- **What changed since round 1.** Only F-103's files: `crates/app-core/src/attachments.rs` (10:33), `crates/app-ffi/tests/edit.rs` (10:33) and the new `macos/AppTests/AttachmentKindsTests.swift` (10:46). Every other part h file is older than round 1's copy (09:49), and round 1 found the copy and the tree equal: keyring.rs, sshagent tests, app-ffi ssh.rs and edit.rs, secret.rs, write_version.rs, EditorEntryPage.swift, ShownPasswordField.swift, deny.toml and the two plan texts. So for those 8 rows I re-ran the tests and one or two mutants each, and I re-ran F-106's and F-105's steps.
- **Shared tree, own target** `/tmp/e13s6h-verify-target`: `env -u SSH_AUTH_SOCK cargo test --locked -p app-sshagent -p app-ffi -p app-core -p app-format -p app-crypto` gave 81 suites, 2,093 passed, 0 failed, 51 ignored. These named tests are `ok`:
  - own_agent: `f_106_…`, `f_108_a_silent_agent_costs_the_lock_one_wait_not_one_per_key`, `f_108_an_add_running_at_the_lock_leaves_too`, `f_108_a_key_added_again_before_the_removals_stays`;
  - agent: `f_109_…`;
  - app-ffi ssh: `f_108_a_silent_agent_never_holds_the_lock`, `f_108_quit_waits_for_the_locks_removals`;
  - app-ffi edit: `f_103_every_type_that_runs_or_acts_asks_first`, `f_104_…`;
  - write_version: `f_100_…`, `cry_03_t11_one_random_source`;
  - app-core `e4_b1_no_plain_copies_of_values`.
- **Private copy.** `rsync -a --exclude target --exclude app-shots --exclude fuzz/target` to `/tmp/e13s6h-verify-copy` at 10:54. It had its own targets: `/tmp/e13s6h-verify-ctarget` for `scripts/build-core.sh` (exit 0), `/tmp/e13s6h-verify-mtarget` for the harness and the mutants, and DerivedData `/tmp/e13s6h-verify-dd`. `xcodebuild … build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` gave TEST BUILD SUCCEEDED. The copy-only harness was `verify_f103_round2_every_registered_extension` (tests/edit.rs) and `verify_r2_f106_red_team_steps` and `verify_r2_f105_agent_socket` (tests/ssh.rs). Each mutant was restored from the tree and checked with `cmp`.
- **LaunchServices.** I used `lsregister -dump` (reads the database), then small Swift tools in `/tmp/e13s6h-verify-scripts`. They call `NSWorkspace.urlForApplication(toOpen:)` and `UTType` on empty demo files, and read apps' Info.plist. Nothing was opened.
- **Lint.** `rustfmt --check` on the part h files: exit 0. `cargo fmt --check` on the 5 crates only reports `app-ffi/src/reports.rs` and `window.rs`, which another agent edited at 11:09 (not part h). `cargo clippy --locked --all-targets -p app-core -p app-ffi -p app-sshagent -p app-crypto -p app-format -- -D warnings`: exit 0. SwiftLint 0.65.1 `lint --strict` and `swift-format lint --strict` on AttachmentKindsTests.swift: exit 0. `scripts/check-names.sh`: names PASS.
- **Rules.**
  - Demo data only: option-a-personal, the INT-06 demo keys, and keys made by `ssh-keygen` in /tmp.
  - The SSH runs used `env -u SSH_AUTH_SOCK` and throwaway agents, each stopped by its PID.
  - The AppTests ran without a host app, with windows offscreen.
  - Open copies made by the tests are wiped by the session. The one file left in the user's `App/open-attachments` folder is dated 10:02, before my run, so it is not mine and I left it alone.

### F-103 (Medium), round 2: the ask-first list

- **Steps.**
  1. RT-E-3's repro and the 13 of round 1 through `open_attachment(vault, name, false)` in GitHub's editor of a Personal copy. Mixed case too: DEMO.SHTM, demo.XHTM, demo.Udif, demo.WEBBOOKMARK, demo.NetworkConnect.
  2. Every extension LaunchServices knows on this Mac: 1,369, from the `tags:` and `bindings:` lines of `lsregister -dump`. Each one goes through the list, and each listed one through `open_attachment`.
  3. Each extension's default app (empty demo file), and each acting system app's document types expanded to extensions (`CFBundleTypeExtensions` plus `LSItemContentTypes` → `UTType` tags).
  4. Each extension's types, all of them (`UTType.types(tag:tagClass:conformingTo:)`, not only the preferred one), against the quarantine list's types. Then each unlisted extension's types against each listed extension's type.
  5. The new AppTest and the f_103 test, with mutants.
- **Before (round 1).** 13 types opened without asking: shtm, xhtm, jhtml, xslt, xbl, asif, udif, dvdr, dmgpart, nslloc, webbookmark, networkconnect and internetconnect.
- **After.**
  - All 13 give `AskFirst`, and so do the mixed-case names. x.term, x.xhtml, x.terminal, x.html, demo.p\u{212A}g and DEMO.SHTML give `AskFirst`; x.txt gives `Opened`.
  - Of the 1,369, 95 calls asked first (84 registered listed types plus the 11 extra names) and 1 opened (x.txt). The set that asks is exactly the listed set. icp, x11app and ipg are listed but not registered on this Mac.
  - Default apps: every extension whose default is Terminal, Script Editor, Automator, Automator Installer, Installer, iOS App Installer, JavaLauncher, DiskImageMounter, System Settings, Shortcuts, Screen Sharing, RegisterPluginIMApp, SystemUIServer or Safari is listed. Finder's are listed except clippings and saved searches. The default browser here is Dia, and its html, htm, shtml, shtm, xhtml, xht and xhtm are all listed.
  - Document types: Terminal, System Settings, DiskImageMounter, Automator, Installer, JavaLauncher, Shortcuts and the installers have no unlisted extension. Every Default or Owner type in Safari's Info.plist is listed: web archive, bookmark, history, webloc, download, extension, HTML, url, XHTML and XML. Safari's js, css and images are Alternate.
  - The unlisted system defaults are all kinds that import or show content: Archive Utility's archives, Keychain Access's certificates, ProfileHelper's profiles, Calendar, Contacts, Mail, Font Book, Pass Viewer, Finder clippings, System Information, Software Update's sucatalog and VoiceOver's voprefs. The system's own list (CoreTypes `System`, `LSRiskCategorySafe`) names mobileconfig, configprofile, provisionprofile, ics and vcard as safe, which supports the builder's choice to leave them out.
- **Mutants** (private copy; each type was swapped for a word that matches nothing):
  - AttachmentKindsTests failed for: dvdr out (`["cdr: dvdr", "toast: dvdr"]`); xslt out (`["xbl: xslt", "xsl: xslt"]`); internetconnect out (`["networkconnect: internetconnect"]`); shtm out (`["htm: shtm", "html: shtm", "shtml: shtm"]`). nslloc out passes the AppTest, because it is in its own Finder type.
  - f_103 failed at edit.rs:605 for: nslloc out (`demo.nslloc` gave Opened), bash out and download out.
- **Not counted, for the lead.**
  1. dist and distz (`com.apple.installer-distribution-package`, on the quarantine list), and placeholder and remoteplaceholder (application placeholders under `com.apple.application`). These are bundle types. As a plain file, .dist gets no default app, and .placeholder is treated as an app itself, as .app and .service are, which a flat file cannot be. Round 1's conformance check used only each extension's preferred type, so it missed them. Listing them would add 4 words.
  2. py, pl, pm, rb, rbw, php, ph3, ph4, php3, php4 and phtml conform to `public.shell-script`, the same reason the builder gave for bash, zsh, csh, ksh and tcsh. Here they open in Xcode, an editor, like sh. The ruling does not require them, but they would make the shell rule consistent (11 words).
  3. ite and itlp (TV and Music packages that conform to `public.html`) are legacy bundle types. A single-file attachment cannot be one.

### F-106, F-108, F-109, F-102, F-104, F-099, F-100, F-105, round 2

- **F-106.**
  - Steps: copy-only `verify_r2_f106_red_team_steps`. Throwaways A and B, and K1e with remove-on-lock. Unlock with A, then `set_ssh_agent(true, B)` (what Settings > OK calls through `save_settings`). Lock, then wait 1 s. Next, the turn-off in the same change as the switch. Last, A stopped after the switch.
  - Before (red team): A kept the key and there was no banner.
  - After: `step 1: A 1 keys, B 0 keys`; `lock after switch, 1 s later: A 0 keys, B 0 keys, banner None`; `off with switch: A before 1, after 0 keys`; `A stopped: … banner Some("App couldn't take the key of “Server root · web-01” out of the SSH agent. …")`.
  - Mutant M1 (records follow the setting): the harness shows `A 1 keys` after the lock and after the turn-off, with `banner None` (the red team's result). f_106 FAILED at own_agent.rs:795 ("lock: the key stayed in A").
- **F-108.** The 5 f_108 tests pass on the tree. M2 (no failed-agent cache) FAILED at own_agent.rs:880 ("the silent agent was asked again", 3). M3 (the lock joins its removal thread) FAILED at ssh.rs:394 ("the lock waited: 2.002188s"). Round 1's red team harness (38 µs lock; quit 2.03 s) ran on the same keyring.rs and ssh.rs.
- **F-109.** f_109 passes. At load average 17 to 18 from other agents, `agent` passed 5 of 5 runs (25 passed each) and `own_agent` 2 of 2 runs (38 passed each). M4 (`answers` does not wait) FAILED at agent.rs:561 ("returned before the agent listened: 667ns").
- **F-102.** In the copy, `EditorMemoryTests/f102EditorShowLeavesNoCopy` passed (with AttachmentKindsTests: 2 tests, 2 suites passed). The mutant `if let shown = editor.shownPassword {` (the field for every Show) was rebuilt and FAILED at EditorMemoryTests.swift:204: "copies after lock and close: 3 UTF-8, 0 UTF-16". Round 1's residual still stands: a press into the shown password makes the field, and 3 copies stay. The check of Tab and click in a visible window is Mac QA (owner's go).
- **F-104.** f_104 passes. M6 (the type test before the vault, editor and name checks) FAILED at edit.rs:616: `left: Ok(AskFirst)`, `right: Err(UnknownVault)` for id 0. `open_attachment` is still the only caller of `risky` (edit.rs:2482).
- **F-099.** The tree's `f_099` was run alone in release 3 times: cropped t 0.09, -1.92 and -0.35, all ok against a bound of 5. M7 (`fold_eq` back to `subtle`'s slice compare, release) FAILED with cropped t -18.18.
- **F-100.**
  - `cargo deny --frozen check bans`: bans ok.
  - Probes in the copy, each against `cry_03_t11`, each FAILED and named the word and the file:
    - RT-B3's `libc::arc4random_buf` line in app-cli zone.rs;
    - `RandomState::new()` in zone.rs;
    - `SecRandomCopyBytes(…)` in AppMain.swift;
    - `drand48()` in AppMain.swift.
  - M8b (f_100's Swift check with no words) FAILED at write_version.rs:800 on `Int.random(in: 0..<10)`.
  - Restored: write_version 33 passed.
- **F-105.** plan/attacks-and-checks.md:68 and plan/security.md:95 still name App's own agent socket of INT-06.32. Copy-only `verify_r2_f105_agent_socket`: `socket mode 140600 uid 501; folder 40700; lsof -U lines naming agent.sock: 1; lsof -i lines: 0`; after turn-off, `socket exists: false`.

## Round 1

Date: 2026-10-29 (the runs took place from 09:49 to 10:25 on 2026-10-30 by the Mac's clock). Role: Verify, round 1. I did not find, build or check these fixes.

| Finding | Result | One line |
|---|---|---|
| F-106 (Medium) | **fixed, re-tested** | The red team's own steps through `save_settings`: after the switch to B and the lock, A is empty after 1 s (before: A still held the key). The turn-off in the same OK empties A too. With A stopped, MI06-19 names the key. |
| F-108 | **fixed, re-tested** | A proxy that never answers a remove, 3 marked keys and 1 asking key: `Session::lock` returns in 38 µs (before: 6.0 s). `lock_all` and `close` take 39 to 41 µs. App's own key is gone at once, and one 2 s wait covers all 3 keys. |
| F-109 | **fixed, re-tested** | The helper now waits until the agent answers. Under 24 extra busy processes (load average up to 82), 10 runs of `agent` and 3 runs of `own_agent` had 0 failures. |
| F-102 (Medium) | **fixed, re-tested** | RT-E-2's own steps (a rich-v4 copy with "E07 entry", its random password made in another process): 0 copies after lock and after close (before: 1). One residual for the lead: a press into the shown password makes the field, and 3 copies stay. |
| F-103 (Medium) | **re-test failed** | RT-E-3's repro now asks first. But 13 more types that this Mac's own apps open in the browser, Safari, Finder, System Settings or DiskImageMounter still open without asking. 5 of them have the very same type as a listed extension: shtm, xhtm, asif, udif, dvdr. |
| F-104 | **fixed, re-tested** | The red team's calls now answer `UnknownVault` for ids u64::MAX, 0 and 999999, `UnknownField` for a missing name and `Locked` for a locked vault (before: `Ok(AskFirst)`). |
| F-099 | **fixed, re-tested** | RT-B2's 8 classes: the fixed compare stays within \|t\| 2.23. The old `subtle` slice compare, run in the same process as the control, reaches \|t\| 70 at byte 8 and later. |
| F-100 | **fixed, re-tested** | RT-B3's arc4random line and 7 more probes now make `cry_03_t11` fail. Calls the word list does not name are listed for the lead. |
| F-105 | **fixed, re-tested** | The AT-E08 row and SR-15 now name App's own agent socket. That socket is a Unix listener, 0600 in a 0700 folder, with no internet socket, and it is gone after turn-off. |

8 of the 9 rows are fixed and re-tested. F-103 failed its re-test: the fix follows RT-E-3's list instead of the ruling's rule (macOS's own kinds), so it misses sibling types. Verdict: **failed (1)**.

## Setup

- **Private copy.** `rsync -a --exclude target --exclude app-shots --exclude fuzz/target` to `/tmp/e13s6h-verify-copy`, made at 09:49. It had its own targets: `/tmp/e13s6h-verify-ctarget` for `scripts/build-core.sh`, `/tmp/e13s6h-verify-mtarget` for my harness and the mutants, and DerivedData `/tmp/e13s6h-verify-dd`. At the end, `cmp` showed these files equal in the tree and the copy: keyring.rs, app-ffi ssh.rs and edit.rs, attachments.rs, secret.rs, write_version.rs, the sshagent tests common/mod.rs, own_agent.rs and agent.rs, app-crypto tests/secret.rs, ShownPasswordField.swift, EditorEntryPage.swift, MainWindowModel.swift, deny.toml, plan/attacks-and-checks.md, plan/security.md, app-platform lib.rs, app-cli zone.rs and AppMain.swift. So nothing in part h changed during my run.
- **Harness, copy only.** These files are deleted with the copy:
  - appended to `crates/app-ffi/tests/ssh.rs`: `verify_f106_red_team_steps`, `verify_f108_red_team_steps`, `verify_f105_agent_socket_listener`;
  - appended to `crates/app-ffi/tests/edit.rs`: `verify_f104_red_team_calls`, `verify_f103_red_team_repro_and_probes`;
  - new: `crates/app-ffi/tests/verify_e07.rs` (RT-E-2 step 1, in its own process), `crates/app-crypto/tests/verify_f099.rs` and `macos/AppTests/VerifyE13S6hTests.swift`;
  - in the copy's `EditorMemoryTests.swift`, `MaskedNeedle.init(masked:mask:)` lost its `private`, so my test can build the needle from the other process's masked bytes.
- **LaunchServices queries.** Swift scripts in `/tmp/e13s6h-verify-scripts` ask `NSWorkspace.urlForApplication(toOpen:)` and `UTType` about empty demo files. Nothing was opened.
- **Shared tree, own target** (`/tmp/e13s6h-verify-target`, `--locked`):
  - `cargo test --locked -p app-sshagent -p app-ffi -p app-core -p app-format -p app-crypto`: 81 targets, 2,093 passed, 0 failed, 51 ignored (09:52 to 09:55).
  - Every named part h test is `ok`:
    - own_agent: `f_106_keys_leave_the_agent_they_went_to_after_the_socket_changed`, `f_108_a_silent_agent_costs_the_lock_one_wait_not_one_per_key`, `f_108_an_add_running_at_the_lock_leaves_too`, `f_108_a_key_added_again_before_the_removals_stays`;
    - agent: `f_109_the_throwaway_helper_waits_until_the_agent_answers`;
    - app-ffi ssh: `f_108_a_silent_agent_never_holds_the_lock`, `f_108_quit_waits_for_the_locks_removals`;
    - app-ffi edit: `f_103_every_type_that_runs_or_acts_asks_first`, `f_104_open_attachment_checks_the_vault_and_the_name_before_it_asks`;
    - write_version: `f_100_the_guard_catches_the_systems_own_random_calls`, `cry_03_t11_one_random_source`;
    - app-crypto secret: 10 passed; the ignored `f_099_…` test was run in release (see F-099).
- **Swift in the copy.**
  - `scripts/build-core.sh`: exit 0.
  - `xcodebuild -project macos/App.xcodeproj -scheme App -destination 'platform=macOS' -derivedDataPath /tmp/e13s6h-verify-dd build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`: TEST BUILD SUCCEEDED.
  - Then `test-without-building -only-testing:AppTests/VerifyE13S6hTests -only-testing:AppTests/EditorMemoryTests`.
- **Rules.**
  - Demo data only: option-a-personal (demo-pass-7), a rich-v4 copy (demo-pass-5) in `/tmp/e13s6h-verify-run`, the INT-06 demo keys and keys made by `ssh-keygen` in /tmp.
  - The SSH tests ran under `env -u SSH_AUTH_SOCK`, against throwaway `ssh-agent -D` processes stopped by their PID (the shared helper).
  - AppTests ran without a host app. Windows were offscreen at (-20000, -20000) and never ordered front. No window, focus, key events or general pasteboard.
  - The 24 `yes` load processes were stopped by their PIDs.
  - At the end, `pgrep -fl ssh-agent` shows only the system's `/usr/bin/ssh-agent -l` and another agent's `/tmp/spec-int05-07` agent, and no `/tmp/e9s1-*` folder is left.

## F-106 (Medium): the lock removes the key from the agent it went to

- **Steps (F-H1, demo data).** Two throwaway agents, A and B. A vault with one entry: K1 (Ed25519) in attachment `id_key`, with Allow, Add on unlock and remove-on-lock on. Then:
  1. A `Session` with App's agent socket in /tmp; `save_settings` with `ssh.enabled` on and `ssh.socket_override` A; unlock; `SSH_AUTH_SOCK=A ssh-add -l`.
  2. `save_settings` with `ssh.socket_override` B (Settings > OK).
  3. Lock, then wait 1 s; `ssh-add -l` on A and on B, and `take_banner()`.
  4. The same with `ssh.enabled` off and the override B in one `save_settings`.
  5. The same again with A stopped (by its PID) after the switch to B.
  - The test is copy-only `verify_f106_red_team_steps`.
- **Before** (red team): after the lock, A still listed the key, B was empty and there was no MI06-19. The turn-off left the key in A too.
- **After.**

  ```
  step 3: A lists: "256 SHA256:R3aMsbAq88Fv8wlNcuy3oN+ZIl7yqPd3lRkAP/AP+uc demo@app (ED25519)"
  step 6 (after 1 s): A "The agent has no identities."; B "The agent has no identities."; banner None
  off (after 1 s): A "The agent has no identities."; banner None
  A stopped: banner Some("App couldn't take the key of “Server root · web-01” out of the SSH agent. Use Remove All Keys from SSH Agent… to clear it.")
  ```
- **Mutant M1** (records follow the setting again: `set_agent_settings` points every system record at the new socket):
  - own_agent `f_106_…` FAILED at own_agent.rs:795;
  - my `verify_f106_red_team_steps` FAILED, with "step 6 (after 1 s): A "256 SHA256:R3aMsbAq88… demo@app (ED25519)"", which is the red team's result.
- **Code read.** `Record.agent` is set by `load_held`. `remove_from_system` (lock, `remove_left`, `turn_off`) and `unload` use it, not `system_agent()`. A second load after the switch removes the key from the old agent first (R06-5). A record of App's own agent has `None` and is skipped there.

## F-108: a silent system agent never holds the lock

- **Steps (F-H2, demo data).** A proxy in front of a throwaway agent passes every message on, except remove (18), which it reads and never answers. The vault has 3 remove-on-lock keys (K1e with its passphrase, a P-256 key and an Ed25519 key) and 1 key with "Ask before each use". Then:
  1. Unlock, `ssh_settled`.
  2. Time `Session::lock(id)`.
  3. Read App's own agent's list at once and the vault's lock state.
  4. `ssh_settled`, then count the removes the proxy saw and read the banner.
  - The same for `lock_all` and `close`, and quit as the window does it (`lock_all`, then `stop_ssh_agent`).
  - The test is copy-only `verify_f108_red_team_steps`.
- **Before** (red team): `Session::lock` returned after 6.0 s (2 s per key) on the window's main thread. App's own key was gone at 52 ms.
- **After.**

  ```
  lock:     before system 3 own 1; returned in 37.792µs; own after 0; locked true; removals settled at 2.002239958s; removes sent 1; banner names all 3 keys
  lock_all: returned in 38.875µs; own after 0; locked true; settled at 2.002215209s; removes sent 1
  close:    returned in 41.417µs; own after 0; locked true; settled at 2.002252292s; removes sent 1
  quit:     lock_all 38.125µs, stop_ssh_agent returned at 2.032544792s; banner names all 3 keys
  ```
  The window calls `session.lock`, `session.lockAll` and `session.close` on the main thread (MainWindowModel.swift:183, :211, :230), so it never waits for the agent. Quit waits once (INT-06.25), so App never ends before the removals.
- **Mutants**, each in the copy, each FAILED:
  - M2 (no failed-agent cache): own_agent `f_108_a_silent_…` at :880. My harness showed "removes sent 3", settled at 6.004 s;
  - M3 (the lock waits for its thread): `f_108_a_silent_agent_never_holds_the_lock` at ssh.rs:394. My harness showed "returned in 2.002125041s";
  - M3b (quit does not join): `f_108_quit_waits_for_the_locks_removals` at ssh.rs:432;
  - M3c (no late leave): `f_108_an_add_running_at_the_lock_leaves_too` at own_agent.rs:935;
  - M3d (no is-recorded filter): `f_108_a_key_added_again_before_the_removals_stays` at own_agent.rs:961.
- **Brief note.** The brief names a LockSignalsTests `lockAllWhileMainIsBusy` test as possible F-108 work. That helper serves APP-09.12 (`channelLock`), not F-108. F-108 needs no Swift change, because the Rust calls the window makes no longer wait.
- **Left for the lead (not F-108's path).** Turning the feature off in Settings (`set_ssh_agent(false)` through `save_settings`) still runs `turn_off` on the caller's thread. With a silent agent, that is one 2 s wait (one, thanks to the cache), not one per key.

## F-109: the throwaway helper waits until the agent answers

- **Steps.**
  - `f_109_the_throwaway_helper_waits_until_the_agent_answers` on the tree.
  - Then the finding's own condition, load: 24 `yes` processes (stopped by PID afterwards), 10 runs of the tree's `agent` test binary and 3 runs of `own_agent`.
- **Before** (red team): at load average 160 to 250, `agent` failed 2 of 24 once (`Unreachable { …, why: Connect }` at a fresh throwaway).
- **After.**
  - f_109: ok.
  - Under load (load average 15.9 at the start, 81.9 at the end): `agent` 10 of 10 runs `25 passed; 0 failed`; `own_agent` 3 of 3 runs `38 passed; 0 failed`.
- **Mutant M4** (`answers` waits for the socket file only): f_109 FAILED at agent.rs:561.

## F-102 (Medium): the editor's Show leaves no copy after lock and close

- **Steps (RT-E-2, demo data).**
  1. `verify_e07.rs`, in its own process, copies rich-v4 and adds "E07 entry" with a random 26-character password from app-crypto random. It saves the vault and writes only the XOR-masked bytes and the mask.
  2. The AppTest `VerifyE13S6hTests/rtE2Steps` uses `ParityDemo.session()`, opens and unlocks the copy (demo-pass-5) and renders `MainWindow` offscreen (`Screen`).
  3. It selects "E07 entry", `main.edit()`, `editor.toggleShowPassword()` twice, `main.cancelEditor()`, `window.lock(id)`, `window.close(id)`.
  4. It scans the process's own memory with the red team's method (`MemoryScan`: `mach_vm_region_recurse`, `mincore`, `mach_vm_read_overwrite`).
  - The builder's `EditorMemoryTests/f102EditorShowLeavesNoCopy` ran in the same run.
- **Before** (red team): 1 UTF-8 copy after lock and after close.
- **After.** `VERIFY RT-E-2: unlocked 1, editor shown 6, hidden 3, after lock 0 (utf16 0), after close 0 (utf16 0)`. Both tests passed.
- **Mutant** (the field for every Show: `if let shown = editor.shownPassword {`): "after lock 3 (utf16 0), after close 3"; both tests FAILED (f102 at EditorMemoryTests.swift:204: "3 UTF-8, 0 UTF-16"). After restoring (`cmp` equal to the tree), both passed again.
- **Residual, for the lead.** Copy-only test `rtE2EditPath`: Show, then an accessibility press on the shown password (what a click or Tab does). That makes the no-copy field, and the field takes the focus. Then Hide, Cancel, lock and close: `field made true; after lock and close 3 UTF-8`. So a user who clicks into a shown password, even without typing, leaves AppKit's copies after lock. The builder already listed this as open: a plain NSTextField leaves the copy too.

## F-103 (Medium): the ask-first list

- **Steps.**
  1. RT-E-3's repro: attach demo files to GitHub's editor in a Personal copy, then `open_attachment(vault, name, false)` for x.term, x.xhtml, x.terminal, x.html, demo.p\u{212A}g, DEMO.SHTML and x.txt (copy-only `verify_f103_red_team_repro_and_probes`).
  2. An independent LaunchServices query on this Mac:
     - every extension declared by the system's and the installed apps' type declarations and document types (1,326 resolved);
     - each one's `UTType` conformance to the system quarantine list's types (CoreTypes.bundle `System`);
     - its default app;
     - for each listed extension, the other extensions of the same `UTType`;
     - odd spellings.
  3. `open_attachment` for each type the query found.
- **Before** (red team): x.term and x.xhtml returned `Opened`, without asking.
- **After, the repro:** x.term, x.xhtml, x.terminal, x.html, demo.p\u{212A}g and DEMO.SHTML give `AskFirst`; x.txt gives `Opened`. Mutants M5 (the card's 18 only) and Ma (ASCII-only case) each FAILED f_103 at edit.rs:576.
- **After, the conformance check:** every declared extension that conforms to a type of `LSRiskCategoryUnsafeExecutable` or of the installer and ipa types of `LSRiskCategoryMayContainUnsafeExecutable` is on the list: app, class, command, dylib, ipa, jar, jnlp, mpkg, pkg, qtz, term, terminal, tool, war, webarchive. None is missing. Odd spellings ("command " with a trailing space, a zero-width space, a no-break space, a Cyrillic "а") resolve to no app.
- **Failed: same kind of default app, not on the list.** Each name was checked on an empty demo file (`urlForApplication(toOpen:)`, nothing opened), then sent to `open_attachment(…, false)`:

  | Extension | Type on this Mac | Default app | Listed sibling | `open_attachment` |
  |---|---|---|---|---|
  | shtm | public.html (the same type as html, htm, shtml) | the default browser | html, htm, shtml | Opened |
  | xhtm | public.xhtml (the same type as xhtml, xht) | the default browser | xhtml, xht | Opened |
  | jhtml | Safari's "HTML document" with html, htm, shtml | Safari | html | Opened |
  | xslt, xbl | Safari's "XML document" with xsl | Safari | xsl | Opened |
  | asif | com.apple.disk-image-sparse (the same type as sparseimage) | DiskImageMounter | sparseimage | Opened |
  | udif | com.apple.disk-image-udif (the same type as img, dmg) | DiskImageMounter | img, dmg | Opened |
  | dvdr | com.apple.disk-image-cdr (the same type as cdr) | DiskImageMounter | cdr | Opened |
  | dmgpart | com.apple.disk-image-udif-segment | DiskImageMounter | dmg | Opened |
  | nslloc | Finder's "NSL Internet Location" | Finder | afploc, ftploc, atloc | Opened |
  | webbookmark | com.apple.safari.bookmark | Safari | webloc | Opened |
  | networkconnect, internetconnect | com.apple.preference.network, System Settings' "Internet Connect Document" (Editor) | System Settings | (none: it acts) | Opened |

  An HTML or XHTML copy opened in the browser runs its scripts, as .html does. A disk image mounts, as .dmg and .iso do. The 13 rows are in the very apps and kinds the fix's own doc comment names ("the browser, Safari, … Finder's server … links, … the disk image mounter"). LD-225 (1) asks the list to follow macOS's own kinds, but the fix took RT-E-3's examples, so it misses their siblings. Checker 1 sent back dylib and war for the same reason (types that conform to a listed one).
- **Smallest fix.** Add the 13 (shtm, xhtm, jhtml, xslt, xbl, asif, udif, dvdr, dmgpart, nslloc, webbookmark, networkconnect, internetconnect) to `attachments::risky`, and add them to f_103. A guard that stops the next miss: an AppTest that, for each listed extension, asks `UTType(filenameExtension:)` for its type's other extensions and expects each to be listed (5 of the 13 are of that kind).
- **For the lead, not counted in the failure.**
  - On this Mac, .xml opens in Xcode, but Safari claims .xml as "XML document" Viewer (Default). On a Mac without Xcode, .xml may open in Safari, as xsl does.
  - Third-party apps add more: Chrome's .crwebloc opens a URL like .webloc; Claude's .dxt and .mcpb install an extension. The ruling limits the list to macOS's own types.
  - Archives (zip, tar, gz and others: Archive Utility) conform to `public.archive` on `LSRiskCategoryMayContainUnsafeExecutable`, but so do docx and epub, so leaving them out is reasonable.

## F-104: open_attachment checks the vault and the name before the type

- **Steps (RT-E-4).** `Session::new().open_attachment(v, name, false)` for v = u64::MAX, 0, 999999 and name = "x.command", "x.txt". Then, in a Personal copy: no editor; "missing.command" and "missing.txt" in GitHub's editor; the vault locked (copy-only `verify_f104_red_team_calls`).
- **Before** (red team): `Ok(AskFirst)` for "x.command" with each id, a locked vault and a missing name; `Err(UnknownVault)` for "x.txt".
- **After.** All six id calls give `Err(UnknownVault)`. With no editor the answer is `Err(Refused("The editor is not open."))`. Both missing names give `Err(UnknownField)`, and the locked vault gives `Err(Locked)`.
- **Mutant M6** (the type test first): `f_104_…` FAILED at edit.rs:587, and my test FAILED with `open_attachment(18446744073709551615, "x.command", false) = Ok(AskFirst)`.
- **Code read.** `open_attachment` (edit.rs:2466) runs `with_draft` and `attachments::find` before `attachments::risky`. It is the only caller of `risky`.

## F-099: the byte compare's time does not depend on where tags differ

- **Steps (RT-B2's classes).** Copy-only `verify_f099.rs`, in release: want is 32 bytes of 0x5A, with classes equal and a flip at byte 0, 1, 8, 16, 24, 30 and 31. Each sample is a batch of 256 calls on one fixed buffer, 60,000 batches per class, in random class order. Welch t against byte 0, after cropping the slowest 10%. The fixed `ct_eq` runs twice, with `subtle`'s slice compare (the old code) as the control in between. Also the tree's ignored test `f_099_compare_time_does_not_depend_on_where_tags_differ`, 3 runs (`--release -- --ignored`).
- **Before** (red team): byte 8 and later were about 0.2 ns slower, with cropped t -5.9 to -36.
- **After.** These ran at load average 15 to 17 from other agents.
  - Tree test: cropped t -2.31, -2.96, 1.77, all ok (bound 5).
  - RT-B2 classes, run 1: fixed worst \|t\| 2.23 and 1.76; control: byte 8 t -55.31, byte 16 -62.46, byte 24 -57.97, byte 30 -59.82, byte 31 -69.89.
  - Run 2: fixed 1.32 and 2.00; control -5.47 to -6.53 at byte 8 and later.

  So the measurement still sees the old step on this Mac, and the fix removes it.
- **Mutant M7** (`fold_eq` back to `subtle`'s slice compare): f_099 FAILED twice, with cropped t -36.35 and -42.41.
- **Code read.** `ct_eq`, `SecretBytes` and `SecretString` equality all go through `fold_eq`. `mac.rs:95` (HMAC verify), `integrity.rs`, `hashed_blocks.rs`, `payload.rs:385`, `read.rs:1857` and `keys.rs:256` all use `secret::ct_eq`.

## F-100: the one-random-source guard

- **Steps (RT-B3).**
  1. `cargo tree --offline --locked -p app-ffi -e normal -i getrandom` and `-i fastrand`, and `cargo deny --frozen check bans` on the tree.
  2. In the copy, RT-B3's own line `pub fn rt_b3_probe(buf: &mut [u8]) { unsafe { libc::arc4random_buf(buf.as_mut_ptr().cast(), buf.len()) } }`, then `cry_03_t11`.
  3. More probe lines, one at a time.
  4. Mutants of the word lists.
- **Before** (red team): the arc4random line passed `cry_03_t11`, and no guard read the Swift code.
- **After.**
  - `cargo tree`: tempfile 3.27.0 (through uniffi_pipeline) still links getrandom and fastrand into app-ffi, and app-crypto is the other getrandom caller. deny.toml now allows getrandom only through app-crypto, tempfile, ring and rand, and fastrand only through tempfile. `cargo deny --frozen check bans`: `bans ok`.
  - The RT-B3 line made `cry_03_t11` FAIL with "arc4random in …/crates/app-cli/src/zone.rs". In app-platform itself, that line no longer compiles (the crate denies `unsafe` and missing docs), so I put it in a file app-format does not build, as Checker 1 did.
  - Probes caught (`cry_03_t11` FAILED, naming the word and the file):
    - Rust: `libc::getentropy`, `RandomState::new()`, a `File::open("/dev/urandom")`;
    - Swift: `SecRandomCopyBytes`, `getentropy`, `arc4random_uniform` (in a new file macos/App/VerifyProbe.swift) and `Int.random(in:)`.
  - Mutants, each FAILED f_100: M8 (the old 5-word Rust list) at write_version.rs:769, and M8b (no Swift words) at :786.
  - After every probe was restored, write_version passed 33 of 33.
- **Left for the lead (not caught, and no product code uses them today).** Swift: `rand()`, `lrand48()`, `GKRandomSource`, `SecKeyCreateRandomKey`, CryptoKit `SymmetricKey(size:)` and `CFUUIDCreate`. Rust: a hand-declared `extern "C" fn rand` and `libc::lrand48`. Each made `cry_03_t11` pass in the copy. Checker 1 listed the first four kinds too. Adding "rand(", "rand48", "GKRandom", "SecKeyCreateRandomKey", "SymmetricKey(" and "CFUUIDCreate" would close them. tempfile's own random path stays linked, by the deny.toml wrapper ruling.

## F-105: the AT-E08 row names App's agent socket

- **Steps (RT-E-5).**
  - Read the row and SR-15.
  - Then check the listener itself without launching App: a `Session` with S-SSH-01 on and the agent socket in /tmp. Read the socket's and folder's modes, `lsof -nP -a -U -p <pid>` and `lsof -nP -a -i -p <pid>`, then turn the feature off (copy-only `verify_f105_agent_socket_listener`).
- **Before:** the row named only the instance socket and the bridge sockets.
- **After.**
  - plan/attacks-and-checks.md:68 now says "the listeners are the instance socket of APP-09.14, with the SSH agent on (S-SSH-01) App's own agent socket of INT-06.32, and, with the browser bridge on, the bridge sockets of INT-01 …".
  - plan/security.md:95 (SR-15) says "with the SSH agent on (S-SSH-01), App's own agent socket of INT-06.32".
  - Listener: `socket mode 140600 uid 501; folder 40700; lsof unix: [… unix … /tmp/e9s1-95936-v50/App/agent.sock]; lsof -i lines: 0`. After turn-off, the socket exists: false. This matches INT-06.32 and the red team's observation.

## Mutant summary

All mutants ran in `/tmp/e13s6h-verify-copy` with its own target. Each file was restored afterwards with a fresh mtime, and the restored files are `cmp`-equal to the tree.

| Mutant | Finding | Test that failed |
|---|---|---|
| M1 records follow the setting | F-106 | own_agent f_106 (:795); verify_f106 |
| M2 no failed-agent cache | F-108 | own_agent f_108_a_silent (:880); verify_f108 (3 removes, 6.0 s) |
| M3 the lock waits for its thread | F-108 | ssh f_108_a_silent_agent_never_holds_the_lock (:394); verify_f108 (2.0 s) |
| M3b quit does not join | F-108 | ssh f_108_quit_waits_for_the_locks_removals (:432) |
| M3c no late leave | F-108 | own_agent f_108_an_add_running_at_the_lock_leaves_too (:935) |
| M3d no is-recorded filter | F-108 | own_agent f_108_a_key_added_again_before_the_removals_stays (:961) |
| M4 helper waits for the file only | F-109 | agent f_109 (:561) |
| field for every Show (Swift) | F-102 | EditorMemoryTests f102 (:204); VerifyE13S6hTests rtE2Steps |
| M5 the card's 18 only | F-103 | edit f_103 (:576); verify_f103 |
| Ma ASCII-only case | F-103 | edit f_103 (:576) |
| M6 the type test first | F-104 | edit f_104 (:587); verify_f104 |
| M7 subtle's slice compare | F-099 | secret f_099 (release; t -36.35, -42.41) |
| M8 old Rust word list | F-100 | write_version f_100 (:769) |
| M8b no Swift words | F-100 | write_version f_100 (:786) |
