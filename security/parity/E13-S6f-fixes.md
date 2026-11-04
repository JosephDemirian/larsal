# E13-S6 part f: re-test of F-079, F-080, F-093, F-094, F-107

Story: E13-S6 part f ([plan/epics.md](../../plan/epics.md)). Rows: [security/findings.md](../findings.md). Earlier proof: [E13-S1 SR](E13-S1-SR.md) (SR-10 = F-079, SR-11 and SR-12 = F-080), [E13-S1 SN](E13-S1-SN.md) (SN-02 = F-094, SN-05 = F-093), [E13-S2 AT-H](E13-S2-AT-H.md) (F-H3 = F-107), [E13-S6b](E13-S6b-fixes.md) (F-071). Rulings: LD-223 (3), LD-225 (1), LD-232, LD-70, LD-97.

Round 2 comes first. Round 1, which failed F-080, is kept below it for history.

# Round 2

Date: 2026-10-29, as the brief gives it (the runs took place from 06:51 to 07:16 on 2026-10-30 by the Mac's clock). Role: Verify, round 2. I did not find, build or check these fixes.

| Finding | Result | One line |
|---|---|---|
| Build blocker (`crate::hwkey`) | **fixed** | `lib.rs:15 pub mod hwkey;` declares the real module. `cargo check -p app-ffi --locked`: Finished in 15.5 s, no error. |
| F-079 (Medium) | **fixed, re-tested** | Round 2 moved `targets` onto `resolve_field` and changed the unlock path. The f_079 tests still pass, a hidden App opened both AutoOpen vaults again, and mutant M-V8 is caught. |
| F-080 (Low) | **fixed, re-tested** | Round 1's failing steps now ask again and run nothing; with the fix undone, the new program runs with no question. "Remember my choice" is offered only when resolving changes nothing and the URL is not protected. A key file path holding a protected value is used, but not remembered and named `******`. On disk, 0 hits for the secret. 10 of 10 mutants caught. |
| F-093 (Low) | **fixed, re-tested** | `f_093`'s oracle is now the build's feature, so round 1's survivor M27 is caught. The no-net core still has 0 network symbols. |
| F-094 (Low) | **fixed, re-tested** | No product change since round 1 (same `net.rs` hash). Its tests pass with and without `net`. |
| F-107 (Medium) | **fixed, re-tested** | The unlock path now takes `key_secret`. All 9 f_107 tests pass, and mutant M-V9 is caught. |

5 of 5 rows re-tested as fixed. F-071 (part b's row) is fixed by the same code, which I re-tested here (see the lead notes). One Low race remains for the lead: a Yes pressed after a sync changed the command runs the new command.

## Setup (round 2)

- **Shared tree, own target** (`/tmp/e13s6f-verify-target`, `--locked`). I made no product edits.
  - `cargo check -p app-ffi`: Finished, no error.
  - `cargo test --no-fail-fast -p app-ffi -p app-cli -p app-core -p app-hwkey`: 55 suites, 1,170 passed, 0 failed, 30 ignored.
  - `cargo test -p app-platform --features net`: 40 passed, 0 failed, 7 ignored.
  - `cargo test -p app-ffi --features net --lib -- icon_fetch hwkey auto_open`: 16 passed, 0 failed.
  - `cargo clippy -p app-ffi -p app-cli -p app-core -p app-hwkey -p app-platform --all-targets -- -D warnings` and `cargo clippy --features app-ffi/net,app-platform/net -p app-ffi -p app-platform --all-targets -- -D warnings`: both "No issues found", exit 0. `cargo fmt --all -- --check`: exit 0.
- **Private copies.** Both made with `rsync -a --exclude target --exclude app-shots --exclude fuzz/target`.
  - `/tmp/e13s6f-verify-copy` had its own target `/tmp/e13s6f-verify-copy-target` and `TMPDIR=/tmp/e13s6f-verify-tmp`. It held my probe module `crates/app-ffi/src/verify_e13s6f.rs` (13 tests) and the mutants.
  - `/tmp/e13s6f-verify-app` had target `/tmp/e13s6f-verify-app-target` and DerivedData `/tmp/e13s6f-verify-dd`. It held the core builds, the App tests, the `app` tool and the hidden App.
  - From start to end, the part f files had the same SHA-256 (first 16 hex digits) in the tree and in the copies: app-ffi `auto_open.rs` 4ca75eb6f27d7c94, app-core `auto_open.rs` 246bd6ab6fed3a0c, `session.rs` 47148ab1a32c3cad, `hwkey.rs` 8261708de5207e5b, `icon_fetch.rs` 8023a57bf179f4b0, `OpenURL.swift` fa6829aa4601028b, `net.rs` 1f383f19b26e1769, `build-core.sh` ffc2226ba8efb37f.
- **Swift.** `scripts/build-core.sh`: exit 0. The generated AppCore.swift has `case ask(message: String, command: String, remember: Bool)`.
  - The first `xcodebuild … -skip-testing:AppUITests test` ran with my `TMPDIR` override left set by mistake. 2 tests outside part f failed: ParityEditorPagesTests "dialogs-delete-forever", and SavingWatchTests F-101 with "The folder 'recovery' doesn't exist".
  - I re-ran with the default `TMPDIR` (`test-without-building`, same build): "Test run with 310 tests in 42 suites passed", exit 0. AppTests has no host app, so no window opened.
- **Rule 10.** The only App launch was the debug App with `APP_TEST_HIDDEN=1` and its own `APP_TEST_INSTANCE_DIR`. It had no window and no focus. I stopped it with `kill -TERM 44223`, its own PID. Nothing touched the general pasteboard. MSG-08-2 never shows in a hidden launch.
- **Network.** Nothing left the Mac. No server was needed this round, because F-094's code is unchanged.

## Build blocker (round 2)

- **Steps:** `grep -n "pub mod hwkey" crates/app-ffi/src/lib.rs`, `grep -n hwkey::Choice crates/app-ffi/src/edit.rs`, then `cargo check -p app-ffi --locked`.
- **Before (22:17):** `edit.rs:70` and `:105` used `crate::hwkey::Choice`, but no module was declared.
- **After:** `lib.rs:15 pub mod hwkey;` is the real module (`Choice`, `KeyPick`, `look_for_keys`), and `edit.rs:70` and `:105` use it. `cargo check`: `Finished dev profile … in 15.51s`.

## F-080 (round 2): the remembered Yes and the key file path

- **Steps.**
  1. Round 1's failing probe, re-run in the private copy (`v_r2_sync_report`). The entry's URL is `cmd:///usr/bin/touch <dir>/{USERNAME}`, with UserName `first`. Open, then Yes with "Remember my choice". Another device rewrites the vault with UserName `second`, then `resolve_disk(Reload)`, then open again.
  2. Nine more probes (`v_r2_*`, listed below).
  3. Round 1's key file leak, end to end in a hidden App:
     - I made demo vaults with our `app` tool. `a.appvault` holds an AutoOpen group with two entries: KF (URL `b.appvault`, UserName `{PASSWORD}.appkey`, Password `demo-kf-secret`) and Plain (URL `c.appvault`, UserName `c.appkey`).
     - `settings_debug.json` turned on `recent.remember_keys`.
     - I launched `App --password-stdin a.appvault` and fed `demo-a` on stdin.
  4. Mutants in the private copy.
- **Before** (the round 1 code, rebuilt by undoing the "resolving changes nothing" check, mutant M-cmpfull, with the same probe):
  ```
  first question Ask { command: ".../first", remember: true }; after sync Done; second ran = true
  ```
  For the key file, round 1's probe gave `remembered_keys(B).key_file = ".../demo-kf-secret.appkey"`, which is written to `state.key_files`.
- **After:**
  ```
  first question Ask { command: ".../first", remember: false }; after sync Ask { command: ".../second", remember: false }; second ran = false
  ```
  | Probe | Result |
  |---|---|
  | `v_r2_sync_changes_the_command_asks_again` | Before Yes: `remember: false`. After Yes with Remember: asks again. After the sync: `Ask { …/second, remember: false }`, and `second` was not made. |
  | `v_r2_custom_field_command_never_remembered` (`cmd://{S:Tool}`) | `remember: false`. After a sync changes Tool: asks, and `t2` was not made. |
  | `v_r2_placeholder_that_resolves_to_itself_then_a_sync_adds_the_field` (`{S:Tool}` with no Tool field) | Resolves to empty, `remember: false`. After a sync adds `Tool=evil`: `Ask { …/evil, remember: false }`, and nothing ran. |
  | `v_r2_value_equal_to_its_placeholder` (UserName literally `{USERNAME}`) | Remember is offered, because the text resolves to itself. After a sync to `second`: `remember: false`, asks, and nothing ran. |
  | `v_r2_plain_command_text_changed_by_sync_asks_again` | A plain command is remembered: `Done`, and it runs. A sync edits the URL text: `Ask { …/p2, remember: true }`, and `p2` was not made. |
  | `v_r2_vault_flag_protects_url_no_remember` (the vault's URL flag on, the field's flag off) | `Ask { command: "******", remember: false }`. After Yes with Remember: still asks. |
  | `v_r2_reference_never_remembered` (`{REF:U@I:…}`) | `Ask { …/r1, remember: false }`. After Yes with Remember: still asks. |
  | `v_r2_auto_open_key_file_from_password_not_kept` | `The key file "******" cannot be found. Choose it again.` Nothing kept. |
  | `v_r2_vault_link_key_file_from_a_reference_not_kept` (`{REF:P@I:<other entry>}.appkey`, a planted entry reading another entry's protected password) | The same masked message, and nothing kept. |
  | `v_r2_vault_password_flag_key_file_not_kept` (the vault's password flag on, the field's flag off) | The same masked message, and nothing kept. |
  | `v_r2_secret_named_key_file_still_unlocks` (`demo-kf-ok.appkey` exists) | B unlocks with the key file, and nothing kept. |
- **Hidden App, on disk.** A few seconds after the launch, and again after TERM, `state_debug.json` held:
  ```
  "state.key_files": {".../e2e/c.appvault": ".../e2e/c.appkey"},
  "state.recent": [c, b, a], "state.open_at_quit": [a, b, c], "state.last_active": a
  ```
  So b opened, and its key file was not kept. `grep -rc demo-kf-secret` over the instance folder (lock file, `settings_debug.json`, `state_debug.json`) and over the App's output gave 0 hits.
- **Builder tests, all ok:** `auto_open::tests::f_080_open_url_follows_mod_08_31` (rows 33 and 39 included) and `f_080_a_key_file_path_holding_a_secret_is_not_kept`.
- **Mutants (private copy), 10 of 10 caught.** Each run exited 101, and the file was restored and checked with `cmp`.

  | Mutant | Change | Failing test, line |
  |---|---|---|
  | M-cmpfull | `remember_key` drops "stored text == full resolution" (the round 1 code) | `f_080_open_url_follows_mod_08_31`, :704 (row 39 offered Remember). The probe `v_r2_sync_report` shows the silent run (above). |
  | M14b | `remember_key` drops the protected check | `f_080_open_url_follows_mod_08_31`, :663 (row 33). Round 1: survived. |
  | M-offer | `remember: true` always | the same test, :663 |
  | M-core-keysecret | app-core `Target.key_secret` always false | `f_080_a_key_file_path_holding_a_secret_is_not_kept`, :543 (the message names the secret) |
  | M-link-keysecret | the vault link passes `key_secret` false | the same test, :550 |
  | M-notekeys | `note_keys` is not skipped | the same test, :545 (`kept() == None`) |
  | M-name | `read_key_as` gets no shown name | the same test, :543 |
  | M-V1-maskcheck | `resolve_field` drops "shows the mask" | `f_080_open_url_follows_mod_08_31`, :665 (row 37) |
  | M-V2-protectedfield | `resolve_field` drops the protected-field return | the same test, :662 (row 32) |
  | M-V3-differs | `resolve_field` drops "full differs from display" | the same test, :667 (row 38) |
- **Swift.**
  - OpenURL.swift sets `box.showsSuppressionButton = offered` and sends `remember = offered && box.suppressionButton?.state == .on`.
  - No test can drive the modal alert, but the rule does not rest on Swift. `run_url_command(…, remember: true)` stores nothing when `remember_key` gives `None`: rows 33 and 39, and my probes, call it straight with `true`, and the next open still asks.
  - How the box looks in a visible window is Mac QA (owner's go).

**Result: fixed, re-tested.**

## F-093 (round 2)

- **Steps:**
  - `cargo test -p app-ffi --lib -- f_093` (no-net build) and `cargo test -p app-ffi --features net --lib -- f_093`.
  - Mutant M27 (`core_has_network()` returns `true`) in the no-net build.
  - `scripts/build-core.sh --no-net` in the App copy, then `nm -a libapp_ffi.a | grep -ciE 'rustls|ureq'` and `grep -c SecTrust`.
- **Before (round 1):** `f_093` used `core_has_network()` as its own oracle, so M27 survived.
- **After:**
  - `f_093` asserts `core_has_network() == cfg!(feature = "net")`. It passes in both builds.
  - M27 fails at icon_fetch.rs:279, exit 101.
  - `--no-net`: exit 0, 0 rustls/ureq symbols and 0 SecTrust references. The default build has 7,869.

**Result: fixed, re-tested.**

## F-079, F-094, F-107 (round 2: re-run after the round 2 changes)

- **F-079.**
  - `targets` now resolves through `resolve_field`, and `unlock_passed` takes `key_secret`.
  - The 4 app-ffi `f_079_*` tests and the 4 app-core `f_079_*` tests pass.
  - The hidden App above opened b and c from a's AutoOpen group (state.recent, state.open_at_quit).
  - Mutant M-V8 (`targets` gives no password) fails all 4 app-ffi `f_079` tests (first at auto_open.rs:391).
- **F-094.**
  - No product change since round 1: the `net.rs` hash is the same, and `icon_fetch.rs` changed only in the `f_093` test.
  - `net::tests::f_094_*` and `sn03_*` pass. `icon_fetch::tests::f_094_*` and app-core `icons::tests::f_094_*` pass with and without `net`.
  - Round 1's servers and its 7 mutants still stand.
- **F-107.**
  - All 9 `f_107` tests (app-ffi and app-cli) and `f_080_unlock_remembers_key_parts_while_the_option_is_on` pass.
  - Mutant M-V9 (`unlock_passed` drops the remembered slot) fails `hwkey::tests::f_107_passed_in_unlock_uses_the_remembered_slot` (hwkey.rs:345).
  - A real key is still Mac QA.

**Result: all three fixed, re-tested.**

## For the lead (round 2)

1. **Low, new evidence for round 1's note 4: a Yes pressed after a sync runs a command the user never saw.**
   - Probe `v_r2_yes_after_a_sync_runs_the_new_command`: the question shows `/usr/bin/touch …/shown` with `remember: true`. A sync rewrites the URL to `…/swapped`, and App reloads it (APP-05.31 allows a silent reload, T53). Then Yes with Remember.
   - Output: `Yes ran=true; shown exists=false, swapped exists=true; next open Done`.
   - So the swapped command ran, and it is now remembered. The window is the time the MSG-08-2 alert is open.
   - **Smallest fix.** `run_url_command` takes the command text the question showed and runs (and remembers) only when the entry's current display resolution still gives that text. When it no longer does, it returns false and the caller asks again.
   - I did not send the row back for this. It is not round 1's failure, and round 1 already listed it as a note.
2. **Spec lines needed (from the builder's decisions 1 and 2).**
   - MOD-08.31 says "The question has a 'Remember my choice' box". App now shows the box only when resolving the URL changes nothing and the URL is not protected (LD-70, F-071).
   - M06-11 now names a key file path holding a protected value as `******`.
3. **F-071 (part b's row; I did not edit it).** Its fix is now in code: `remember_key` in app-ffi auto_open.rs gives a key only for an unprotected URL whose stored text equals its full resolution. I re-tested it here: rows 33 and 39, M-cmpfull, M14b and M-offer caught, and 7 probes. Part b's Verify, or the lead, can mark it from this proof once Spec has the line in item 2.
4. **The builder's decision 3 (a vault path built from a protected value): I agree to accept it.**
   - The path reaches `open_beside` and the recent list only when a regular file exists at that exact path. Only someone who already knows the value can make such a file.
   - A missing one gives MSG-08-3 with no path, or M06-39 with only a count.
5. **Known limit, unchanged:** a transform that gives the same text for the protected value and for the mask (Checker 1's regex probe). The key file path now has the same one-fact limit as the URL. I recommend accepting it as Low, or giving it part b's `masked` flag.

## Clean-up (round 2)

- All my `/tmp/e13s6f-verify-*` folders are deleted: copies, targets, DerivedData, TMPDIR and work folder.
- My mutant and probe runs used `TMPDIR=/tmp/e13s6f-verify-tmp`, so they left nothing in the user temp folder.
- No process of mine is still running. The hidden App (44223) was stopped by its PID.

# Round 1

Date: 2026-10-29 (the runs took place from 05:57 to 06:40 on 2026-10-30 by the Mac's clock). Role: Verify, round 1. I did not find, build or check these fixes.

| Finding | Result | One line |
|---|---|---|
| Build blocker (`crate::hwkey`) | **fixed** | `crates/app-ffi/src/lib.rs:15` declares `pub mod hwkey;`, the real module (`hwkey.rs`, 16.7 KB, `Choice`, `KeyPick`, `look_for_keys`). `cargo check -p app-ffi --locked`: Finished, no error. |
| F-079 (Medium) | **fixed, re-tested** | A hidden App unlocked by a stdin password opened both vaults of the AutoOpen group (before: nothing opened). Device rule, share skip, loops, M06-06, M06-11 and M06-39 hold. 9 of 9 mutants caught. |
| F-080 (Low) | **re-test failed** | Every URL kind of MOD-08.31 works and no protected value reaches Swift. But a remembered Yes is keyed on the stored URL text, not the command: after a sync changes a field the command reads, a different program runs with no question (MOD-08.31 "a changed command asks again", LD-70). |
| F-093 (Low) | **fixed, re-tested** | `build-core.sh --no-net`: 0 rustls/ureq symbols and 0 SecTrust references (default build: 7,869 and 36). The switch undone gives 7,869. The README line is there. |
| F-094 (Low) | **fixed, re-tested** | Through the product path against three 127.0.0.1 servers I started and stopped by PID: only `/favicon.ico` is asked, with no user name, path, query or fragment; 5 redirects are followed, the 6th is not; a redirect carrying a user name is not followed. 7 of 7 mutants caught. |
| F-107 (Medium) | **fixed, re-tested** | The tests unlock and save through the session and through `app` with the software key (OD-01). `app --hw-key 2` now goes through app-hwkey's USB layer (8 IOHID imports, 397 app_hwkey symbols; before, no crate depended on it). 5 of 5 mutants caught. A real key is still Mac QA. |

4 of 5 rows re-tested as fixed. F-080 failed. Two new problems for the lead are listed at the end. One is a leak: with S-START-08 on, a protected value reaches the state file on disk.

## Setup

- **Shared tree, own target** (`/tmp/e13s6f-verify-target`, `--locked`). I made no product edits.
  - `cargo check -p app-ffi`: Finished in 18 s.
  - `cargo test --no-fail-fast -p app-ffi -p app-cli -p app-core -p app-hwkey`: 55 suites, 1,169 passed, 0 failed, 30 ignored.
  - `cargo test -p app-platform --features net`: 41 passed, 0 failed (all `net::tests::f_094_*`, `sn03_*` and `redirect_not_followed` ok).
  - `cargo test -p app-ffi --features net --lib -- icon_fetch hwkey auto_open`: 15 passed, 0 failed.
  - Clippy with `-D warnings` exited 0 twice: once on `-p app-ffi -p app-cli -p app-core -p app-hwkey -p app-platform --all-targets`, once on `--features app-ffi/net,app-platform/net -p app-ffi -p app-platform --all-targets`. `cargo fmt --all -- --check` exited 0.
- **Private copies.**
  - `/tmp/e13s6f-verify-copy`, made with `rsync -a --exclude target --exclude app-shots --exclude fuzz/target`. It had its own target, `/tmp/e13s6f-verify-copy-target`, and `TMPDIR=/tmp/e13s6f-verify-tmp` for the mutant runs. It held the mutants and my probe module `crates/app-ffi/src/verify_e13s6f.rs`.
  - `/tmp/e13s6f-verify-app`, with target `/tmp/e13s6f-verify-app-target` and DerivedData `/tmp/e13s6f-verify-dd`. It held the core builds and the App.
  - At the end, the SHA-256 (first 16 hex digits) of the 20 part f files matched in the tree and the copies. Examples: `auto_open.rs` 229143129454be06, `hwkey.rs` 188d00494fcb9878, `icon_fetch.rs` f3eeaca801b5a31d, `session.rs` d6d1c0c3dacb9859, `net.rs` 1f383f19b26e1769, `build-core.sh` ffc2226ba8efb37f, `OpenURL.swift` d8da5a288e24e7fe, `UnlockKeys.swift` 7cc6cc4d6b685401.
- **Swift.** `scripts/build-core.sh`, then `xcodebuild -project macos/App.xcodeproj -scheme App -destination 'platform=macOS' -derivedDataPath /tmp/e13s6f-verify-dd SWIFT_TREAT_WARNINGS_AS_ERRORS=YES -skip-testing:AppUITests test`: "Test run with 309 tests in 41 suites passed", TEST SUCCEEDED. AppTests has no host app, so no window opened.
- **Rule 10.** The only App launch was the debug App with `APP_TEST_HIDDEN=1` and `APP_TEST_INSTANCE_DIR=/tmp/e13s6f-verify-work/app/inst`. It had no window and no focus, and it used its own settings folder. I stopped it with `kill -TERM 63426`, its own PID. Nothing touched the general pasteboard. The MSG-08-2 alert never runs in a hidden launch (`guard !launchHidden()`).
- **No security key was plugged in.** `ioreg -r -c IOHIDDevice` listed only Apple, Logitech and NuPhy devices, so the `--hw-key` runs could not touch any key's slot (OD-01).
- **Network.** Nothing left the Mac. The icon tests use a fake transport, or 127.0.0.1 servers that the tests start themselves. My own three servers ran on 127.0.0.1 only.

## Build blocker: `crate::hwkey`

- **Steps:** `grep -n "mod " crates/app-ffi/src/lib.rs`; `grep -n hwkey crates/app-ffi/src/edit.rs`; `cargo check -p app-ffi --locked`.
- **Before (22:17):** `edit.rs:70` and `:105` used `crate::hwkey::Choice`, but no `hwkey` module was declared, so app-ffi did not compile.
- **After:** `lib.rs:15 pub mod hwkey;` declares `hwkey.rs`, which holds `Choice`, `KeyPick`, `KeyItem`, `KeyLook`, `look_for_keys` and `security_key_waits`. It is the real module, not a stub. `cargo check` gave `Finished dev profile … in 18.31s`.

## F-079: auto-open after unlock (SR-10, APP-06.25, M06-39, LD-97)

- **Steps (the row's own, end to end in App).** I made the demo vaults with our `app` tool (`db-create -p -t 100`, `mkdir AutoOpen`, `add -p --url`):
  - `a.appvault` holds the group AutoOpen with three entries: OpenB (URL `b.appvault`, password `demo-b-pass`), OpenC (URL `c.appvault`, UserName `c.appkey`, which does not exist) and Missing (URL `missing.appvault`).
  - I launched the hidden App as `App --password-stdin a.appvault` and fed `demo-a-pass` on stdin. `settings_debug.json` turned on `recent.remember_keys`.
- **Before:** nothing opened. No code read the group.
- **After:** within 2 s, `state_debug.json` held:
  ```
  "state.recent": [".../c.appvault", ".../b.appvault", ".../a.appvault"],
  "state.key_files": {".../c.appvault": ".../c.appkey"}
  ```
  After TERM it also held `"state.open_at_quit": [a, b, c]` and `"state.last_active": ".../a.appvault"`, so the shown vault stayed A. The file is mode 0600.
- **Probes** (my module in the private copy, `cargo test -p app-ffi --features net --lib -- verify_e13s6f`, all ok):
  - **Device rule on this Mac** (host name `Josephs-MacBook-Pro.local`). `IfDevice = "other-mac, !JOSEPHS-MACBOOK-PRO.LOCAL"` is not opened. `"!other-mac, <host>"` opens and unlocks.
  - **LD-97.** An AutoOpen group carrying the share key opens nothing and shows no banner.
  - **Loop.** A opens B and B opens A. The run ends with 2 vaults open.
  - **Failures.**
    - A wrong password leaves B locked, with M06-06 waiting in its message. The password does not appear in that message.
    - A missing key file gives `M06-11 "The key file "nokey.appkey" cannot be found. Choose it again."`.
    - Two missing vaults give one banner: "2 vaults listed in the AutoOpen group are missing. …".
    - A vault that is already unlocked keeps its id and gets no second slot. A stays the shown vault.
- **Builder tests (all ok):**
  - app-ffi `auto_open::tests::f_079_auto_open_after_unlock`, `_after_reload`, `_after_the_forced_key_change` and `_after_the_unlock_answer`;
  - app-core `tests/auto_open.rs`: `f_079_device_rule`, `f_079_auto_open_targets_follow_app_06_25`, `f_079_only_the_first_auto_open_group_under_the_root` and `f_079_shared_auto_open_group_is_skipped`.
- **Mutants (private copy), 9 of 9 caught, exit 101 each:**
  - M01 removes the unlock hook: `f_079_auto_open_after_unlock` fails.
  - M02 removes the reload hook (`saving.rs`): `_after_reload` fails.
  - M03 removes the hook at the end of the forced key change: `_after_the_forced_key_change` fails.
  - M04 opens while the forced change still waits: the same test fails, at `!…any(b)`.
  - M05 removes the hook after the "Unlock" answer: `_after_the_unlock_answer` fails.
  - M06 shows no M06-39: `f_079_auto_open_after_unlock` fails, at the banner.
  - M07 lets a matching `!name` not end the device rule: `f_079_device_rule` fails.
  - M08 drops the share skip: `f_079_shared_auto_open_group_is_skipped` fails.
  - M09 takes the last group, in any letter case: `f_079_only_the_first_auto_open_group_under_the_root` fails.

**Result: fixed, re-tested.**

## F-080: MOD-08.31 URL rules and remembered key files (SR-11, SR-12)

- **Steps (the row's own):** the open action on `example.com`, on `mailto:`, on a `cmd://` command and on a vault link; then an unlock with `recent.remember_keys` on.
- **Before:**
  - Swift's URLOpener opened only http and https. Commands, vault links, `mailto` and bare hosts did nothing, and MSG-08-4 never showed.
  - Nothing wrote `state.key_files` or `state.hardware_keys`.
- **After, what works:**
  - Rows 20 to 38 of `f_080_open_url_follows_mod_08_31` pass:
    - `example.com` opens `http://example.com`; `mailto` opens;
    - `javascript:`, `file:` and `{S:a}:` give MSG-08-4;
    - `cmd://` asks MSG-08-2;
    - a vault link opens B in front and unlocks it; a missing one gives MSG-08-3;
    - a protected value never comes back (rows 28 and 32 to 38).
  - Every entry Open URL action in Swift calls `openURL`, then `session.openUrl`: Menus.swift:67, RailView.swift:49 and :94, EditorEntryPage.swift:83, AppCommandsVault.swift:58 and ContextMenus.swift:22. `NSWorkspace.shared.open` appears only in URLOpener (links outside an entry), VaultEdits (attachments) and AutoTypeTyping (the settings pane).
  - The hidden App wrote `state.key_files` while S-START-08 was on (see F-079). `f_080_unlock_remembers_key_parts_while_the_option_is_on` passes.
  - A remembered Yes is not kept for a protected URL. My probe `v_f080_remembered_yes_is_exact_and_never_protected` shows that a protected `cmd://` still asks, masked as `******`, after a Yes with Remember. An edit of the URL text asks again.
- **After, what fails: a remembered Yes outlives a change of the command.** Probe `v_f080_remembered_yes_after_a_sync_changes_the_command`:
  - The entry's URL is `cmd:///usr/bin/touch /private/tmp/e13s6f-verify-work/sync/{USERNAME}`, with UserName `first`.
  - The first open gives `Ask { command: ".../sync/first" }`. Yes with "Remember my choice" runs it.
  - Another device then rewrites the vault with UserName `second` only. App reloads it (`resolve_disk(Reload)`: `Reloaded`).
  - The next open gives `Done`, and `/usr/bin/touch …/second` ran with no question. Both files exist.
  - **Cause.** `Session::remember_key` (auto_open.rs) hashes the URL text as stored, `cmd:///usr/bin/touch …/{USERNAME}`, following the F-071 doc in `app_core::url::remember_key`. MOD-08.31 says: "The command is the resolved text after `cmd://`", and the Yes is remembered "for this vault, entry id and exact command text … so a changed command asks again". LD-70 exists because "anyone who can change the vault (sync, shared group, import) could otherwise make one click run a program".
  - **Consequence.** With `cmd://{USERNAME}` or `cmd://{S:Tool}`, whoever can change that field by sync or by a shared group chooses the program, and the user's remembered Yes runs it. This is the hole that part b's Verify predicted under F-071: "the future MOD-08.31 caller would follow the doc into LD-70's hole". Before part f, App never ran a command, so the hole is new with this wiring.
  - **Smallest fix: F-071's own.** Offer and honour "Remember my choice" only when resolving the URL changes nothing (the stored text is the exact command) and the URL is not protected.
    - In `Session::remember_key`, also return `None` when the full resolution differs from the stored text. `open_url` and `run_url_command` both go through it.
    - `UrlAction::Ask` carries whether Remember is offered, so OpenURL.swift shows the box only then.
    - Add the sync row above to `f_080_open_url_follows_mod_08_31`.
    - This closes F-071 too.
- **Mutants (private copy):**
  - Caught: M10 (the Url branch ignores the protected flag; f_080 fails at row 28), M11 (a vault link does not unlock; fails at `unlocked(&s, &b)`), M12 (key parts remembered while S-START-08 is off) and M13 (no `note_keys`). M12 and M13 each fail `f_080_unlock_remembers_key_parts_while_the_option_is_on`.
  - Survived: M14b, which also remembers a Yes for a protected URL. The full app-ffi suite passed with it (exit 0). Only my probe catches it, so no builder test covers the F-071 rule for protected URLs. Add one with the fix above.

**Result: re-test failed** (the remembered Yes). The rest of F-080 is in place.

## F-093: no-network build switch (SN-05)

- **Steps:** `scripts/build-core.sh --no-net`, then the default `scripts/build-core.sh`. Each time, `nm -a libapp_ffi.a | grep -ciE 'rustls|ureq'` and `grep -c SecTrust`.
- **Before:** both scripts hard-coded `--features net`. No document said how to leave it out.
- **After:**
  - `--no-net`: exit 0, 0 rustls/ureq symbols, 0 SecTrust references.
  - Default: 7,869 and 36.
  - `--bogus` prints "unknown argument --bogus (only --release, --no-net)", exit 2.
  - `repro-build.sh` takes `--no-net` too. It passes `net=()` to its `cargo build -p app-ffi` and `--no-net` to `build-core.sh` (line 81). I did not run it: it builds in the one shared folder `/private/tmp/app-repro`, which other agents' release runs use.
  - README.md:59 has the line.
  - In the no-net core, `icon_fetch::tests::f_093_no_network_build_says_so` passes (part of the 146 lib tests above). `ReportsView.swift:232` shows "This build of App has no network code…" in place of the check when `coreHasNetwork()` is false (code read; I rendered no no-net window).
- **Mutants:**
  - M28 makes `--no-net` keep `net` in build-core.sh: the "no-net" library has 7,869 network symbols. Restored, it has 0.
  - M27 makes `core_has_network()` always true: it survives `f_093`. That test compares the refusal with `core_has_network()` itself, so a wrong answer from the function is not caught. The build-level check above is the real proof. Low, test-only (see the lead notes).

**Result: fixed, re-tested.**

## F-094: icon download on request (SN-02)

- **Steps:**
  - I started three servers on 127.0.0.1 (`python3 -I server.py <mode>`) and kept their PIDs: 57962 `chain5`, 57964 `chain6`, 57966 `userinfo`, on ports 63188, 63189 and 63190.
  - In a session, I made one entry per server with URL `http://alice:demo-pw@127.0.0.1:<port>/acct/page?token=demo-q#frag`. I called `fetch_site_icons` first with S-ENTRY-11 off, then on. This is the product path: `Net`, app-platform `Client::get_icon`, feature `net`.
  - I stopped the servers with `kill -TERM 57962 57964 57966`. All three were gone afterwards.
- **Before:** no story built the download, and `get_icon` had no product caller.
- **After:**
  - **Off.** `Err(Refused("Website icon downloads are off. Turn them on in Settings › Entries."))`, and the servers logged nothing for it.
  - **chain5.** `/favicon.ico` → `/h1` → … → `/h5` → 200 PNG. Answer: `IconFetch { set: 1, "Fetched the site icon for 1 entry." }`. Five redirects were followed.
  - **chain6.** The requests are `/favicon.ico`, `/h1` to `/h5`, and never `/h6`. Answer: `set: 0, "The site icon could not be fetched."`.
  - **userinfo.** A 301 to `http://u:p@127.0.0.1:…` is not followed: one request only, `set: 0`.
  - **What was sent.** Every request is `GET /favicon.ico` or a redirect path, with only `user-agent: App`, `accept: */*` and `host`. `grep -ciE "alice|demo-pw|token|demo-q|acct|frag|authorization|cookie|referer"` over the three logs gives 0, 0, 0.
- **Other checks:**
  - **Defaults.** `icons.download` (S-ENTRY-11) and `icons.use_service` (S-PRIV-01) are off, and `icons.download_timeout` is 10 s.
  - **One caller.** `fetchSiteIcons` is called only from OpenURL.swift:59, by Entry › Fetch Site Icon (⇧⌘D, no clash; ⌘D is Clone).
  - **https and redirect rules.** Never from https to http, and the whole limit covers every hop. The builder tests prove both: `net::tests::f_094_icon_redirects_followed_within_the_rules` and `f_094_icon_time_limit_covers_every_redirect`.
- **Mutants, 7 of 7 caught:**
  - M20 allows https to http, and M21 allows a sixth hop: `f_094_icon_redirects_followed_within_the_rules` fails for each.
  - M22 gives each hop the full limit: `f_094_icon_time_limit_covers_every_redirect` fails (1.41 s).
  - M23 allows a user name on a hop: `sn03_http_only_for_icons` fails.
  - M24 downloads while S-ENTRY-11 is off: `f_094_icons_download_on_request_only` fails (`set: 2`).
  - M25 gives each address the full limit: `f_094_time_limit_covers_every_address` fails.
  - M26 makes a bare host get `http`: app-core `icons::tests::f_094_download_addresses_follow_the_row` fails.

**Result: fixed, re-tested.** The reference's redirect capture (installed 2.7.11) still needs the owner's go, as SN-02 says.

## F-107: hardware keys in unlock, save and `app` (INT-07, AT-H03, AT-H04)

- **Steps:**
  - I wrote a demo vault `/tmp/e13s6f-verify-work/cli/hk.appvault` with password `demo-pass` and the software key (demo secret D, variable mode, OD-01).
  - Then I ran the copy's `app` (debug, built from the tree's sources):
    - `db-info --hw-key 2` with the password on stdin;
    - `db-info` without `--hw-key`;
    - `db-info --no-password --hw-key 2`;
    - `db-info --hw-key 3`.
- **Before:**
  - `db-info --hw-key 2` printed "Your security key is not connected" without looking for a key, because `read_creds` always gave M06-17.
  - No crate depended on app-hwkey, and the unlock screen's switch was disabled ("Security keys come in E10.").
- **After:**
  - **`--hw-key 2`.** "app: Your security key is not connected. Plug it in, then try again.", exit 1, in 0.71 s. This now comes from app-hwkey's USB layer: the `app` binary imports 8 IOHID functions and holds 397 `app_hwkey` symbols. `libapp_ffi.a` holds 1,610 `app_hwkey` symbols and 38 `IOHIDManager` references.
  - **Without `--hw-key`.** M06-06 "Wrong password, key file or security key…".
  - **`--no-password --hw-key 2`.** M06-17.
  - **`--hw-key 3`.** "3 is not a slot (1 or 2) …".
  - The vault's SHA-256 was the same before and after the runs (0b825102a6fec2ca).
- **The App side:**
  - `SecurityKeyRow` (UnlockKeys.swift) has a working switch. ParityTests "the security key enabled" passes (one of the 309).
  - `UnlockModel.unlock` passes `useKey ? pick : nil` to `unlockWithKey`.
  - Hidden launches and tests never look for keys (`reachesKeys`).
  - The wizard's and vault settings' Add… and Change… are still marked later. They are F-126, part k (LD-232 (4)).
- **Builder tests (all ok):**
  - app-ffi `hwkey::tests::f_107_unlock_and_save_use_the_hardware_key`, `f_107_reload_and_key_change_keep_the_hardware_key`, `f_107_passed_in_unlock_uses_the_remembered_slot`, `f_107_touch_events_drive_m06_35`, `f_107_choice_round_trips_through_the_remembered_text` and `f_107_look_lists_items_with_the_m06_36_note`;
  - app-cli `hwkey::tests::f_107_hw_key_unlocks_and_saves`, `f_107_db_edit_keeps_the_hw_key_part` and `f_107_slot_values_become_choices`.
- **Mutants, 5 of 5 caught:**
  - M15 passes no key part to the open: `f_107_unlock_and_save_use_the_hardware_key` fails.
  - M16 does not keep the key for the save: the same test fails (the saved file unlocks without the key).
  - M17 does not use the remembered slot in a passed-in unlock: `f_107_passed_in_unlock_uses_the_remembered_slot` fails (M06-06).
  - M18 drops `--hw-key` in `read_creds`: `f_107_hw_key_unlocks_and_saves` and `f_107_db_edit_keeps_the_hw_key_part` fail.
  - M19 drops the key part from db-edit's last-part check: `f_107_db_edit_keeps_the_hw_key_part` fails.
- **Not proven here (Mac QA, owner's go):**
  - a real key's challenge, touch and M06-35;
  - AT-H04 with another physical key through the session;
  - the Swift pick passing through to Rust. In test builds, Swift's core reaches USB, so no Swift test can unlock with a key.

**Result: fixed, re-tested** (software key per OD-01).

## For the lead

1. **F-080 goes back (above).** The remembered Yes must follow the resolved command, or be offered only when resolving changes nothing. F-071 (part b, re-test failed) closes with the same fix, because part f is its first caller.
2. **New, Low to Medium (rule 4, SR-12 "never stores a password there"): a protected value reaches the state file on disk.**
   - Probe `v_f080_protected_key_file_name_is_remembered`: an AutoOpen entry with UserName `{PASSWORD}.appkey` and a protected Password `demo-kf-secret`, with S-START-08 on.
   - `remembered_keys(B).key_file` gives `".../kfname/demo-kf-secret.appkey"`, which is written to `state.key_files` (S-STATE-02, plain JSON on disk). B's message is `The key file "demo-kf-secret.appkey" cannot be found.`
   - A vault link takes the same path. Through `{REF:P@I:…}`, a planted entry can do this with another entry's password.
   - Checker 1 raised the message half and recommended accepting it (APP-06.24, "paths are not secret"). The disk half is worse.
   - **Smallest fix.** When the resolved UserName of an auto-open or vault-link entry holds a protected value (the same test as `url_of`: the field is protected, or the display resolution differs or shows the mask), pass the key file without remembering it (skip `note_keys` for it) and with no name in M06-11.
3. **Low, test only.** `f_093_no_network_build_says_so` uses `core_has_network()` as its own oracle, so mutant M27 (`core_has_network()` always true) survives. The no-net build's symbol count is the real proof. It is a one-line `cfg!`, so I suggest accepting it.
4. **Low, note.** `run_url_command` resolves the command again when Yes is pressed. A reload between the question and the Yes would run a command that was not the one shown. The fix in item 1 makes the remembered key exact. Passing the shown text's hash back with the Yes would close this window too, if wanted.

## Clean-up

- All `/tmp/e13s6f-verify-*` folders are deleted: copies, targets, DerivedData, logs, the server folder and the work folder.
- Before I set `TMPDIR` for the mutant runs, my failing runs left six `app-ffi-auto-<case>-<pid>` folders in the user temp folder. I deleted them by their PIDs: 64213, 64477, 64771, 65344, 65433 and 65800. Other agents' older folders there were not touched.
- No process of mine is still running. The App (63426), its stdin feeder (63425) and the servers (57962, 57964, 57966) were each stopped by PID.
