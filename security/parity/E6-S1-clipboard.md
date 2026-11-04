# E6-S1 Clipboard (SC-01, SC-02, SC-03; AT-D01 to AT-D03)

Story: E6-S1 Clipboard, Rust and Swift sides.
- Card: [APP-03](../../spec/app/APP-03-clipboard.md).
- Decisions: LD-168, LD-170, LD-181.

Date: 2026-10-28.
Role: Verify. I did not build or review this story. No reference access was needed, and none was used.

Result: **signed.** Every check passed. Three checks need the general pasteboard or a second device, so they go to Mac QA with the owner's go (AGENTS.md rule 10):
- AT-D01 with a real clipboard history app;
- AT-D02 and AT-D03 in the real app on the general pasteboard;
- Universal Clipboard staying on this Mac.

**General pasteboard change count:** 10124 at 06:00:11, before any work. It was 10124 after every Rust and Swift run, and 10124 at 06:18:35, after clean-up. Nothing I ran wrote to it or cleared it.

| Check | Result |
|---|---|
| 1. AT-D01 markers | PASS on a private pasteboard, read by another process: one item, text plus `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType` with 0 bytes each, no other type. Current host only is proven by code read only. The history app and Universal Clipboard go to Mac QA. |
| 2. AT-D02 countdown | PASS. Cleared at 323 ms for a 300 ms delay, and still there at 150 ms. A newer write is left alone, including one from another process and one with the same text. A new copy restarts the countdown (cleared at 623 ms, not at 400). The session's 10 s copy is there at 9.5 s and gone at 10.6 s. |
| 3. AT-D03 | PASS. Lock, lock-all, close, a lock of another vault and quit all clear App's copy. Each one leaves newer content alone. `quit()` is `lockAll()` then `clearClipboard()`, called from `applicationWillTerminate`. |
| 4. No secret reaches Swift | PASS. `Copied` has `label`, `seconds` and `empty` only, in Rust and in the generated Swift. 450 strings of Swift state hold neither the password nor the copied code, and the positive control was found. The logs hold neither value. |
| 5. `copy_code`, `copy_fingerprint`, hostile ids | PASS. Codes are 6 or 8 digits with no space and equal app-core and RFC 6238. Fingerprints equal `ssh-keygen -lf` for two new demo keys. All 71 hostile calls were refused with nothing written, plus the locked case. |
| 6. Shown password on the unlock form | PASS. The hidden-window probe and `ShownPasswordFieldTests` both pass. |
| 7. Empty values, failed write | PASS. `Copied { empty: true, seconds: 0 }` comes back and the pasteboard is untouched. `refused_copy_leaves_nothing_of_ours` passes. |
| 8. Design parity `states-copied` | PASS: `states: 13/13 PASS`, `states-copied` light 1.58 %, dark 1.62 %, 0 missing strings, 0 token mismatches. The notice wording follows the card (LD-181 (1), accepted). |
| 9. Tests | PASS. `cargo test -p app-platform -p app-ffi` has 0 failed. `xcodebuild test -skip-testing:AppUITests` ran 47 tests in 11 suites, all passed. |

## Setup

- **Isolated copy.** Other agents were working in the project tree: an E8-S1 fuzz run and E9-S1 and LD-185 changes. So everything ran in a copy at `/tmp/v-e6s1-src`.
  - The copy was made at 06:04 with `rsync -a --exclude /target --exclude /fuzz/target`.
  - Its `target` linked to `/tmp/v-e6s1-target`, with `CARGO_TARGET_DIR=/tmp/v-e6s1-target` and `-derivedDataPath /tmp/v-e6s1-dd`.
  - `diff -rq` printed `identical` for `crates`, `vendor`, `macos`, `scripts`, `design/parity/tools`, `design/option-a` and `testdata`. `cmp` matched `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml`.
- **Later project changes.** By 06:12 the project's `app-ffi/src/views.rs` had changed. The change is LD-185 (search ratings), not copy code. `cmp` showed these files still identical to my copy:
  - `clipboard.rs`, `macos/pasteboard.rs`, `app-ffi/src/session.rs`, `app-ffi/tests/clipboard.rs`;
  - `Copy.swift`, `ShownPasswordField.swift`, `MainWindowModel.swift`, `AppDelegate.swift`, `AppMain.swift`, `UnlockView.swift`;
  - `ShownPasswordFieldTests.swift` and `ParityStatesTests.swift`.
- **SHA-256 (first 16 hex digits) of the verified files:**
  - `clipboard.rs` 430197c4fa8bcb4a
  - `pasteboard.rs` 8721f0801785f74f
  - `views.rs` 3d19d10943a2c235 (copy as verified)
  - `session.rs` 010bad594061c800
  - `Copy.swift` 46d0890272f4d0ac
  - `ShownPasswordField.swift` c45ba483ac933e53
  - `MainWindowModel.swift` f2d0414a49ce2cf8
- **My own drivers.** Product code is unchanged. The drivers were only ever in the copy, and are kept in `/tmp/v-e6s1-work`:
  - `verify_e6s1.rs`: 11 Rust tests over the `Clipboard` API and the `Session`, on my own demo vault (password `demo-verify-master`).
  - `VerifyE6S1Tests.swift`: two Swift suites, each run alone with `-only-testing`.
  - `pbtool`: a separate Swift program that reads or writes a named pasteboard through Apple's API. It refuses any name outside `com.app.clipboard.*`; `pbtool read "Apple CFPasteboard general"` printed `refused name … exit 2`.
- **Demo keys.** I made them for this check with `ssh-keygen -t ed25519` and `-t rsa -b 2048`, then deleted the private halves.
- **Private pasteboards only.** I used `Session::new()`, `Clipboard::private()` and `Session()` in Swift. `Clipboard::general()` and `Session::shared()` were never called. No window was ordered front; the Swift views rendered in borderless windows at x −20000. No app was launched.
- **Tools.** cargo and rustc 1.99.1, Xcode at `/Applications/Xcode.app`, macOS 26.6, OpenSSH 10.3p1, Python 3 `hmac`.

## 1. AT-D01: markers (SC-02)

Test `v01_markers_and_other_app_cross_process`, run alone. The session copied the demo password with `copy_field`. Then a separate process (`pbtool`) read the session's private pasteboard:

```
com.app.clipboard.73205.0 changeCount=1 items=1
  item0 org.nspasteboard.ConcealedType bytes=0
  item0 org.nspasteboard.TransientType bytes=0
  item0 public.utf8-plain-text bytes=13 text="verify-pass-1"
after lock_all:
com.app.clipboard.73205.0 changeCount=2 items=0
```

- **The Swift path writes the same item.** In `VerifyCopyPathTests`, `main.copy("Password")` left one item. Its types equal the set {text, concealed, transient}, both markers are empty, the text equals the field's value, and the change count rose by exactly 1.
- **Current host only.** This has no read-back API, so it is proven by code read. `pasteboard.rs` calls `prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly)` before `writeObjects`. It records the count that call returns, and the run above shows that count is the one kept: `changeCount=1` after the write.
- **Mac QA, with the owner's go:**
  - V-A03-1: run a clipboard history app, copy in App, and check that the history does not store the value.
  - Universal Clipboard: with a second Apple device nearby, the value must not arrive there.

## 2. AT-D02: the countdown (SC-01)

My own tests over the crate API, with short delays:

```
v02 delay 300 ms: present at 150 ms = Some(true); first seen empty at Some(323.265458ms)
v03 newer "other": at 909.365417ms the pasteboard holds Some("other")
v03 newer "verify-pass-1": at 908.596291ms the pasteboard holds Some("verify-pass-1")
v04 first copy 400 ms at 0, second 400 ms at 200: at 500 ms Some("second"); empty at Some(622.5825ms)
v06 session copy: at 9.5 s Some("verify@example.com"); at 10.6 s items []
```

In v03, a `clear()` after the newer write also returned false and left the content. The same text copied again counts as newer, because the change count differs (APP-03.12).

**Another process as "another app"** (v01): the crate copied with a 2000 ms countdown, and `pbtool` wrote `other-app-text` from its own process. At 3.03 s the pasteboard still held `changeCount=2 items=1 … text="other-app-text"`. The countdown left it, and `clear()` returned false.

**Mac QA:** the same checks in the real app on the general pasteboard. Copy and wait 10 s. Copy, then copy something in another app before 10 s.

## 3. AT-D03: lock, lock-all, close, quit (SC-03)

**Rust (v05).** Each action runs on a fresh session with vaults a and b unlocked. First a copy from a, then the action. "quit" is the Swift `quit()` sequence: `lock_all()` then `clear_clipboard()`.

```
lock, other app wrote first = false: items after = []
lock, other app wrote first = true: items after = [[("public.utf8-plain-text", "other")]]
lock_all  … false: []   … true: "other"
close     … false: []   … true: "other"
lock_other (lock b after a copy from a) … false: []   … true: "other"
quit      … false: []   … true: "other"
```

The byte arrays printed by the run are shown here as text.

**Swift (`VerifyCopyPathTests`)**, on the real `MainWindowModel` with the private pasteboard:
- `model.lock`, `model.lockAll` and `model.quit` each cleared the copy;
- after `quit`, every vault was locked;
- after another app's write, `model.lock` left `"other"`;
- `model.close` cleared the copy and removed the vault.

The run printed `VERIFY lock, lock-all, quit, close: cleared; another app's content kept`.

**Code read.**
- `AppDelegate.applicationWillTerminate` calls `window.quit()`. The Quit menu, ⌘Q and the quit signals (`QuitSignals` → `NSApp.terminate`) all go through it.
- `MainWindowModel.quit()` is `session.lockAll()` then `session.clearClipboard()`.
- In Rust, `lock`, `lock_all` and `close` call `clipboard.clear()` before they wipe.

**Mac QA:** in the real app, copy then ⌘L, and copy then ⌘Q. The general pasteboard must be empty both times.

## 4. No secret reaches Swift

- **The answer type.** `Copied` in Rust has `label`, `seconds` and `empty`. The test `v11_copied_holds_no_value` destructures exactly those three fields, so an added field would break the build. Its Debug text is `Copied { label: "Password", seconds: 10, empty: false }`. The generated Swift (`target/app-core/Swift/AppCore.swift`) has `public var label: String`, `public var seconds: UInt32` and `public var empty: Bool`, and nothing else.
- **Swift state after copies** (`VerifyCopyPathTests`). The test walks every String reachable from `MainWindowModel` by reflection.
  - After Copy password: `450 strings in Swift state; holding the value: []; shown: 0`.
  - After Copy one-time code: the copied form is held nowhere. The screen keeps only its own display form of the live code (FEA-04.24, by design).
  - Positive control: `"alex-dev" found at 6 paths`, for example `window._opened._.value._rows._.subtitle`.
- **Logs.**
  - This process's unified log: 372 entries, none with the password or code.
  - The four xcodebuild logs and the parity behaviour log: 0 hits for either value.
  - `log show --last 20m --predicate 'process == "xctest"'`: 1,357 lines, 0 hits.
  - In code, `Logger.app` is declared and never used in `macos/App`. There are no `print`, `NSLog` or `os_log` calls.
- **The notice.** `Copy.swift` builds the notice from `copied.label` and `copied.seconds` only.

## 5. `copy_code`, `copy_fingerprint`, hostile ids

**One-time codes (v07).** Each code was read inside one 30 s step and compared with `app_core::totp::code_for` for the same second:

```
unix=1793164217 digits=6 copied="693098" app-core="693098" shown="693 098"
unix=1793164217 digits=8 copied="34693098" app-core="34693098" shown="3469 3098"
```

- An independent RFC 6238 computation with Python `hmac` (SHA-1, secret `12345678901234567890`) gave `6: 693098 8: 34693098` for that second. The same code gives the RFC 6238 Appendix B vector `94287082` for T=59.
- An entry with no settings gives `UnknownField`, and the pasteboard keeps `"user text"`.

**Fingerprints (v08), against `ssh-keygen -lf` run inside the test:**

```
k1.pub: ssh-keygen -lf → 256 SHA256:g2ggL3z+kgp+Myq5aGQJYFy92eluv0TPC9xnnB5SbqY verify@example.com (ED25519) | copied SHA256:g2ggL3z+kgp+Myq5aGQJYFy92eluv0TPC9xnnB5SbqY
k2.pub: ssh-keygen -lf → 2048 SHA256:P5E+Hg8LBHU/JKDtdWWFkm8YMu4ntTTUdUdrwIP6GzQ verify-rsa@example.com (RSA) | copied SHA256:P5E+Hg8LBHU/JKDtdWWFkm8YMu4ntTTUdUdrwIP6GzQ
```

An attachment that only looks like a key, and an entry with no key, both give `UnknownField`, with nothing written.

**Hostile arguments (v09).** The pasteboard held `"user text"` from "another app" throughout.

- Entry ids, each tried with `copy_field`, `copy_code` and `copy_fingerprint`:
  - empty, 2, 30 and 33 characters;
  - `+` and `-` signs, a leading space, `g`×32, a path, an embedded NUL;
  - `é`×16 and full-width digits (32 bytes each);
  - 1 MiB of hex;
  - an unknown id, the root group's id and the nil id.
- Field names:
  - `otp` on an entry that has it;
  - `TOTP Seed` and `TOTP Settings` on an entry that has them;
  - four `TimeOtp-*` names;
  - `KPEX_PASSKEY_PRIVATE_KEY_PEM` on an entry that holds a demo value, and `KPEX_PASSKEY_USERNAME`;
  - an unknown name, an empty name, and a 70,000-byte name.
- Vault ids: 0, `u64::MAX` and an unknown id. A locked vault gives `Locked`.

The run printed `hostile calls refused: 71 (+1 locked copy_field); pasteboard still "user text"`. No error text contained the password, the one-time secret or the passkey value.

Uppercase hex is a valid id and names the same entry, so it was not counted as hostile.

## 6. The unlock form's shown password

`ShownPasswordFieldTests` passed: `✔ Test "Parity lock-locked-password-key-file-security-key: the shown password has no Copy or Cut, writes nothing out"`.

My probe, `VerifyShownPasswordProbe`, ran in a hidden window and never gave the field focus. It set the editor up as editing does, with the whole text selected:

```
VERIFY writable types: 0; write and Services send refused for 10 types
VERIFY Services send: nil from the editor and 4 views up to the window
VERIFY validate: copy false, cut false, paste false, startSpeaking false, textFinderSetSearchString false, useSelectionForFind false; usesFindPanel false usesFindBar false field.menu nil
```

| Way out | Result |
|---|---|
| Writable types | None. |
| Write calls | `writeSelection(to:type:)` returns false for each of 10 text, RTF, HTML, URL and legacy types, and so does `writeSelection(to:types:)`. The private probe board stayed empty. |
| Services | `validRequestor(forSendType:)` is nil for every type, also with a return type. It is nil too for the field, the 3 views above it and the window. |
| Writing Tools | `writingToolsBehavior == .none`. |
| Context menu | Exactly Paste, Delete, Select All, with `allowsContextMenuPlugIns == false`, so there is no Look Up, Translate, Share or Speech. The field itself has no menu. |
| Force-click Look Up and Speech | `quickLook(with:)` and `startSpeaking(_:)` are the editor's own empty overrides, not the text view's implementations. Start Speaking validates false. |
| Find pasteboard ("Use Selection for Find") | Validates false, and the editor has neither the Find panel nor the Find bar. |
| Drag | `dragSelection` returns false. |
| Edit menu | Copy and Cut are disabled while the unlock form shows (`AppMain.swift`), and `copyCommand()` returns at once in that state. |

**Limits, as with the system's own password field once shown in clear:**
- The field's accessibility value carries the shown text. Showing it is the user's Show (rule 4).
- The system-wide Look Up shortcut and the "speak selection" accessibility shortcut need a key window, so they were not probed. They are listed for Mac QA.

## 7. Empty values and a failed write

**Empty values (v10).** The pasteboard held `"user text"` from "another app".

- These all returned `Copied { empty: true, seconds: 0 }`:
  - the empty password;
  - the empty username;
  - a username that is a reference to an empty username;
  - an empty URL (standard fields always exist).
- The pasteboard stayed `"user text"`.
- A custom field that does not exist gives `UnknownField`, which Swift shows as `MSG-COPY-EMPTY`.
- After App's own copy, an empty copy left App's copy in place. Notes with line breaks and `é ✓` were copied exactly.

**In Swift.** `Parity states-copied: an empty value copies nothing and says so (APP-03.5)` passed. The notice reads "Password is empty. Nothing to copy." (LD-181 (2)).

**Failed write.** `cargo test -p app-platform --lib -- --exact clipboard::tests::refused_copy_leaves_nothing_of_ours` printed `test … ok`, `1 passed`. A refused copy clears the older copy while it is still App's, and leaves another app's newer content.

The refusal hook exists only in the crate's unit-test build, so this check comes from that test plus a code read:
- `copy` clears first;
- `write` clears after a failed `writeObjects` only while the count is still the one `prepareForNewContents` returned (LD-170 (1), (2)).

## 8. Design parity: `states-copied`

These ran after the Swift tests in the copy:
- `swift design/parity/tools/ocr.swift app-shots/light/*.png app-shots/dark/*.png`;
- `node design/parity/tools/compare.mjs states`.

Output:

```
states: 13/13 PASS
states-copied                                  PASS                   L 1.58% (1) D 1.62% (1.04)
```

- **Report row:** `states-copied | present | present | 1.58 % (1 %) / 1.62 % (1.04 %) | 0 | 0 / 0 | 0 + 0 / 0 + 0 | PASS`. The project's own states report (Builder run) shows 1.55 % / 1.59 %.
- **Compared by eye.** I looked at `app-shots/light/states-copied.png` next to `reference/light/states-copied.png`. The notice is in the same place, centred and 20 above the foot, with the same fill, glyph and shadow.
- **Known difference, accepted (LD-181 (1)).** The card's words "Password copied. Clears in 10 s." replace the mockup's "Password copied · clipboard clears in 30 s", so the box is narrower.

My parity run was in the copy, so the project's `design/parity/states/` report was not rewritten.

## 9. Tests

**`cargo test -p app-platform -p app-ffi`, in the copy:**
- app-ffi lib: 24 passed;
- `clipboard`: 9 passed;
- `messages`: 7 passed;
- `option_a`: 8 passed, 1 ignored (by hand);
- `session`: 10 passed;
- app-platform lib: 20 passed, 6 ignored (child helpers).

That is 0 failed: real 52.6 s, user 398 s.

The clipboard tests by name:
- app-ffi `clipboard`: `app_03_copy_fields`, `app_03_3_copy_resolves_references`, `app_03_5_empty_value_copies_nothing`, `app_03_15_lock_close_and_quit_clear`, `app_03_15_lock_of_another_vault_clears`, `app_03_copy_code`, `app_03_copy_fingerprint`, `at_e03_copy_refuses_hostile_arguments`, `at_e03_copy_code_and_fingerprint_refuse_hostile_arguments`;
- app-platform: `copy_writes_text_and_both_markers`, `clear_only_while_still_ours`, `refused_copy_leaves_nothing_of_ours`, `countdown_clears`, `new_copy_restarts_countdown`, `countdown_leaves_newer_content`, `clear_stops_countdown`.

**Swift.** First `scripts/build-core.sh` printed `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`. Then:

`xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/v-e6s1-dd test -skip-testing:AppUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`

This ran on the copy as the Builder left it, with my Swift file not yet added. Result: `✔ Test run with 47 tests in 11 suites passed after 31.927 seconds`, `** TEST SUCCEEDED **`, exit 0. It included `ShownPasswordFieldTests`, `ScreenTests` ("Edit > Copy copies the password; the notice goes; quit locks every vault") and the four "Parity states-copied" tests.

**My driver.**
- Rust: `cargo test -p app-ffi --test verify_e6s1`. v01 ran alone; v02 to v11 ran with `--test-threads=1`. All 11 passed.
- One run failed first, on my own wrong assumption: that a missing URL field is refused. Standard fields always exist, so an empty URL correctly copies nothing. I fixed the test and v10 passed.
- Swift: `VerifyCopyPathTests` and `VerifyShownPasswordProbe` each printed `** TEST SUCCEEDED **`.

## Parity rows

- **SC-01, SC-02, SC-03:** verified on private pasteboards (this report). What remains is the general-pasteboard and real clipboard-history checks for Mac QA, below.
- **SC-01's countdown display:** App shows the copy notice instead (APP-03.11).
- **SC-01's selected-text copy:** has no path yet, because no unprotected vault text is selectable (LD-181 (5)).
- **SC-07** (command line copy) uses the same routine: `app-cli` `commands.rs` `clipboard()`, which in debug test runs is private only, through `APP_TEST_PASTEBOARD`. Its own cases belong to E12-S1's Verify, so the row stays open there.

## For Mac QA, with the owner's go (they need the general pasteboard, a key window or a second device)

1. **AT-D01 / V-A03-1:** a clipboard history app does not store a copied password.
2. **AT-D02** in the real app: cleared after 10 s, and left alone after a copy in another app.
3. **AT-D03** in the real app: ⌘L and ⌘Q leave the general pasteboard empty.
4. **Universal Clipboard:** a copy does not reach a second Apple device.
5. **Shown unlock password:** the system Look Up shortcut and the "speak selection" accessibility shortcut, with the field focused.

## Notes (not blocking)

- **N1.** `Clipboard::peek` and `write_as_other_app` are `#[doc(hidden)] pub` in product builds. They act only on private pasteboards: `peek` returns nothing and the write does nothing for the general one. Gating them behind a test feature would be tidier.
- **N2.** Each timed copy starts one sleeping thread. A superseded thread wakes after its delay and does nothing. This is harmless at human copy rates.
- **N3.** As LD-170 (3) says, private pasteboards stay until logout. My runs left a handful named `com.app.clipboard.<pid>.<n>`. A few still hold demo test text (`other`, `user text`, `other-app-text`, a demo fingerprint); none holds a password.

## CPU and clean-up

**CPU.** The largest runs:
- cargo test: user 398 s;
- build-core: user 384 s, wall 69 s;
- the full Swift run: user 108 s;
- my Swift runs: about 45 s each.

The driver build and the other runs add a few minutes. In total that is about 20 CPU-minutes, and no single run took over 70 s of wall time.

**Clean-up.** I deleted `/tmp/v-e6s1-target` (1.9 GB), `/tmp/v-e6s1-dd` (434 MB) and the copy `/tmp/v-e6s1-src`. `/tmp/v-e6s1-work` keeps my drivers, the logs and the demo public keys. All my processes ended on their own; none was left (`ps` showed no `v-e6s1` or `xctest` process), so I stopped nothing.
