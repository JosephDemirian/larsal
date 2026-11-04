# E8-S3 Typing on macOS and the Accessibility permission (INT-05.37 to INT-05.47, AT-G02, AT-G03)

Story: E8-S3. Card: [INT-05](../../spec/integrations/INT-05-auto-type.md). Decisions: LD-186 (3), LD-195, LD-196, LD-231, LD-232 (5); W-17. Code: `crates/app-autotype/src/typing.rs`, `crates/app-ffi/src/autotype_typing.rs`, `crates/app-ffi/src/autotype.rs` (`autotype_type`, `autotype_locked`), `crates/app-platform/src/macos/keyboard.rs`, `macos/App/AutoType.swift`, `macos/App/AutoTypeTyping.swift`, `macos/App/Platform/Accessibility.swift`, `macos/App/AppDelegate.swift`.

## Round 1 (2026-10-30 06:02 to 06:45, signed)

Role: Verify, round 1, after the Builder's fix round and Checker 1's re-check. I did not build or check this story. I read the reference source only to compare how it types (its Mac typing part and its typing loop); nothing was copied.
Result: **signed.** Every INT-05 typing and permission case the build reaches passes, through the fake sink and the fake permission. AT-G02 and AT-G03 hold through the typing engine. No test posts a real event, shows a prompt, registers a real hot key or reads a real window. Real typing into another app, the real permission prompt and the real hot key go to Mac QA with the owner's go.

### Numbers

- **Rust** (private copy): `cargo test -p app-autotype -p app-ffi -p app-platform` gave 24 suites, **406 passed, 0 failed, 11 ignored** (`test exit 0`), before the mutants and again after them. `tests/int05_typing.rs` 14 of 14, app-ffi `tests/autotype_typing.rs` 2 of 2, the layout, `cg_flags` and keyboard unit tests ok. `cargo clippy -p app-autotype -p app-ffi -p app-platform --all-targets -- -D warnings`: `clippy exit 0`. `cargo fmt --all -- --check`: `fmt exit 0`. `scripts/build-core.sh` (own `CARGO_TARGET_DIR`): `build-core (debug): target/app-core/AppFFI.xcframework and target/app-core/Swift/AppCore.swift`, exit 0.
- **Swift** (private copy, own derived data, AppUITests skipped, `SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`): `✔ Test run with 309 tests in 41 suites passed after 254.576 seconds.` `** TEST SUCCEEDED **`, at load average 19 to 25. Every Auto-Type test passed, among them AutoTypeTests' 21 (`✔ Suite AutoTypeTests passed`).
- **My probes:** Rust, 16 tests written from the card (about 120 checks), **16 of 16 pass**. app-ffi, 3 tests, **3 of 3 pass**. Swift, 6 tests, **6 of 6 pass** (`✔ Test run with 27 tests in 1 suite passed`: AutoTypeTests' 21 plus my 6).
- **Mutants:** **37** in the private copy: 25 Rust and 12 Swift. Story tests catch **28**. My probes catch 4 more (R15, R17, R26, S13). 5 survive: R24 and R25 can only be seen with real keys or real posting (Mac QA), and R21, S5 and S6 are small test gaps (notes N1 to N3).
- **Lint and names** (shared tree): `swift format lint --strict` on the five E8-S3 Swift files gave exit 0. SwiftLint 0.65.1 `lint --strict --quiet` on the same files gave exit 0. On the whole tree it gave exit 2, with 5 errors, all in other agents' files: CopySelectionTests.swift:16, NewVaultTests.swift (file length and type body length) and PasteboardProof.swift:30 (twice). `scripts/check-names.sh`: PASS (see Cleanup).

### Setup

- **Private copy.** `rsync -a --exclude target --exclude app-shots` to `/tmp/e8s3-verify-copy` at 06:07:51 (143 MB). `CARGO_TARGET_DIR=/tmp/e8s3-verify-target`, `-derivedDataPath /tmp/e8s3-verify-dd`, the copy's own `scripts/build-core.sh`. Probes and mutants lived only in the copy.
- **The verified snapshot** (SHA-256, first 12 digits, at the sync): typing.rs `aea567590bef`, lib.rs `1197de6dbd7a`, int05_typing.rs `0ef70554bcfc`, autotype_typing.rs `ac02f9ecbf20`, autotype.rs `cdfeea33672f`, tests/autotype_typing.rs `6227491a9bfd`, keyboard.rs `2622dd0e4710`, AutoType.swift `8d5f1bfea075`, AutoTypeTyping.swift `d7eea17a93d2`, AutoTypePicker.swift `74bdc0eab51d`, Accessibility.swift `49b51fab43be`, AppDelegate.swift `118a34287f26`, AutoTypeTests.swift `1e9e42e7fc27`, AutoTypeTypingTests.swift `869ad0425d4c`, AutoTypeUnlockTests.swift `13d239f1bd4d`. At 06:32, `shasum -c` showed all 15 equal in the shared tree, so no other agent changed them during the run. The copy's files were equal too, once the mutants and probes were taken out.
- **Rule 10.** No event was posted to any process. No prompt, no System Settings, no real hot key, no real window title, no window ordered front. The general pasteboard was not touched. Views were rendered offscreen by the tree's own tests. The only system reads were the installed keyboard layouts (TIS, read-only) and two permission checks without a prompt (part 4).
- **Rule 11.** Every process I started ended by itself. In the shared tree I wrote only this file and the E8-S3 status line.
- **CPU.** The longest single run was the full Swift run: 5 min 49 s from start to end. The 12 Swift mutants took 9 minutes in total (06:23 to 06:32), and the 25 Rust mutants 5 minutes (06:17 to 06:22).

### 1. Every INT-05 typing and permission case the build reaches

"Story" means the tree's test, "probe" my own test, and "QA" the Mac QA session with the owner's go. Times are on the fake clock. Unless a case says otherwise: S-AT-09 500 ms, S-AT-10 25 ms, and a US table from `Events.h`.

| Case | What ran | Result |
|---|---|---|
| T01 INT-05.40 | Story t01; probe v_t01 | Text `Username`, 0x30, text `Password@1`, 0x24. First event at 500 ms, then 25 ms apart. `Finished(20)` |
| T02, T04, T13, T14 | Probe | `{x}`, `}{`, `{}`, `{}()()[]+%^~#`, `+++~@`, all as Unicode text |
| T05, T10, T11, T12 | Probe | 0x30⇧, 0x00⌃, 0x09⌘, 0x76⌥. Then 0x30, 0x24, 0x79, 0x79, 0x33. Then 0x57, 0x45, 0x4E, 0x43, 0x4B, 0x36. T12 gives no event |
| T07 | Probe | 3 × 0x30, nothing for `{SPACE 0}`, 100 × 0x7B |
| T15, T16, T18 | Story; probe | `{DELAY 500}` waits 500 ms. `{DELAY 10000}a` puts `a` at 10,500 ms. `{DELAY 10001}` gives MI05-13. 50 ms after `a`, 0 ms after `b`, 40 ms after `c`. `{DELAY=501}` gives MI05-14 and `{DELAY = 5}` MI05-19. T18: `a` at 100 ms, `b` at 600 ms, the clock ends at 1,100 ms. S-AT-09 99,999 is used as 10,000 |
| T19, T41, T101 (recorder half) | Probe | 0x00⌘ then 0x33, once. `{CLEARFIELD}new` gives ⌘A, Delete, `n`, `e`, `w`. T41: ⌘A at 505 ms, after the 5 ms wait; no code; no pick |
| T20, T21 | Story; probe | The code of the 10:00:30 step, not the 10:00:00 step. `x{TOTP}` with no code types `x`. Invalid settings give MI05-16 |
| T22, T24, D-INT05-9 | Story; probe | `{PICKCHARS}` asks for 14 buttons and types nothing (`Stopped(0, Picks)`). Picks 1 and 3 with Tab give `d`, 0x30, `m`. An unfilled plan types nothing |
| T26, T97 (fake US) | Story; probe | 0x00, 0x0B⇧, text `c`. `{MODE=VIRTUAL}aZ1é` gives 0x00, 0x06⇧, 0x12, then `é` as Unicode text (a dead key) |
| T97, T98, T99 on macOS's own tables | Swift probe dumped the tables from `UCKeyTranslate`; Rust probe typed with them | US: `aZ1é` as above; `{CLEARFIELD}` = 0x00⌘, 0x33; `ç©` by key with ⌥ (0x08⌥, 0x05⌥); every printable ASCII character has a key; `^ü` gives MI05-23. French: `#a` = 0x0C⌘ (not ⌘Q); `{CLEARFIELD}` = 0x0C⌘, 0x33; `aq1` = 0x0C, 0x00, 0x12⇧ |
| T98 (fake AZERTY), LD-186 (3) | Story; probe | 0x0C⌘. The fewest modifiers win, a combination needs the plain form (`^!` gives MI05-23), and `^A` presses 0x00⌃ |
| T27, T33, T34, T35, R05-3 | Story (T33, T35); probe | Ignored commands type only `x`. The notes' CR LF, LF and CR each give 0x24, Tab gives 0x30, BEL is dropped. `+{USERNAME}` is text with no flags. `é😀`: two pairs, the emoji in one event holding `D83D DE00`, code 0 and flags 0 on every event. In the sequence, LF and CR are dropped, Tab is 0x30 and NUL is dropped |
| R05-4 | Probe | `x^%v` with S-AT-07 ⌃⌥V gives MI05-26 |
| T90, T91, T103 (AT-G02) | Story Rust t90_t91_t103; Swift `focusChange` (another app, and another window of the same app); probes | `a`, `b`, `c` only, then `Stopped(3, Changed)`. No check after the stop (5 checks: step 1 and 4 keys). Target quit after `b`: `a`, `b` only. After the first no, the run never resumes, even when later answers are yes. A stop inside `{DELAY 10000}`: the next key is checked and never goes out. Swift: 6 reads, `Auto-Type stopped: window-changed after 3 keys`, one alert sound |
| T103 in the controller | Swift probe `vTargetQuits` (no app in front after 2 keys) | 5 reads, one alert sound, `window-changed after 2 keys`. No MI05-10 and no window: the only windows were the picker shown and hidden |
| T92 | Story (Rust, app-ffi lock and `autotype_stop`, Swift `shortcutStopsTyping` off the main thread); probe | A stop after 0 to 7 presses of `a#v{TAB}`, key-code `B`, `😀` and `{CLEARFIELD}` always leaves every key-down with its key-up. A lock during the third key's check: `Stopped{keys: 2, reason: "stopped"}`. The shortcut: 1 key, `stopped`. A stop before a run does not reach the next run. Swift probe `vLockStops`: a lock during the second key's check gives `stopped after 1 keys` and no look after it |
| T93 INT-05.38 step 3 | Story; probe | ⌃ held until 1 s: `a` at 1,000 ms. Held until 2,500 ms (2 s after the start delay): still in time. Held until 2,501 ms or 3 s: `Stopped(0, Held)`, no event |
| T110 INT-05.38 step 1 | Story; Rust probe; Swift probe `vNeverBack` | Never in front: 41 looks, 50 ms apart, over 2,000 ms; `Stopped(0, NotInFront)`; no start delay waited; no event. Swift: macOS asked for pid 4242 once, 1 + 41 reads, `Auto-Type stopped: not-in-front after 0 keys`, one alert sound. Step 1 comes before the start delay: in front at 500 ms, the delay ends at 1,000 ms, the keys are let go at 1,000 ms, and `a` is typed at 1,000 ms |
| INT-05.38 step 1 after the picker | Story `targetAskedBack` | macOS is asked for the target (`[4242]`), and the run types to the end |
| T60, T111 (INT-05.37) | Story T60 (E8-S2); Swift probes `vAppInFront`, `vNoFocusedWindow` | App in front: 1 read, no permission check, no layout read, nothing shown. An app with no focused window: an empty title, the header `Type into Notes`, and typing to the end (nil equals nil) |
| T94, V-INT05-5 (INT-05.44) | Story `accessMissing` | Two presses without access: MI05-30 twice, macOS's request once, no picker, no layout read, 2 reads. Granted: the next press goes on with no restart. MI05-30's texts and its pane URL are exact |
| T88 (INT-05.35) | Story `settingsNotice` | MI05-32, then MI05-31 after a simulated activation. The page never asks macOS (`requests == 0`) |
| T102, INT-05.43 | Story keyboard.rs test, `cg_flags` test, t98_t102; app-ffi probe | Events come from the private source (state id not 0 or 1, and equal to what the event carries), with exact flags; text has code 0 and flags 0; the emoji is one event. All 16 modifier sets map to exactly their Quartz bits (16 of 16) |
| T106, INT-05.47 | Story `failureLine`, `focusChange`, `shortcutStopsTyping`; Swift probes | `Auto-Type failed: MI05-12`; `Auto-Type stopped: window-changed after 3 keys`; `stopped after 1 keys`; `not-in-front after 0 keys`. No title, value or sequence. `Logger.app.debug("\($0)")` is private by default (no `privacy: .public` in the E8-S3 files) |
| INT-05.41 (the table) | Story `layoutTable`; Swift probe `vDumpLayouts` | US 190 keys, French 198, German 196, Dvorak 190. Every key is one scalar, no control or private-use character, code below 0x80, no keypad. On US, ⌥E, ⌥U, ⌥I, ⌥N and ⌥` are left out (dead keys). On Dvorak, `s` is 0x29. The layout is read once per run (T94 `layouts == 1`) |
| LD-231 (3) | app-ffi probe `v_quartz_wait_ends_on_stop` (a private source is made; nothing is made or posted) | A 10 s wait with the stop already up returns at once. A 10 s wait with the stop raised at 200 ms ends 215 ms in |
| Rule 10, the hidden launch | app-ffi probe `v_hidden_launch_never_posts`, run alone with `APP_TEST_HIDDEN=1` | `autotype_post_events` keeps the recorder. Without the variable the probe's own check fails, as it should (control) |
| T105, INT-05.45 | By reading the bindings | Swift to Rust: the window title, the UTC offset, the layout table, a row index with an action, and the window check's yes or no. Rust to Swift: picker rows (display title and user name, masked under LD-207 and S-VIEW-06), plan handles, MI05 reasons with their ids (sequence tokens only, INT-05.18), and the key count with a reason code. No field value, code or picked character crosses. `AutoTypeEnd` has only `keys` and `reason` |
| T95, INT-05.33, INT-05.36 | Not built (LD-231 (6), W-06) | Type Login, the pick dialog and the shortcut recorder wait for the owner's mockup OK |
| INT-05.32 | Not this story | Owned by E13-S6 part i (LD-232 (5)), with test T74 |
| T96, T97, T100, T101 and T104 (real target), T107, V-INT05-1 to V-INT05-8 | QA | See part 4 |

### 2. AT-G02 and AT-G03 through the typing engine

- **AT-G02 (switch windows during typing: typing stops).** `type_plan` asks `go_on` before every press and ends at the first no. app-ffi reads the stop flag before and after Swift's window check. Swift's check compares the pid and the focused-window element, and no app in front counts as a change. The proof is the rows T90, T91, T103 and T92 above, at three levels: the engine, app-ffi and the Swift controller. Mutants R1 (no check before a press), S1 (pid only, as the reference does) and S13 (no app in front counts as the same) each fail a test.
- **AT-G03 (bounded, nothing hangs).** Run through `type_plan` with S-AT-09 10,000 and S-AT-10 500 (the largest values). The bound is 2 s + start delay + 2 s + 500 ms per action + 60 s:

| Sequence | Result | Fake clock | CPU |
|---|---|---|---|
| `{TAB 100}` × 100 | 10,000 presses | 5,010,000 ms (bound 5,074,000) | 202 µs |
| the same plus `a` | MI05-21 | none | none |
| `{DELAY=500}` + 9,999 × `a` | 9,999 presses | 5,009,500 ms | 446 µs |
| `{DELAY=500}` + 10,000 × `a` | MI05-21 | none | none |
| `{DELAY 10000}` × 6 | 0 presses | 70,000 ms (bound 77,000) | 0.1 µs |
| `{DELAY 10000}` × 7 | MI05-22 | none | none |
| `{DELAY 0}` × 10,001 | MI05-21 (zero waits count, LD-186 (2)) | none | none |
| `{USERNAME}` × 1,250 / × 1,251 | 10,000 presses / MI05-21 | 5,010,000 ms | 378 µs |
| `{MODE=VIRTUAL}` + `{PASSWORD}` × 1,000 | 10,000 presses | 5,010,000 ms | 227 µs |

  No run makes more than 10,000 presses, and every fake clock stays within its bound. The real sink's waits end at once on a stop (LD-231 (3), probe above), so a lock or the shortcut ends even the longest run (about 84 minutes, at the 500 ms pause cap) right away.

### 3. No real event and no prompt in any test (grep and read)

`grep -rnE "CGEventPost|CGEventTapCreate|PostToPid|AXIsProcessTrusted|kAXTrustedCheckOptionPrompt|AXTrustedCheckOptionPrompt|RegisterEventHotKey|osascript|keystroke|NSWorkspace\.shared\.open|x-apple\.systempreferences|autotype_post_events|autotypePostEvents|NSPasteboard\.general|generalPasteboard" crates macos scripts` (target excluded) found:
- `CGEventPost` only in `Keyboard::post` (keyboard.rs:118). That is reached only through app-ffi's `Quartz` sink, and only when `post` is true. `post` is set only by `autotype_post_events`, which a hidden launch refuses (probe above). Its only caller is AppDelegate.swift:62, inside `if !launchHidden()`. No test calls it: tests/autotype_typing.rs says so, and the grep finds no test caller.
- `AXIsProcessTrustedWithOptions` with the prompt only in Platform/Accessibility.swift:13. `SystemAccessibility()` is made only at AppDelegate.swift:61. AppTests has no host app (no `TEST_HOST` or `BUNDLE_LOADER` in project.pbxproj), and its membership list, the only App files AppTests compiles, has neither AppDelegate.swift nor Platform/Accessibility.swift.
- `AXIsProcessTrusted()` (no prompt) is the default of AppSettingsModel.swift:52. Only a check, and `settingsNotice` passes a fake.
- `RegisterEventHotKey` only in `CarbonHotKeys` (AutoType.swift:95). `CarbonHotKeys()`, `SystemWindows()` and `AutoTypePanel.present` are made only at AppDelegate.swift:58. Tests use `FakeHotKeys`, `FakeWindows`, `GatedWindows` and my `ScriptedWindows` and `LockingWindows`.
- `NSWorkspace.shared.open(pane)` only in `AccessAlert.show()`, after the user clicks its default button. `show()` returns at once in a test or hidden launch (the `XCTestConfigurationFilePath` and `launchHidden()` guard), and every test replaces `needsAccess`. The settings page's pane URL is a link that opens only on a click.
- No `osascript`, `keystroke`, `PostToPid` or event tap anywhere. `NSPasteboard.general` appears only in PasteboardProof.swift:12, which reads `changeCount` (another story's proof helper), and in app-platform pasteboard.rs:62 for App's own launch (E6-S1).
- Typing puts nothing on a pasteboard: none of the E8-S3 files names a pasteboard (INT-05.40, D-INT05-4).
- `activate` (`NSRunningApplication.activate`) is replaced by a fake in every Auto-Type test (`autoType()`, `shortcutStopsTyping` and my probes); its default returns in a hidden launch.

### 4. The hidden probe, and what goes to Mac QA

A process started from this session cannot post events. My read-only probe (`swiftc` binary, no prompt) printed `CGPreflightPostEventAccess: false` and `AXIsProcessTrusted: false`. So `CGEventPostToPid` into a hidden helper I started would need the event-posting (Accessibility) permission, and macOS drops events from an untrusted process. I posted nothing. Under the brief and V-INT05-3, this is **needs Mac QA (owner's go)**, not a fail. Asking for the permission would show a system dialog, so I did not ask.

Mac QA with the owner's go: T96, T97, T100, T101 and T104 into the `AutoTypeTarget` helper; V-INT05-1 to V-INT05-8; T107 (the real hot key, registration only); the real MI05-30 and macOS's own permission request; T93 with physical keys (mutant R24); the session tap itself (mutant R25); macOS activating the target after the unlock panel (cooperative activation on macOS 14 and later); and the real Accessibility reads of INT-05.37 (V-INT05-4, V-INT05-8).

### 5. Mutants (private copy, own target and derived data)

Each mutant was applied with `perl`, checked as applied (`cmp`), run, then restored from a saved copy. Rust story commands: `cargo test -p app-autotype --test int05_typing`, `-p app-ffi --test autotype_typing` with `--lib autotype_typing::tests`, and `-p app-platform --lib keyboard`. Swift: `xcodebuild test -only-testing:AppTests/AutoTypeTests` (story tests plus my 6 probes). No mutant can make a test post: I made none that turns `post` on or calls `Keyboard::post`.

| ID | Change | Caught by |
|---|---|---|
| R1 | no window check before a press | t90_t91_t103, t92 (int05_typing.rs:288) |
| R2 | key-down only | t01, t15_t16_t18, t110 |
| R3 | 2,100 ms instead of 2,000 ms for the target and the modifiers | t93 (int05_typing.rs:335), t110 |
| R4 | no start delay | t93, t33, t15_t16_t18 |
| R5 | start delay before step 1 | t110 (int05_typing.rs:343) |
| R6 | key-code mode for all text | int_05_10, t90, t110 |
| R7 | only the first UTF-16 unit of an emoji | t35 (int05_typing.rs:149) |
| R8 | a plan with picks left types | int_05_10 (int05_typing.rs:359) |
| R9 | `{DELAY=n}` ignored | t15_t16_t18 (int05_typing.rs:242) |
| R10 | `{DELAY n}` ignored | t15_t16_t18 |
| R11 | `{TOTP}` 1 s early | t20 (int05_typing.rs:278) |
| R12 | a timed-out wait counts as ready | t110 (int05_typing.rs:342), t93 |
| R13 | no modifier wait | t93 (int05_typing.rs:327) |
| R14 | presses not counted | int_05_10, t20, t35 |
| R15 | the real sink's waits ignore the stop | story: **survived**; probe v_quartz_wait_ends_on_stop |
| R17 | `autotype_post_events` ignores a hidden launch | story: **survived** (AppDelegate guards it too); probe v_hidden_launch_never_posts |
| R18 | no fresh stop flag per run | int_05_39_t92 (tests/autotype_typing.rs:113) |
| R19 | a lock does not raise the stop flag | int_05_39_t92 (tests/autotype_typing.rs:85) |
| R20 | ⌥ forms dropped from the table | int_05_45 (autotype_typing.rs:193) |
| R21 | `not-in-front` logged as `keys-held` | **survived** (note N1) |
| R22 | text cut to one UTF-16 unit | keyboard test (keyboard.rs:198) |
| R23 | ⇧ added to every event | keyboard test (keyboard.rs:188) |
| R24 | Caps Lock counted as a held modifier | **survived**: real keys only, Mac QA |
| R25 | HID tap instead of the session tap | **survived**: real posting only, Mac QA |
| R26 | ⇧ and ⌥ bits swapped together (Checker's two-point mutant) | story: **survived**; probe v_cg_flags_all_sets |
| S1 | window check compares the pid only | AT-G02 T90, T91 (AutoTypeTests.swift:254) |
| S2 | the shortcut during typing does not stop it | T92 `shortcutStopsTyping` (AutoTypeTypingTests.swift:131) |
| S3 | macOS's request on every press | T94 (AutoTypeTypingTests.swift:66) |
| S4 | no permission check | T94 |
| S5 | App's own secure input not turned off before typing (step 4) | **survived** (note N2) |
| S6 | the target is asked to come forward only after typing | **survived** (note N3) |
| S7 | no ⌥ forms in the Swift table | `layoutTable` (AutoTypeTypingTests.swift:96) |
| S10 | no alert sound on a stop | AT-G02, T92 |
| S11 | no stop line in the log | AT-G02 (AutoTypeTests.swift:258), T92 |
| S12 | layout read before the permission check | T94 (AutoTypeTypingTests.swift:68) |
| S13 | no app in front counts as the same window | story: **survived**; probe Verify T103 (VerifyE8S3Probe.swift:77) |
| S14 | `typing` never set | T92 (AutoTypeTypingTests.swift:124) |

### 6. Compared with the reference (behaviour only)

The reference's Mac typing part makes each character as a key event with key code 0 and a one-unit Unicode string, from no event source, and posts it to the session tap. Key combinations come from fixed key positions, with their flags. Its typing loop checks once per action that the active window is the same (process level), retries a failed action up to 5 times, and waits the start delay before the first action. App does the same where the card says "as the reference", and goes further where the card says so: a private event source with explicit flags (INT-05.43), both UTF-16 units of a character in one event (INT-05.40), the layout lookup (D-INT05-5), a check of the window as well as the process (D-INT05-2), no retry, and the waits for the target and the modifier keys (INT-05.38). The session tap App uses matches the reference and INT-05.43.

### Notes, not blocking

- **N1** (R21): no story test checks the `not-in-front` or `keys-held` line. Smallest fix: a controller test like my `vNeverBack`, which expects `Auto-Type stopped: not-in-front after 0 keys`. Also, a stop raised during step 1's or step 3's wait is logged as `not-in-front` or `keys-held`, not `stopped`, because only `Changed` looks at the flag (autotype_typing.rs 113 and 114). Nothing is typed either way; only the log word differs.
- **N2** (S5): INT-05.38 step 4 (`SecureInput.shared.release()` in `AutoType.type`) has no test. App is not active while typing, so its own call is already off (APP-10.8). Smallest fix: one test with a fake `SecureInput.shared.system` that expects `disable` once App's call was on.
- **N3** (S6): `targetAskedBack` proves that macOS is asked, not that it is asked before the run waits: the fake windows ignore activation. Smallest fix: a fake whose target comes to the front only after `activate` was called.
- **N4** (R15, R17, R26, S13): four guarantees hold only by my probes: the stopped waits end at once (LD-231 (3)), the hidden launch keeps the recorder, `cg_flags` (⇧ and ⌥ swapped together), and no app in front stops typing. Each needs one story test, the same as my probes.
- **N5**: `KeyboardLayoutTable.current()` makes both TIS copies up front (AutoTypeTyping.swift:52 to 54). When the first has layout data, the second is never released: one input-source reference leaks per run. Smallest fix: make the ASCII-capable copy only when the first fails.
- **N6** (Checker's notes, confirmed by reading): `type(_:into:front:)`'s `front` is always nil or the target's pid. A shortcut press between `typing = true` and `autotype_type` making the run's fresh stop flag is lost; the window is only as long as starting the thread takes.
- **N7**: LD-231 (1) says MacPass posts to the session tap; INT-05's research note says it posts at the HID level. One of the two needs correcting (lead or Spec). This could not be settled without reaching the web. INT-05.43 and the code agree: the session tap.
- **N8**: whole-tree SwiftLint exits 2 on 5 errors in other agents' files (Numbers). The E8-S3 files lint clean.

### Cleanup

After this file and the status line were written, `scripts/check-names.sh` in the shared tree gave `names: PASS (3185 files scanned, 16 vault files name-only)`, exit 0. The probes and mutants lived only in `/tmp/e8s3-verify-copy`. Afterwards I deleted `/tmp/e8s3-verify-copy`, `-target`, `-dd`, `-hold`, `-probe`, `-layouts` and the log and sum files. `ls -d /tmp/e8s3-verify*` then found nothing (`no matches found`).
