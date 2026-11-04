# E6-S2 Lock signals (SR-01, SR-02, SR-03; the APP-09 lock request; AT-K01)

Story: E6-S2 Lock signals.
- Cards: [APP-02](../../spec/app/APP-02-lock.md); also APP-03.15, APP-06.5 and APP-09.12.
- Decision: LD-187.
- Code:
  - `macos/App/Platform/LockSignals.swift`;
  - the `AppDelegate` hook (`applicationDidFinishLaunching`);
  - `MainWindowModel.lockAll()` and `refresh()`;
  - `macos/AppTests/LockSignalsTests.swift`, with the weak spy.

Date: 2026-10-28.
Role: Verify. I did not build or review this story. No reference access was needed, and none was used.

Result: **signed.** Every check passed. Only the real system events are left: AT-K01 on this Mac needs a real screen lock, sleep and user switch, and real input in another app. Those wait for Mac QA with the owner's go (AGENTS.md rule 10).

**General pasteboard change count:** `10124` before any build. It was `10124` before and after every test run, and `10124` at 07:10:04 after the last run. Nothing I ran wrote to it or cleared it.

| Check | Result |
|---|---|
| 1. Each E6-S2 trigger has a passing test, by T-number | PASS. The 22 `LockSignalsTests` pass. 3 `app09` cases cover the lock flag (T29 to T31). The Verify driver passes 4 tests, 18 cases. The T-cases left for later are listed in section 2 with reasons. |
| 2. Rust lock-all first, then Swift state | PASS, proven by my own driver for all 7 triggers: screen lock, sleep, user switch, idle, minimize, Hide App and the channel. When Rust's `lockAll()` returns, App's copy is already gone from its private pasteboard and every vault is locked. At that moment the shown value, the live codes, the detail and the typed unlock password are still held. Afterwards all of them are gone. |
| 3. Mutation proof | PASS. 7 mutations were tried, one at a time: screen lock, sleep, idle, minimize, the channel, the relay and the order. Each one makes at least one test fail. Each file was restored and confirmed with `cmp`. |
| 4. No real notification, owner's clipboard untouched | PASS. Every `post` in the tests goes to a private `NotificationCenter()`. An observer on the real system centers saw 0 notifications during the 7 driver triggers. The general pasteboard count was the same before and after every run. |
| 5. swift format and SwiftLint | PASS on all of `macos/` and on the four E6-S2 files. Both exit 0, with no output. |

## Setup

- **Isolated copy.**
  - `rsync -a --exclude .swiftpm macos /tmp/verify-e6s2/`, plus copies of `target/app-core` and `testdata`. `AppCore/Generated` points at the copied core.
  - The core is a debug build: its library is 176 MB, against 48 MB for the release one.
  - Before any change, `cmp` showed the copy's `LockSignals.swift`, `MainWindowModel.swift`, `AppDelegate.swift` and `LockSignalsTests.swift` were the same as the project's.
  - At the end, `cmp` showed those four, `Front.swift` and `UnlockModel.swift` still unchanged in the project.
  - Only `VaultModel.swift` changed in the project during the run. `afterChange` moved out of it as part of the editor work. `leave()` and `clear()`, which the lock uses, are unchanged.
- **Build note.**
  - `EditorModel.swift` and `VaultEdits.swift` were already in the AppTests file list when I copied, and `EditorScreen.swift` compiled. The plain copy gave `** TEST BUILD SUCCEEDED **` with `SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`.
  - My one change to the copy's project: `Platform/Front.swift` joined the test target, so the driver can call the real `WindowEvents`.
- **Commands.** `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`, then:

  ```
  xcodebuild -project macos/App.xcodeproj -scheme App -destination platform=macOS -derivedDataPath /tmp/verify-e6s2/dd build-for-testing SWIFT_TREAT_WARNINGS_AS_ERRORS=YES
  xcodebuild ... test-without-building -only-testing:AppTests/LockSignalsTests -only-testing:AppTests/VerifyE6S2DriverTests
  ```

- **No windows.** AppTests has no test host, so the tests run in the xctest runner with no window. The `app09` cases start `App.app` with `APP_TEST_HIDDEN=1`, and each run is stopped by its own child handle. Afterwards, `pgrep` found no App process left.
- **Rust.** `CARGO_TARGET_DIR=/tmp/verify-e6s2/cargo-target`, `--offline`.

## 1. Triggers by T-number

Final run, with the originals rebuilt: `xcodebuild ... test-without-building -skip-testing:AppUITests`, giving `Suite LockSignalsTests passed`, `Suite VerifyE6S2DriverTests passed`.

| Trigger (APP-02) | T-cases | Tests that pass |
|---|---|---|
| Screen lock `com.apple.screenIsLocked` (APP-02.5) | T01, T12, T13 | `APP-02 T01: a screen lock locks every vault`; `APP-02 T12, T13: com.apple.screenIsLocked locks when the setting is on` |
| The system distributed center uses `.deliverImmediately` (LD-187) | T12 in the background | `APP-02 T12: the system distributed center delivers the screen lock at once, also in the background`. The spy holds the relay weakly. It checks the name, `behaviour == .deliverImmediately`, that the relay is still alive, and that firing it locks. |
| Sleep `willSleepNotification`, locked before the handler returns (APP-02.6) | T14 | `APP-02 T14: on will-sleep the vault is locked before the handler returns`. The vaults are locked and `window.main == nil` when `post` returns. |
| User switch `sessionDidResignActiveNotification` (APP-02.7) | T15 | `APP-02 T15: the session resigning active locks when the setting is on`, also with the setting off |
| Idle: settings restart the countdown (APP-02.1) | T02 | `APP-02 T02: ...` (lock at 240) |
| Idle: activity and throttle (APP-02.2) | T03, T04 | `APP-02 T03: each key restarts the countdown`; `APP-02 T04: events within 0.5 s of a restart are ignored` |
| Idle: own input only (APP-02.2) | T05 (part) | Verify driver: `input that reaches App's own event queue restarts the idle countdown`. A `mouseMoved` posted to App's own queue and dispatched with `sendEvent` reaches the local monitor of `watchInput()`: no lock at 10 s, lock at 15 s. By code read, the only idle source is `NSEvent.addLocalMonitorForEvents`. `grep` finds no global monitor, `CGEventSource` or HID idle time in `macos/App`. `activity()` is called only from that monitor, so the clipboard countdown and the session never count as activity (T06 by code read). |
| Idle: bounds (APP-02.3) | T07, T08 | `APP-02 T07, T08: the period is used within 10 s and 12 h` (3 gives 10, 100000 gives 43200, the default is 300) |
| Idle: off (APP-02.3) | T09 | `APP-02 T09: idle lock off never locks` |
| Idle: nothing unlocked (APP-02.3) | T10 | `APP-02 T10: the countdown runs with nothing unlocked, does nothing, and starts again` |
| Idle: late timer (APP-02.20) | (no T-number) | `APP-02 idle: input after the period locks first and never restarts the countdown` |
| Minimize: delay `clamp(r, 1, 20)` (APP-02.8) | T16 to T20 | `APP-02 T16`, `T17`, `T18`, `T19`, `T20`. `r` comes from a fake source here (see section 2). |
| Minimize after unlock turns lock on minimize off (APP-02.9, settings model) | T24 | `APP-02 T24: minimize after unlock turns lock on minimize off` |
| Hide App counts as minimize (APP-02.10, D-A02-2) | T25 | `APP-02 T25: Hide App counts as minimize (D-A02-2)` |
| Minimize and Hide App are off by default | (defaults) | Verify driver: `minimize and Hide App do not lock with the default settings`. Minimize and Hide are posted, the clock steps to 25 s, and there are 0 locks. The default settings are idle on, screen lock on, user switch on and minimize off. |
| The channel `lock` (APP-09.12, APP-02.12) | T29, T30, T31 | Swift: `APP-09.12 lock request: Rust's lock-all, then the session-changed refresh, clears the Swift state`. Rust: `start::tests::app09_12_activate_and_open_raise_the_window_lock_does_not ... ok`. Against the copy's `App.app`: `app09_12_a_lock_request_is_delivered ... ok` (T29, M09-02, exit 0), `app09_11_a_lock_without_an_instance ... ok` (T30), `app09_11_b_lock_with_a_stopped_primary_gives_m09_05 ... ok` (T31). The `app09` test binary holds the path `/private/tmp/verify-e6s2/crates/app-ffi/../../target/xcode/.../App.app` (`strings`), so it ran the copy's build. |
| Clipboard and screen-layer state on lock (APP-03.15, AT-E07) | T52 (no timing) | `APP-02 T52, APP-03.15: a lock signal clears the clipboard in Rust, shown values and live codes`. Rust: `app_03_15_lock_close_and_quit_clear ... ok` and `app_03_15_lock_of_another_vault_clears ... ok`. |
| The unlock field (APP-06.5) | APP-06 T11 | `APP-06 T11: a lock signal clears the typed password` |

The Builder's suite: 22 tests, all passed. My driver: 4 tests with 18 cases, all passed.

The full unit suite in the copy ran 81 tests in 15 suites. 78 passed. 3 failed, all from the editor work in progress, not from E6-S2:
- `Parity main-main-window-light: later-story controls are drawn and disabled`;
- `Parity states-more-menu: ...`;
- `Parity states-recycle-bin: ...`.

They expect "Edit entry", "New Entry", "Clone Entry…", "Restore" and similar controls to be disabled, and the editor now enables them.

## 2. T-cases not proven here, with reasons

| Case | Waits for | Reason |
|---|---|---|
| AT-K01: a real screen lock, sleep, user switch and idle on this Mac; T12, T14, T15 and T52 with real events and timing; T05 with real typing in another app; T49 (window not moved, App not brought to front) and T51 (no unlock on screen unlock) in the real app | Mac QA, with the owner's go | AGENTS.md rule 10: no agent locks the screen, sleeps the Mac, switches users or types into another app. By code read, `lockAll()` never calls `Front.bring()`, and nothing in `LockSignals` unlocks. |
| T06 browser bridge requests | E7 (browser bridge) | The bridge does not exist yet. By code read, nothing but the local event monitor calls `activity()`. |
| T17, T18, T20 with the real `r`; T21 (no stale value) | E5-S9 (settings), with a Rust export of the clipboard countdown's seconds left (LD-187 "Later") | `AppDelegate` passes no `secondsLeft`, so `r` is 0 and `d` is always 1 s (see the note in `LockSignals.init`). This is harmless today: lock on minimize is off and has no switch before E5-S9. The formula is proven with a fake source. |
| T22 hide to the menu bar icon; the hide-on-copy path (APP-03.17) | E5-S11 (APP-08 menu bar icon), and the APP-03.17 option | Neither exists yet. |
| T23 the settings switch and `MSG-LOCK-MIN-CONFLICT` | E5-S9 | No settings screen yet. The settings-model half is T24, which passes. |
| T11, T32, T33 manual lock actions and menus | E5-S11 | These are not automatic triggers. |
| T26 to T28 the quit flow with prompts | the save and quit stories (APP-02.11, APP-05) | `quit()` is `lockAll()` then `clearClipboard()`, as verified in E6-S1. The prompts need the editor and save work. |
| T34 browser lock, T35 Auto-Type relock | E7, E8 | Those integrations do not exist yet. |
| T36 to T48, T50, T53 to T59: the lock routine's steps, saves, recovery copies, the unlock view after a lock | the session, save and unlock stories (APP-02.15, APP-02.16, APP-05, APP-06) | These belong to Rust's lock and the save flow. E6-S2 only calls `lock_all()`. |
| A typed unlock password when idle fires with nothing unlocked, or when the channel locks with nothing unlocked | E5-S3 (the 30-second clear of APP-06.5), E5-S10 (LD-187 "Later") | APP-02.3 says an idle firing with nothing unlocked does nothing. LD-187 already plans the channel case. With at least one vault unlocked, every trigger clears the field (section 3). Note, not a failure. |

## 3. Verify driver: Rust lock-all first, then Swift

The file was `macos/AppTests/VerifyE6S2DriverTests.swift`, in the copy only and deleted with it.

- **Setup.** Each trigger fires through a `LockSignals` wired as `AppDelegate` wires it:
  - `unlocked: { session.vaults().contains { !$0.locked } }`;
  - `lock: { [window] in window.lockAll() }`;
  - private centers and a fake clock.
- **Order probe.** The session is a subclass that records the state at the moment Rust's lock-all returns:

  ```swift
  private nonisolated final class OrderSession: Session, @unchecked Sendable {
      var atReturn: (@MainActor () -> Void)?
      var calls = 0
      override func lockAll() {
          super.lockAll()
          calls += 1
          MainActor.assumeIsolated { atReturn?() }
      }
  }
  ```

- **How each trigger fires.**
  - Screen lock: `distributed.post`.
  - Sleep and user switch: `workspace.post`.
  - Idle: no lock at 299.9 s, then a lock at 300 s.
  - Minimize and Hide App, with the setting on: no lock at 0.9 s, then a lock at 1.0 s.
  - Channel: `session.lockAll()`, then the real `WindowEvents(window:).sessionChanged()`, then a wait of up to 2 s for the refresh.
- **`viewState`, 7 cases, all passed.**
  - Setup: Personal and Work unlocked, Personal shown, an entry with a one-time code selected, the code ticked, the password shown and the password copied.
  - The copy's private pasteboard is the one `com.app.clipboard.<pid>.<n>` whose change count moved, exactly 1. It holds the shown value.
  - Then, for each trigger:
    - `session.calls == 1`.
    - At Rust's return: the pasteboard string is `nil`, every vault is locked, and `shown`, `codes`, `detail` and the opened model are still there.
    - Afterwards: the pasteboard is `nil`; `shown`, `codes`, `detail` and `rows` are empty; `window.opened` is empty and `window.main == nil`; no vault is unlocked.
    - `SystemWatch.seen == 0`. This observer sits on `DistributedNotificationCenter.default()` (`com.apple.screenIsLocked`, `.deliverImmediately`) and on `NSWorkspace.shared.notificationCenter` (will-sleep, session resign active).
    - `NSPasteboard.general.changeCount` is unchanged.
- **`unlockField`, 7 cases, all passed.**
  - Setup: Personal unlocked, Family shown and locked, `demo-pass-9` typed and Show on.
  - At Rust's return, the field still held the text with Show on. Afterwards it was empty with Show off, and every vault was locked.
- **Run:** `Test run with 4 tests in 1 suite passed after 5.375 seconds`.

## 4. Mutations

Runner: `/tmp/verify-e6s2-tools/mutate.sh`. For each mutation it:
1. replaces exactly one pattern in the copy;
2. rebuilds with warnings as errors;
3. runs `LockSignalsTests` and the driver (26 tests);
4. restores the file from a saved original and runs `cmp`.

Each run printed `restored, cmp identical`. At the end, `cmp` against the project printed `restored = project` for `LockSignals.swift` and `MainWindowModel.swift`. After the mutations, the originals were rebuilt before the final run.

| # | Trigger | Mutation | Tests that failed |
|---|---|---|---|
| M1 | Screen lock | `suspensionBehavior: .deliverImmediately` → `.coalesce` | `APP-02 T12: the system distributed center delivers the screen lock at once, also in the background` (`added.behaviour == .deliverImmediately`) |
| M2 | Sleep (and user switch) | The private-center observer runs the lock with `DispatchQueue.main.async`, after the handler returns, instead of inside it. | `APP-02 T14` (`window.session.vaults().allSatisfy(\.locked) && window.main == nil`). Also T01, T12/T13, T15, T52 and APP-06 T11. Driver: screenLock, sleep and userSwitch in both tests. 46 issues. |
| M3 | Idle | `throttle = Duration.milliseconds(500)` → `0` | `APP-02 T04: events within 0.5 s of a restart are ignored` |
| M4 | Keeping the relay | `relays.append(relay)` removed | `APP-02 T12 ... also in the background`, at `LockSignalsTests.swift:175:25: Expectation failed: added.observer`. The weak spy works. |
| M5 | Minimize | `min(max(secondsLeft(), 1), 20)` → `30` | `APP-02 T18: the minimize delay is at most 20 s` |
| M6 | Channel | In `refresh()`, the `unlock?.clear()` for "a vault went from unlocked to locked" is removed. | `APP-09.12 lock request: ...` (`unlock.password.isEmpty && window.opened.isEmpty`). Driver: `unlockField` channel. |
| M7 | Order | In `lockAll()`, `unlock?.clear()` moved before `session.lockAll()` | Driver `unlockField`, 6 cases (screenLock, sleep, userSwitch, idle, minimize, hide) at `heldAtReturn == true`. The Builder's 22 tests all pass under M7: only the driver pins the order. |

Note on M6: a first try that removed the whole `if` did not compile (unused `before`, warnings as errors). The runner now stops on a failed build and restores the file. The M6 result above comes from the version that compiles: the `if` is kept with an empty body.

## 5. No real notification, clipboard

- `grep` of `LockSignalsTests.swift`:
  - every `.post(` goes to `probe.distributed`, `probe.workspace`, `probe.local` or `local`. These are the private `NotificationCenter()` instances on lines 15 to 17.
  - The only system object named is `NSPasteboard.general.changeCount`, which is a read.
  - `SpyCenter` overrides `addObserver` only and registers nothing with the system.
- **Product code** has no `.post(` to a notification center. The only hit is an accessibility announcement in `VaultView.swift`.
- **Driver:** `SystemWatch.seen == 0` in all 7 `viewState` cases.
- **General pasteboard:** `10124` before the first test run, after each run (Builder plus driver, driver alone, full suite) and at 07:10:04. The probe was a read-only `NSPasteboard.general.changeCount` reader built in `/tmp/verify-e6s2-tools`.

## 6. swift format and SwiftLint

These ran in the project itself, read-only:

```
swift format lint --strict --recursive macos                        exit=0
swift format lint --strict <the four E6-S2 files>                   exit=0
swiftlint 0.65.1: (cd macos && swiftlint lint --strict --quiet)     exit=0
swiftlint on the four E6-S2 files                                   exit=0
```

## Notes, not failures

1. **Order test.** The Builder's tests do not pin "Rust first, then Swift" (M7). Adding an order test like the driver's `OrderSession` to `LockSignalsTests` would keep that proof in the product tests.
2. **`r` of APP-02.8.** It is 0 until E5-S9 (section 2).
3. **Typed password with nothing unlocked.** When nothing is unlocked, an idle firing or a channel lock leaves a typed unlock password in place. This follows APP-02.3 and LD-187. The 30-second clear (E5-S3) and E5-S10 cover it.

## Clean-up and CPU

- **Deleted** with `rm -rf`: `/tmp/verify-e6s2` (the copy, the derived data, the cargo target) and `/tmp/verify-e6s2-tools`.
- **Processes:** no App process was left. I stopped no process.
- **CPU:** about 12 minutes of wall time in builds and tests.
  - The longest single runs were the full unit suite (71 s wall, 52 s CPU) and the first cargo build of app-ffi (40 s wall, 351 s CPU over all cores).
  - The seven incremental rebuilds took under a minute each.
  - No run came near 30 minutes.
