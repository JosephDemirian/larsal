import AppKit
import LarsalCore
import Testing

/// LockSignals over private notification centers and a fake clock: no test
/// posts a real system notification or waits in real time (AGENTS.md rule
/// 10). `at(t)` moves the clock to `t` seconds and runs what the timer runs.
private final class Probe {
    let start = ContinuousClock.now
    var time: ContinuousClock.Instant
    var locks = 0
    /// The clipboard countdown's seconds left (APP-02.8 `r`).
    var left = 0
    var unlocked = true
    let workspace = NotificationCenter()
    let distributed = NotificationCenter()
    let local = NotificationCenter()
    var signals: LockSignals!

    init(_ settings: LockSettings = LockSettings(), lock: (() -> Void)? = nil) {
        time = start
        signals = LockSignals(
            settings: settings, workspace: workspace, distributed: distributed, local: local,
            now: { [unowned self] in time }, secondsLeft: { [unowned self] in left },
            unlocked: { [unowned self] in unlocked },
            lock: { [unowned self] in
                locks += 1
                lock?()
            }
        )
    }

    func at(_ seconds: Double) {
        time = start + .seconds(seconds)
        signals.tick()
    }

    /// Steps the clock by 0.1 s from `from` to `until` and gives the time of
    /// the first lock.
    func firstLock(from: Double, until: Double) -> Double? {
        for tenth in Int((from * 10).rounded())...Int((until * 10).rounded()) {
            at(Double(tenth) / 10)
            if locks > 0 { return Double(tenth) / 10 }
        }
        return nil
    }

    func idle(_ seconds: Int) -> Probe {
        signals.settings.idleSeconds = seconds
        return self
    }

    func minimizeLocks() -> Probe {
        signals.settings.onMinimize = true
        return self
    }

    func minimize(at seconds: Double, left: Int = 0) {
        at(seconds)
        self.left = left
        local.post(name: NSWindow.didMiniaturizeNotification, object: nil)
    }
}

/// Records how observers register; registers nothing with the system.
private nonisolated final class SpyCenter: DistributedNotificationCenter, @unchecked Sendable {
    /// Holds the observer weakly, as the system center does: a relay that
    /// LockSignals stops keeping is gone, and T12 fails.
    struct Added {
        weak var observer: AnyObject?
        let selector: Selector
        let name: Notification.Name?
        let behaviour: SuspensionBehavior
    }
    var added: [Added] = []

    override func addObserver(
        _ observer: Any, selector: Selector, name: Notification.Name?, object: String?,
        suspensionBehavior: SuspensionBehavior
    ) {
        added.append(
            Added(observer: observer as AnyObject, selector: selector, name: name, behaviour: suspensionBehavior))
    }
}

@MainActor
struct LockSignalsTests {
    @Test("APP-02 T02: applied settings restart the countdown from the new period")
    func t02() {
        let probe = Probe()
        probe.at(180)
        probe.signals.settings.idleSeconds = 60
        #expect(probe.firstLock(from: 180, until: 400) == 240)
    }

    @Test("APP-02 T03: each key restarts the countdown")
    func t03() throws {
        let probe = Probe().idle(10)
        for key in [0.0, 4, 8] {
            probe.at(key)
            probe.signals.activity()
        }
        let lock = try #require(probe.firstLock(from: 8, until: 30))
        #expect(lock >= 17.5 && lock <= 19)
    }

    @Test("APP-02 T04: events within 0.5 s of a restart are ignored")
    func t04() throws {
        let probe = Probe().idle(10)
        probe.at(5)
        probe.signals.activity()
        probe.at(5.3)
        probe.signals.activity()
        let lock = try #require(probe.firstLock(from: 5.3, until: 30))
        #expect(lock >= 14.5 && lock < 15.3)
    }

    @Test("APP-02 T07, T08: the period is used within 10 s and 12 h")
    func t07t08() {
        #expect(LockSettings(idleSeconds: 3).idle == .seconds(10))
        #expect(LockSettings(idleSeconds: 100_000).idle == .seconds(43_200))
        #expect(LockSettings().idle == .seconds(300))
        let probe = Probe().idle(3)
        #expect(probe.firstLock(from: 0, until: 30) == 10)
    }

    @Test("APP-02 T09: idle lock off never locks")
    func t09() {
        var settings = LockSettings()
        settings.idleEnabled = false
        let probe = Probe(settings)
        probe.at(3600)
        #expect(probe.locks == 0)
    }

    @Test("APP-02 T10: the countdown runs with nothing unlocked, does nothing, and starts again")
    func t10() throws {
        let probe = Probe().idle(10)
        probe.unlocked = false
        #expect(probe.firstLock(from: 0, until: 25) == nil)
        probe.unlocked = true
        probe.signals.activity()
        let lock = try #require(probe.firstLock(from: 25, until: 60))
        #expect(lock >= 34.5 && lock <= 36)
    }

    @Test("APP-02 idle: input after the period locks first and never restarts the countdown")
    func lateTimer() {
        let probe = Probe().idle(10)
        probe.time = probe.start + .seconds(500)
        probe.signals.activity()
        #expect(probe.locks == 1)
    }

    @Test("APP-02 T12, T13: com.apple.screenIsLocked locks when the setting is on")
    func t12t13() {
        let probe = Probe()
        probe.distributed.post(name: LockSignals.screenIsLocked, object: nil)
        #expect(probe.locks == 1)
        probe.signals.settings.onScreenLock = false
        probe.distributed.post(name: LockSignals.screenIsLocked, object: nil)
        #expect(probe.locks == 1)
    }

    @Test("APP-02 T12: the system distributed center delivers the screen lock at once, also in the background")
    func t12Background() throws {
        let spy = SpyCenter()
        var locks = 0
        let signals = LockSignals(
            workspace: NotificationCenter(), distributed: spy, local: NotificationCenter(), unlocked: { true },
            lock: { locks += 1 })
        let added = try #require(spy.added.first)
        #expect(spy.added.count == 1 && added.name == LockSignals.screenIsLocked)
        #expect(added.behaviour == .deliverImmediately)
        let relay = try #require(added.observer, "LockSignals keeps its relay alive")
        _ = relay.perform(added.selector, with: Notification(name: LockSignals.screenIsLocked))
        #expect(locks == 1)
        withExtendedLifetime(signals) {}
    }

    @Test("APP-02 T15: the session resigning active locks when the setting is on")
    func t15() {
        let probe = Probe()
        probe.workspace.post(name: NSWorkspace.sessionDidResignActiveNotification, object: nil)
        #expect(probe.locks == 1)
        probe.signals.settings.onUserSwitch = false
        probe.workspace.post(name: NSWorkspace.sessionDidResignActiveNotification, object: nil)
        #expect(probe.locks == 1)
    }

    @Test("APP-02 T16: minimize with nothing copied locks after 1 s")
    func t16() {
        let probe = Probe().minimizeLocks()
        probe.minimize(at: 0)
        #expect(probe.firstLock(from: 0, until: 25) == 1)
    }

    @Test("APP-02 T17: minimize waits for the clipboard countdown")
    func t17() {
        let probe = Probe().minimizeLocks()
        probe.minimize(at: 3, left: 7)
        #expect(probe.firstLock(from: 3, until: 25) == 10)
    }

    @Test("APP-02 T18: the minimize delay is at most 20 s")
    func t18() {
        let probe = Probe().minimizeLocks()
        probe.minimize(at: 0.5, left: 29)
        #expect(probe.firstLock(from: 0.5, until: 25) == 20.5)
    }

    @Test("APP-02 T19: a restore does not stop the minimize lock")
    func t19() {
        let probe = Probe().minimizeLocks()
        probe.minimize(at: 0)
        probe.at(0.5)
        probe.local.post(name: NSWindow.didDeminiaturizeNotification, object: nil)
        #expect(probe.firstLock(from: 0.5, until: 25) == 1)
    }

    @Test("APP-02 T20: a new minimize starts the delay again")
    func t20() {
        let probe = Probe().minimizeLocks()
        probe.minimize(at: 1, left: 9)
        probe.at(2)
        probe.minimize(at: 6, left: 9)
        #expect(probe.firstLock(from: 6, until: 25) == 15)
    }

    @Test("APP-02 T24: minimize after unlock turns lock on minimize off")
    func t24() {
        let probe = Probe().minimizeLocks()
        probe.signals.settings.minimizeAfterUnlock = true
        probe.minimize(at: 0)
        #expect(probe.firstLock(from: 0, until: 25) == nil)
    }

    @Test("APP-02 T25: Hide Larsal counts as minimize (D-A02-2)")
    func t25() {
        let probe = Probe().minimizeLocks()
        probe.local.post(name: NSApplication.didHideNotification, object: nil)
        #expect(probe.firstLock(from: 0, until: 25) == 1)
    }

    @Test("APP-02 T01: a screen lock locks every vault")
    func t01() throws {
        let window = try ParityDemo.window("lock-signals-t01", unlocked: [0, 1])
        #expect(window.vaults.filter { !$0.locked }.count == 2)
        let probe = Probe { window.lockAll() }
        probe.distributed.post(name: LockSignals.screenIsLocked, object: nil)
        #expect(window.session.vaults().allSatisfy(\.locked) && window.opened.isEmpty)
    }

    @Test("APP-02 T14: on will-sleep the vault is locked before the handler returns")
    func t14() throws {
        let window = try ParityDemo.window("lock-signals-t14")
        let probe = Probe { window.lockAll() }
        probe.workspace.post(name: NSWorkspace.willSleepNotification, object: nil)
        #expect(window.session.vaults().allSatisfy(\.locked) && window.main == nil)
    }

    @Test("APP-02 T52, APP-03.15: a lock signal clears the clipboard in Rust, shown values and live codes")
    func clearsState() async throws {
        let window = try ParityDemo.window("lock-signals-state")
        // The copy comes from a vault no other test copies from, so its
        // private pasteboard is found by its value.
        let path = ParityDemo.root.appending(path: "testdata/password-only.larsalvault").path(percentEncoded: false)
        let other = try window.session.open(path: path)
        #expect(try window.session.unlock(vault: other, password: "demo-pass-1", keyFile: nil) == .unlocked)
        window.refresh()
        let copier = try #require(window.main)
        copier.select(copier.rows.first { $0.title == "Demo login" }?.id)
        copier.copy("Password")
        #expect(copier.toast?.text == "Password copied.")
        let value = try window.session.showField(
            vault: other, entry: copier.selection ?? "", field: "Password")
        let board = NSPasteboard(name: .init(try #require(window.session.pasteboardName())))
        #expect(board.string(forType: .string) == value)

        window.switchTo(window.vaults[0].id)
        let main = try #require(window.main)
        main.select(main.rows.first { $0.hasTotp }?.id)
        main.tick()
        await main.toggleShow("Password")
        #expect(!main.codes.isEmpty && !main.shown.isEmpty)

        let probe = Probe { window.lockAll() }
        probe.distributed.post(name: LockSignals.screenIsLocked, object: nil)
        #expect(board.string(forType: .string) == nil)
        #expect(main.shown.isEmpty && main.codes.isEmpty && main.detail == nil)
        #expect(window.main == nil && window.opened.isEmpty)
        // AGENTS.md rule 10: the owner's clipboard was never touched (LD-206).
        PasteboardProof.expectOnlyPrivate(window.session)
    }

    @Test("APP-06 T11: a lock signal clears the typed password")
    func clearsUnlockField() throws {
        let window = try ParityDemo.window("lock-signals-field", unlocked: [])
        let unlock = try #require(window.unlock)
        unlock.password = "demo-pass-7"
        unlock.reveal = true
        let probe = Probe { window.lockAll() }
        probe.distributed.post(name: LockSignals.screenIsLocked, object: nil)
        #expect(unlock.password.isEmpty && !unlock.reveal)
    }

    @Test(
        "APP-09.12 lock request: WindowEvents.lockAll answers at once (under 50 ms), then lockAll clears Swift state"
    )
    func channelLock() async throws {
        let window = try ParityDemo.window("lock-signals-channel")
        window.switchTo(window.vaults[1].id)
        let unlock = try #require(window.unlock)
        unlock.password = "demo-pass-8"
        #expect(window.opened.count == 1)
        // What `answer(Request::Lock)` does with a window (LD-217 (4)): the
        // channel's thread calls the events' `lock_all` and answers; the
        // sender waits 1 s at most, so the call must not wait for the busy
        // main thread.
        let took = Self.lockAllWhileMainIsBusy(WindowEvents(window: window))
        #expect(took < .milliseconds(50), "answered in \(took)")
        for _ in 0..<100 where !window.opened.isEmpty { try await Task.sleep(for: .milliseconds(20)) }
        #expect(unlock.password.isEmpty && window.opened.isEmpty)
        #expect(window.session.vaults().allSatisfy { $0.locked })
    }

    /// Calls `events.lockAll()` on another thread while this (main) thread
    /// is held busy for 300 ms; how long the call took.
    private static func lockAllWhileMainIsBusy(_ events: WindowEvents) -> Duration {
        let started = DispatchSemaphore(value: 0)
        let done = DispatchSemaphore(value: 0)
        let took = Took()
        Thread.detachNewThread {
            started.signal()
            took.set(ContinuousClock().measure { events.lockAll() })
            done.signal()
        }
        started.wait()
        Thread.sleep(forTimeInterval: 0.3)
        done.wait()
        return took.get()
    }
}

/// One measured duration handed from the caller's thread to the test.
nonisolated private final class Took: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Duration.zero

    func set(_ duration: Duration) { lock.withLock { value = duration } }
    func get() -> Duration { lock.withLock { value } }
}
