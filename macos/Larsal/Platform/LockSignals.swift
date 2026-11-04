import AppKit
import LarsalCore

/// The lock settings of APP-02 with the card's Larsal defaults, held here until
/// the settings model exists (E5-S9).
nonisolated struct LockSettings: Equatable, Sendable {
    var idleEnabled = true
    /// As stored; `idle` is the period in use.
    var idleSeconds = 300
    /// Screen lock and sleep (APP-02.5, APP-02.6).
    var onScreenLock = true
    var onUserSwitch = true
    var onMinimize = false
    var minimizeAfterUnlock = false

    /// APP-02.3: a stored value is used within 10 seconds to 12 hours.
    var idle: Duration { .seconds(min(max(idleSeconds, 10), 43_200)) }
    /// APP-02.9: minimize after unlock turns lock on minimize off.
    var locksOnMinimize: Bool { onMinimize && !minimizeAfterUnlock }
}

/// APP-02's automatic triggers (E6-S2). Each calls `lock`, which in the app
/// is `MainWindowModel.lockAll()`: Rust locks every vault and first clears
/// Larsal's clipboard copy (APP-03.15), then the Swift state goes (shown values,
/// live codes, the unlock field). The channel's `lock` request comes through
/// Rust to `WindowEvents.lockAll`, which runs the same `lockAll()` (APP-09.12,
/// LD-217 (4)).
///
/// The system events are those of the card and of proven Mac password
/// managers (plan/native-app-research.md section 7, AGENTS.md rule 9):
/// `com.apple.screenIsLocked` on the distributed center (APP-02.5; posted for
/// Lock Screen, and for the screen saver or display sleep when the password
/// is asked at once), and Apple's `NSWorkspace.willSleepNotification`
/// (APP-02.6) and `sessionDidResignActiveNotification` (APP-02.7).
///
/// Idle (APP-02.2) counts only input delivered to Larsal's windows, through an
/// AppKit local event monitor, never the Mac's idle time.
final class LockSignals {
    static let screenIsLocked = Notification.Name("com.apple.screenIsLocked")
    static let throttle = Duration.milliseconds(500)

    /// APP-02.1: a change applies at once; the idle countdown restarts from
    /// the full new period, and a trigger turned off stops.
    var settings: LockSettings {
        didSet {
            restarted = now()
            if !settings.locksOnMinimize { minimizeDue = nil }
            wake()
        }
    }
    private let now: () -> ContinuousClock.Instant
    private let secondsLeft: () -> Int
    private let unlocked: () -> Bool
    private let lock: () -> Void
    /// The last counted activity, or the last idle lock.
    private var restarted: ContinuousClock.Instant
    private var minimizeDue: ContinuousClock.Instant?
    private var timer: (any DispatchSourceTimer)?
    private var monitor: Any?
    /// The system distributed center keeps its observers unretained.
    private var relays: [Relay] = []

    /// - Parameters:
    ///   - workspace, distributed, local: notification centers; tests pass
    ///     private ones and never post a real system notification.
    ///   - now: a clock that runs on during sleep; tests pass a fake one.
    ///   - secondsLeft: whole seconds left on the clipboard countdown
    ///     (APP-02.8 `r`).
    ///   - unlocked: whether any vault is unlocked; idle with none does
    ///     nothing (APP-02.3), so it never cancels an unlock that runs.
    init(
        settings: LockSettings = LockSettings(),
        workspace: NotificationCenter = NSWorkspace.shared.notificationCenter,
        distributed: NotificationCenter = DistributedNotificationCenter.default(),
        local: NotificationCenter = .default,
        now: @escaping () -> ContinuousClock.Instant = { .now },
        secondsLeft: @escaping () -> Int = { 0 },
        unlocked: @escaping () -> Bool,
        lock: @escaping () -> Void
    ) {
        self.settings = settings
        self.now = now
        self.secondsLeft = secondsLeft
        self.unlocked = unlocked
        self.lock = lock
        restarted = now()
        observe(distributed, Self.screenIsLocked, \.onScreenLock)
        // APP-02.6: the lock ends before this handler returns, so before sleep.
        observe(workspace, NSWorkspace.willSleepNotification, \.onScreenLock)
        observe(workspace, NSWorkspace.sessionDidResignActiveNotification, \.onUserSwitch)
        for name in [NSWindow.didMiniaturizeNotification, NSApplication.didHideNotification] {
            _ = local.addObserver(forName: name, object: nil, queue: nil) { [weak self] _ in
                onMain { self?.minimized() }
            }
        }
        wake()
    }

    /// The app's signals over `session` (AppDelegate): the stored settings,
    /// idle only while a vault is unlocked, and `r` from Rust's clipboard
    /// countdown (APP-02.8, F-078). Tests pass private centers and a clock.
    static func app(
        session: Session, workspace: NotificationCenter = NSWorkspace.shared.notificationCenter,
        distributed: NotificationCenter = DistributedNotificationCenter.default(),
        local: NotificationCenter = .default, now: @escaping () -> ContinuousClock.Instant = { .now },
        lock: @escaping () -> Void
    ) -> LockSignals {
        LockSignals(
            settings: LockSettings(store: session.settings()), workspace: workspace, distributed: distributed,
            local: local, now: now, secondsLeft: { Int(session.clipboardSecondsLeft()) },
            unlocked: { session.vaults().contains { !$0.locked } }, lock: lock)
    }

    /// Counts input to Larsal's windows (APP-02.2). Call once in the app.
    func watchInput() {
        let kinds: NSEvent.EventTypeMask = [
            .keyDown, .keyUp, .flagsChanged, .leftMouseDown, .leftMouseUp, .rightMouseDown, .rightMouseUp,
            .otherMouseDown, .otherMouseUp, .mouseMoved, .mouseEntered, .leftMouseDragged, .rightMouseDragged,
            .otherMouseDragged, .scrollWheel,
        ]
        monitor = NSEvent.addLocalMonitorForEvents(matching: kinds) { [weak self] event in
            self?.activity()
            return event
        }
    }

    /// One counted event: restarts the idle countdown, then ignores events
    /// for 0.5 s. An event after the period is over locks first: a timer that
    /// came late (Larsal Nap, sleep) never lets input keep a vault open.
    func activity() {
        let time = now()
        guard time - restarted >= Self.throttle else { return }
        if settings.idleEnabled && time - restarted >= settings.idle {
            tick()
        } else {
            restarted = time
        }
    }

    /// APP-02.8, APP-02.10: the window was minimized or Larsal hidden. Locks
    /// after `clamp(r, 1, 20)` seconds; a new event starts the delay again,
    /// a restore does not stop it.
    func minimized() {
        guard settings.locksOnMinimize else { return }
        minimizeDue = now() + .seconds(min(max(secondsLeft(), 1), 20))
        wake()
    }

    /// Locks when the idle period or the minimize delay is over, then sets
    /// the timer for the next deadline. The timer calls it; tests call it
    /// with a fake clock.
    func tick() {
        let time = now()
        var due = false
        if let minimize = minimizeDue, time >= minimize {
            minimizeDue = nil
            due = true
        }
        if settings.idleEnabled && time - restarted >= settings.idle {
            // The countdown starts again, whether or not anything locked.
            restarted = time
            due = due || unlocked()
        }
        if due { lock() }
        wake()
    }

    /// Locks on `name` while `setting` is on, read at the event (APP-02.1).
    private func observe(
        _ center: NotificationCenter, _ name: Notification.Name, _ setting: KeyPath<LockSettings, Bool> & Sendable
    ) {
        let handle: @MainActor () -> Void = { [weak self] in
            if let self, self.settings[keyPath: setting] { self.lock() }
        }
        if let system = center as? DistributedNotificationCenter {
            // Apple (DistributedNotificationCenter.SuspensionBehavior): a
            // plain observer is held back while Larsal is not the front app;
            // the screen lock must arrive at once (APP-02.5, APP-02.20).
            let relay = Relay(handle)
            relays.append(relay)
            system.addObserver(
                relay, selector: #selector(Relay.fire), name: name, object: nil,
                suspensionBehavior: .deliverImmediately)
        } else {
            _ = center.addObserver(forName: name, object: nil, queue: nil) { _ in onMain(handle) }
        }
    }

    /// One timer for the nearest deadline. A wall-clock deadline fires at
    /// once after a wake when the time passed during sleep; strict, so Larsal
    /// Nap does not stretch it (APP-02.20: within 1 second).
    private func wake() {
        timer?.cancel()
        timer = nil
        let idle = settings.idleEnabled ? restarted + settings.idle : nil
        guard let next = [idle, minimizeDue].compactMap({ $0 }).min() else { return }
        let source = DispatchSource.makeTimerSource(flags: .strict, queue: .main)
        source.schedule(wallDeadline: .now() + max(0, (next - now()) / .seconds(1)), leeway: .milliseconds(100))
        source.setEventHandler { [weak self] in
            MainActor.assumeIsolated { self?.tick() }
        }
        source.resume()
        timer = source
    }
}

/// A selector target for the distributed center, which has no block observer
/// with a suspension behaviour.
private final class Relay: NSObject {
    private let handle: @MainActor () -> Void

    init(_ handle: @escaping @MainActor () -> Void) {
        self.handle = handle
    }

    @objc nonisolated func fire(_ note: Notification) {
        onMain(handle)
    }
}

/// AppKit posts these notifications on the main thread, and the sleep lock
/// must end before the handler returns (APP-02.6): the work runs there and
/// then, never later.
private nonisolated func onMain(_ body: @escaping @MainActor () -> Void) {
    if Thread.isMainThread {
        MainActor.assumeIsolated(body)
    } else {
        DispatchQueue.main.sync { MainActor.assumeIsolated(body) }
    }
}
