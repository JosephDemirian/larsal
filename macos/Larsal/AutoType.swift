import AppKit
import Carbon.HIToolbox
import LarsalCore
import Observation
import SwiftUI
import os

/// The app and window in front at the shortcut (INT-05.37).
nonisolated struct FrontWindow: Equatable, Sendable {
    let pid: pid_t
    let appName: String
    let title: String
    /// The focused window, compared with the system's equality test
    /// (V-INT05-8); `nil` when the app has none.
    let window: WindowID?
}

/// A window's identity: an Accessibility element, or a test's fake.
nonisolated struct WindowID: Hashable, @unchecked Sendable {
    let ref: AnyHashable
}

/// Reads the app and window in front (INT-05.37). Tests give fake windows
/// and never read the owner's (AGENTS.md rule 10).
nonisolated protocol WindowSource: Sendable {
    func front() -> FrontWindow?
}

/// macOS: the active app and its focused window's title through the
/// Accessibility API (D-INT05-1: no Screen Recording). Without the
/// permission the window and title stay empty; it never asks for it
/// (INT-05.44 is `AutoType.trust`).
nonisolated struct SystemWindows: WindowSource {
    func front() -> FrontWindow? {
        guard let app = NSWorkspace.shared.frontmostApplication else { return nil }
        let element = AXUIElementCreateApplication(app.processIdentifier)
        var value: CFTypeRef?
        var window: AXUIElement?
        let read = AXUIElementCopyAttributeValue(element, kAXFocusedWindowAttribute as CFString, &value)
        if read == .success, let value, CFGetTypeID(value) == AXUIElementGetTypeID() {
            window = unsafeDowncast(value, to: AXUIElement.self)
        }
        var title: CFTypeRef?
        if let window { _ = AXUIElementCopyAttributeValue(window, kAXTitleAttribute as CFString, &title) }
        return FrontWindow(
            pid: app.processIdentifier, appName: app.localizedName ?? "", title: (title as? String) ?? "",
            window: window.map { WindowID(ref: $0) })
    }
}

/// The typer's window check (INT-05.39, AT-G02): Rust asks before every
/// key whether the captured app and window are still in front.
nonisolated final class FocusCheck: AutoTypeFocus {
    let target: FrontWindow
    let windows: any WindowSource

    init(target: FrontWindow, windows: any WindowSource) {
        self.target = target
        self.windows = windows
    }

    func sameWindow() -> Bool {
        guard let now = windows.front() else { return false }
        return now.pid == target.pid && now.window == target.window
    }
}

/// The system's hot key service, one shortcut at a time (INT-05.30).
protocol HotKeys: AnyObject {
    /// Registers `key` in place of the last one; false when macOS refuses.
    func register(_ key: AutoTypeHotKey, fired: @escaping () -> Void) -> Bool
    func unregister()
}

/// Carbon's hot keys: no permission, no other key seen (no event tap).
/// macOS removes them when Larsal quits.
final class CarbonHotKeys: HotKeys {
    private var ref: EventHotKeyRef?
    private var handler: EventHandlerRef?
    /// Carbon calls back on the main thread with no context.
    private static var fired: (() -> Void)?

    func register(_ key: AutoTypeHotKey, fired: @escaping () -> Void) -> Bool {
        unregister()
        Self.fired = fired
        if handler == nil {
            var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
            InstallEventHandler(GetApplicationEventTarget(), carbonHotKeyPressed, 1, &spec, nil, &handler)
        }
        let flags: [(Bool, Int)] = [
            (key.command, cmdKey), (key.shift, shiftKey), (key.option, optionKey), (key.control, controlKey),
        ]
        let modifiers = flags.reduce(UInt32(0)) { $1.0 ? $0 | UInt32($1.1) : $0 }
        let id = EventHotKeyID(signature: 0x4150_5041, id: 1)
        return RegisterEventHotKey(UInt32(key.code), modifiers, id, GetApplicationEventTarget(), 0, &ref) == noErr
    }

    func unregister() {
        if let ref { UnregisterEventHotKey(ref) }
        ref = nil
    }

    fileprivate static func pressed() { fired?() }
}

private nonisolated func carbonHotKeyPressed(
    _: EventHandlerCallRef?, _: EventRef?, _: UnsafeMutableRawPointer?
) -> OSStatus {
    MainActor.assumeIsolated { CarbonHotKeys.pressed() }
    return noErr
}

/// Global Auto-Type (INT-05.25): the shortcut, the capture, the picker or
/// the single match, and the run with its window check. Matching, rows,
/// the remembered choice and the plan are Rust's (INT-05.45).
@MainActor
@Observable
final class AutoType {
    @ObservationIgnored let session: Session
    @ObservationIgnored private let hotKeys: any HotKeys
    @ObservationIgnored private let windows: any WindowSource
    /// Shows the picker panel, or hides it with `nil`.
    @ObservationIgnored private let present: (AutoTypePicker?) -> Void
    /// The system alert sound (INT-05.25 step 5, INT-05.39).
    @ObservationIgnored var alert: () -> Void = { NSSound.beep() }
    /// INT-05.25 step 5: shows the unlock panel (APP-06.27), or hides it
    /// with `nil`.
    @ObservationIgnored var unlock: (AutoTypeUnlock?) -> Void = { AutoTypeUnlockPanel.present($0) }
    /// Asks macOS to bring the target app back to the front (INT-05.29).
    @ObservationIgnored var activate: (pid_t) -> Void = { pid in
        guard !launchHidden() else { return }
        NSRunningApplication(processIdentifier: pid)?.activate()
    }
    /// The panel unlocked a vault: the main window shows it (the app sets
    /// `MainWindowModel.refresh`).
    @ObservationIgnored var refreshed: () -> Void = {}
    /// INT-05.32 (S-AT-06): the vault the unlock panel opened for this run,
    /// and the main window's lock that locks it again (save first).
    @ObservationIgnored var relock: (UInt64) -> Void = { _ in }
    @ObservationIgnored private var unlockedForRun: UInt64?
    /// MI05-10 with its reason (INT-05.15).
    @ObservationIgnored var stopped: (String) -> Void = { AutoType.alertStopped($0) }
    /// INT-05.47: one debug line per failure or stop, with a reason code
    /// and the key position; never a title, a value or a sequence. Private
    /// in the log, as every value (Swift rule 4).
    @ObservationIgnored var log: (String) -> Void = { Logger.app.debug("\($0)") }
    /// INT-05.44: Larsal's launch sets the system's permission; tests a fake.
    @ObservationIgnored var trust: any AccessibilityTrust = AssumedAccessibility()
    /// MI05-30 (INT-05.44).
    @ObservationIgnored var needsAccess: () -> Void = { AccessAlert.show() }
    /// The current keyboard layout's table, read once per run (INT-05.41).
    @ObservationIgnored var layout: () -> [AutoTypeKey] = { KeyboardLayoutTable.current() }
    /// Runs the typing off the main thread; tests run it at once.
    @ObservationIgnored var runner: AutoTypeRunner = AutoType.offMain
    /// Larsal's own secure input, off before typing (INT-05.38 step 4); tests give a fake.
    @ObservationIgnored var secureInput = SecureInput.shared
    /// macOS's own request was asked for in this Larsal run (INT-05.44).
    @ObservationIgnored private var askedAccess = false
    /// A run is checking, waiting or typing (INT-05.46).
    private(set) var typing = false
    @ObservationIgnored private var observers: [NSObjectProtocol] = []
    private(set) var picker: AutoTypePicker?
    /// The unlock panel of INT-05.25 step 5, with the captured target.
    private(set) var waiting: AutoTypeUnlock?
    /// Larsal was made active for the unlock panel: a picker closed without
    /// typing brings this app back (INT-05.29).
    @ObservationIgnored private var back: pid_t?
    /// The shortcut is registered; false when macOS refused it (MI05-33,
    /// MI05-36 wait for the recorder, W-06).
    private(set) var registered = false
    private let ownPid = ProcessInfo.processInfo.processIdentifier

    init(
        session: Session, hotKeys: any HotKeys, windows: any WindowSource,
        present: @escaping (AutoTypePicker?) -> Void
    ) {
        self.session = session
        self.hotKeys = hotKeys
        self.windows = windows
        self.present = present
        // APP-06.27: every lock-everything event closes the panel as a cancel.
        let center = NotificationCenter.default
        observers.append(
            center.addObserver(forName: .appLockedEverything, object: session, queue: nil) { [weak self] _ in
                MainActor.assumeIsolated { self?.cancelUnlock(back: false) }
            })
    }

    /// At start: the shortcut, and the picker closes when another app
    /// becomes active or the target quits (INT-05.29).
    func start() {
        register()
        let center = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.didActivateApplicationNotification, NSWorkspace.didTerminateApplicationNotification] {
            observers.append(
                center.addObserver(forName: name, object: nil, queue: .main) { [weak self] note in
                    let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication
                    let pid = app?.processIdentifier ?? 0
                    let quit = name == NSWorkspace.didTerminateApplicationNotification
                    MainActor.assumeIsolated { self?.appChanged(pid: pid, quit: quit) }
                })
        }
    }

    /// INT-05.30: S-AT-07 at start and after each settings change; a
    /// cleared or invalid shortcut is removed.
    func register() {
        guard let key = session.autotypeHotKey() else {
            hotKeys.unregister()
            registered = false
            return
        }
        registered = hotKeys.register(key) { [weak self] in self?.fired() }
    }

    /// INT-05.25: the shortcut was pressed.
    func fired() {
        // Step 2, INT-05.46: a press while Larsal types stops the run.
        if typing { return session.autotypeStop() }
        // Steps 1 and 2: never into Larsal itself; one picker or panel at a time.
        guard picker == nil, waiting == nil, let target = windows.front(), target.pid != ownPid else { return }
        // No flow is open: a target kept by an earlier panel flow that typed
        // at once or failed is stale (INT-05.29).
        back = nil
        // Step 4 (INT-05.44): without the permission nothing is typed.
        guard trust.trusted() else { return accessMissing() }
        session.autotypeLayout(keys: layout())
        run(target)
    }

    /// INT-05.44: macOS's own request at most once per Larsal run, then MI05-30.
    private func accessMissing() {
        if !askedAccess {
            askedAccess = true
            trust.request()
        }
        needsAccess()
    }

    /// Steps 5 to 7 for the captured target.
    private func run(_ target: FrontWindow) {
        switch session.autotypeStart(title: target.title, utcOffset: Self.offset) {
        case .noVault: alert()
        case .locked(let vault):
            guard let info = session.vaults().first(where: { $0.id == vault }) else { return }
            // MOD-13.8: behind the forced key change prompt the vault is open
            // but counts as locked: no unlock panel, no Auto-Type; after the
            // panel the target comes back (INT-05.29).
            guard info.keyChange == nil else {
                alert()
                if let back { activate(back) }
                return ended()
            }
            let form = UnlockModel(session: session, vault: info) { [weak self] in
                self?.refreshed()
                self?.vaultsChanged()
            }
            waiting = AutoTypeUnlock(target: target, form: form) { [weak self] in self?.cancelUnlock(back: true) }
            unlock(waiting)
        case .picker(let list):
            let done: (AutoTypeChosen?) -> Void = { [weak self] chosen in self?.finish(chosen, into: target) }
            let picker = AutoTypePicker(session: session, target: target, list: list, unlocked: unlocked(), done: done)
            picker.maskUserNames = session.settings().flag(key: "display.hide_usernames")
            self.picker = picker
            present(picker)
        case .type(let plan): type(plan, into: target)
        case .failed(let reason, let code): failed(reason, code)
        }
    }

    /// MI05-10, and INT-05.47's line with the message id only (the reason
    /// may hold the token).
    private func failed(_ reason: String, _ code: String) {
        log("Auto-Type failed: \(code)")
        stopped(reason)
        ended()
    }

    /// INT-05.32 T74: typed, stopped, failed or closed untyped: relock.
    private func ended() {
        guard let id = unlockedForRun else { return }
        unlockedForRun = nil
        if session.settings().flag(key: "lock.relock_after_autotype") { relock(id) }
    }

    /// A vault unlocked, locked or closed: after the panel's vault unlocks
    /// the flow goes on with every unlocked vault (INT-05.25 step 5); its
    /// close cancels the panel; a lock closes the picker (SR-16).
    func vaultsChanged() {
        if let waiting {
            switch session.vaults().first(where: { $0.id == waiting.form.vault.id })?.locked {
            case false?:
                close(waiting)
                back = waiting.target.pid
                unlockedForRun = waiting.form.vault.id
                run(waiting.target)
            case nil: cancelUnlock(back: true)
            case true?: break
            }
        }
        guard let picker, !unlocked().isSuperset(of: picker.unlocked) else { return }
        picker.cancel()
    }

    /// Cancel or Escape in the panel, a lock-everything event, or its vault
    /// closed: nothing is typed; `back` brings the target back (INT-05.29).
    func cancelUnlock(back: Bool) {
        guard let waiting else { return }
        close(waiting)
        if back { activate(waiting.target.pid) }
    }

    private func close(_ panel: AutoTypeUnlock) {
        waiting = nil
        panel.form.clear()
        unlock(nil)
    }

    /// Another app became active, or the target quit (INT-05.29).
    func appChanged(pid: pid_t, quit: Bool) {
        guard let picker else { return }
        if quit ? pid == picker.target.pid : pid != picker.target.pid && pid != ownPid {
            back = nil
            picker.cancel()
        }
    }

    /// The picker closed: the panel goes first, then the run (INT-05.29).
    private func finish(_ chosen: AutoTypeChosen?, into target: FrontWindow) {
        picker = nil
        present(nil)
        let back = back
        self.back = nil
        switch chosen {
        case .type(let plan): type(plan, into: target)
        case .failed(let reason, let code): failed(reason, code)
        case .gone, nil:
            if let back { activate(back) }
            ended()
        }
    }

    /// Runs the plan off the main thread, the window checked before every
    /// key (AT-G02). INT-05.38 step 1: macOS is asked to make the target
    /// active (Larsal may have come in front of it for the unlock panel or
    /// while the picker showed; asking an active app does nothing); Rust
    /// waits for it, at most 2 s.
    private func type(_ plan: UInt64, into target: FrontWindow) {
        activate(target.pid)
        secureInput.release()  // step 4: Larsal's own secure input off (APP-10.12)
        typing = true
        let focus = FocusCheck(target: target, windows: windows)
        let work: @Sendable () -> AutoTypeEnd = { [session] in session.autotypeType(plan: plan, focus: focus) }
        runner(work) { [weak self] end in
            self?.typing = false
            if case .stopped(let keys, let reason) = end {
                self?.log("Auto-Type stopped: \(reason) after \(keys) keys")
                self?.alert()
            }
            self?.ended()
        }
    }

    private func unlocked() -> Set<UInt64> { Set(session.vaults().filter { !$0.locked }.map(\.id)) }

    static var offset: Int32 { Int32(TimeZone.current.secondsFromGMT()) }

    /// MI05-10, never in a hidden launch (AGENTS.md rule 10).
    private static func alertStopped(_ reason: String) {
        guard !launchHidden() else { return }
        let box = ScreenProtection.shared.alert()
        box.messageText = "Auto-Type stopped"
        box.informativeText = reason
        box.runModal()
    }
}

/// The unlock panel's model (INT-05.25 step 5, APP-06.27): the captured
/// target waits while the form unlocks the shown vault.
@MainActor
final class AutoTypeUnlock {
    /// M06-40, Auto-Type's purpose line.
    static let purpose = "Auto-Type needs this vault unlocked."
    let target: FrontWindow
    let form: UnlockModel
    /// Cancel, or Escape.
    let cancel: () -> Void

    init(target: FrontWindow, form: UnlockModel, cancel: @escaping () -> Void) {
        self.target = target
        self.form = form
        self.cancel = cancel
    }
}

extension Notification.Name {
    /// `MainWindowModel.lockAll` ran on the session in `object`: every
    /// lock-everything event of APP-02.
    static let appLockedEverything = Notification.Name("app.larsal.desktop.lockedEverything")
}
