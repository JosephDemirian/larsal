import AppKit
import Carbon.HIToolbox

/// The system's secure event input, behind a seam: a test never makes the
/// real calls, which change keyboard input for every app on the Mac
/// (AGENTS.md rule 10).
protocol SecureEventInput {
    func enable()
    func disable()
}

/// `EnableSecureEventInput` and `DisableSecureEventInput` (APP-10.10).
struct SystemSecureEventInput: SecureEventInput {
    func enable() { _ = EnableSecureEventInput() }
    func disable() { _ = DisableSecureEventInput() }
}

/// A test run's calls, unless the test brings its own fake.
struct InertSecureEventInput: SecureEventInput {
    func enable() {}
    func disable() {}
}

/// Larsal's own secure input call (SR-06, AT-D05, APP-10.8 to APP-10.13). A
/// masked field (`NSSecureTextField`) turns secure input on by itself while
/// it has the focus; a password shown in clear is a `NoCopyTextField`, which
/// turns nothing on, so Larsal's call covers it: on exactly while that field has
/// the focus, its window is key and Larsal is active. It goes off on focus out,
/// hide, removal, another key window, deactivation, window close and quit,
/// whatever the field reports, and comes back when Larsal becomes active or a
/// window becomes key with the field still focused (APP-10.13). A lock
/// checks the three again: a field that outlives it (the New Vault wizard's)
/// keeps Larsal's call while it still edits; a missed focus-out ends there. The
/// calls alternate, so Larsal adds at most 1 to the system's counter
/// (APP-10.10) and leaves none on (APP-10.12).
@MainActor
final class SecureInput {
    static let shared = SecureInput()

    /// The system calls; a test run gets inert ones, or its own fake.
    var system: any SecureEventInput =
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil
        ? SystemSecureEventInput() : InertSecureEventInput()
    var isActive: () -> Bool = { NSApp?.isActive == true }
    var isKey: (NSWindow) -> Bool = { $0.isKeyWindow }
    /// The shown password field that has the focus.
    private weak var field: NSControl?
    /// Off after a window close or quit until Larsal becomes active or a window
    /// becomes key again, or a field takes the focus.
    private var released = false
    /// Larsal's own call is on.
    private(set) var enabled = false

    /// Watches Larsal and its windows on `center` (tests give a private one).
    init(center: NotificationCenter = .default) {
        let changes = [
            NSApplication.didResignActiveNotification, NSApplication.didHideNotification,
            NSWindow.didResignKeyNotification,
        ]
        // Synchronous (no queue): off at once, before the next key event.
        for name in changes {
            center.addObserver(forName: name, object: nil, queue: nil) { [weak self] _ in
                MainActor.assumeIsolated { self?.update() }
            }
        }
        // APP-10.13: back on with the field still focused.
        for name in [NSApplication.didBecomeActiveNotification, NSWindow.didBecomeKeyNotification] {
            center.addObserver(forName: name, object: nil, queue: nil) { [weak self] _ in
                MainActor.assumeIsolated {
                    self?.released = false
                    self?.update()
                }
            }
        }
        center.addObserver(forName: NSWindow.willCloseNotification, object: nil, queue: nil) { [weak self] note in
            let closing = note.object as? NSWindow
            MainActor.assumeIsolated {
                guard let self, let closing, closing === self.field?.window else { return }
                self.release()
            }
        }
        let quit = NSApplication.willTerminateNotification
        center.addObserver(forName: quit, object: nil, queue: nil) { [weak self] _ in
            MainActor.assumeIsolated { self?.release() }
        }
    }

    /// A shown password field took the focus.
    func focused(_ field: NSControl) {
        self.field = field
        released = false
        update()
    }

    /// It lost the focus, was hidden or left its window.
    func left(_ field: NSControl) {
        if self.field === field { self.field = nil }
        update()
    }

    /// Window close and quit end Larsal's call (APP-10.11).
    func release() {
        released = true
        update()
    }

    /// On exactly while the field edits in the key window of an active Larsal
    /// (APP-10.8). A lock calls it (APP-10.11): off unless all three hold.
    func update() {
        let editing = field.flatMap { $0.currentEditor() == nil ? nil : $0.window }
        let wanted = !released && editing.map { isKey($0) && isActive() } == true
        guard wanted != enabled else { return }
        enabled = wanted
        if wanted { system.enable() } else { system.disable() }
    }
}
