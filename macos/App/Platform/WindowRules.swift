import AppKit

/// The calls the window rules make on macOS. Tests swap them for recorders,
/// so no test shows, hides, activates or quits anything on the owner's
/// screen (AGENTS.md rule 10).
struct AppCalls {
    var policy: () -> NSApplication.ActivationPolicy = { NSApp.activationPolicy() }
    var setPolicy: (NSApplication.ActivationPolicy) -> Void = { _ = NSApp.setActivationPolicy($0) }
    var isActive: () -> Bool = { NSApp.isActive }
    var activate: () -> Void = {
        // Not `activate()`: since macOS 14 that call is cooperative, and a
        // request from another process (the secondary) left App behind the
        // active app on this Mac. This one is only marked "to be deprecated".
        NSApp.activate(ignoringOtherApps: true)
    }
    var unhide: () -> Void = { NSApp.unhide(nil) }
    var quit: () -> Void = { NSApp.terminate(nil) }

    /// Calls that do nothing: the default inside a test run, so a test that
    /// reaches a menu action never takes the owner's screen.
    static let inert = AppCalls(
        policy: { .prohibited }, setPolicy: { _ in }, isActive: { false }, activate: {}, unhide: {}, quit: {})
    static let system = ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil ? AppCalls() : inert
}

/// The main window's ways out and back (APP-08.19 to APP-08.23, APP-09.21,
/// APP-09.22): close, minimize, hide to the menu bar icon, and bring to
/// front, which every trigger runs through `Front.bring()`.
@MainActor
final class WindowRules: NSObject {
    static let shared = WindowRules()

    struct Settings {
        /// S-UI-09 `window.close_hides`.
        var closeHides = false
        /// S-UI-10 `menubar_icon.show`.
        var icon = false
        /// S-UI-12 `menubar_icon.minimize_to`.
        var minimizeToIcon = false
    }

    var calls = AppCalls.system
    /// Read at each close and minimize (APP-01, set by the app delegate).
    var settings: () -> Settings = { Settings() }
    /// A minimize for the lock-on-minimize delay (APP-02.8): hiding to the
    /// icon counts as one (macOS reports real minimizes itself).
    var minimized: () -> Void = {}
    /// The window in front; tests put a recorder here.
    var keyWindow: () -> NSWindow? = { NSApp?.keyWindow }
    /// The main window (the one `MainWindow` shows in).
    private(set) weak var window: NSWindow?
    /// The window is hidden to the menu bar icon (APP-08.22).
    private(set) var hidden = false
    private var onTop = false

    /// The main window appeared: its red and yellow buttons follow these
    /// rules, and Keep Window on Top applies.
    func attach(_ window: NSWindow) {
        self.window = window
        window.standardWindowButton(.closeButton)?.target = self
        window.standardWindowButton(.closeButton)?.action = #selector(closeClicked)
        window.standardWindowButton(.miniaturizeButton)?.target = self
        window.standardWindowButton(.miniaturizeButton)?.action = #selector(minimizeClicked)
        window.level = onTop ? .floating : .normal
    }

    @objc private func closeClicked() { close() }
    @objc private func minimizeClicked() { minimize() }

    /// APP-08.19: with S-UI-09 off App quits (APP-02.11); on, the window
    /// hides to the menu bar icon when it shows, else it goes to the Dock.
    func close() {
        let now = settings()
        if !now.closeHides {
            calls.quit()
        } else if now.icon {
            hideToIcon()
        } else {
            window?.miniaturize(nil)
        }
    }

    /// APP-08.19: to the menu bar icon with S-UI-12 and S-UI-10 on, with no
    /// animation; else into the Dock.
    func minimize() {
        let now = settings()
        if now.icon && now.minimizeToIcon {
            hideToIcon()
        } else {
            window?.miniaturize(nil)
        }
    }

    /// File > Close Vault, Close Window and Window > Minimize: another of
    /// App's windows in front (the settings) closes or minimizes as on every
    /// Mac; for the main window Close Vault runs `main`, the others follow
    /// the rules above.
    func closeKeyWindow(main: (() -> Void)? = nil) {
        if let key = keyWindow(), key !== window { key.performClose(nil) } else { (main ?? close)() }
    }

    func minimizeKeyWindow() {
        if let key = keyWindow(), key !== window { key.performMiniaturize(nil) } else { minimize() }
    }

    /// APP-09.21: started minimized: hidden to the menu bar icon when it
    /// shows, with no animation; else into the Dock.
    func startMinimized() {
        if settings().icon {
            hideToIcon()
        } else {
            (window ?? NSApp.windows.first { $0.canBecomeMain && $0.isVisible })?.miniaturize(nil)
        }
    }

    /// APP-08.22: the window hides and App leaves the Dock and the app
    /// switcher (an accessory app) until the window shows again.
    func hideToIcon() {
        window?.orderOut(nil)
        hidden = true
        // A hidden launch stays prohibited, so bring() never takes the screen.
        if calls.policy() != .prohibited { calls.setPolicy(.accessory) }
        minimized()
    }

    /// APP-09.22: un-minimize, show if hidden, raise, and make App active
    /// with the main window as key window. Triggers outside this type call
    /// `Front.bring()`.
    func bring() {
        // A hidden test launch never takes the screen (HiddenLaunch).
        guard calls.policy() != .prohibited else { return }
        if hidden || calls.policy() == .accessory { calls.setPolicy(.regular) }
        hidden = false
        calls.unhide()
        if let window {
            if window.isMiniaturized { window.deminiaturize(nil) }
            window.makeKeyAndOrderFront(nil)
        }
        calls.activate()
    }

    /// App became active by any means (APP-09.22): a window that is
    /// minimized or hidden comes back; one already on screen keeps its place
    /// behind another of App's windows.
    func activated() {
        guard hidden || window?.isMiniaturized == true else { return }
        bring()
    }

    /// APP-08.21: "Hide Window" while the window is shown in front.
    var inFront: Bool {
        guard let window, !hidden else { return false }
        return window.isVisible && !window.isMiniaturized && calls.isActive()
    }

    /// APP-08.22: the icon was turned off while the window hid behind it.
    func iconTurnedOff() {
        if hidden { bring() }
    }

    /// S-VIEW-05 Keep Window on Top.
    func keepOnTop(_ floating: Bool) {
        onTop = floating
        window?.level = floating ? .floating : .normal
    }
}
