import AppCore
import AppKit
import Observation
import Security
import os

/// AppKit's app events: the end of the launch and files opened from macOS.
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// The window's model over the app's one Rust session.
    let window = MainWindowModel()
    /// APP-02: the system events and the idle countdown that lock every vault.
    private var lockSignals: LockSignals?
    /// APP-08.20: the optional menu bar icon.
    private var icon: MenuBarIcon?
    /// INT-05.25: the global Auto-Type shortcut and its picker.
    private var autoType: AutoType?
    /// LD-159 (9): Finder opens that come before the launch ends wait for
    /// it, so the reopened vaults come first (APP-09.20); `nil` after.
    private var early: [String]? = []

    func applicationWillFinishLaunching(_ notification: Notification) {
        // APP-10.1, APP-10.5: every window protected from its creation,
        // unless F07 allows capture for this run; M10-01 in the banner.
        ScreenProtection.shared.refused = { [window] in window.banner = ScreenProtection.refusedText }
        ScreenProtection.shared.start(allowCapture: allowsScreenCapture())
        Fonts.register()
        #if DEBUG
            DebugUI.appearance()
        #endif
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // APP-09.1 steps 11 to 13; from here the instance channel answers.
        FileAccess.launch { launchFinished(events: WindowEvents(window: window)) }
        window.refresh()
        window.open(early ?? [])
        early = nil
        let session = window.session
        let settings = session.settings()
        // APP-01: the stored settings reach the parts that use them; OK,
        // Reset and Import apply them again (APP-01.3).
        lockSignals = LockSignals.app(session: session) { [window] in window.lockAll() }
        lockSignals?.watchInput()
        Appearance.apply(settings)
        // E7-S6 (INT-01): the browser bridge's sockets follow S-BRW-01 and the
        // Safari switch; App's setup files are written again at start (INT-01.11).
        let team = Signing.teamID()
        let browsers = Browsers(settings: settings, teamId: team, groupFolder: team.flatMap(Signing.groupFolder))
        AppBrowsers.shared = browsers
        _ = browsers.start()
        NotificationCenter.default.addObserver(
            self, selector: #selector(settingsApplied), name: .appSettingsApplied, object: nil)
        // D-01-1: a settings file that could not be read, once.
        if let notice = settings.takeNotice() { window.banner = notice }
        // APP-08.19 to APP-08.22: closing, minimizing and the menu bar icon.
        let rules = WindowRules.shared
        rules.settings = {
            WindowRules.Settings(
                closeHides: settings.flag(key: "window.close_hides"), icon: settings.flag(key: "menubar_icon.show"),
                minimizeToIcon: settings.flag(key: "menubar_icon.minimize_to"))
        }
        rules.minimized = { [weak self] in self?.lockSignals?.minimized() }
        icon = MenuBarIcon(window: window, slot: MenuBarIcon.slot())
        icon?.update()
        watchVaults()
        // INT-05.30: the global shortcut; a hidden launch registers none
        // (AGENTS.md rule 10).
        if !launchHidden() {
            autoType = AutoType(
                session: session, hotKeys: CarbonHotKeys(), windows: SystemWindows(), present: AutoTypePanel.present)
            autoType?.refreshed = { [window] in window.refresh() }
            autoType?.relock = { [window] in window.lock($0) }  // INT-05.32
            // INT-05.43, INT-05.44: the real permission and keyboard, only here.
            autoType?.trust = SystemAccessibility()
            session.autotypePostEvents()
            autoType?.start()
        }
        // APP-09.21: hidden to the menu bar icon, or minimized into the Dock.
        if startsMinimized() {
            DispatchQueue.main.async { rules.startMinimized() }
        }
        #if DEBUG
            Snapshot.startIfAsked(window)
        #endif
    }

    /// OK, Reset or Import stored new settings (APP-01.3).
    @objc private func settingsApplied() {
        let settings = window.session.settings()
        lockSignals?.settings = LockSettings(store: settings)
        Appearance.apply(settings)
        window.view.load(settings)
        icon?.update()
        autoType?.register()
        // INT-08.24, INT-08.15 (F-176): Allow import and Allow export reach
        // the badges, the label and the watches at once.
        window.refresh()
    }

    /// APP-08.20: the icon follows every lock and unlock at once.
    private func watchVaults() {
        withObservationTracking {
            _ = window.vaults
        } onChange: { [weak self] in
            DispatchQueue.main.async {
                self?.icon?.update()
                self?.autoType?.vaultsChanged()
                self?.watchVaults()
            }
        }
    }

    /// APP-08.23, APP-09.22: a click on the Dock icon, or a launch while
    /// App runs, brings the window to front.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        Front.bring()
        return false
    }

    /// APP-09.22: App became active by any means (the app switcher, Finder).
    func applicationDidBecomeActive(_ notification: Notification) {
        WindowRules.shared.activated()
    }

    /// APP-02.15 steps 7 and 8 (E5-S10, F-122): editor edits ask first;
    /// changed vaults save first, off the main thread while AppKit waits
    /// (LD-228 (1)); one that cannot asks on its screen and the quit waits
    /// for the answer. A quit signal or a logout, restart or shut down
    /// never asks (APP-02.16).
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        let reason = NSAppleEventManager.shared().currentAppleEvent?.attributeDescriptor(forKeyword: kAEQuitReason)
        return window.quitReply(asks: !QuitSignals.received && reason == nil) {
            sender.reply(toApplicationShouldTerminate: $0)
        }
    }

    /// Menu, ⌘Q and the quit signals all end here (APP-09.27).
    func applicationWillTerminate(_ notification: Notification) {
        AppBrowsers.shared?.stop()
        window.quit()
    }

    /// APP-09.23: Finder, Open With, the Dock icon and `open FILE`.
    func application(_ application: NSApplication, open urls: [URL]) {
        let paths = FileOpen.paths(urls)
        Logger.app.notice("Open request from macOS: \(paths.count) files")
        guard early == nil else {
            early?.append(contentsOf: paths)
            return
        }
        window.open(paths)
    }
}

/// App's own code signature (INT-01.15): the Safari route needs a team id.
enum Signing {
    /// The team id App is signed with; `nil` in an ad hoc or unsigned build.
    static func teamID() -> String? {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
            SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
            SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
                == errSecSuccess,
            let info = info as? [String: Any]
        else { return nil }
        return info[kSecCodeInfoTeamIdentifier as String] as? String
    }

    /// The app group `‹team id›.com.app.browser`'s container (INT-01.13).
    static func groupFolder(team: String) -> String? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "\(team).com.app.browser")?.path
    }
}
