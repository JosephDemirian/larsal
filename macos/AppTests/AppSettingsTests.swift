import AppCore
import AppKit
import SwiftUI
import Testing

/// The Settings frames of design/option-a/manifest.json (section
/// `settings`, E5-S9), light and dark. W-15's Settings > Shared Groups
/// replaces the locked settings-settings-shared-groups (LD-270 (3)).
enum SettingsFrame: String, CaseIterable, CustomTestStringConvertible {
    case general = "settings-settings-general"
    case security = "settings-settings-security"
    case autoType = "settings-settings-auto-type"
    case browser = "settings-settings-browser-integration"
    case ssh = "settings-settings-ssh-agent"
    case share = "w-15-app-settings"
    case keys = "settings-settings-shortcuts"

    var testDescription: String { rawValue }

    var page: AppSettingsPage {
        switch self {
        case .general: .general
        case .security: .security
        case .autoType: .autoType
        case .browser: .browser
        case .ssh: .ssh
        case .share: .share
        case .keys: .keys
        }
    }
}

/// APP-09.28 in tests: records what would be registered; never the system's
/// login items.
final class FakeLoginItem: LoginItem {
    var isOn = false
    var calls: [Bool] = []
    var refuse = false

    struct Refused: Error {}

    func set(_ enabled: Bool) throws {
        if refuse { throw Refused() }
        calls.append(enabled)
        isOn = enabled
    }
}

/// The frame's SSH status (mockup `SETP.ssh`); the user's agent is never
/// asked.
nonisolated let frameSshStatus = SshAgentStatus(
    socket: "/private/tmp/com.apple.launchd.Kp9w/Listeners", connected: true, message: nil)

/// A throwaway settings folder under /tmp, never the user's.
func settingsFolder(_ name: String) -> String {
    let path = "/tmp/e5s9-tests/\(name)-\(UUID().uuidString)"
    try? FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
    return path
}

@MainActor
func settingsModel(
    _ session: Session = Session(), login: FakeLoginItem = FakeLoginItem(), editable: Bool = true
) -> AppSettingsModel {
    AppSettingsModel(
        session: session, loginItem: login, loginEditable: editable, accessibility: { true },
        sshProbe: { _ in frameSshStatus })
}

/// Each frame's state as the mockup draws it (mockup.js `SETP`).
@MainActor
enum AppSettingsFrameState {
    static func apply(_ frame: SettingsFrame, _ model: AppSettingsModel) {
        switch frame {
        case .general: general(model)
        case .security: security(model)
        case .autoType: autoType(model)
        case .browser: browser(model)
        case .ssh:
            model.setFlag("ssh.enabled", true)
            model.sshStatus = frameSshStatus
        case .share:
            // INT-08.26, T09, T44: the defaults (D-INT08-10).
            flags(model, ["share.import", "share.export"], false)
            model.setFlag("share.quiet", true)
        case .keys: break
        }
        model.go(frame.page)
    }

    private static func flags(_ model: AppSettingsModel, _ keys: [String], _ value: Bool) {
        for key in keys { model.setFlag(key, value) }
    }

    private static func general(_ model: AppSettingsModel) {
        model.loginOn = false
        flags(model, ["recent.reopen_at_start", "recent.remember", "expiry.notice_on_unlock", "update.check"], true)
        model.setNumber("recent.count", 10)
        model.setNumber("expiry.notice_days", 7)
        flags(model, ["update.include_beta", "save.alternative", "window.hide_on_copy"], false)
        flags(model, ["save.after_every_change", "save.on_lock", "save.reload_on_change", "backup.enabled"], true)
        flags(model, ["entry.confirm_recycle", "entry.autogen_password", "list.copy_on_double_click"], true)
        model.setText("window.hide_on_copy.mode", "minimize")
        model.setText("ui.theme", "auto")
        model.setText("menubar_icon.style", "monochrome")
        flags(model, ["display.color_passwords", "menubar_icon.show", "window.close_hides"], true)
        model.setFlag("display.monospace_notes", false)
    }

    private static func security(_ model: AppSettingsModel) {
        model.setNumber("clipboard.clear.seconds", 30)
        model.setNumber("lock.idle.seconds", 300)
        model.setNumber("search.clear_after_minutes", 5)
        flags(model, ["clipboard.clear.enabled", "lock.idle.enabled", "quick_unlock.enabled"], true)
        flags(model, ["lock.on_screen_lock", "lock.on_user_switch", "display.hide_password_in_preview"], true)
        flags(model, ["search.clear_when_idle", "lock.on_minimize", "display.hide_password_in_editor"], false)
        flags(model, ["display.hide_totp_in_preview", "display.hide_notes", "display.dots_for_empty"], false)
    }

    private static func autoType(_ model: AppSettingsModel) {
        model.accessibility = true
        model.setText("autotype.global_shortcut", "⌃⌥V")
        flags(model, ["autotype.match_title", "autotype.match_url", "autotype.hide_expired"], true)
        flags(model, ["autotype.always_ask", "lock.relock_after_autotype"], false)
        model.setNumber("autotype.start_delay_ms", 500)
        model.setNumber("autotype.key_delay_ms", 25)
        model.setNumber("autotype.retype_seconds", 15)
    }

    private static func browser(_ model: AppSettingsModel) {
        flags(model, ["browser.enabled", "browser.safari", "browser.rewrite_manifests"], true)
        model.browsersOn = ["googlechrome", "firefoxbrowser"]
        model.safariAllowed = true  // the frame's App is signed (INT-01.15)
        flags(model, ["browser.notify", "browser.unlock_on_request", "browser.search_all_vaults"], true)
        flags(model, ["browser.best_match_only", "browser.never_ask_access", "browser.passkeys_localhost"], false)
        model.setFlag("browser.custom_proxy", false)
    }
}

@MainActor
@Suite(.serialized)
struct AppSettingsFrameTests {
    init() { Fonts.register() }

    @Test("Option A settings frame, offscreen, light and dark", arguments: SettingsFrame.allCases)
    func frame(_ frame: SettingsFrame) async throws {
        let model = settingsModel()
        AppSettingsFrameState.apply(frame, model)
        // The status probe answers on its own task: let it land first.
        try await Task.sleep(for: .milliseconds(50))
        if frame == .ssh { #expect(model.sshStatus == frameSshStatus) }
        let shots = SnapshotTests()
        let size = NSRect(origin: .zero, size: CGSize(width: 900, height: 680))
        let host = NSHostingView(rootView: AppSettingsView(model: model).frame(width: size.width, height: size.height))
        host.frame = size
        // Never ordered front (AGENTS.md rule 10).
        let offscreen = NSWindow(
            contentRect: size.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless], backing: .buffered,
            defer: false
        )
        offscreen.colorSpace = .sRGB
        offscreen.contentView = host
        for (folder, look) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            offscreen.appearance = NSAppearance(named: look)
            let png = try await shots.render(host)
            let out = ParityDemo.root.appending(path: "app-shots/\(folder)/\(frame.rawValue).png")
            try FileManager.default.createDirectory(
                at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
            try png.write(to: out)
            #expect(png.count > 10_000, "\(out.path)")
            let tree = try shots.accessibilityTree(host)
            try tree.write(to: out.deletingPathExtension().appendingPathExtension("ax.json"))
            let text = String(bytes: tree, encoding: .utf8) ?? ""
            #expect(text.contains("Search settings") && text.contains(frame.page.title))
        }
        offscreen.contentView = nil
    }
}

@MainActor
@Suite(.serialized)
struct AppSettingsTests {
    init() { Fonts.register() }

    @Test("APP-01.3 OK stores every page and the parts read the new values")
    func okStores() throws {
        let session = Session()
        let model = settingsModel(session)
        model.setNumber("clipboard.clear.seconds", 30)
        model.setNumber("lock.idle.seconds", 600)
        // S-LOCK-02 to -04, each away from its default.
        model.setFlag("lock.on_screen_lock", false)
        model.setFlag("lock.on_user_switch", false)
        model.setFlag("lock.on_minimize", true)
        #expect(session.settings().number(key: "clipboard.clear.seconds") == 10, "nothing stored before OK")
        #expect(model.ok())
        #expect(session.settings().number(key: "clipboard.clear.seconds") == 30)
        // The lock timers and switches (APP-02) take the stored values.
        let lock = LockSettings(store: session.settings())
        #expect(lock.idleSeconds == 600 && lock.idleEnabled)
        #expect(!lock.onScreenLock && !lock.onUserSwitch && lock.onMinimize)
    }

    @Test("APP-01.3 Cancel drops every edit")
    func cancelDrops() {
        let session = Session()
        let model = settingsModel(session)
        model.setNumber("clipboard.clear.seconds", 30)
        model.setFlag("display.hide_notes", true)
        #expect(model.changed)
        model.cancel()
        #expect(!model.changed)
        #expect(model.number("clipboard.clear.seconds") == 10)
        #expect(session.settings().number(key: "clipboard.clear.seconds") == 10)
    }

    @Test("APP-01.5 dependent controls are disabled and keep their values")
    func dependentControls() {
        let model = settingsModel()
        model.setNumber("recent.count", 9)
        model.setFlag("recent.remember", false)
        #expect(model.isDisabled("recent.count") && model.number("recent.count") == 9)
        #expect(model.isDisabled("clipboard.clear.seconds") == false)
        model.setFlag("clipboard.clear.enabled", false)
        #expect(model.isDisabled("clipboard.clear.seconds"))
        #expect(model.isDisabled("browser.notify"), "the Browser tabs follow S-BRW-01")
        model.setFlag("browser.enabled", true)
        #expect(!model.isDisabled("browser.notify"))
        #expect(model.isDisabled("update.include_beta"))
    }

    @Test("APP-01.6 auto-save forces its partners on and disables them")
    func autosavePartners() {
        let model = settingsModel()
        model.setFlag("save.after_every_change", false)
        model.setFlag("save.on_lock", false)
        model.setFlag("save.non_data_on_lock", false)
        #expect(!model.isDisabled("save.on_lock"))
        model.setFlag("save.after_every_change", true)
        #expect(model.flag("save.on_lock") && model.flag("save.non_data_on_lock"))
        #expect(model.isDisabled("save.on_lock"))
        model.setFlag("save.after_every_change", false)
        #expect(!model.isDisabled("save.on_lock") && model.flag("save.on_lock"))
    }

    @Test("APP-01.7 and .8 forgetting, and minimize after unlock excludes lock on minimize")
    func forgettingAndMinimize() throws {
        let session = Session()
        let model = settingsModel(session)
        model.setFlag("recent.remember", false)
        #expect(!model.flag("recent.reopen_at_start") && !model.flag("recent.remember_keys"))
        model.setFlag("lock.on_minimize", true)
        model.setFlag("window.minimize_after_unlock", true)
        #expect(!model.flag("lock.on_minimize") && model.isDisabled("lock.on_minimize"))
        #expect(model.ok())
        #expect(!session.settings().flag(key: "lock.on_minimize"))
        // APP-01.8 b: on opening, stored on with S-START-04 on shows unchecked.
        #expect(!settingsModel(session).flag("lock.on_minimize"))
    }

    @Test("APP-01.9 Reset puts the defaults back, keeps Browser, SSH and shared groups, and the login item")
    func reset() {
        let session = Session()
        let login = FakeLoginItem()
        login.isOn = true
        let model = settingsModel(session, login: login)
        model.setNumber("clipboard.clear.seconds", 30)
        model.setFlag("display.hide_passwords", false)
        model.setFlag("browser.enabled", true)
        model.setFlag("share.import", true)
        #expect(model.ok())
        #expect(model.reset())
        let store = session.settings()
        #expect(store.number(key: "clipboard.clear.seconds") == 10)
        #expect(store.flag(key: "display.hide_passwords"))
        #expect(store.flag(key: "browser.enabled") && store.flag(key: "share.import"))
        #expect(model.number("clipboard.clear.seconds") == 10, "the screen reloads")
        #expect(login.isOn && login.calls.isEmpty, "launch at login is not touched")
    }

    @Test("APP-09.28 launch at login: the switch shows the system's state and OK registers through the service")
    func launchAtLogin() {
        let login = FakeLoginItem()
        let model = settingsModel(login: login)
        #expect(!model.loginOn)
        model.loginOn = true
        model.cancel()
        #expect(login.calls.isEmpty, "Cancel registers nothing")
        model.loginOn = true
        #expect(model.ok())
        #expect(login.calls == [true] && model.loginSaved)
        login.isOn = false  // turned off in System Settings meanwhile
        model.load()
        #expect(!model.loginOn, "the switch shows the real registration")
        login.refuse = true
        model.loginOn = true
        #expect(!model.ok())
        #expect(model.error?.hasPrefix("App could not change its login item") == true)
        // APP-09.29: a debug build shows it disabled and never registers.
        let debug = FakeLoginItem()
        let locked = settingsModel(login: debug, editable: false)
        locked.loginOn = true
        #expect(locked.ok())
        #expect(debug.calls.isEmpty)
    }

    @Test("APP-01.12 a settings folder that cannot be written: error on open and on OK, nothing stored")
    func notWritable() throws {
        let folder = settingsFolder("ro")
        defer { try? FileManager.default.removeItem(atPath: folder) }
        let session = Session()
        session.settings().useFolder(folder: folder)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: folder) }
        try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: folder)
        let model = settingsModel(session)
        #expect(model.error?.contains(folder) == true)
        model.setNumber("clipboard.clear.seconds", 30)
        #expect(!model.ok())
        #expect(model.error?.contains(folder) == true)
        #expect(session.settings().number(key: "clipboard.clear.seconds") == 10)
        #expect(model.number("clipboard.clear.seconds") == 30, "the screen keeps the edit")
    }

    @Test("APP-01.10, .11 export, then an import that lowers protection asks first")
    func exportImport() throws {
        let folder = settingsFolder("io")
        defer { try? FileManager.default.removeItem(atPath: folder) }
        let session = Session()
        session.settings().useFolder(folder: folder)
        let model = settingsModel(session)
        model.setFlag("lock.idle.enabled", false)
        model.setNumber("clipboard.clear.seconds", 45)
        #expect(model.ok())
        #expect(model.export(to: folder + "/out.json"))
        let file = try String(contentsOfFile: folder + "/out.json", encoding: .utf8)
        #expect(file.contains("clipboard.clear.seconds") && !file.contains("state."))
        #expect(model.reset())
        let listed = model.importFile(folder + "/out.json", apply: false)
        #expect(listed.map(\.id) == ["S-TIME-02", "S-TIME-03"])
        #expect(session.settings().flag(key: "lock.idle.enabled"), "nothing changed before Apply")
        #expect(model.importFile(folder + "/out.json", apply: true).isEmpty)
        #expect(!session.settings().flag(key: "lock.idle.enabled"))
        #expect(model.number("clipboard.clear.seconds") == 45)
        _ = model.importFile(folder + "/settings.json", apply: true)
        #expect(model.error?.hasSuffix("is not a settings file App can use.") == true)
    }

    @Test("Settings pages: the nav, back and forward, and the search field")
    func pages() {
        let model = settingsModel()
        #expect(model.page == .general && !model.canGoBack)
        model.go(.security)
        model.go(.keys)
        model.goBack()
        #expect(model.page == .security && model.canGoForward)
        model.goForward()
        #expect(model.page == .keys)
        model.query = "clipboard"
        #expect(model.visiblePages == [.security])
        model.query = "lock"
        #expect(model.visiblePages.contains(.security) && model.visiblePages.contains(.keys))
        model.query = ""
        #expect(model.visiblePages == AppSettingsPage.allCases)
    }

    @Test("APP-01.31 the SSH status row asks only while S-SSH-01 is on")
    func sshStatus() async throws {
        let model = settingsModel()
        #expect(model.sshStatus == nil)
        model.setFlag("ssh.enabled", true)
        for _ in 0..<40 where model.sshStatus == nil { try await Task.sleep(for: .milliseconds(25)) }
        #expect(model.sshStatus == frameSshStatus)
        model.setFlag("ssh.enabled", false)
        #expect(model.sshStatus == nil)
    }

    @Test("S-ENTRY-02 reaches the delete question; LD-204 generator options persist in the store")
    func settingsReachTheVault() throws {
        let session = Session()
        let model = settingsModel(session)
        model.setFlag("entry.confirm_recycle", true)
        #expect(model.ok())
        let path = try ParityDemo.path(0, folder: "settings-reach")
        let id = try session.open(path: path)
        #expect(try session.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        let window = MainWindowModel(session: session)
        window.refresh()
        #expect(window.main?.askBeforeBin == true)
        var options = session.generatorOptions(vault: nil)
        options.length = 16
        session.closeGenerator(save: options)
        #expect(session.settings().number(key: "generator.password.length") == 16)
        window.lockAll()
    }
}
