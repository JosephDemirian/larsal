import AppCore
import AppKit
import Observation
import SwiftUI

/// The settings window's model (APP-01, E5-S9): the values of every page as
/// edited, over the Rust store. OK stores them all at once, Cancel drops
/// them (APP-01.3). Settings never hold a secret.
@MainActor
@Observable
final class AppSettingsModel {
    let session: Session
    let store: AppSettingsStore
    private let loginItem: LoginItem
    /// APP-09.29: a debug build shows the login item disabled.
    let loginEditable: Bool
    /// The values as stored, and as edited.
    private(set) var saved: [String: AppSettingValue] = [:]
    private var draft: [String: AppSettingValue] = [:]
    /// S-START-02, from the OS (APP-01.37).
    private(set) var loginSaved = false
    var loginOn = false
    private(set) var page = AppSettingsPage.general
    private var back: [AppSettingsPage] = []
    private var forward: [AppSettingsPage] = []
    /// The nav's search field.
    var query = ""
    /// APP-01.12 and failed actions: the error shown on the page.
    var error: String?
    /// The SSH page's status row (APP-01.31), while S-SSH-01 is on.
    var sshStatus: SshAgentStatus?
    /// Accessibility access for Auto-Type (INT-05.35): checked again when
    /// the Auto-Type page shows and when App becomes active.
    var accessibility: Bool
    /// Asks macOS whether App has it (a check only, never the request);
    /// tests give a fake.
    private let trusted: () -> Bool
    /// The browsers whose setup file App wrote (S-BRW-03 to -07, INT-01.8),
    /// as edited; Safari is S-BRW-02. OK writes and removes the files
    /// (APP-01.30).
    var browsersOn: Set<String> = []
    private var browsersSaved: Set<String> = []
    /// App's browser integration (E7-S6); `nil` where none runs (tests
    /// give their own over a throwaway folder).
    let browsers: Browsers?
    /// INT-01.15: the Safari switch needs a build signed with a team id;
    /// without one it shows disabled with `safariNote` (MI01-04).
    var safariAllowed = false
    var safariNote: String?
    /// MI01-02, MI01-05 and MI01-06 while S-BRW-01 is on.
    var browserNotes: [String] = []
    /// Asks the agent for the status row; tests pass a fake (never the
    /// user's agent).
    private let sshProbe: @Sendable (String) -> SshAgentStatus

    init(
        session: Session,
        loginItem: LoginItem = SystemLoginItem(),
        loginEditable: Bool = !coreIsDebug(),
        accessibility trusted: @escaping () -> Bool = { AXIsProcessTrusted() },
        sshProbe: @escaping @Sendable (String) -> SshAgentStatus = { sshAgentStatus(socketOverride: $0) },
        browsers: Browsers? = AppBrowsers.shared
    ) {
        self.session = session
        store = session.settings()
        self.loginItem = loginItem
        self.loginEditable = loginEditable
        self.trusted = trusted
        accessibility = trusted()
        self.sshProbe = sshProbe
        self.browsers = browsers
        load()
    }

    /// INT-05.35: the permission checked again.
    func recheckAccess() { accessibility = trusted() }

    /// APP-01.3: every page shows the current values, the first page first.
    func load() {
        saved = Dictionary(store.values().map { ($0.key, $0.value) }, uniquingKeysWith: { first, _ in first })
        draft = saved
        // APP-01.8: lock on minimize shows checked only with S-START-04 off.
        if flag("window.minimize_after_unlock") { draft["lock.on_minimize"] = .flag(on: false) }
        loginSaved = loginItem.isOn
        loginOn = loginSaved
        page = .general
        back = []
        forward = []
        error = store.checkWritable()
        refreshSsh()
        refreshBrowsers()
    }

    /// The browser page's switches and messages, from App's files (INT-01.8).
    private func refreshBrowsers() {
        guard let page = browsers?.page() else { return }
        let written = Set(page.switches.filter(\.on).map(\.browser))
        browsersOn = Set(Self.browserNames.filter { written.contains($0.value) }.keys)
        browsersSaved = browsersOn
        safariAllowed = page.safariAllowed
        safariNote = page.safariNote
        browserNotes = page.notes.map(\.text)
    }

    /// The page's brand names and the core's browser names (INT-01.8); Opera
    /// waits for V-INT01-1 and Edge's row for W-07.
    static let browserNames = [
        "googlechrome": "Chrome", "firefoxbrowser": "Firefox", "brave": "Brave", "vivaldi": "Vivaldi",
    ]

    /// A browser's switch as the user edits it (stored on OK, APP-01.30).
    func setBrowser(_ brand: String, _ isOn: Bool) {
        if isOn { browsersOn.insert(brand) } else { browsersOn.remove(brand) }
    }

    // MARK: Values

    func flag(_ key: String) -> Bool {
        if case .flag(let value) = draft[key] { return value }
        return false
    }

    func number(_ key: String) -> Int64 {
        if case .number(let value) = draft[key] { return value }
        return 0
    }

    func text(_ key: String) -> String {
        if case .text(let text) = draft[key] { return text }
        return ""
    }

    /// The screen's rules as the user edits (APP-01.6 to .8).
    func setFlag(_ key: String, _ value: Bool) {
        draft[key] = .flag(on: value)
        switch (key, value) {
        case ("save.after_every_change", true):
            draft["save.on_lock"] = .flag(on: true)
            draft["save.non_data_on_lock"] = .flag(on: true)
        case ("recent.remember", false):
            draft["recent.reopen_at_start"] = .flag(on: false)
            draft["recent.remember_keys"] = .flag(on: false)
        case ("window.minimize_after_unlock", true):
            draft["lock.on_minimize"] = .flag(on: false)
        case ("ssh.enabled", _):
            refreshSsh()
        default:
            break
        }
    }

    func setNumber(_ key: String, _ value: Int64) { draft[key] = .number(value: value) }

    func setText(_ key: String, _ text: String) { draft[key] = .text(text: text) }

    func binding(_ key: String) -> Binding<Bool> {
        Binding(get: { self.flag(key) }, set: { self.setFlag(key, $0) })
    }

    /// The control each one depends on (APP-01.5).
    static let dependsOn: [String: String] = [
        "recent.count": "recent.remember", "recent.reopen_at_start": "recent.remember",
        "recent.remember_keys": "recent.remember", "update.include_beta": "update.check",
        "expiry.notice_days": "expiry.notice_on_unlock", "backup.pattern": "backup.enabled",
        "save.alternative.mode": "save.alternative", "window.hide_on_copy.mode": "window.hide_on_copy",
        "menubar_icon.style": "menubar_icon.show", "menubar_icon.minimize_to": "menubar_icon.show",
        "autotype.skip_ask_main_window": "autotype.always_ask", "clipboard.clear.seconds": "clipboard.clear.enabled",
        "lock.idle.seconds": "lock.idle.enabled", "search.clear_after_minutes": "search.clear_when_idle",
        "browser.custom_proxy.path": "browser.custom_proxy", "ssh.socket_override": "ssh.enabled",
        "ssh.sk_provider_override": "ssh.enabled",
    ]

    /// APP-01.5, .6, .8: disabled controls keep their values.
    func isDisabled(_ key: String) -> Bool {
        if let parent = Self.dependsOn[key], !flag(parent) { return true }
        // Both Browser tabs follow S-BRW-01.
        if key.hasPrefix("browser."), key != "browser.enabled", !flag("browser.enabled") { return true }
        if key == "browser.safari", !safariAllowed { return true }  // INT-01.15
        if key == "save.on_lock" || key == "save.non_data_on_lock" { return flag("save.after_every_change") }
        if key == "lock.on_minimize" { return flag("window.minimize_after_unlock") }
        return false
    }

    /// Edits not yet stored.
    var changed: Bool { draft != saved || loginOn != loginSaved || browsersOn != browsersSaved }

    // MARK: OK, Cancel, Reset, Import, Export

    /// APP-01.3 OK: stores every page, then the parts that use them apply
    /// them. False, with `error`, when the file cannot be written: nothing
    /// is stored and the window stays open (APP-01.12).
    @discardableResult
    func ok() -> Bool {
        let changes = draft.filter { saved[$0.key] != $0.value }.map { AppSetting(key: $0.key, value: $0.value) }
        do {
            if !changes.isEmpty { try session.saveSettings(changes: changes) }
        } catch {
            self.error = Self.message(error)
            return false
        }
        saved = draft
        // APP-01.37: written to the OS, never to the settings file.
        if loginEditable, loginOn != loginSaved {
            do {
                try loginItem.set(loginOn)
            } catch {
                loginOn = loginItem.isOn
                self.error = "App could not change its login item: \(error.localizedDescription)"
                return false
            }
            loginSaved = loginItem.isOn
            loginOn = loginSaved
        }
        error = nil
        // APP-01.30: a checked box writes the setup file, an unchecked one
        // removes it; a failure names the browser and the switch shows the
        // file's state again.
        var failed: String?
        for brand in browsersOn.symmetricDifference(browsersSaved).sorted() {
            guard let name = Self.browserNames[brand] else { continue }
            if let note = browsers?.set(browser: name, on: browsersOn.contains(brand)) { failed = failed ?? note.text }
        }
        applied()
        if let failed {
            error = failed
            return false
        }
        return true
    }

    /// APP-01.3 Cancel: every edit is dropped. The global Auto-Type
    /// shortcut is registered again once Auto-Type exists (E8).
    func cancel() {
        draft = saved
        loginOn = loginSaved
        browsersOn = browsersSaved
        error = nil
    }

    /// APP-01.9, after the user confirmed: every value back to its default
    /// (Browser, SSH and shared groups keep theirs), applied at once; launch
    /// at login is left alone.
    @discardableResult
    func reset() -> Bool {
        do {
            try session.resetSettings()
        } catch {
            self.error = Self.message(error)
            return false
        }
        let page = page
        load()
        self.page = page
        applied()
        return true
    }

    /// APP-01.10: every stored portable value to `path`.
    @discardableResult
    func export(to path: String) -> Bool {
        do {
            try store.exportTo(path: path)
            return true
        } catch {
            self.error = Self.message(error)
            return false
        }
    }

    /// APP-01.11: imports `path`. An import that lowers protection returns
    /// the list and changes nothing until it is asked again with `apply`.
    func importFile(_ path: String, apply: Bool) -> [SettingsWeakening] {
        do {
            let result = try session.importSettings(path: path, apply: apply)
            if result.applied {
                load()
                applied()
            }
            return result.weakened
        } catch {
            self.error = Self.message(error)
            return []
        }
    }

    private func applied() {
        // INT-01.6, INT-01.13: the sockets follow S-BRW-01 and the Safari switch.
        _ = browsers?.apply()
        refreshBrowsers()
        NotificationCenter.default.post(name: .appSettingsApplied, object: session)
    }

    static func message(_ error: Error) -> String {
        guard let error = error as? AppSettingsError else { return "Something went wrong. Try again." }
        switch error {
        case .NotWritable(let text), .NotSettingsFile(let text), .Invalid(let text), .CannotWrite(let text):
            return text
        }
    }

    // MARK: Pages

    func go(_ next: AppSettingsPage) {
        guard next != page else { return }
        back.append(page)
        forward = []
        page = next
    }

    var canGoBack: Bool { !back.isEmpty }
    var canGoForward: Bool { !forward.isEmpty }

    func goBack() {
        guard let last = back.popLast() else { return }
        forward.append(page)
        page = last
    }

    func goForward() {
        guard let next = forward.popLast() else { return }
        back.append(page)
        page = next
    }

    /// The pages whose title or rows hold the search words.
    var visiblePages: [AppSettingsPage] {
        let words = query.trimmingCharacters(in: .whitespaces)
        guard !words.isEmpty else { return AppSettingsPage.allCases }
        return AppSettingsPage.allCases.filter { page in
            ([page.title] + page.words).contains { $0.localizedCaseInsensitiveContains(words) }
        }
    }

    /// APP-01.31: the status row, asked off the main thread.
    func refreshSsh() {
        guard flag("ssh.enabled") else {
            sshStatus = nil
            return
        }
        let socket = text("ssh.socket_override")
        let probe = sshProbe
        Task { [weak self] in
            let status = await Task.detached { probe(socket) }.value
            self?.sshStatus = status
        }
    }
}

/// The app's one browser integration (E7-S6), made at the end of the launch.
@MainActor
enum AppBrowsers {
    static var shared: Browsers?
}
