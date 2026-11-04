import AppKit
import LarsalCore
import ServiceManagement
import SwiftUI

/// The settings window's pages (mockup `SETTINGS`), in the mockup's order.
enum LarsalSettingsPage: String, CaseIterable, Identifiable {
    case general, security, autoType, browser, ssh, share, keys

    var id: String { rawValue }

    var title: String {
        switch self {
        case .general: "General"
        case .security: "Security"
        case .autoType: "Auto-Type"
        case .browser: "Browser Integration"
        case .ssh: "SSH Agent"
        case .share: "Shared Groups"
        case .keys: "Shortcuts"
        }
    }

    /// The nav tile: colour token and Phosphor glyph.
    var tile: (color: String, glyph: String) {
        switch self {
        case .general: ("gray", "gear-six")
        case .security: ("blue", "lock-key")
        case .autoType: ("orange", "keyboard")
        case .browser: ("teal", "globe-simple")
        case .ssh: ("graphite", "terminal-window")
        case .share: ("green", "share-network")
        case .keys: ("purple", "command")
        }
    }
}

/// APP-09.28: launch at login through the system's login item service
/// (D-APP09-8, SMAppService). Behind a protocol, so tests use a fake and
/// never register or unregister anything on this Mac.
protocol LoginItem: AnyObject {
    /// The system's actual registration (the checkbox shows it).
    var isOn: Bool { get }
    func set(_ enabled: Bool) throws
}

/// The main app as a login item (macOS 13 and later).
final class SystemLoginItem: LoginItem {
    var isOn: Bool { SMAppService.mainApp.status == .enabled }

    func set(_ enabled: Bool) throws {
        if enabled {
            try SMAppService.mainApp.register()
        } else {
            try SMAppService.mainApp.unregister()
        }
    }
}

extension Notification.Name {
    /// Posted after OK, Reset or Import stored new settings: the parts that
    /// read them at start take them again (APP-01.3).
    static let larsalSettingsApplied = Notification.Name("app.larsal.desktop.settingsApplied")
}

extension LarsalSettingsPage {
    /// Each page's row titles, for the search field.
    static let rowTitles: [LarsalSettingsPage: [String]] = [
        .general: [
            "Startup", "Open Larsal at login", "Reopen the last vaults at start", "Remember recent vaults",
            "Show entries that expire soon after unlocking", "Check for updates", "Include beta versions", "Saving",
            "Save changes as you make them", "Save when locking", "Reload the vault when another app changes it",
            "Keep a backup before saving", "Safe saving", "Entries", "Ask before moving to the Recycle Bin",
            "Make a password for every new entry", "Double-clicking a row copies", "Hide Larsal after copying", "Look",
            "Appearance", "Colour digits and symbols in passwords", "Monospace font in notes",
            "Show Larsal in the menu bar", "Closing the window keeps Larsal running",
        ],
        .security: [
            "Timeouts", "Clear the clipboard after", "Lock after no use for", "Clear the search after", "Locking",
            "Unlock with Touch ID", "Lock when the screen locks", "Lock when you switch user",
            "Lock when the window is minimized", "Showing secrets", "Hide passwords in the editor",
            "Hide passwords in the detail pane", "Hide one-time codes in the detail pane", "Hide notes",
            "Show dots for empty passwords", "Privacy", "Let other apps record Larsal's windows",
        ],
        .autoType: [
            "Shortcut", "Type the login for the window in front", "Matching", "Match by window title",
            "Match by website address in the title", "Always ask which entry to type", "Skip expired entries",
            "Lock again after typing", "Timing", "Wait before typing", "Pause between keys",
            "Do not type the same login again within",
        ],
        .browser: [
            "Let browsers use Larsal", "Browsers", "Safari", "Chrome", "Firefox", "Brave", "Vivaldi", "Opera",
            "When a browser asks", "Show a notification", "Ask to unlock a locked vault", "Offer only the best matches",
            "Search every open vault", "Never ask before giving access", "Allow passkeys on localhost", "Advanced",
            "Use my own proxy program", "Rewrite the browser setup files at start",
        ],
        .ssh: ["Work with the SSH agent", "Agent", "Status", "Use a different socket", "Security key provider"],
        .share: ["Allow import", "Allow export", "Hide sync success messages"],
        .keys: LarsalSettingsShortcuts.groups.flatMap { [$0.title] + $0.items.map(\.title) },
    ]

    var words: [String] { Self.rowTitles[self] ?? [] }
}

extension LockSettings {
    /// APP-02's settings as stored (S-TIME-03, -04, S-LOCK-02 to -04,
    /// S-START-04).
    init(store: LarsalSettingsStore) {
        self.init(
            idleEnabled: store.flag(key: "lock.idle.enabled"),
            idleSeconds: Int(store.number(key: "lock.idle.seconds")),
            onScreenLock: store.flag(key: "lock.on_screen_lock"),
            onUserSwitch: store.flag(key: "lock.on_user_switch"),
            onMinimize: store.flag(key: "lock.on_minimize"),
            minimizeAfterUnlock: store.flag(key: "window.minimize_after_unlock")
        )
    }
}

/// APP-01.27 (S-TIME-05, -06): clears a vault's search a while after its
/// field lost focus; focus back stops it, a new selection restarts it.
final class SearchClearTimer {
    /// The length of S-TIME-06's minute; each timer has its own, so tests
    /// that shorten it never change another suite's (LD-244 (2)).
    var minute = Duration.seconds(60)
    private var task: Task<Void, Never>?
    var running: Bool { task != nil }

    func focus(_ focused: Bool, _ model: VaultModel) {
        task?.cancel()
        task = nil
        let settings = model.session.settings()
        guard !focused, settings.flag(key: "search.clear_when_idle") else { return }
        let wait = minute * settings.number(key: "search.clear_after_minutes")
        task = Task { [weak self, weak model] in
            try? await Task.sleep(for: wait)
            guard !Task.isCancelled, let self else { return }
            task = nil
            model?.setSearch("")
        }
    }
}

/// S-VIEW-01 (APP-01.28): auto follows macOS, light and dark are fixed.
enum Appearance {
    static func apply(
        _ store: LarsalSettingsStore, environment: [String: String] = ProcessInfo.processInfo.environment
    ) {
        let stored = store.text(key: "ui.theme")
        #if DEBUG
            // Mac QA snapshots choose their look (DebugUI); it wins.
            let theme = environment["LARSAL_DEBUG_APPEARANCE"] ?? stored
        #else
            let theme = stored
        #endif
        switch theme {
        case "light": NSApp?.appearance = NSAppearance(named: .aqua)
        case "dark": NSApp?.appearance = NSAppearance(named: .darkAqua)
        default: NSApp?.appearance = nil
        }
    }
}

/// The Shortcuts page's actions (APP-08 ids, mockup order) with their
/// default keys.
enum LarsalSettingsShortcuts {
    struct Item {
        let id: String
        let title: String
        let keys: String
    }

    static let groups: [(title: String, items: [Item])] = [
        (
            "Entries",
            [
                Item(id: "copy.username", title: "Copy Username", keys: "⌘B"),
                Item(id: "copy.password", title: "Copy Password", keys: "⌘C"),
                Item(id: "copy.url", title: "Copy URL", keys: "⇧⌘U"),
                Item(id: "ACT-OTP-COPY", title: "Copy One-Time Code", keys: "⌘T"),
                Item(id: "action.autotype", title: "Type Login", keys: "⇧⌘V"),
                Item(id: "action.open_url", title: "Open URL", keys: "⌘U"),
                Item(id: "action.edit_entry", title: "Edit Entry", keys: "⌘E"),
                Item(id: "entry.clone", title: "Clone Entry", keys: "⌘D"),
                Item(id: "action.delete_entry", title: "Delete Entry", keys: "⌘⌫"),
            ]
        ),
        (
            "Larsal",
            [
                Item(id: "action.lock_vault", title: "Lock Vault", keys: "⌘L"),
                Item(id: "action.lock_all", title: "Lock Everything", keys: "⇧⌘L"),
                Item(id: "ACT-GEN-OPEN-TOOL", title: "Password Generator", keys: "⌥⌘G"),
                Item(id: "action.reports", title: "Reports", keys: "⇧⌘R"),
                Item(id: "action.vault_settings", title: "Vault Settings", keys: "⇧⌘,"),
                Item(id: "action.toggle_sidebar", title: "Show Sidebar", keys: "⌃⌘S"),
            ]
        ),
    ]
}
