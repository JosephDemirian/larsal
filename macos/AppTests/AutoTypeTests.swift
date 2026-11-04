import AppCore
import AppKit
import SwiftUI
import Testing

/// The hot key service of the tests: records, never registers a real key
/// (AGENTS.md rule 10).
final class FakeHotKeys: HotKeys {
    var registered: [AutoTypeHotKey] = []
    var unregistered = 0
    var refuse = false
    private var action: (() -> Void)?

    func register(_ key: AutoTypeHotKey, fired: @escaping () -> Void) -> Bool {
        registered.append(key)
        action = fired
        return !refuse
    }

    func unregister() {
        unregistered += 1
        action = nil
    }

    /// The user presses the shortcut.
    func press() { action?() }
}

/// Fake windows in front: the first read is the capture, each later one a
/// key's window check; the last window stays in front. Never the owner's.
nonisolated final class FakeWindows: WindowSource, @unchecked Sendable {
    var windows: [FrontWindow]
    private(set) var reads = 0

    init(_ windows: [FrontWindow]) { self.windows = windows }

    func front() -> FrontWindow? {
        defer { reads += 1 }
        return windows.isEmpty ? nil : windows[min(reads, windows.count - 1)]
    }
}

/// The frame's picture (mockup `autotypePicker`): the desktop and the
/// picker 40 points from the top. The desktop is macOS's, so its colours
/// are the mockup's literal ones and live here, not in the app.
struct AutoTypePickerFrame: View {
    let picker: AutoTypePicker
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        ZStack(alignment: .top) {
            LinearGradient(
                stops: scheme == .dark
                    ? [
                        .init(color: rgb(0x1c2a30), location: 0), .init(color: rgb(0x10161a), location: 0.6),
                        .init(color: rgb(0x15191b), location: 1),
                    ]
                    : [
                        .init(color: rgb(0x9fb4bf), location: 0), .init(color: rgb(0xc9d3d1), location: 0.6),
                        .init(color: rgb(0xb9c4c6), location: 1),
                    ],
                // CSS 160deg over 720 × 420.
                startPoint: UnitPoint(x: 0.348, y: -0.217), endPoint: UnitPoint(x: 0.652, y: 1.217)
            )
            .accessibilityHidden(true)
            AutoTypePickerView(model: picker).padding(.top, 40)
        }
        .frame(width: 720, height: 420)
        .foregroundStyle(Tok.text)
    }

    private func rgb(_ hex: Int) -> Color {
        Color(red: Double(hex >> 16 & 255) / 255, green: Double(hex >> 8 & 255) / 255, blue: Double(hex & 255) / 255)
    }
}

@MainActor
@Suite(.serialized)
struct AutoTypeTests {
    static let safari = "Sign in to GitHub · GitHub — Safari"
    let ownPid = ProcessInfo.processInfo.processIdentifier
    let session = Session()
    let keys = FakeHotKeys()

    init() { ParityDemo.setUp() }

    // MARK: The shortcut seam (INT-05.25, INT-05.30)

    @Test("INT-05.30 T75: ⌃⌥V is registered once through the seam; the fake press opens the picker")
    func shortcutOpensPicker() throws {
        _ = try personal("at-shortcut")
        let log = Log()
        let auto = autoType(FakeWindows([Self.window(Self.safari)]), log: log)
        #expect(keys.registered.count == 1)
        let key = try #require(keys.registered.first)
        #expect((key.code, key.control, key.option, key.shift, key.command) == (0x09, true, true, false, false))
        #expect(auto.registered)
        keys.press()
        let picker = try #require(auto.picker)
        #expect(log.shown.count == 1 && log.shown.first! === picker)
        #expect(picker.header == "Type into “\(Self.safari)”")
        #expect(picker.rows.map(\.title) == ["GitHub", "GitHub", "GitHub (work bot)"])
        // Step 2: a second press while the picker is open does nothing.
        keys.press()
        #expect(log.shown.count == 1)
        picker.cancel()
        #expect(auto.picker == nil && log.shown.last! == nil)
    }

    @Test("INT-05.30 T77, T78: a refused key is reported; cleared or invalid S-AT-07 unregisters")
    func shortcutSettings() throws {
        keys.refuse = true
        let log = Log()
        let auto = autoType(FakeWindows([]), log: log)
        #expect(!auto.registered)
        keys.refuse = false
        for text in ["", "⌥V"] {
            try set("autotype.global_shortcut", .text(text: text))
            let before = keys.unregistered
            auto.register()
            #expect(keys.unregistered == before + 1 && !auto.registered, "\(text)")
        }
        try set("autotype.global_shortcut", .text(text: "⌘⇧K"))
        auto.register()
        #expect(auto.registered && keys.registered.last?.code == 0x28)
    }

    // MARK: The picker (INT-05.26 to INT-05.29)

    @Test(
        "Parity menubar-auto-type-picker: keys move, typing searches all, Escape clears, then closes (T57, T64, T67)"
    )
    func pickerStates() throws {
        _ = try personal("at-picker")
        let log = Log()
        let windows = FakeWindows([Self.window(Self.safari)])
        let auto = autoType(windows, log: log)
        auto.fired()
        let picker = try #require(auto.picker)
        #expect(picker.highlight == 0)
        #expect(picker.press(.downArrow, []) && picker.highlight == 1)
        #expect(picker.press(.pageDown, []) && picker.highlight == 2, "stops at the last row")
        #expect(picker.press(.upArrow, []) && picker.press(.pageUp, []) && picker.highlight == 0)
        #expect(!picker.press(.tab, []), "other keys go to the field")
        picker.search = "proton"
        #expect(picker.rows.map(\.title) == ["Proton Mail"] && picker.highlight == 0)
        #expect(picker.press(.escape, []) && picker.search.isEmpty && picker.rows.count == 3)
        #expect(picker.press(.escape, []) && auto.picker == nil)
        #expect(windows.reads == 1, "closed without typing: no window check ran")
        // INT-05.24: no title, the app's name; every candidate.
        autoType(FakeWindows([Self.window("", app: "Notes")]), log: log).fired()
        let notes = try #require(log.shown.last ?? nil)
        #expect(notes.header == "Type into Notes")
        #expect(notes.rows.count > 10)
        notes.cancel()
    }

    @Test(
        "Parity menubar-auto-type-picker: Return confirms; the run checks the window per key; ⇧⌘2 copies"
    )
    func confirmTypes() throws {
        let id = try personal("at-confirm")
        let log = Log()
        let windows = FakeWindows([Self.window(Self.safari)])
        let auto = autoType(windows, log: log)
        auto.fired()
        #expect(windows.reads == 1, "nothing runs before the user's choice")
        #expect(try #require(auto.picker).press(.return, []))
        #expect(auto.picker == nil && log.shown.count == 2 && log.shown.last! == nil)
        // GitHub's Safari rule: 8 + 1 + 20 + 1 keys, one window check each,
        // after the one that the target is in front (INT-05.38 step 1).
        #expect(windows.reads == 1 + 1 + 30)
        #expect(log.alerts == 0 && log.stopped.isEmpty)
        // T66: ⇧⌘2 and ⇧⌘1 copy the highlighted entry's password and user
        // name to the session's private pasteboard and close the picker
        // without typing (APP-03). The bot gets a password no other session
        // holds.
        let unique = "bot-\(UUID().uuidString)"
        let bot = try #require(try session.list(vault: id, view: .all).rows.first { $0.title == "GitHub (work bot)" })
        _ = try session.beginEdit(vault: id, entry: bot.id)
        _ = try session.setPassword(vault: id, value: unique)
        _ = try session.commitEdit(vault: id)
        func copy(_ digit: Int) throws {
            auto.fired()
            let picker = try #require(auto.picker)
            picker.move(by: 2)
            #expect(picker.rows[picker.highlight].title == "GitHub (work bot)")
            picker.command(digit, shift: true)
            #expect(auto.picker == nil, "\(digit)")
        }
        try copy(2)
        let board = try #require(board(holding: unique), "⇧⌘2 copied the password")
        try copy(1)
        #expect(board.string(forType: .string) == "morgan-labs-ci", "⇧⌘1 copied the user name")
        #expect(windows.reads == 3 + 1 + 30, "nothing typed")
    }

    @Test("INT-05.28, INT-05.31 T70: the previous choice is highlighted in the next picker")
    func remembered() throws {
        _ = try personal("at-memory")
        let log = Log()
        let auto = autoType(FakeWindows([Self.window(Self.safari)]), log: log)
        auto.fired()
        try #require(auto.picker).choose(.login, row: 2)
        auto.fired()
        #expect(auto.picker?.highlight == 2)
        auto.picker?.cancel()
    }

    // MARK: AT-G01 and AT-G02 at the model level

    @Test("AT-G01: a lookalike window gets the picker, never typing, while Always ask is on")
    func lookalike() throws {
        _ = try personal("at-g01", bot: false)
        let log = Log()
        // Another program's window with a mail sign-in title: one match.
        let evil = Self.window("Inbox – Proton Mail", app: "Evil", pid: 4343)
        let windows = FakeWindows([evil])
        let auto = autoType(windows, log: log)
        auto.fired()
        let picker = try #require(auto.picker, "S-AT-03 on: the single match waits for the user")
        #expect(picker.rows.map(\.title) == ["Proton Mail"] && picker.target.appName == "Evil")
        #expect(windows.reads == 1, "no key, no window check")
        picker.cancel()
        // INT-05.25 step 7 with S-AT-03 off: several rows, an empty title
        // and a title nothing matches still open the picker.
        try set("autotype.always_ask", .flag(on: false))
        for title in [Self.safari, "", "Quiet"] {
            let other = FakeWindows([Self.window(title)])
            let auto = autoType(other, log: log)
            auto.fired()
            #expect(auto.picker != nil && other.reads == 1, "\(title)")
            auto.picker?.cancel()
        }
        // Only then does one match type at once (the weakening APP-01 lists).
        let direct = FakeWindows([evil])
        let typed = autoType(direct, log: log)
        typed.fired()
        #expect(typed.picker == nil && direct.reads == 1 + 1 + 71)
    }

    @Test("AT-G02 T90, T91: the run stops when another app or another window comes to the front")
    func focusChange() throws {
        _ = try personal("at-g02")
        for other in [Self.window("Mail", app: "Mail", pid: 4444), Self.window(Self.safari, id: 2)] {
            let log = Log()
            let target = Self.window(Self.safari)
            // Capture, INT-05.38 step 1 and three checks pass, then the front
            // changes.
            let windows = FakeWindows([target, target, target, target, target, other])
            let auto = autoType(windows, log: log)
            auto.fired()
            try #require(auto.picker).choose(.login)
            #expect(windows.reads == 6, "three keys, then the failed check")
            #expect(log.alerts == 1, "the alert sound, no window")
            // T106: one stop line with its reason code and position; no
            // title, no value.
            #expect(log.lines == ["Auto-Type stopped: window-changed after 3 keys"])
        }
    }

    @Test("LD-219 (1), APP-01.23: Mask User Names (S-VIEW-06) masks the picker's user names, read \"hidden\"")
    func maskedUserNames() async throws {
        _ = try personal("at-mask")
        let log = Log()
        let auto = autoType(FakeWindows([Self.window(Self.safari)]), log: log)
        for masked in [true, false] {
            try set("display.hide_usernames", .flag(on: masked))
            auto.fired()
            let picker = try #require(auto.picker)
            #expect(picker.maskUserNames == masked)
            let text = try await tree(AutoTypePickerView(model: picker))
            for user in ["alex-dev", "morgan-labs-ci"] {
                #expect(text.contains(user) != masked, "\(user), mask \(masked)")
            }
            #expect(text.contains("hidden") == masked)
            picker.cancel()
        }
    }

    // MARK: The frame (menubar-auto-type-picker)

    @Test("Option A frame menubar-auto-type-picker, offscreen, light and dark")
    func frame() async throws {
        let id = try personal("at-frame")
        // The frame draws one GitHub row: its Safari rule is left out here
        // (in memory, never saved).
        let github = try #require(try session.list(vault: id, view: .all).rows.first { $0.title == "GitHub" })
        _ = try session.beginEdit(vault: id, entry: github.id)
        try session.removeWindow(vault: id, index: 1)
        _ = try session.commitEdit(vault: id)
        let log = Log()
        let auto = autoType(FakeWindows([Self.window(Self.safari)]), log: log)
        auto.fired()
        let picker = try #require(auto.picker)
        #expect(picker.rows.map(\.title) == ["GitHub", "GitHub (work bot)"])
        let size = NSRect(x: 0, y: 0, width: 720, height: 420)
        let host = NSHostingView(rootView: AutoTypePickerFrame(picker: picker))
        host.frame = size
        // Never ordered front (AGENTS.md rule 10).
        let offscreen = NSWindow(
            contentRect: size.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless], backing: .buffered,
            defer: false)
        offscreen.colorSpace = .sRGB
        offscreen.contentView = host
        let shots = SnapshotTests()
        for (folder, look) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            offscreen.appearance = NSAppearance(named: look)
            let png = try await shots.render(host)
            let out = ParityDemo.root.appending(path: "app-shots/\(folder)/menubar-auto-type-picker.png")
            try FileManager.default.createDirectory(
                at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
            try png.write(to: out)
            #expect(png.count > 10_000)
            let tree = try shots.accessibilityTree(host)
            try tree.write(to: out.deletingPathExtension().appendingPathExtension("ax.json"))
            let text = String(bytes: tree, encoding: .utf8) ?? ""
            for word in [
                "Type into “\(Self.safari)”", "alex-dev", "Type login ⏎", "GitHub (work bot)", "morgan-labs-ci",
                "Search all entries…", "⇧⏎ types the password only",
            ] {
                #expect(text.contains(word), "\(word)")
            }
        }
        offscreen.contentView = nil
        picker.cancel()
    }
}

/// The suite's helpers.
extension AutoTypeTests {
    /// A window of another app (pid 4242).
    static func window(_ title: String, app: String = "Safari", id: Int = 1, pid: pid_t = 4242) -> FrontWindow {
        FrontWindow(pid: pid, appName: app, title: title, window: WindowID(ref: id))
    }

    /// Personal unlocked; GitHub (work bot) added as the frame draws it.
    func personal(_ folder: String, bot: Bool = true) throws -> UInt64 {
        let id = try session.open(path: try ParityDemo.path(0, folder: folder))
        #expect(try session.unlock(vault: id, password: ParityDemo.vaults[0].2, keyFile: nil) == .unlocked)
        if bot {
            _ = try session.beginNew(vault: id, group: nil)
            try session.setText(vault: id, field: .title, value: "GitHub (work bot)")
            try session.setText(vault: id, field: .userName, value: "morgan-labs-ci")
            try session.setText(vault: id, field: .url, value: "https://github.com")
            try session.addWindow(vault: id, window: "*GitHub*", sequence: "")
            _ = try session.commitEdit(vault: id)
        }
        return id
    }

    func set(_ key: String, _ value: AppSettingValue) throws {
        try session.saveSettings(changes: [AppSetting(key: key, value: value)])
    }

    /// The controller over the fakes; `shown` collects what it presents.
    func autoType(_ windows: FakeWindows, log: Log) -> AutoType {
        let auto = AutoType(session: session, hotKeys: keys, windows: windows) { log.shown.append($0) }
        auto.alert = { log.alerts += 1 }
        auto.unlock = { log.unlocks.append($0?.form.vault.id) }
        auto.activate = { log.activated.append($0) }
        auto.stopped = { log.stopped.append($0) }
        auto.log = { log.lines.append($0) }
        auto.runner = { work, done in done(work()) }
        auto.register()
        return auto
    }

    final class Log {
        var shown: [AutoTypePicker?] = []
        var alerts = 0
        /// The unlock panel's vault shown; `nil` when it hid.
        var unlocks: [UInt64?] = []
        var activated: [pid_t] = []
        var stopped: [String] = []
        /// The debug log's lines (INT-05.47).
        var lines: [String] = []
    }

    /// The accessibility tree of `view`, laid out offscreen (never ordered
    /// front, AGENTS.md rule 10).
    func tree(_ view: some View) async throws -> String {
        let host = NSHostingView(rootView: view)
        host.frame = NSRect(origin: .zero, size: host.fittingSize)
        let offscreen = NSWindow(
            contentRect: host.frame.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless],
            backing: .buffered, defer: false)
        offscreen.contentView = host
        defer { offscreen.contentView = nil }
        let shots = SnapshotTests()
        _ = try await shots.render(host)
        return String(bytes: try shots.accessibilityTree(host), encoding: .utf8) ?? ""
    }

    /// The test session's private pasteboard that holds `value`.
    func board(holding value: String) -> NSPasteboard? {
        (0..<1000).lazy.map { NSPasteboard(name: .init("com.app.clipboard.\(getpid()).\($0)")) }
            .first { $0.string(forType: .string) == value }
    }
}
