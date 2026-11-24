import AppKit
import LarsalCore
import SwiftUI
import Testing

// APP-08.19 to APP-08.23, APP-09.21, APP-09.22 (E5-S11): the menu bar icon,
// its menu, closing, minimizing, hiding to the icon and bringing the window
// to front. A recording slot stands in for the status bar and recording
// calls for NSApp, and the window is a recorder too: no test adds a status
// item, shows, hides or activates anything (AGENTS.md rule 10).

/// The status bar, recorded.
final class FakeSlot: StatusSlot {
    struct Shown {
        let image: NSImage
        let toolTip: String
    }

    var shown: Shown?
    var removed = 0

    func show(image: NSImage, toolTip: String, menu: NSMenu) { shown = Shown(image: image, toolTip: toolTip) }
    func remove() {
        shown = nil
        removed += 1
    }
}

/// A main window that only records what is asked of it; never on screen.
final class FakeWindow: NSWindow {
    var log: [String] = []
    var fakeVisible = true
    var fakeMini = false

    init() {
        super.init(
            contentRect: NSRect(x: 0, y: 0, width: 100, height: 100), styleMask: [.titled], backing: .buffered,
            defer: true)
    }

    override var isVisible: Bool { fakeVisible }
    override var isMiniaturized: Bool { fakeMini }
    override func orderOut(_ sender: Any?) {
        log.append("hide")
        fakeVisible = false
    }
    override func makeKeyAndOrderFront(_ sender: Any?) {
        log.append("front")
        fakeVisible = true
    }
    override func miniaturize(_ sender: Any?) {
        log.append("minimize")
        fakeMini = true
    }
    override func deminiaturize(_ sender: Any?) {
        log.append("unminimize")
        fakeMini = false
    }
    override func performClose(_ sender: Any?) { log.append("close") }
}

/// NSApp's calls, recorded.
@MainActor
final class FakeApp {
    var log: [String] = []
    var policy = NSApplication.ActivationPolicy.regular
    var active = false

    var calls: LarsalCalls {
        LarsalCalls(
            policy: { self.policy },
            setPolicy: { policy in
                self.policy = policy
                self.log.append(policy == .accessory ? "accessory" : policy == .regular ? "regular" : "prohibited")
            },
            isActive: { self.active },
            activate: {
                self.active = true
                self.log.append("activate")
            },
            unhide: { self.log.append("unhide") },
            quit: { self.log.append("quit") })
    }
}

/// A demo session with its icon and the recorded status bar.
struct IconDemo {
    let model: MainWindowModel
    let icon: MenuBarIcon
    let slot: FakeSlot
}

@MainActor
@Suite(.serialized)
struct MenuBarIconTests {
    let app = FakeApp()
    let window = FakeWindow()
    let rules = WindowRules()

    init() {
        ParityDemo.setUp()
        rules.calls = app.calls
        rules.attach(window)
    }

    func set(_ settings: WindowRules.Settings) { rules.settings = { settings } }

    // MARK: Closing and minimizing (APP-08.19)

    @Test("APP-08.19 T33: closing with S-UI-09 off quits (APP-02.11)")
    func closeQuits() {
        set(.init(closeHides: false, icon: true, minimizeToIcon: true))
        rules.close()
        #expect(app.log == ["quit"])
        #expect(window.log.isEmpty)
    }

    @Test("APP-08.19 T34: S-UI-09 and S-UI-10 on: closing hides to the icon, out of the Dock, and counts as a minimize")
    func closeHides() {
        var counted = 0
        rules.minimized = { counted += 1 }
        set(.init(closeHides: true, icon: true, minimizeToIcon: false))
        rules.close()
        #expect(window.log == ["hide"])
        #expect(app.log == ["accessory"])
        #expect(rules.hidden)
        #expect(counted == 1)
    }

    @Test("APP-08.19: S-UI-09 on, S-UI-10 off: closing minimizes into the Dock")
    func closeMinimizes() {
        set(.init(closeHides: true, icon: false, minimizeToIcon: true))
        rules.close()
        #expect(window.log == ["minimize"])
        #expect(app.log.isEmpty)
        #expect(!rules.hidden)
    }

    @Test("APP-08.19 T35: ⌘M with S-UI-12 and S-UI-10 on hides to the icon; else into the Dock")
    func minimize() {
        set(.init(closeHides: false, icon: true, minimizeToIcon: true))
        rules.minimize()
        #expect(window.log == ["hide"])
        #expect(app.log == ["accessory"])
        let other = WindowRules()
        let plain = FakeWindow()
        other.calls = app.calls
        other.attach(plain)
        other.settings = { .init(closeHides: false, icon: false, minimizeToIcon: true) }
        other.minimize()
        #expect(plain.log == ["minimize"])
    }

    @Test("APP-08.3: ⌘W with Settings in front closes Settings, not the shown vault; else it closes the vault")
    func commandWKeyWindow() async throws {
        let model = try ParityDemo.window("close-key-window")
        let settings = FakeWindow()
        var sent = try await MenuBarTests.commandW(model, key: settings)
        #expect(sent.handled)
        #expect(settings.log == ["close"])
        #expect(model.vaults.contains { $0.name == "Personal" })
        #expect(sent.log.isEmpty)
        sent = try await MenuBarTests.commandW(model, key: nil)
        #expect(sent.handled)
        #expect(!model.vaults.contains { $0.name == "Personal" })
        #expect(settings.log == ["close"])
        model.lockAll()
    }

    @Test("APP-09.21: started minimized with S-UI-10 on: hidden to the icon, out of the Dock")
    func startMinimizedToIcon() {
        set(.init(closeHides: false, icon: true, minimizeToIcon: false))
        rules.startMinimized()
        #expect(window.log == ["hide"])
        #expect(app.log == ["accessory"])
        #expect(rules.hidden)
    }

    @Test("APP-09.21: started minimized with S-UI-10 off: into the Dock, Larsal stays a regular app")
    func startMinimizedToDock() {
        set(.init(closeHides: true, icon: false, minimizeToIcon: true))
        rules.startMinimized()
        #expect(window.log == ["minimize"])
        #expect(app.log.isEmpty)
        #expect(!rules.hidden)
    }

    @Test("Rule 10: a hidden launch (tests, Verify drivers, Mac QA) gets no status item; a normal launch the system's")
    func hiddenLaunchSlot() {
        #expect(MenuBarIcon.slot(hidden: true) is NoStatusSlot)
        #expect(MenuBarIcon.slot(hidden: false) is SystemStatusSlot)
    }

    // MARK: Bring to front (APP-09.22)

    @Test("APP-09.22: bring to front un-minimizes, shows, raises and activates; back in the Dock after a hide")
    func bring() {
        set(.init(closeHides: true, icon: true, minimizeToIcon: false))
        rules.close()
        window.fakeMini = true
        app.log = []
        window.log = []
        rules.bring()
        #expect(app.log == ["regular", "unhide", "activate"])
        #expect(window.log == ["unminimize", "front"])
        #expect(!rules.hidden)
    }

    @Test("APP-09.22: a hidden test launch (prohibited) never comes to front")
    func bringHiddenLaunch() {
        app.policy = .prohibited
        rules.bring()
        #expect(app.log.isEmpty)
        #expect(window.log.isEmpty)
    }

    @Test("APP-09.22: Larsal becoming active brings a minimized or hidden window back, and leaves a shown one alone")
    func activated() {
        rules.activated()
        #expect(window.log.isEmpty)
        window.fakeMini = true
        rules.activated()
        #expect(window.log == ["unminimize", "front"])
    }

    @Test("APP-09.22: Front.bring() is the shared rules' bring, the one function every trigger calls")
    func frontIsShared() {
        let shared = WindowRules.shared
        let saved = shared.calls
        let fake = FakeApp()
        let main = FakeWindow()
        main.fakeMini = true
        shared.calls = fake.calls
        shared.attach(main)
        Front.bring()
        shared.calls = saved
        #expect(fake.log == ["unhide", "activate"])
        #expect(main.log == ["unminimize", "front"])
        // Inside a test run the shared rules' calls do nothing.
        #expect(saved.policy() == .prohibited)
    }

    // MARK: The icon (APP-08.20)

    /// Three demo vaults, Personal unlocked and shown; the icon setting on.
    func demo(_ folder: String, icon: Bool = true) throws -> IconDemo {
        let model = try ParityDemo.window(folder)
        try model.session.saveSettings(changes: [LarsalSetting(key: "menubar_icon.show", value: .flag(on: icon))])
        let slot = FakeSlot()
        let icon = MenuBarIcon(window: model, rules: rules, slot: slot)
        icon.update()
        return IconDemo(model: model, icon: icon, slot: slot)
    }

    @Test("APP-08.20 T36 T37: unlocked, then locked: the glyph and M08-03 change; a template image with no vault name")
    func icon() throws {
        let setup = try demo("icon-state")
        let (model, icon, slot) = (setup.model, setup.icon, setup.slot)
        let shown = try #require(slot.shown)
        #expect(shown.toolTip == "Larsal: 1 vault unlocked")
        #expect(shown.image.isTemplate)
        let unlocked = shown.image.tiffRepresentation
        model.lockAll()
        icon.update()
        #expect(slot.shown?.toolTip == "Larsal: all vaults locked")
        #expect(slot.shown?.image.tiffRepresentation != unlocked)
        #expect(MenuBarIcon.toolTip(unlocked: 2) == "Larsal: 2 vaults unlocked")
        for vault in model.vaults { #expect(slot.shown?.toolTip.contains(vault.name) == false) }
        #expect(!MenuBarIcon.image(unlocked: true, colorful: true).isTemplate)
    }

    @Test("APP-08.20: S-UI-10 off: no status item")
    func iconOff() throws {
        let setup = try demo("icon-off", icon: false)
        let (model, slot) = (setup.model, setup.slot)
        #expect(slot.shown == nil)
        model.lockAll()
    }

    @Test("Parity menubar-menu-bar-icon: the menu's items; Hide Window hides, then it reads Show Window (T38)")
    func menu() throws {
        let setup = try demo("icon-menu")
        let (model, icon) = (setup.model, setup.icon)
        app.active = true
        icon.build()
        var lines = MenuLine.lines(icon.menu)
        #expect(
            lines.titles == [
                "Vaults", "Personal", "Work", "Family", "-", "Search Entries…", "Password Generator", "Lock Everything",
                "-", "Hide Window", "Settings…", "Quit Larsal",
            ])
        #expect(lines.map(\.keys).suffix(7) == ["⌥⌘Space", "⌥⌘G", "⇧⌘L", "", "", "⌘,", "⌘Q"])
        #expect(icon.menu.items[1].badge?.stringValue == "Unlocked")
        #expect(icon.menu.items[2].badge?.stringValue == "Locked")
        #expect(lines.line("Lock Everything")?.enabled == true)
        let hide = try #require(icon.menu.items.firstIndex { $0.title == "Hide Window" })
        icon.menu.performActionForItem(at: hide)
        #expect(window.log == ["hide"])
        #expect(app.log == ["accessory"])
        icon.build()
        lines = MenuLine.lines(icon.menu)
        #expect(lines.line("Show Window") != nil)
        let show = try #require(icon.menu.items.firstIndex { $0.title == "Show Window" })
        icon.menu.performActionForItem(at: show)
        #expect(window.log == ["hide", "front"])
        #expect(app.log == ["accessory", "regular", "unhide", "activate"])
        // Lock Everything locks; then it is off.
        let lock = try #require(icon.menu.items.firstIndex { $0.title == "Lock Everything" })
        icon.menu.performActionForItem(at: lock)
        #expect(model.vaults.allSatisfy { $0.locked })
        icon.build()
        #expect(MenuLine.lines(icon.menu).line("Lock Everything")?.enabled == false)
        #expect(MenuLine.lines(icon.menu).line("Search Entries…")?.enabled == false)
    }

    @Test("APP-08.22 T39: S-UI-10 turned off while hidden: the window shows and Larsal is back in the Dock")
    func iconTurnedOff() throws {
        let setup = try demo("icon-turned-off")
        let (model, icon, slot) = (setup.model, setup.icon, setup.slot)
        rules.hideToIcon()
        try model.session.saveSettings(changes: [LarsalSetting(key: "menubar_icon.show", value: .flag(on: false))])
        icon.update()
        #expect(slot.shown == nil)
        #expect(window.log == ["hide", "front"])
        #expect(app.log.contains("regular"))
        #expect(!rules.hidden)
        model.lockAll()
    }

    @Test("APP-08.21: choosing a vault in the icon's menu shows it")
    func chooseVault() throws {
        let setup = try demo("icon-vault")
        let (model, icon) = (setup.model, setup.icon)
        let work = try #require(icon.menu.items.firstIndex { $0.title == "Work" })
        icon.menu.performActionForItem(at: work)
        #expect(model.shown?.name == "Work")
        model.lockAll()
    }

    // MARK: The frame (menubar-menu-bar-icon)

    @Test("Option A frame menubar-menu-bar-icon, offscreen, light and dark")
    func frame() async throws {
        let setup = try demo("icon-frame")
        let (model, icon) = (setup.model, setup.icon)
        icon.build()
        let size = NSRect(x: 0, y: 0, width: 720, height: 420)
        let host = NSHostingView(rootView: MenuBarIconFrame(icon: icon, vaults: model.vaults))
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
            let out = ParityDemo.shotsDirectory.appending(path: "\(folder)/menubar-menu-bar-icon.png")
            try FileManager.default.createDirectory(
                at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
            try png.write(to: out)
            #expect(png.count > 10_000)
            let tree = try shots.accessibilityTree(host)
            try tree.write(to: out.deletingPathExtension().appendingPathExtension("ax.json"))
            let text = String(bytes: tree, encoding: .utf8) ?? ""
            for word in ["Vaults", "Personal", "Unlocked", "Search Entries…", "⌥⌘Space", "Show Window", "Quit Larsal"] {
                #expect(text.contains(word), "\(word)")
            }
        }
        offscreen.contentView = nil
        model.lockAll()
    }
}

// Rule 10 for a hidden launch, and rule 9's record.
@MainActor
extension MenuBarIconTests {
    @Test("Rule 10: a hidden launch started minimized to the icon stays prohibited; a bring never takes the screen")
    func startMinimizedHiddenLaunch() {
        app.policy = .prohibited
        set(.init(closeHides: false, icon: true, minimizeToIcon: false))
        rules.startMinimized()
        rules.bring()
        #expect(app.log.isEmpty)
        #expect(app.policy == .prohibited)
    }

    @Test("Rule 9: each decision ID names one row, so the menu code's LD-214 comments lead to E5-S11's row")
    func decisionIDsUnique() throws {
        let rows = try String(contentsOf: ParityDemo.root.appending(path: "spec/decisions.md"), encoding: .utf8)
            .split(separator: "\n").filter { $0.hasPrefix("| ") }
        let ids = rows.compactMap { $0.firstMatch(of: /^\| ([A-Z]+-\d+) \|/).map { String($0.1) } }
        #expect(ids.count == Set(ids).count, "\(Dictionary(grouping: ids) { $0 }.filter { $0.value.count > 1 }.keys)")
        #expect(rows.first { $0.hasPrefix("| LD-214 |") }?.contains("(E5-S11)") == true)
    }
}
