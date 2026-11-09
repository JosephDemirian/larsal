import AppKit
import LarsalCore
import SwiftUI
import Testing

// APP-08 (E5-S11): every menu item of the menu bar against the card's tables:
// its label, shortcut, enabled state and the hidden rules. Each menu's items
// are the same view Larsal puts in its SwiftUI commands; `NSHostingMenu` turns
// it into the native NSMenu the menu bar shows, which these tests read. No
// menu is opened and nothing is shown (AGENTS.md rule 10).

/// The card's tables (APP-08.2 to APP-08.11).
enum MenuCard {
    /// APP-08.2 to APP-08.11 with the Personal vault unlocked and shown and
    /// its first entry selected: title and shortcut of every item, in order
    /// ("-" is a separator). The card's tables, row by row.
    nonisolated static let card: [(menu: String, items: [(String, String)])] = [
        ("Larsal", [("Check for Updates…", "")]),
        ("Settings", [("Settings…", "⌘,")]),
        (
            "File",
            [
                ("New Vault…", "⇧⌘N"), ("Open Vault…", "⌘O"), ("Open Recent", ""), ("-", ""), ("Close Vault", "⌘W"),
                ("Close Window", "⇧⌘W"), ("Save", "⌘S"), ("Save As…", "⇧⌘S"), ("Save a Copy…", ""), ("-", ""),
                ("Import…", ""), ("Export", ""),
                // FIL-02.1 (E22-S4): no vault needs to be open.
                ("-", ""), ("Encrypt File…", ""), ("Decrypt File…", ""),
            ]
        ),
        (
            "Edit",
            [("Cut", "⌘X"), ("Copy", "⌘C"), ("Paste", "⌘V"), ("Select All", "⌘A"), ("-", ""), ("Find…", "⌘F")]
        ),
        (
            "Vault",
            [
                ("Lock Personal", "⌘L"), ("Lock Everything", "⇧⌘L"), ("-", ""), ("Vault Settings…", "⇧⌘,"),
                ("Change Credentials…", ""), ("Reports", "⇧⌘R"), ("Passkeys…", ""), ("Import Passkey…", ""),
                ("Merge Another Vault…", ""),
            ]
        ),
        (
            "Entry",
            [
                ("New Entry", "⌘N"), ("Edit Entry", "⌘E"), ("Clone Entry…", "⌘D"), ("Expire Entry", ""),
                ("Delete Entry", "⌘⌫"), ("-", ""), ("Copy Username", "⌘B"), ("Copy Password", "⌘C"),
                ("Copy URL", "⇧⌘U"), ("Copy Field", ""), ("One-Time Password", ""), ("Tags", ""), ("-", ""),
                ("Show as QR Code", "⌃⌥⌘Q"), ("Show Field as QR Code", ""), ("Show Wi-Fi Join Code", ""), ("-", ""),
                ("Open URL", "⌘U"), ("Fetch Site Icon", "⇧⌘D"), ("Type Login", "⇧⌘V"),
                ("Auto-Type Username Only", ""), ("Auto-Type Password Only", ""),
            ]
        ),
        (
            "Group",
            [
                ("New Group…", ""), ("Edit Group…", ""), ("Clone Group…", ""), ("Delete Group…", ""),
                ("Fetch Site Icons for Group…", ""),
            ]
        ),
        (
            "View",
            [
                ("Appearance", ""), ("-", ""), ("Hide Sidebar", "⌃⌘S"), ("Hide Details", ""), ("-", ""),
                ("Mask User Names", "⇧⌘B"), ("Mask Passwords", "⇧⌘C"), ("Keep Window on Top", "⇧⌘A"),
                ("Permit Screen Capture", ""),
            ]
        ),
        ("Tools", [("Password Generator", "⌥⌘G")]),
        (
            "Window",
            [
                ("Minimize", "⌘M"), ("Zoom", ""), ("-", ""), ("Show Next Vault", "⌃Tab"),
                ("Show Previous Vault", "⌃⇧Tab"), ("-", ""), ("Personal", "⌘1"), ("Work", "⌘2"), ("Family", "⌘3"),
            ]
        ),
        ("Help", [("Keyboard Shortcuts", "⌘/")]),
    ]
}

@MainActor
@Suite(.serialized)
struct MenuBarTests {
    init() {
        ParityDemo.setUp()
    }

    // One case per menu: a table, not logic.
    // swiftlint:disable:next cyclomatic_complexity
    static func read(_ menu: String, _ window: MainWindowModel) async -> [MenuLine] {
        switch menu {
        case "Larsal": await MenuLine.read(LarsalMenuItems())
        case "Settings": await MenuLine.read(SettingsMenuItem(window: window))
        case "File": await MenuLine.read(FileMenuItems(window: window))
        case "Edit": await MenuLine.read(EditMenuItems(window: window))
        case "Vault": await MenuLine.read(VaultMenuItems(window: window))
        case "Entry": await MenuLine.read(EntryMenuItems(window: window))
        case "Group": await MenuLine.read(GroupMenuItems(window: window))
        case "View": await MenuLine.read(ViewMenuItems(window: window))
        case "Tools": await MenuLine.read(ToolsMenuItems(window: window))
        case "Window": await MenuLine.read(WindowMenuItems(window: window))
        default: await MenuLine.read(HelpMenuItems(window: window))
        }
    }

    /// The Personal vault unlocked and shown, `title` selected.
    static func unlocked(_ folder: String, select title: String? = nil) throws -> (MainWindowModel, VaultModel) {
        let window = try ParityDemo.window(folder)
        let main = try #require(window.main)
        if let title { main.select(main.rows.first { $0.title == title }?.id) }
        return (window, main)
    }

    @Test(
        "APP-08.2 to APP-08.11: every menu's items, labels and shortcuts as the card's tables",
        arguments: MenuCard.card.indices)
    func table(_ index: Int) async throws {
        let (window, _) = try Self.unlocked("menus-table", select: "Google")
        let (menu, expected) = MenuCard.card[index]
        let lines = await Self.read(menu, window)
        #expect(lines.map(\.title) == expected.map(\.0), "\(menu): \(lines)")
        #expect(lines.map(\.keys) == expected.map(\.1), "\(menu): \(lines)")
        window.lockAll()
    }

    @Test("APP-08.1: labels in title case, an ellipsis only on items that ask for more")
    func titleCase() async throws {
        let (window, _) = try Self.unlocked("menus-case", select: "Google")
        // Small words stay small, as in "Load into SSH Agent".
        let small: Set<String> = ["a", "an", "to", "on", "into", "from", "for", "with", "as", "of", "the", "and"]
        for (menu, _) in MenuCard.card {
            for line in await Self.read(menu, window) where line.title != "-" {
                let words = line.title.split(separator: " ").dropFirst()
                let lower = words.filter { $0.first?.isLowercase == true && !small.contains(String($0)) }
                #expect(lower.isEmpty, "\(menu) > \(line.title)")
                #expect(!line.title.hasSuffix("..."), "\(menu) > \(line.title): one ellipsis character")
            }
        }
        window.lockAll()
    }

    @Test("APP-08.12 T04: no vault open: New and Open on; Save, Save As, a Copy, Export off; ⌘W closes")
    func noVault() async throws {
        let window = MainWindowModel(session: Session())
        let file = await Self.read("File", window)
        #expect(file.line("New Vault…")?.enabled == true)
        #expect(file.line("Open Vault…")?.enabled == true)
        for title in ["Close Vault", "Save", "Save As…", "Save a Copy…", "Export", "Open Recent"] {
            #expect(file.line(title)?.enabled == false, "\(title)")
        }
        #expect(file.line("Close Window")?.keys == "⌘W")
        #expect(file.line("Close Window")?.enabled == true)
        for menu in ["Vault", "Entry", "Group"] {
            let lines = await Self.read(menu, window).filter { $0.title != "-" }
            #expect(lines.allSatisfy { !$0.enabled }, "\(menu): \(lines)")
        }
        #expect(await Self.read("Vault", window).line("Lock Vault") != nil)
        #expect(await Self.read("Edit", window).line("Find…")?.enabled == false)
        #expect(await Self.read("Help", window).line("Keyboard Shortcuts")?.enabled == true)
        #expect(await Self.read("Settings", window).line("Settings…")?.enabled == true)
    }

    @Test("APP-08.12 T09 T22: the shown vault locked: Lock and every vault item off, Entry and Group all off")
    func locked() async throws {
        let window = try ParityDemo.window("menus-locked", unlocked: [], shown: 0)
        let vault = await Self.read("Vault", window)
        #expect(vault.line("Lock Personal")?.enabled == false)
        #expect(vault.line("Lock Everything")?.enabled == false)
        #expect(vault.filter { $0.title != "-" }.allSatisfy { !$0.enabled }, "\(vault)")
        for menu in ["Entry", "Group"] {
            let lines = await Self.read(menu, window).filter { $0.title != "-" }
            #expect(lines.allSatisfy { !$0.enabled }, "\(menu): \(lines)")
        }
        #expect(await Self.read("File", window).line("Save")?.enabled == false)
        // LD-219 (2): Cut and Copy act in any window's field while locked.
        #expect(await Self.read("Edit", window).line("Copy")?.enabled == true)
    }

    @Test("APP-08.5 T09: Lock Everything stays on while another vault is unlocked")
    func lockOthers() async throws {
        let window = try ParityDemo.window("menus-others", unlocked: [1], shown: 0)
        let vault = await Self.read("Vault", window)
        #expect(vault.line("Lock Personal")?.enabled == false)
        #expect(vault.line("Lock Everything")?.enabled == true)
        window.lockAll()
    }

    @Test("APP-08.6 T11: Edit and Expire Entry follow the selection")
    func selection() async throws {
        let (window, main) = try Self.unlocked("menus-selection")
        main.select(nil)
        var entry = await Self.read("Entry", window)
        #expect(entry.line("Edit Entry")?.enabled == false)
        #expect(entry.line("Expire Entry")?.enabled == false)
        #expect(entry.line("New Entry")?.enabled == true)
        main.select(main.rows.first { $0.title == "Google" }?.id)
        entry = await Self.read("Entry", window)
        for title in [
            "Edit Entry", "Clone Entry…", "Expire Entry", "Delete Entry", "Copy Username", "Copy URL", "Open URL",
        ] {
            #expect(entry.line(title)?.enabled == true, "\(title)")
        }
        // The copy submenus: Title ⌘I, Notes; the one-time password items.
        let field = try #require(entry.line("Copy Field")?.submenu)
        #expect(field.prefix(2).map(\.title) == ["Title", "Notes"])
        #expect(field.first?.keys == "⌘I")
        let code = try #require(entry.line("One-Time Password")?.submenu)
        #expect(
            code.map(\.title) == [
                "Copy One-Time Password", "Copy Password with Code", "Show Code", "Show as QR Code",
                "Change One-Time Code…",
            ])
        #expect(code.map(\.keys) == ["⌘T", "⌘Y", "⇧⌘T", "", ""])
        #expect(code.first?.enabled == true)
        window.lockAll()
    }

    @Test("APP-08.6 T12: SSH items, Remove Passkey, Move Up and Move Down hidden without their reason")
    func hidden() async throws {
        let (window, _) = try Self.unlocked("menus-hidden", select: "Google")
        let titles = await Self.read("Entry", window).titles
        for title in ["Load into SSH Agent", "Remove from SSH Agent", "Remove Passkey", "Move Up", "Move Down"] {
            #expect(!titles.contains(title), "\(title)")
        }
        #expect(!titles.contains("Restore Entry"))
        window.lockAll()
    }

    @Test("APP-08.6: Remove Passkey shows for an entry with a passkey")
    func passkey() async throws {
        let (window, _) = try Self.unlocked("menus-passkey", select: "GitHub")
        #expect(await Self.read("Entry", window).line("Remove Passkey") != nil)
        window.lockAll()
    }

    @Test(
        "APP-08.6 T14 APP-08.7 T15: a bin entry shows Restore Entry ⌘R; Group shows Empty Recycle Bin…, New Group… off")
    func bin() async throws {
        let (window, main) = try Self.unlocked("menus-bin")
        main.choose(.bin)
        main.select(main.rows.first?.id)
        let entry = await Self.read("Entry", window)
        #expect(entry.line("Restore Entry")?.keys == "⌘R")
        #expect(entry.line("Restore Entry")?.enabled == true)
        #expect(entry.line("New Entry")?.enabled == false)
        #expect(entry.line("Edit Entry")?.enabled == false)
        let group = await Self.read("Group", window)
        #expect(group.line("Empty Recycle Bin…")?.enabled == true)
        #expect(group.line("New Group…")?.enabled == false)
        window.lockAll()
    }

    @Test("APP-08.12: while the editor is open, list and group actions are off and ⌘S stays on")
    func editor() async throws {
        let (window, main) = try Self.unlocked("menus-editor", select: "Google")
        main.edit()
        #expect(main.editor != nil)
        let entry = await Self.read("Entry", window)
        for title in ["New Entry", "Edit Entry", "Clone Entry…", "Delete Entry", "Open URL"] {
            #expect(entry.line(title)?.enabled == false, "\(title)")
        }
        // The copy items act on the edited entry.
        #expect(entry.line("Copy Password")?.enabled == true)
        #expect(await Self.read("Group", window).line("New Group…")?.enabled == false)
        #expect(await Self.read("File", window).line("Save")?.enabled == true)
        #expect(await Self.read("Tools", window).line("Password Generator")?.enabled == false)
        main.cancelEditor()
        window.lockAll()
    }

    @Test("APP-08.12: a sheet on the window turns the vault's items off")
    func sheet() async throws {
        let (window, main) = try Self.unlocked("menus-sheet", select: "Google")
        main.dialog = .newGroup(name: "")
        let vault = await Self.read("Vault", window)
        for title in ["Vault Settings…", "Reports", "Change Credentials…"] {
            #expect(vault.line(title)?.enabled == false, "\(title)")
        }
        #expect(await Self.read("Entry", window).filter { $0.title != "-" }.allSatisfy { !$0.enabled })
        // Locking stays one key away (APP-08 security notes).
        #expect(vault.line("Lock Everything")?.enabled == true)
        main.dialog = nil
        window.lockAll()
    }

    @Test("APP-08.10 T20: ⌘1 to ⌘8 for the first eight vaults, ⌘9 for the last; the shown one checked")
    func windowKeys() async throws {
        let keys = (0..<10).map { WindowMenuItems.key($0, of: 10).map { String($0.key.character) } ?? "" }
        #expect(keys == ["1", "2", "3", "4", "5", "6", "7", "8", "", "9"])
        let window = try ParityDemo.window("menus-window", unlocked: [0], shown: 1)
        let lines = await Self.read("Window", window)
        #expect(lines.line("Work")?.checked == true)
        #expect(lines.line("Personal")?.checked == false)
        #expect(lines.line("Show Next Vault")?.enabled == true)
        window.lockAll()
    }

    @Test("APP-08.10: Show Next Vault wraps around to the first")
    func nextVault() async throws {
        let window = try ParityDemo.window("menus-next", unlocked: [], shown: 2)
        #expect(window.shown?.name == "Family")
        guard #available(macOS 14.4, *) else { return }
        let menu = NSHostingMenu(rootView: WindowMenuItems(window: window))
        menu.update()
        let next = try #require(menu.items.first { $0.title == "Show Next Vault" })
        NSApp.sendAction(try #require(next.action), to: next.target, from: next)
        try await Task.sleep(for: .milliseconds(50))
        #expect(window.shown?.name == "Personal")
    }

    @Test("APP-08.8 T16: View > Mask Passwords twice turns S-VIEW-07 off, then on; the check follows")
    func maskPasswords() async throws {
        let window = MainWindowModel(session: Session())
        #expect(await Self.read("View", window).line("Mask Passwords")?.checked == true)
        window.view.set("display.hide_passwords", false, window.session)
        #expect(window.session.settings().flag(key: "display.hide_passwords") == false)
        #expect(await Self.read("View", window).line("Mask Passwords")?.checked == false)
        window.view.set("display.hide_passwords", true, window.session)
        #expect(await Self.read("View", window).line("Mask Passwords")?.checked == true)
        // T17: screen capture is unchecked at every start.
        #expect(await Self.read("View", window).line("Permit Screen Capture")?.checked == false)
        // The sidebar item's label flips with S-VIEW-03.
        window.view.set("ui.show_groups", false, window.session)
        #expect(await Self.read("View", window).line("Show Sidebar")?.keys == "⌃⌘S")
    }

    @Test("APP-08.3 T05: Open Recent names a file, with its folder when two names are equal")
    func recentTitles() {
        let titles = OpenRecentMenu.titles([
            "/Users/demo/Documents/Personal.larsalvault", "/Users/demo/Work/Personal.larsalvault",
            "/Users/demo/Family.larsalvault",
        ])
        #expect(titles == ["Personal.larsalvault — Documents", "Personal.larsalvault — Work", "Family.larsalvault"])
    }

    @Test("APP-08.9 T18: SSH agent off: the Tools menu is Password Generator ⌥⌘G only")
    func tools() async throws {
        let (window, _) = try Self.unlocked("menus-tools", select: "Google")
        let tools = await Self.read("Tools", window)
        #expect(tools.titles == ["Password Generator"])
        #expect(tools.first?.enabled == true)
        window.lockAll()
    }

    @Test("APP-08.11 T21: the Help menu opens no web address")
    func help() async {
        let lines = await Self.read("Help", MainWindowModel(session: Session()))
        #expect(lines.titles == ["Keyboard Shortcuts"])
        #expect(!lines.contains { $0.title.lowercased().contains("website") || $0.title.contains("http") })
    }

    @Test("APP-08.4 V-A08-3: Edit > Copy owns ⌘C, and Edit comes before Entry in the menu bar")
    func copyKey() async throws {
        let (window, _) = try Self.unlocked("menus-copy", select: "Google")
        #expect(await Self.read("Edit", window).line("Copy")?.keys == "⌘C")
        let order = MenuCard.card.map(\.menu)
        let edit = try #require(order.firstIndex(of: "Edit"))
        let entry = try #require(order.firstIndex(of: "Entry"))
        #expect(edit < entry)
        window.lockAll()
    }
}

// ⌘W's route through the File menu (APP-08.3, APP-08.19).
@MainActor
extension MenuBarTests {
    /// ⌘W sent to the File menu as the menu bar sends it, with `key` the
    /// window in front (nil: none or the main window). The shared rules' calls
    /// are recorded, so the quit never happens; the log says what ran.
    static func commandW(_ window: MainWindowModel, key: NSWindow?) async throws -> (handled: Bool, log: [String]) {
        guard #available(macOS 14.4, *) else { return (false, []) }
        _ = NSApplication.shared  // the test process's own, never shown
        let menu = NSHostingMenu(rootView: FileMenuItems(window: window))
        menu.update()
        try await Task.sleep(for: .milliseconds(30))
        menu.update()
        let event = try #require(
            NSEvent.keyEvent(
                with: .keyDown, location: .zero, modifierFlags: .command, timestamp: 0, windowNumber: 0, context: nil,
                characters: "w", charactersIgnoringModifiers: "w", isARepeat: false, keyCode: 13))
        let shared = WindowRules.shared
        let saved = (shared.calls, shared.keyWindow, shared.settings)
        let app = FakeApp()
        shared.calls = app.calls
        shared.keyWindow = { key }
        shared.settings = { WindowRules.Settings() }
        let handled = menu.performKeyEquivalent(with: event)
        (shared.calls, shared.keyWindow, shared.settings) = saved
        return (handled, app.log)
    }

    @Test("APP-08.3 APP-08.19: ⌘W with no vault open, S-UI-09 off: Close Window runs and Larsal quits")
    func commandWNoVault() async throws {
        let sent = try await Self.commandW(MainWindowModel(session: Session()), key: nil)
        #expect(sent.handled)
        #expect(sent.log == ["quit"])
    }
}
