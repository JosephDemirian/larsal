import AppKit
import LarsalCore
import SwiftUI

/// The menu bar (APP-08.1 to APP-08.11) as SwiftUI commands over the window's
/// model. Each menu's items are one view, so tests read the native menu
/// SwiftUI makes from them. macOS keeps its own items (Services, Hide, Undo,
/// AutoFill, Enter Full Screen, the window list, the Help search field).
/// SwiftUI puts Larsal's own menus between View and Window, as Apple's menu bar
/// guidelines do (LD-214 (1)).
struct LarsalCommands: Commands {
    let window: MainWindowModel

    var body: some Commands {
        CommandGroup(after: .appInfo) { LarsalMenuItems() }
        CommandGroup(replacing: .appSettings) { SettingsMenuItem(window: window) }
        CommandGroup(replacing: .newItem) { FileMenuItems(window: window) }
        CommandGroup(replacing: .saveItem) {}
        CommandGroup(replacing: .importExport) {}
        CommandGroup(replacing: .printItem) {}
        CommandGroup(replacing: .pasteboard) { EditMenuItems(window: window) }
        CommandGroup(replacing: .toolbar) { ViewMenuItems(window: window) }
        CommandGroup(replacing: .sidebar) {}
        CommandMenu("Vault") { VaultMenuItems(window: window) }
        CommandMenu("Entry") { EntryMenuItems(window: window) }
        CommandMenu("Group") { GroupMenuItems(window: window) }
        CommandMenu("Tools") { ToolsMenuItems(window: window) }
        CommandGroup(replacing: .windowSize) { WindowMenuItems(window: window) }
        CommandGroup(replacing: .help) { HelpMenuItems(window: window) }
    }
}

/// What the enabled rules read (APP-08.12).
@MainActor
struct MenuState {
    let window: MainWindowModel

    /// The shown vault's screen, while it is unlocked.
    var main: VaultModel? { window.main }
    /// The shown vault, unlocked, with no sheet or question on the window:
    /// items that act on the vault wait for the sheet (APP-08.12).
    var vault: VaultModel? { main?.dialog == nil && window.sshAsk == nil ? main : nil }
    /// List and group actions: not while the entry editor or the group
    /// editor covers the list (F-174).
    var list: VaultModel? { vault?.editor == nil && vault?.sharing.editor == nil ? vault : nil }
    /// One entry selected in the list (the list selects one at a time).
    var entry: EntryDetail? { list?.detail }
    /// The copy items: the selected entry, also the one the editor shows.
    var copyEntry: EntryDetail? { vault?.detail }
    var anyUnlocked: Bool { window.vaults.contains { !$0.locked } }
    /// A group is selected: one of the sidebar's groups, or all entries (the
    /// root group).
    var group: Bool {
        switch list?.place {
        case .all, .group: true
        default: false
        }
    }
    var url: String { entry?.fields.first { $0.kind == .url }?.value ?? "" }
}

/// APP-08.2: the Larsal menu's own item. About, Settings, Services, Hide and
/// Quit are the macOS items.
struct LarsalMenuItems: View {
    var body: some View {
        // APP-01.19: the update check comes with publishing (E14).
        Button("Check for Updates…") {}.disabled(true)
    }
}

/// APP-08.2: Settings… (APP-01).
struct SettingsMenuItem: View {
    let window: MainWindowModel

    var body: some View {
        Button("Settings…") { LarsalSettingsWindow.show(session: window.session) }.keyboardShortcut(",")
    }
}

/// APP-08.3: the File menu.
struct FileMenuItems: View {
    let window: MainWindowModel

    var body: some View {
        let state = MenuState(window: window)
        Button("New Vault…") { AuxWindows.newVault(window) }.keyboardShortcut("n", modifiers: [.command, .shift])
        Button("Open Vault…") { window.chooseVault() }.keyboardShortcut("o")
        OpenRecentMenu(window: window)
        Divider()
        // ⌘W closes the window in front: Settings or another of Larsal's
        // windows, else the shown vault. A disabled item keeps its key, so
        // with no vault open Close Vault gives ⌘W to Close Window (APP-08.19).
        Button("Close Vault") { WindowRules.shared.closeKeyWindow { window.shown.map { window.close($0.id) } } }
            .keyboardShortcut(window.shown == nil ? nil : KeyboardShortcut("w"))
            .disabled(window.shown == nil)
        Button("Close Window") { WindowRules.shared.closeKeyWindow() }
            .keyboardShortcut("w", modifiers: window.shown == nil ? .command : [.command, .shift])
        Button("Save") { save(state) }.keyboardShortcut("s").disabled(state.vault == nil)
        Button("Save As…") { state.list?.saveAs() }.keyboardShortcut("s", modifiers: [.command, .shift])
            .disabled(state.list == nil)
        // APP-05.6: a copy that keeps the vault where it is comes with saving.
        Button("Save a Copy…") {}.disabled(true)
        Divider()
        Button("Import…") {}.disabled(true)
        Menu("Export") {
            // FEA-09: Rust's warning comes before any file (SD-07).
            Button("CSV…") { state.vault?.askExport(.csv) }
            Button("HTML…") { state.vault?.askExport(.html) }
            Button("XML…") { state.vault?.askExport(.xml) }
        }
        .disabled(state.vault == nil)
    }

    /// ⌘S: the entry while the editor is open (the mockup's Save), else
    /// the vault (APP-05.6).
    private func save(_ state: MenuState) {
        guard let vault = state.vault else { return }
        if vault.editor != nil {
            vault.saveEditor()
        } else {
            Task { _ = await vault.saveNow(asks: true) }
        }
    }
}

/// Open Recent ▸ (APP-01.14): one item per path, by file name, with the
/// folder's name when two names are equal.
struct OpenRecentMenu: View {
    let window: MainWindowModel

    var body: some View {
        let paths = window.session.settings().recentVaults()
        Menu("Open Recent") {
            ForEach(Array(Self.titles(paths).enumerated()), id: \.offset) { index, title in
                Button(title) { Task { await window.open(paths[index]) } }
            }
            Divider()
            // Emptying the stored list needs its Rust call (APP-01.14).
            Button("Clear Menu") {}.disabled(true)
        }
        .disabled(paths.isEmpty)
    }

    /// "Personal.larsalvault", or "Personal.larsalvault — Work" when another
    /// path has the same file name.
    static func titles(_ paths: [String]) -> [String] {
        let urls = paths.map { URL(fileURLWithPath: $0) }
        return urls.map { url in
            let same = urls.filter { $0.lastPathComponent == url.lastPathComponent }.count > 1
            let folder = url.deletingLastPathComponent().lastPathComponent
            return url.lastPathComponent + (same ? " — " + folder : "")
        }
    }
}

/// APP-08.4: the Edit menu's text items, then Find. Copy copies the
/// selected text, or the selected entry's password when no text is selected
/// (APP-03.7). Undo and Redo are the macOS items.
struct EditMenuItems: View {
    let window: MainWindowModel

    var body: some View {
        // LD-219 (2): Cut and Copy act in any of Larsal's windows, also while
        // the shown vault is locked.
        Button("Cut") { window.textCommand(#selector(NSText.cut(_:))) }
            .keyboardShortcut("x")
        Button("Copy") { window.copyCommand() }
            .keyboardShortcut("c")
        Button("Paste") { NSApp.sendAction(#selector(NSText.paste(_:)), to: nil, from: nil) }
            .keyboardShortcut("v")
        Button("Select All") { NSApp.sendAction(#selector(NSText.selectAll(_:)), to: nil, from: nil) }
            .keyboardShortcut("a")
        Divider()
        Button("Find…") { NotificationCenter.default.post(name: .larsalFind, object: nil) }
            .keyboardShortcut("f")
            .disabled(MenuState(window: window).vault == nil)
    }
}

/// APP-08.10: Minimize (APP-08.19) and Zoom, then the open vaults.
struct WindowMenuItems: View {
    let window: MainWindowModel

    var body: some View {
        Button("Minimize") { WindowRules.shared.minimizeKeyWindow() }.keyboardShortcut("m")
        Button("Zoom") { NSApp.keyWindow?.performZoom(nil) }
        Divider()
        let many = window.vaults.count > 1
        Button("Show Next Vault") { step(1) }.keyboardShortcut(.tab, modifiers: .control).disabled(!many)
        Button("Show Previous Vault") { step(-1) }.keyboardShortcut(.tab, modifiers: [.control, .shift])
            .disabled(!many)
        Divider()
        ForEach(Array(window.vaults.enumerated()), id: \.element.id) { index, vault in
            Toggle(
                vault.name,
                isOn: Binding(get: { vault.shown }, set: { _ in show(vault.id) })
            )
            .keyboardShortcut(Self.key(index, of: window.vaults.count))
        }
    }

    /// ⌘1 to ⌘8 for the first eight, ⌘9 for the last.
    static func key(_ index: Int, of count: Int) -> KeyboardShortcut? {
        if index < 8 { return KeyboardShortcut(KeyEquivalent(Character(String(index + 1)))) }
        return index == count - 1 ? KeyboardShortcut("9") : nil
    }

    private func step(_ offset: Int) {
        let ids = window.vaults.map(\.id)
        guard let index = ids.firstIndex(where: { $0 == window.shown?.id }) else { return }
        show(ids[(index + offset + ids.count) % ids.count])
    }

    private func show(_ id: UInt64) {
        window.switchTo(id)
        Front.bring()
    }
}

/// APP-08.11: the Help menu. The bundled guide comes with E14; no item
/// opens a web page before publishing.
struct HelpMenuItems: View {
    let window: MainWindowModel

    var body: some View {
        // APP-08.17's sheet is not drawn in Option A: the Shortcuts page of
        // the settings lists them (LD-214 (5)).
        Button("Keyboard Shortcuts") { LarsalSettingsWindow.show(session: window.session, page: .keys) }
            .keyboardShortcut("/")
    }
}

extension Notification.Name {
    /// Edit > Find…: the search field takes the focus (FEA-01).
    static let larsalFind = Notification.Name("app.larsal.desktop.find")
}
