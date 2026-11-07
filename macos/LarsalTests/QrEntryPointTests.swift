import AppKit
import LarsalCore
import SwiftUI
import Testing

/// QR-T01: each way to Show as QR Code, really invoked: visible buttons, field
/// menus, the row menu, the Entry menu and its submenu, More actions and the
/// shortcut (FEA-10.1, .2, .4). Offscreen only, no real menu on screen
/// (AGENTS.md rule 10).
@MainActor
@Suite(.serialized)
struct QrEntryPointTests {
    init() { ParityDemo.setUp() }

    @Test("QR-T01 FEA-10.1: every visible button, masked and shown, gives exactly its field; no vault change")
    func visibleButtons() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let (demo, values) = try QrDemo.protected("qr-buttons")
        defer { demo.window.lockAll() }
        let (window, main, id) = (demo.window, demo.main, demo.entry)
        let before = try QrDemo.savedAt(demo)
        let screen = Screen(window)
        await screen.settle()
        #expect(try await QrDemo.pressEach(screen.host, main) == wanted(id, values), "masked")
        for name in values.keys { await main.toggleShow(name) }
        #expect(main.shown.count == values.count, "all shown")
        await screen.settle()
        #expect(try await QrDemo.pressEach(screen.host, main) == wanted(id, values), "shown")
        try QrDemo.expectUnchanged(demo, since: before)
    }

    @Test("QR-T01 FEA-10.1: protected standard fields and notes, and a card's secrets, have the button")
    func standardAndCard() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-standard")
        defer { demo.window.lockAll() }
        let (window, main) = (demo.window, demo.main)
        let (session, vault) = (demo.session, demo.vault)
        let values = [
            "Title": "Standard", "UserName": "demo-user", "URL": "https://demo.example", "Notes": "demo notes",
        ]
        let id = try QrDemo.entry(session, vault, [("Title", "Standard"), ("UserName", "demo-user")])
        _ = try session.beginEdit(vault: vault, entry: id)
        try session.setText(vault: vault, field: .url, value: "https://demo.example")
        try session.setText(vault: vault, field: .notes, value: "demo notes")
        _ = try session.commitEdit(vault: vault)
        main.afterChange(select: id)
        main.select(id)
        // What Rust sends for a protected standard field (F-060): flagged, with no value.
        var detail = try #require(main.detail)
        detail.fields = detail.fields.map {
            FieldView(name: $0.name, kind: $0.kind, value: "", protected: values[$0.name] != nil)
        }
        // A protected title comes as a field of its own (Rust: qr_t01_a_protected_title_...).
        detail.fields.insert(FieldView(name: "Title", kind: .title, value: "", protected: true), at: 0)
        let rail = VStack(spacing: 8) {
            Panel(rows: EntryFields(model: main, entry: detail).rows + MoreFields(model: main, entry: detail).rows)
        }
        let host = QrDemo.placed(NSHostingView(rootView: rail), size: CGSize(width: 460, height: 700))
        _ = Screen(window)  // Its process flag builds the accessibility nodes.
        host.layoutSubtreeIfNeeded()
        try await Task.sleep(for: .milliseconds(150))
        let asked = try await QrDemo.pressEach(host, main)
        #expect(asked == wanted(id, values))
        // A card: the real view, each protected field beside its value.
        let secrets = [
            "Cardholder": "Demo Holder", "Card number": "4000 1234 5678 9010", "Expires": "12/30",
            "Security code": "737", "PIN": "9931",
        ]
        let card = try QrDemo.entry(session, vault, [("Title", "Card")] + secrets.map { ($0.key, $0.value) })
        _ = try session.beginEdit(vault: vault, entry: card)
        for name in secrets.keys { try session.protectField(vault: vault, name: name, on: true) }
        _ = try session.commitEdit(vault: vault)
        main.afterChange(select: card)
        main.select(card)
        #expect(main.detail?.kind == .card)
        let screen = Screen(window)
        await screen.settle()
        #expect(try await QrDemo.pressEach(screen.host, main) == wanted(card, secrets))
        let shown = screen.strings().joined(separator: " ")
        #expect(shown.contains("••••••••") && shown.contains("••/••"), "the holder and the date are masked, not blank")
        #expect(!shown.contains("Demo Holder") && !shown.contains("12/30"))
    }

    @Test("QR-T01 FEA-10.2: the row menu, the Entry menu and submenu, More and the shortcut ask for exactly the field")
    func menus() async throws {
        guard #available(macOS 14.4, *) else { return }
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let (demo, values) = try QrDemo.protected("qr-menus")
        defer { demo.window.lockAll() }
        let (window, main, id) = (demo.window, demo.main, demo.entry)
        let before = try QrDemo.savedAt(demo)
        let password = QrRequest.field(entry: id, name: "Password")
        let note = values["Private key note"] ?? ""
        // The row menu acts on the clicked row, and the list means its Password.
        let row = try #require(main.rows.first { $0.id == id })
        main.select(try #require(main.rows.first { $0.id != id }?.id))
        var popup = try await run(NSHostingMenu(rootView: EntryContextMenu(model: main, row: row)), QrText.title, main)
        #expect(popup.request == password && main.selection == id, "the row menu")
        #expect(try QrRead.payload(try #require(popup.symbol)).bytes == Data("demo-pass".utf8))
        popup.revoke()
        // The Entry menu, then a field of its submenu.
        let entry = NSHostingMenu(rootView: EntryMenuItems(window: window))
        popup = try await run(entry, QrText.title, main)
        #expect(popup.request == password, "the Entry menu")
        popup.revoke()
        let submenu = try #require(entry.item(withTitle: QrText.field)?.submenu)
        try await filled(submenu)
        #expect(submenu.items.map(\.title).sorted() == values.keys.sorted())
        popup = try await run(submenu, "Private key note", main)
        #expect(popup.request == .field(entry: id, name: "Private key note"), "the submenu")
        #expect(try QrRead.payload(try #require(popup.symbol)).bytes == Data(note.utf8))
        popup.revoke()
        // The shortcut, as the menu bar hands it to the menu.
        let key = try #require(
            NSEvent.keyEvent(
                with: .keyDown, location: .zero, modifierFlags: [.control, .option, .command], timestamp: 0,
                windowNumber: 0, context: nil, characters: "q", charactersIgnoringModifiers: "q", isARepeat: false,
                keyCode: 12))
        try await filled(entry)
        #expect(entry.performKeyEquivalent(with: key), "⌃⌥⌘Q is the item's key")
        for _ in 0..<200 where main.qrPopup == nil { try await Task.sleep(for: .milliseconds(5)) }
        popup = try await QrDemo.answered(main)
        #expect(popup.request == password, "the shortcut's default")
        main.showQrFromKeys(focused: "Private key note")
        #expect(main.qrPopup?.request == .field(entry: id, name: "Private key note"), "focus wins")
        main.qrPopup?.revoke()
        // More actions: its own item says its keys, a field's button does not.
        let screen = Screen(window)
        await screen.settle()
        try await screen.press("More actions")
        let item = try #require(screen.node(QrText.title + ", ⌃⌥⌘Q"), "the item with its keys")
        #expect(item.accessibilityPerformPress?() == true)
        popup = try await QrDemo.answered(main)
        #expect(popup.request == password && main.overlay == nil, "More actions")
        popup.revoke()
        let lines = await MenuLine.read(EntryMenuItems(window: window))
        #expect(lines.line(QrText.title)?.keys == "⌃⌥⌘Q")
        try QrDemo.expectUnchanged(demo, since: before)
    }

    @Test("QR-T01 FEA-10.2: each field's right-click item targets that field; each protected row wears that menu")
    func fieldMenus() async throws {
        guard #available(macOS 14.4, *) else { return }
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let (demo, values) = try QrDemo.protected("qr-field-menus")
        defer { demo.window.lockAll() }
        let (main, id) = (demo.main, demo.entry)
        // A context menu opens only for a real right click on the screen (W-08);
        // offscreen, `menu(for:)` has none. So: the menu's own view as a native
        // menu, its item really run, then each row's wiring by its type.
        for (name, value) in values {
            let menu = NSHostingMenu(rootView: QrFieldMenu(model: main, field: name))
            let popup = try await run(menu, QrText.title, main)
            #expect(popup.request == .field(entry: id, name: name), "\(name)")
            #expect(try QrRead.payload(try #require(popup.symbol)).bytes == Data(value.utf8))
            popup.revoke()
        }
        #expect(FieldView(name: "Plain", kind: .custom, value: "x", protected: false).qrOffered == false)
        #expect(FieldView(name: "Secret", kind: .custom, value: "", protected: true).qrOffered)
        #expect(FieldView(name: "Password", kind: .password, value: "", protected: false).qrOffered)
        var detail = try #require(main.detail)
        let protected: Set<FieldKind> = [.userName, .url, .notes]
        detail.fields.removeAll { protected.contains($0.kind) }
        detail.fields += [
            FieldView(name: "UserName", kind: .userName, value: "", protected: true),
            FieldView(name: "URL", kind: .url, value: "", protected: true),
            FieldView(name: "Notes", kind: .notes, value: "", protected: true),
        ]
        let rows = EntryFields(model: main, entry: detail).rows + MoreFields(model: main, entry: detail).rows
        let worn = try rows.map { try makeup($0) }.filter { $0.contains("QrFieldMenu") }
        #expect(worn.count == 6, "user name, password, PIN, note, address, notes: \(rows.count) rows: \(worn)")
        // A protected title wears it too.
        detail.fields.append(FieldView(name: "Title", kind: .title, value: "", protected: true))
        let titled = EntryFields(model: main, entry: detail).rows
        #expect(try titled.map { try makeup($0) }.filter { $0.contains("QrFieldMenu") }.count == 5)
        // The card's fields, by the same reading.
        let card = try QrDemo.entry(
            demo.session, demo.vault,
            [
                ("Title", "Card"), ("Cardholder", "Demo"), ("Card number", "4000"), ("Expires", "12/30"),
                ("Security code", "737"), ("PIN", "9"),
            ])
        main.afterChange(select: card)
        main.select(card)
        let cardRows = EntryFields(model: main, entry: try #require(main.detail)).rows
        let cardWorn = try cardRows.map { try makeup($0) }.filter { $0.contains("QrFieldMenu") }
        // Holder, number, then one row of three: expires, security code, PIN.
        #expect(cardWorn.count == 3 && cardWorn.last?.components(separatedBy: "QrFieldMenu").count == 4)
    }

    @Test("QR-T01 FEA-10.4: Show Wi-Fi Join Code is on the row menu and the Security row, and only for a join")
    func wifiItems() async throws {
        guard #available(macOS 14.4, *) else { return }
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-wifi-items")
        defer { demo.window.lockAll() }
        let (window, main, id) = (demo.window, demo.main, demo.entry)
        let (session, vault) = (demo.session, demo.vault)
        // An open network the classifier does not name, and a login that is neither.
        let open = try QrDemo.entry(
            session, vault, [("Title", "Cafe"), ("UserName", "Cafe demo"), ("Security", "nopass")])
        main.afterChange(select: open)
        let login = try #require(main.rows.first { $0.id == id })
        let home = try #require(main.rows.first { $0.title == "Home Wi-Fi" })
        let cafe = try #require(main.rows.first { $0.id == open })
        let titles = { (row: EntryRow) in await MenuLine.read(EntryContextMenu(model: main, row: row)).titles }
        main.select(id)
        #expect(!(await titles(login)).contains(QrText.join), "a login has no join")
        #expect(await titles(home).contains(QrText.join), "not selected, by kind")
        #expect(await titles(cafe).contains(QrText.join), "not selected, by Security")
        var popup = try await run(
            NSHostingMenu(rootView: EntryContextMenu(model: main, row: cafe)), QrText.join, main)
        #expect(popup.request == .wifi(entry: open) && main.selection == open, "the row menu")
        #expect(popup.stage == .code)
        popup.revoke()
        // The Security row: its own menu really run, its wiring by type (a real right click is W-08).
        popup = try await run(NSHostingMenu(rootView: QrJoinMenu(model: main)), QrText.join, main)
        #expect(popup.request == .wifi(entry: open), "the Security row's menu")
        popup.revoke()
        let rows = EntryFields(model: main, entry: try #require(main.detail)).rows
        let wearing = try rows.map { try makeup($0) }.filter { $0.contains("QrJoinMenu") }
        #expect(wearing.count == 1, "of \(rows.count) rows")
        // Selected: the Security row's button and the Entry menu.
        let screen = Screen(window)
        await screen.settle()
        try await screen.press(QrText.join)
        popup = try await QrDemo.answered(main)
        #expect(popup.request == .wifi(entry: open), "the Security row")
        popup.revoke()
        await screen.settle()
        popup = try await run(NSHostingMenu(rootView: EntryMenuItems(window: window)), QrText.join, main)
        #expect(popup.request == .wifi(entry: open), "the Entry menu")
        popup.revoke()
    }

    @Test("QR-T02 FEA-10.2: the shortcut and the menu act only with the main window in front")
    func scopedToWindow() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-front")
        defer { demo.window.lockAll() }
        let main = demo.main
        let rules = WindowRules.shared
        let saved = rules.keyWindow
        // Settings in front; nothing suspends here, so no other test sees the swap.
        let settings = NSWindow(contentRect: .zero, styleMask: [.titled], backing: .buffered, defer: true)
        rules.keyWindow = { settings }
        main.showQrFromKeys(focused: nil)
        main.showWifiJoinFromMenu()
        rules.keyWindow = saved
        #expect(main.qrPopup == nil && main.dialog == nil, "another window in front")
        rules.keyWindow = { nil }
        main.showQrFromKeys(focused: nil)
        rules.keyWindow = saved
        #expect(main.qrPopup != nil, "no key window is the hidden launch: as copyCommand")
        main.qrPopup?.revoke()
        main.showQr()
        #expect(main.qrPopup != nil, "a button in the window itself needs no check")
        main.qrPopup?.revoke()
        // R2C2-2: the main window in the Dock and no key window: no code is made.
        let docked = DockedWindow(contentRect: .zero, styleMask: [.titled], backing: .buffered, defer: true)
        seams.mainWindow = docked
        rules.keyWindow = { nil }
        main.showQrFromKeys(focused: nil)
        main.showWifiJoinFromMenu()
        rules.keyWindow = saved
        #expect(main.qrPopup == nil && main.dialog == nil, "the window is in the Dock")
        // The main window in front.
        rules.keyWindow = { docked }
        main.showQrFromKeys(focused: nil)
        rules.keyWindow = saved
        #expect(main.qrPopup != nil, "its own window as the key window")
        main.qrPopup?.revoke()
    }

    /// A window that says it is in the Dock.
    private final class DockedWindow: NSWindow {
        override var isMiniaturized: Bool { true }
    }
}

@MainActor
private func wanted(_ id: String, _ values: [String: String]) -> [QrRequest: Data] {
    Dictionary(uniqueKeysWithValues: values.map { (.field(entry: id, name: $0.key), Data($0.value.utf8)) })
}

/// A hosted menu fills its items on the run loop after an update.
@MainActor
private func filled(_ menu: NSMenu) async throws {
    menu.update()
    try await Task.sleep(for: .milliseconds(30))
    menu.update()
}

/// Runs one item of a native menu and gives the pop-up it opened.
@MainActor
private func run(
    _ menu: NSMenu, _ title: String, _ main: VaultModel, at place: SourceLocation = #_sourceLocation
) async throws -> QrPopup {
    try await filled(menu)
    let index = menu.indexOfItem(withTitle: title)
    try #require(index >= 0, "\(title) is in the menu")
    let item = menu.items[index]
    try #require(item.isEnabled, "\(title) is enabled")
    menu.performActionForItem(at: index)
    if main.qrPopup == nil, let action = item.action {
        // A submenu's item answers through its target only (AppKit's own route).
        NSApp.sendAction(action, to: item.target, from: item)
    }
    return try await QrDemo.answered(main, at: place)
}

/// What a rail row is made of: its view's type, and its body's when it is a
/// view of its own.
@MainActor
private func makeup(_ row: AnyView) throws -> String {
    let storage = try #require(Mirror(reflecting: row).children.first?.value)
    var view = try #require(Mirror(reflecting: storage).children.first?.value as? any View)
    // `.id(_:)` around a row of its own.
    let inner = Mirror(reflecting: view).descendant("content") as? any View
    if String(reflecting: type(of: view)).hasPrefix("SwiftUI.IDView"), let inner { view = inner }
    return String(reflecting: type(of: view)) + " " + bodyType(view)
}

@MainActor
private func bodyType<V: View>(_ view: V) -> String {
    V.Body.self == Never.self ? "" : String(reflecting: type(of: view.body))
}
