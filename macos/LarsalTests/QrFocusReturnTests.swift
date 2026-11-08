import AppKit
import LarsalCore
import SwiftUI
import Testing

/// Where the keys go when the dialog closes and which field the shortcut takes
/// (FEA-10.13, FEA-10.2), with real keys and real focus in a never-ordered window
/// (AGENTS.md rule 10). A person's check in a real key window stays W-08.
@MainActor
@Suite(.serialized)
struct QrFocusReturnTests {
    init() { ParityDemo.setUp() }

    /// Somewhere else for the focus to be while the dialog is up.
    private final class Elsewhere: NSView {
        override var acceptsFirstResponder: Bool { true }
    }

    @Test("QR-T16 FEA-10.13: a text control is an invoker AppKit holds: it has the focus again, or if gone the list")
    func textControlGetsFocusBack() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-invoker")
        defer { demo.window.lockAll() }
        let main = demo.main
        let window = QrKeyWindow(
            contentRect: NSRect(x: -20_000, y: -20_000, width: 400, height: 200), styleMask: [.borderless],
            backing: .buffered, defer: false)
        let holder = NSView(frame: NSRect(x: 0, y: 0, width: 400, height: 200))
        window.contentView = holder
        let notes = NSTextView(frame: NSRect(x: 0, y: 0, width: 100, height: 20))
        let field = NSTextField(frame: NSRect(x: 0, y: 40, width: 100, height: 20))
        let other = Elsewhere(frame: NSRect(x: 0, y: 80, width: 100, height: 20))
        for view in [notes, field, other] { holder.addSubview(view) }
        seams.mainWindow = window
        let turns = QrFocus.shared.turn
        // A text view holds the focus itself.
        #expect(window.makeFirstResponder(notes))
        main.showQr()
        var popup = try await QrDemo.answered(main)
        #expect(window.makeFirstResponder(other))
        popup.revoke()
        #expect(window.firstResponder === notes)
        #expect(QrFocus.shared.turn == turns, "the invoker took it")
        // A text field’s focus sits in its field editor; the field is the invoker.
        #expect(window.makeFirstResponder(field))
        main.showQr()
        popup = try await QrDemo.answered(main)
        #expect(window.makeFirstResponder(other))
        popup.revoke()
        #expect((window.firstResponder as? NSText)?.delegate === field, "the field has it again")
        // The invoker is gone: the entry list’s turn.
        #expect(window.makeFirstResponder(notes))
        main.showQr()
        popup = try await QrDemo.answered(main)
        #expect(window.makeFirstResponder(other))
        notes.removeFromSuperview()
        popup.revoke()
        #expect(QrFocus.shared.turn == turns + 1 && QrFocus.shared.model === main, "this window’s list")
        #expect(window.firstResponder === other, "nothing else moved")
    }

    /// The real main window, never ordered, with the menu’s items beside it, so
    /// the shortcut reads the focused field as the menu does.
    private func mainWindow(_ demo: QrDemo.Demo, _ seams: QrSeams) async throws -> (QrKeyWindow, NSView) {
        let size = CGSize(width: 1_320, height: 820)
        let window = QrKeyWindow(
            contentRect: NSRect(origin: CGPoint(x: -20_000, y: -20_000), size: size), styleMask: [.borderless],
            backing: .buffered, defer: false)
        let root = MainWindow(model: demo.window).frame(width: size.width, height: size.height)
            .background { EntryQrItems(state: MenuState(window: demo.window)).opacity(0) }
        let host = NSHostingView(rootView: root)
        window.layOut { _ = QrDemo.placed(host, size: size, window: window) }
        seams.mainWindow = window
        try await QrDemo.render(host)
        return (window, host)
    }

    /// Only with full keyboard access can a button hold focus. This process
    /// only, as `AccessWalk` turns it on.
    private func keyboardAccess() {
        UserDefaults.standard.setVolatileDomain(["AppleKeyboardUIMode": 2], forName: UserDefaults.argumentDomain)
    }

    /// Focus moves in SwiftUI's own time, and other suites load this actor. A bound, not a pass.
    private func until(_ host: NSView, _ done: () -> Bool) async throws {
        for _ in 0..<100 where !done() { try await QrDemo.render(host) }
    }

    /// Real presses until `done`, for a list that takes the keys in its own time.
    private func press(_ key: NSEvent, _ window: NSWindow, _ host: NSView, until done: () -> Bool) async throws {
        for _ in 0..<40 where !done() { try await QrDemo.press(key, in: window, host) }
    }

    /// Real Tabs to the next QR button that takes the focus.
    private func tabToQrButton(_ window: NSWindow, _ host: NSView) async throws -> Namespace.ID {
        let tab = try QrDemo.key(48, "\t")
        let start = QrFocus.shared.held
        for _ in 0..<120 {
            try await QrDemo.press(tab, in: window, host)
            if let held = QrFocus.shared.held, held != start { return held }
        }
        return try #require(nil as Namespace.ID?, "no QR button took the focus")
    }

    @Test("QR-T16 FEA-10.13: with the list as invoker, real arrows move the selection before and after the pop-up")
    func listGetsFocusBack() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-list-back")
        defer { demo.window.lockAll() }
        let main = demo.main
        let first = try #require(main.rows.first?.id)
        main.select(first)
        let (window, host) = try await mainWindow(demo, seams)
        let down = try QrDemo.key(125, "\u{F701}", [.function, .numericPad])
        QrFocus.shared.give(to: main)
        try await press(down, window, host) { main.selection != first }
        let moved = main.selection
        #expect(moved != first, "the list has the keys")
        main.showQr()
        let popup = try await QrDemo.answered(main)
        try await QrDemo.render(host)
        try await QrDemo.press(down, in: window, host)
        #expect(main.selection == moved && main.qrPopup === popup, "the dialog has them now")
        popup.revoke()
        try await press(down, window, host) { main.selection != moved }
        #expect(main.selection != moved, "the list has them again")
    }

    @Test("QR-T16 FEA-10.13: a QR button with the focus is the invoker: Tab to it, Space, Done; Space reaches it again")
    func buttonGetsFocusBack() async throws {
        keyboardAccess()
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-button-back")
        defer { demo.window.lockAll() }
        let main = demo.main
        let first = try #require(main.selection)
        let (window, host) = try await mainWindow(demo, seams)
        let (space, down) = (try QrDemo.key(49, " "), try QrDemo.key(125, "\u{F701}", [.function, .numericPad]))
        QrFocus.shared.give(to: main)
        try await QrDemo.render(host)
        let button = try await tabToQrButton(window, host)
        try await QrDemo.press(space, in: window, host)
        var popup = try await QrDemo.answered(main)
        try await until(host) { QrFocus.shared.held == nil }
        #expect(QrFocus.shared.held == nil, "the dialog took it")
        popup.revoke()
        try await until(host) { QrFocus.shared.held == button }
        #expect(QrFocus.shared.held == button, "the button has it again")
        try await QrDemo.press(down, in: window, host)
        #expect(main.selection == first, "and the list does not")
        try await QrDemo.press(space, in: window, host)
        popup = try await QrDemo.answered(main)
        popup.revoke()
    }

    @Test("QR-T16 FEA-10.13: the QR button left while the dialog was up: the entry list has the keys")
    func goneButtonGivesTheList() async throws {
        keyboardAccess()
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-button-gone")
        defer { demo.window.lockAll() }
        let main = demo.main
        let first = try #require(main.selection)
        let size = CGSize(width: 1_000, height: 820)
        let window = QrKeyWindow(
            contentRect: NSRect(origin: CGPoint(x: -20_000, y: -20_000), size: size), styleMask: [.borderless],
            backing: .buffered, defer: false)
        let rail = RailShown()
        let root = SheetWithRail(main: main, rail: rail).frame(width: size.width, height: size.height)
        let host = QrDemo.placed(NSHostingView(rootView: root), size: size, window: window)
        seams.mainWindow = window
        try await QrDemo.render(host)
        QrFocus.shared.give(to: main)
        try await QrDemo.render(host)
        _ = try await tabToQrButton(window, host)
        try await QrDemo.press(try QrDemo.key(49, " "), in: window, host)
        let popup = try await QrDemo.answered(main)
        rail.shown = false
        try await QrDemo.render(host)
        popup.revoke()
        let down = try QrDemo.key(125, "\u{F701}", [.function, .numericPad])
        try await press(down, window, host) { main.selection != first }
        #expect(main.selection != first, "the list has the keys")
    }

    @Test("QR-T01 FEA-10.2: the shortcut takes the focused protected field, else Password: real keys, the menu’s item")
    func shortcutFollowsFocus() async throws {
        keyboardAccess()
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let (demo, values) = try QrDemo.protected("qr-shortcut")
        defer { demo.window.lockAll() }
        let (main, id) = (demo.main, demo.entry)
        let (window, host) = try await mainWindow(demo, seams)
        let shortcut = try QrDemo.key(12, "q", [.control, .option, .command])
        func asked() async throws -> QrRequest {
            #expect(host.performKeyEquivalent(with: shortcut), "the menu’s item took it")
            let popup = try await QrDemo.answered(main)
            let request = popup.request
            popup.revoke()
            try await QrDemo.render(host)
            return request
        }
        QrFocus.shared.give(to: main)
        try await QrDemo.render(host)
        #expect(try await asked() == .field(entry: id, name: "Password"), "no field has the focus")
        let want = Set(values.keys.map { QrRequest.field(entry: id, name: $0) })
        var names: Set<QrRequest> = []
        // Under load a Tab can start before the focus is back, and meet a button again.
        for _ in 0..<(want.count * 6) where names != want {
            _ = try await tabToQrButton(window, host)
            names.insert(try await asked())
        }
        #expect(names == want, "\(names)")
    }

    /// Each QR button of this window takes real focus by its own turn, since a text
    /// field in a never-ordered window keeps Tab; then the real shortcut. What each asked for.
    private func eachButton(_ main: VaultModel, _ host: NSView, _ shortcut: NSEvent) async throws -> Set<QrRequest> {
        var names: Set<QrRequest> = []
        for button in try #require(host.window as? QrKeyWindow).buttons {
            QrFocus.shared.give(to: main, button: button)
            try await until(host) { QrFocus.shared.held == button }
            #expect(QrFocus.shared.held == button)
            #expect(host.performKeyEquivalent(with: shortcut), "the menu’s item took it")
            let popup = try await QrDemo.answered(main)
            names.insert(popup.request)
            popup.revoke()
            try await QrDemo.render(host)
        }
        return names
    }

    private func textFields(_ view: NSView) -> [NSTextField] {
        (view as? NSTextField).map { [$0] } ?? view.subviews.flatMap(textFields)
    }

    private func focus(_ prompt: String, _ window: NSWindow, _ host: NSView) async throws {
        let field = try #require(textFields(host).first { $0.placeholderString == prompt }, "\(prompt)")
        #expect(window.makeFirstResponder(field))
        try await QrDemo.render(host)
    }

    @Test("QR-T01 FEA-10.3: in the editor the shortcut takes the focused button’s field and the draft: real keys")
    func shortcutInTheEditor() async throws {
        keyboardAccess()
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let (demo, _) = try QrDemo.protected("qr-shortcut-editor")
        defer { demo.window.lockAll() }
        let (main, id) = (demo.main, demo.entry)
        main.edit(id)
        let real = try #require(main.editor)
        // What Rust sends for a protected standard field (F-060): the flag and no value.
        var view = real.view
        view.protected = [.userName]
        view.user = ""
        let editor = EditorModel(session: demo.session, vault: main.vault, view: view)
        editor.showQr = real.showQr
        main.editor = editor
        let (window, host) = try await mainWindow(demo, seams)
        #expect(window.makeFirstResponder(host))
        let shortcut = try QrDemo.key(12, "q", [.control, .option, .command])
        // Another window's QR button, as a suite running side by side shows one: never this window's.
        try await QrDemo.render(QrDemo.placed(NSHostingView(rootView: QrFieldButton(model: main, field: "PIN"))))
        let onEntry = try await eachButton(main, host, shortcut)
        #expect(onEntry == [.draft(name: "UserName"), .draft(name: "Password")], "\(onEntry)")
        // Into a text field. Focus there saves to the draft and reads Rust's view, which
        // has no protected UserName here, so a protected row is the button's case above.
        try await focus("Add a tag…", window, host)
        try await until(host) { main.qrHeld.field == nil }
        #expect(main.qrHeld.field == nil, "outside the fields")
        // Another window's text field taking focus ends this one's editing: take it again.
        for _ in 0..<20 where main.qrHeld.field != "Password" { try await focus("https://…", window, host) }
        #expect(main.qrHeld.field == "Password", "a plain field gives the Password")
        #expect(host.performKeyEquivalent(with: shortcut), "the menu’s item took it")
        let popup = try await QrDemo.answered(main)
        #expect(popup.request == .draft(name: "Password"))
        popup.revoke()
        try await until(host) { window.firstResponder is NSText }
        #expect((window.firstResponder as? NSText) != nil, "the text field has the focus again")
        window.layOut { editor.page = .advanced }
        let onAdvanced = try await eachButton(main, host, shortcut)
        #expect(onAdvanced == [.draft(name: "PIN"), .draft(name: "Private key note")], "\(onAdvanced)")
    }
}

/// The Security row's join button as an invoker (C1R3-1), and a vault switch (R3C2-2).
extension QrFocusReturnTests {
    @Test("QR-T16 FEA-10.13: the Security row's Show Wi-Fi Join Code is an invoker too: Tab, Space, Done, Space again")
    func joinButtonGetsFocusBack() async throws {
        keyboardAccess()
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-join-back")
        defer { demo.window.lockAll() }
        let main = demo.main
        // An open network with no password: the join's is the one QR button of its rail.
        let cafe = try QrDemo.entry(
            demo.session, demo.vault, [("Title", "Cafe"), ("UserName", "Cafe demo"), ("Security", "nopass")])
        main.afterChange(select: cafe)
        main.select(cafe)
        let (window, host) = try await mainWindow(demo, seams)
        let (space, down) = (try QrDemo.key(49, " "), try QrDemo.key(125, "\u{F701}", [.function, .numericPad]))
        QrFocus.shared.give(to: main)
        try await QrDemo.render(host)
        let button = try await tabToQrButton(window, host)
        try await QrDemo.press(space, in: window, host)
        var popup = try await QrDemo.answered(main)
        #expect(popup.request == .wifi(entry: cafe), "the join's button")
        try await until(host) { QrFocus.shared.held == nil }
        popup.revoke()
        try await until(host) { QrFocus.shared.held == button }
        #expect(QrFocus.shared.held == button, "the button has it again")
        try await QrDemo.press(down, in: window, host)
        #expect(main.selection == cafe, "and the list does not")
        try await QrDemo.press(space, in: window, host)
        popup = try await QrDemo.answered(main)
        #expect(popup.request == .wifi(entry: cafe), "Space reaches it again")
        popup.revoke()
    }

    @Test("QR-T01 FEA-10.2: a vault switch drops the focused field; back, the shortcut takes Password")
    func shortcutAfterVaultSwitch() async throws {
        keyboardAccess()
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let (demo, _) = try QrDemo.protected("qr-shortcut-switch")
        defer { demo.window.lockAll() }
        let (main, id, model) = (demo.main, demo.entry, demo.window)
        let work = try #require(model.vaults.first { $0.name == "Work" }?.id)
        #expect(try demo.session.unlock(vault: work, password: ParityDemo.vaults[1].2, keyFile: nil) == .unlocked)
        let (window, host) = try await mainWindow(demo, seams)
        QrFocus.shared.give(to: main)
        try await QrDemo.render(host)
        // A protected field's button has the focus, so the shortcut would take that field.
        for _ in 0..<6 where [nil, "Password"].contains(main.qrHeld.field) {
            _ = try await tabToQrButton(window, host)
        }
        #expect(![nil, "Password"].contains(main.qrHeld.field), "\(String(describing: main.qrHeld.field))")
        model.switchTo(work)
        try await QrDemo.render(host)
        // Dropped when the vault leaves, not only when the reader reads the focus again on return.
        #expect(model.main !== main && main.qrHeld.field == nil, "the vault that left keeps no focused field")
        model.switchTo(main.vault.id)
        try await QrDemo.render(host)
        #expect(model.main === main && main.qrHeld.field == nil, "no focused field came back with the vault")
        #expect(host.performKeyEquivalent(with: try QrDemo.key(12, "q", [.control, .option, .command])))
        let popup = try await QrDemo.answered(main)
        #expect(popup.request == .field(entry: id, name: "Password"), "\(popup.request)")
        popup.revoke()
    }
}

/// What takes the rail away while the dialog is up.
@Observable
private final class RailShown {
    var shown = true
}

private struct SheetWithRail: View {
    let main: VaultModel
    let rail: RailShown

    var body: some View { SheetView(model: main, details: rail.shown) }
}
