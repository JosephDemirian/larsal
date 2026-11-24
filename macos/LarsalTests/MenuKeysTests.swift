import AppKit
import LarsalCore
import SwiftUI
import Testing

// E5-S11 Verify findings: View > Mask User Names (S-VIEW-06), Edit > Copy
// outside the main window, and the keys inside the window (APP-08.14). The
// main window renders offscreen in a window that is never shown or made key;
// key events go to that window's own methods, never to the owner's session
// (AGENTS.md rule 10).
@MainActor
@Suite(.serialized)
struct MenuKeysTests {
    init() { ParityDemo.setUp() }

    static let user = "alex.morgan@gmail.com"

    /// A key press as AppKit hands it to the window.
    static func key(_ code: UInt16, _ chars: String, _ bare: String, _ mods: NSEvent.ModifierFlags) throws -> NSEvent {
        try #require(
            NSEvent.keyEvent(
                with: .keyDown, location: .zero, modifierFlags: mods, timestamp: 0, windowNumber: 0, context: nil,
                characters: chars, charactersIgnoringModifiers: bare, isARepeat: false, keyCode: code))
    }

    static func controlKey(_ letter: String, _ code: UInt16, _ screen: Screen) throws -> Bool {
        let scalar = UnicodeScalar(try #require(letter.unicodeScalars.first).value - 96)
        return screen.window.performKeyEquivalent(
            with: try key(code, String(Character(try #require(scalar))), letter, .control))
    }

    @Test("APP-08.8 APP-01.23 APP-08.25: Mask User Names hides the user name in the list and detail until Show")
    func maskUserNames() async throws {
        let window = try ParityDemo.window("e5s11-mask")
        defer { window.lockAll() }
        let main = try #require(window.main)
        main.select(main.rows.first { $0.title == "Google" }?.id)
        let screen = Screen(window)
        await screen.settle()
        let shown = { screen.strings().filter { $0.contains(Self.user) } }
        #expect(shown().count == 2, "off: the row and the detail read it: \(shown())")
        window.view.set("display.hide_usernames", true, window.session)
        await screen.settle()
        #expect(shown().isEmpty, "\(shown())")
        #expect(AccessWalk.check(screen.host, screen: "masked", secrets: [Self.user]).isEmpty)
        let row = try #require(screen.nodes().first { ($0.accessibilityLabel?() ?? nil)?.hasPrefix("Google") == true })
        #expect((row.accessibilityLabel?() ?? nil)?.contains(Masked.spoken) == true, "the row reads hidden")
        // APP-01.23: the detail's Show reads it; a new selection drops it.
        try await screen.press("Show username")
        try await screen.wait { main.shown["UserName"] != nil }
        await screen.settle()
        #expect(shown().count == 1, "the detail only: \(shown())")
        try await screen.press("Hide username")
        #expect(shown().isEmpty)
        window.view.set("display.hide_usernames", false, window.session)
        await screen.settle()
        #expect(shown().count == 2)
    }

    @Test("APP-08.4 APP-08.12: ⌘C in a dialog or another of Larsal's windows is the plain copy, never the password")
    func copyOutsideMainWindow() throws {
        let window = try ParityDemo.window("e5s11-copy")
        defer { window.lockAll() }
        let main = try #require(window.main)
        main.select(main.rows.first { $0.title == "Google" }?.id)
        main.dialog = .newGroup(name: "")
        window.copyCommand()
        #expect(main.toast == nil, "the New Group dialog is open")
        main.dialog = nil
        let rules = WindowRules.shared
        let saved = rules.keyWindow
        let settings = NSWindow(
            contentRect: NSRect(x: -20_000, y: -20_000, width: 10, height: 10), styleMask: [.borderless],
            backing: .buffered, defer: true)
        rules.keyWindow = { settings }
        window.copyCommand()
        rules.keyWindow = saved
        #expect(main.toast == nil, "the settings window is in front")
        // The main window in front (none key in a test run): the password.
        window.copyCommand()
        #expect(main.toast?.text == "Password copied.")
    }

    @Test("APP-08.14: ⌃H shows and hides the unlock password")
    func unlockControlH() async throws {
        let window = try ParityDemo.window("e5s11-keys-lock", unlocked: [])
        let unlock = try #require(window.unlock)
        let screen = Screen(window)
        await screen.settle()
        #expect(try Self.controlKey("h", 4, screen))
        #expect(unlock.reveal)
        await screen.settle()
        #expect(try Self.controlKey("h", 4, screen))
        #expect(!unlock.reveal)
    }

    @Test("APP-08.14: in the editor ⌃H shows and hides the password and ⌃G opens the generator")
    func editorKeys() async throws {
        let window = try ParityDemo.window("e5s11-keys-editor")
        defer { window.lockAll() }
        let main = try #require(window.main)
        main.select(main.rows.first { $0.title == "Google" }?.id)
        main.edit()
        let editor = try #require(main.editor)
        let screen = Screen(window)
        await screen.settle()
        #expect(try Self.controlKey("h", 4, screen))
        #expect(editor.shownPassword != nil)
        await screen.settle()
        #expect(try Self.controlKey("h", 4, screen))
        #expect(editor.shownPassword == nil)
        await screen.settle()
        #expect(try Self.controlKey("g", 5, screen))
        #expect(main.generator?.fromEditor == true)
    }

    @Test("APP-08.14: ↓ and ↑ in the search field move the list's selection")
    func searchArrows() async throws {
        let window = try ParityDemo.window("e5s11-keys-search")
        defer { window.lockAll() }
        let main = try #require(window.main)
        let ids = main.rows.map(\.id)
        try #require(ids.count > 2)
        main.select(ids[0])
        let screen = Screen(window)
        await screen.settle()
        let element = try #require(screen.node("Search entries"))
        let field = try #require((element as? NSCell)?.controlView as? NSTextField ?? element as? NSTextField)
        #expect(screen.window.makeFirstResponder(field))
        await screen.settle()
        #expect(field.currentEditor() != nil, "the field is being edited")
        let arrow = { (code: UInt16, char: Int) throws -> NSEvent in
            let text = String(Character(try #require(UnicodeScalar(char))))
            return try Self.key(code, text, text, [.numericPad, .function])
        }
        let downKey = try arrow(125, NSDownArrowFunctionKey)
        let upKey = try arrow(126, NSUpArrowFunctionKey)
        screen.window.sendEvent(downKey)
        await screen.settle()
        #expect(main.selection == ids[1], "↓: the next row")
        screen.window.sendEvent(upKey)
        await screen.settle()
        #expect(main.selection == ids[0], "↑: back")
        #expect(main.search.isEmpty, "the keys type nothing")
        screen.window.makeFirstResponder(nil)
    }
}

// E5-S11 Verify round 2 (LD-219): every user name masked, and Edit's Cut and
// Copy in Larsal's other windows while the shown vault is locked.
@MainActor
extension MenuKeysTests {
    @Test("APP-08.8 LD-219: the Passkey row's user name is masked until Show; Wi-Fi's row says network name")
    func maskPasskeyUser() async throws {
        let window = try ParityDemo.window("e5s11-mask-github")
        defer { window.lockAll() }
        // The settings store is the process's own: the mask goes off again.
        defer { window.view.set("display.hide_usernames", false, window.session) }
        let main = try #require(window.main)
        main.select(main.rows.first { $0.title == "GitHub" }?.id)
        let screen = Screen(window)
        await screen.settle()
        let reads = { (text: String) in screen.strings().contains { $0.contains(text) } }
        #expect(reads("github.com · alex-dev"), "off: the Passkey row reads it")
        window.view.set("display.hide_usernames", true, window.session)
        await screen.settle()
        #expect(AccessWalk.check(screen.host, screen: "masked github", secrets: ["alex-dev"]).isEmpty)
        #expect(reads("github.com, hidden"), "the Passkey row reads the site, then hidden")
        try await screen.press("Show username")
        try await screen.wait { main.shown["UserName"] != nil }
        await screen.settle()
        #expect(reads("github.com · alex-dev"), "Show reveals it with the Username row")
        try await screen.press("Hide username")
        #expect(!reads("alex-dev"))
        // LD-219 (3): a Wi-Fi entry's masked row names the network.
        main.select(try #require(main.rows.first { $0.title == "Home Wi-Fi" }?.id))
        await screen.settle()
        #expect(screen.node("Show network name") != nil && screen.node("Copy network name") != nil)
    }

    @Test("APP-08.8 LD-219: Mask User Names hides the user names of the Health check and Passkeys reports")
    func maskReports() async throws {
        let window = try ParityDemo.window("e5s11-mask-reports")
        defer { window.lockAll() }
        defer { window.view.set("display.hide_usernames", false, window.session) }
        let main = try #require(window.main)
        main.openReports(.health)
        let reports = try #require(main.reports)
        let screen = Screen(window)
        try await screen.wait { reports.health != nil && reports.passkeys != nil }
        // A user name that is also part of a title ("root") is no secret.
        let secret = { (user: String) in !user.isEmpty && !main.rows.contains { $0.title.contains(user) } }
        let health = (reports.health?.rows ?? []).map(\.entry).filter(\.subtitleIsUser).map(\.subtitle).filter(secret)
        let passkeys = (reports.passkeys ?? []).map(\.user).filter(secret)
        try #require(!health.isEmpty && !passkeys.isEmpty)
        for (tab, users) in [(ReportsModel.Tab.health, health), (.passkeys, passkeys)] {
            reports.choose(tab)
            window.view.set("display.hide_usernames", false, window.session)
            await screen.settle()
            let seen = { users.filter { user in screen.strings().contains { $0.contains(user) } } }
            #expect(seen().count == users.count, "off: \(tab) reads \(users), saw \(seen())")
            window.view.set("display.hide_usernames", true, window.session)
            await screen.settle()
            #expect(AccessWalk.check(screen.host, screen: "masked \(tab)", secrets: users).isEmpty)
            #expect(screen.strings().contains { $0.contains(Masked.spoken) }, "\(tab) reads hidden")
        }
    }

    @Test("APP-08.4 APP-08.12 LD-219: with the shown vault locked, ⌘C and ⌘X act in a settings and a wizard field")
    func cutCopyWhileLocked() async throws {
        guard #available(macOS 14.4, *) else { return }
        _ = NSApplication.shared  // the test process's own, never shown
        let window = try ParityDemo.window("e5s11-locked-edit", unlocked: [])
        try #require(window.unlock != nil)
        let edit = await MenuLine.read(EditMenuItems(window: window))
        #expect(edit.line("Cut")?.enabled == true && edit.line("Copy")?.enabled == true, "\(edit)")
        let settings = settingsModel()
        settings.query = "demo text"
        let wizard = NewVaultModel(session: Session())
        wizard.name = "demo text"
        let menu = NSHostingMenu(rootView: EditMenuItems(window: window))
        menu.update()
        try await Task.sleep(for: .milliseconds(30))
        menu.update()
        let rules = WindowRules.shared
        let saved = rules.keyWindow
        defer { rules.keyWindow = saved }
        let fields: [(AnyView, String)] = [
            (AnyView(LarsalSettingsView(model: settings).frame(width: 900, height: 680)), "Search settings"),
            (AnyView(NewVaultView(model: wizard).frame(width: 720, height: 720)), "Name"),
        ]
        for (view, name) in fields {
            let other = OtherWindow(view)
            await other.settle()
            let field = try #require(other.field(name), "\(name) is on screen")
            #expect(other.makeFirstResponder(field))
            let editor = try #require(other.firstResponder as? NSTextView, "the field editor edits \(name)")
            let spy = try #require(CopySpy(editor), "\(name): no copy may reach the general pasteboard")
            defer { spy.detach() }
            editor.selectAll(nil)
            rules.keyWindow = { other }
            for (code, key) in [(UInt16(8), "c"), (7, "x")] {
                #expect(menu.performKeyEquivalent(with: try Self.key(code, key, key, .command)))
            }
            // LD-241 (1): the override goes before the next pass's await, so
            // suites running side by side never see `other` as key window.
            rules.keyWindow = saved
            #expect(spy.log.log == ["copy demo text", "cut demo text"], "\(name): \(spy.log.log)")
            other.makeFirstResponder(nil)
        }
    }

    @Test("APP-08.4 APP-03.19 LD-219: with the shown vault locked, ⌘X and ⌘C leave a selected typed password alone")
    func cutCopyPasswordField() async throws {
        guard #available(macOS 14.4, *) else { return }
        _ = NSApplication.shared  // the test process's own, never shown
        let window = try ParityDemo.window("e5s11-locked-cut", unlocked: [])
        let unlock = try #require(window.unlock)
        unlock.password = "demo-master-pass-19"
        let screen = Screen(window)
        await screen.settle()
        let element = try #require(screen.node("Password", role: "AXTextField"))
        let field = try #require((element as? NSCell)?.controlView as? NSTextField ?? element as? NSTextField)
        #expect(screen.window.makeFirstResponder(field))
        let editor = try #require(screen.window.firstResponder as? NSTextView, "the field editor")
        #expect(editor.className == "NSSecureTextView", "the masked field's editor")
        let spy = try #require(CopySpy(editor), "no cut or copy may reach the general pasteboard")
        defer { spy.detach() }
        editor.selectAll(nil)
        #expect(editor.selectedRange().length == 19)
        let menu = NSHostingMenu(rootView: EditMenuItems(window: window))
        menu.update()
        try await Task.sleep(for: .milliseconds(30))
        menu.update()
        let rules = WindowRules.shared
        let saved = rules.keyWindow
        defer { rules.keyWindow = saved }
        rules.keyWindow = { screen.window }
        for (code, key) in [(UInt16(7), "x"), (8, "c")] {
            #expect(menu.performKeyEquivalent(with: try Self.key(code, key, key, .command)))
        }
        #expect(spy.log.log.isEmpty, "the password field refuses Cut and Copy: \(spy.log.log)")
        #expect(unlock.password.count == 19 && editor.string.count == 19)
        screen.window.makeFirstResponder(nil)
    }
}

/// One of Larsal's other windows, offscreen and never shown (AGENTS.md rule 10).
@MainActor
final class OtherWindow: NSWindow {
    private let host: NSHostingView<AnyView>

    init(_ view: AnyView) {
        host = NSHostingView(rootView: view)
        super.init(
            contentRect: NSRect(x: -20_000, y: -20_000, width: 900, height: 720), styleMask: [.borderless],
            backing: .buffered, defer: false)
        contentView = host
        NSApplication.shared.setValue(true, forKey: "accessibilityEnhancedUserInterface")
    }

    func settle() async {
        host.layoutSubtreeIfNeeded()
        try? await Task.sleep(for: .milliseconds(150))
        host.layoutSubtreeIfNeeded()
    }

    /// The text field VoiceOver reads as `name`.
    func field(_ name: String) -> NSTextField? {
        func walk(_ any: Any, _ depth: Int) -> NSTextField? {
            let element = any as AnyObject
            guard depth < 80 else { return nil }
            let field = (element as? NSCell)?.controlView as? NSTextField ?? element as? NSTextField
            if (element.accessibilityLabel?() ?? nil) == name, let field { return field }
            return (element.accessibilityChildren?() ?? []).lazy.compactMap { walk($0, depth + 1) }.first
        }
        return walk(host, 0)
    }
}

/// SwiftUI's own field editor with Cut and Copy recorded instead of run, so
/// no test writes the general pasteboard (AGENTS.md rule 10): this one
/// instance gets a test subclass until `detach()`. Nil when that fails, and
/// then the test sends no key.
@MainActor
final class CopySpy {
    final class Log { var log: [String] = [] }

    let log = Log()
    private let editor: NSTextView
    private let base: AnyClass
    private static var made = 0

    init?(_ editor: NSTextView) {
        guard let base = object_getClass(editor) else { return nil }
        Self.made += 1
        let name = "E5S11CopySpy\(Self.made)"
        guard let spy = objc_allocateClassPair(base, name, 0) else { return nil }
        for (action, verb) in [(#selector(NSText.copy(_:)), "copy"), (#selector(NSText.cut(_:)), "cut")] {
            let record: @convention(block) (NSTextView, Any?) -> Void = { [log] view, _ in
                log.log.append(verb + " " + (view.string as NSString).substring(with: view.selectedRange()))
            }
            class_addMethod(spy, action, imp_implementationWithBlock(record), "v@:@")
        }
        objc_registerClassPair(spy)
        object_setClass(editor, spy)
        guard object_getClass(editor) === spy else { return nil }
        (self.editor, self.base) = (editor, base)
    }

    func detach() { object_setClass(editor, base) }
}
