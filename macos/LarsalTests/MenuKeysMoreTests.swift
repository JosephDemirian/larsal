import AppKit
import LarsalCore
import SwiftUI
import Testing

// E5-S11 Checker 1 round 2 and the LD-219 addendum: Cut and Copy check the
// target AppKit really uses, and the editor, History sheet and Wi-Fi QR
// title mask user names.
@MainActor
extension MenuKeysTests {
    @Test("APP-08.4 APP-03.19 LD-219: another window in front, nothing focused: ⌘X and ⌘C leave the password alone")
    func cutCopyBehindOtherWindow() async throws {
        guard #available(macOS 14.4, *) else { return }
        _ = NSApplication.shared  // the test process's own, never shown
        let window = try ParityDemo.window("e5s11-locked-behind", unlocked: [])
        let unlock = try #require(window.unlock)
        unlock.password = "demo-master-pass-19"
        let screen = Screen(window)
        await screen.settle()
        let element = try #require(screen.node("Password", role: "AXTextField"))
        let field = try #require((element as? NSCell)?.controlView as? NSTextField ?? element as? NSTextField)
        #expect(screen.window.makeFirstResponder(field))
        let editor = try #require(screen.window.firstResponder as? NSTextView, "the field editor")
        let spy = try #require(CopySpy(editor), "no cut or copy may reach the general pasteboard")
        defer { spy.detach() }
        editor.selectAll(nil)
        let menu = NSHostingMenu(rootView: EditMenuItems(window: window))
        menu.update()
        try await Task.sleep(for: .milliseconds(30))
        menu.update()
        let other = OtherWindow(AnyView(LarsalSettingsView(model: settingsModel()).frame(width: 900, height: 680)))
        await other.settle()
        // Nothing focused in the Settings window: its first responder is the
        // window, then its hosting view; AppKit's chain goes on to the main
        // window's password field.
        for responder in [nil, other.contentView] as [NSResponder?] {
            other.makeFirstResponder(responder)
            let front = try #require(FrontWindows(key: other, main: screen.window))
            defer { front.detach() }
            for (code, key) in [(UInt16(7), "x"), (8, "c")] {
                #expect(menu.performKeyEquivalent(with: try Self.key(code, key, key, .command)))
            }
        }
        #expect(spy.log.log.isEmpty, "the password field refuses Cut and Copy: \(spy.log.log)")
        #expect(unlock.password.count == 19 && editor.string.count == 19)
        screen.window.makeFirstResponder(nil)
    }

    @Test("APP-08.8 LD-219: Mask User Names hides the editor's Passkey row and the History sheet's user name")
    func maskEditorAndHistory() async throws {
        let window = try ParityDemo.window("e5s11-mask-editor")
        defer { window.lockAll() }
        defer { window.view.set("display.hide_usernames", false, window.session) }
        let main = try #require(window.main)
        main.edit(try #require(main.rows.first { $0.title == "GitHub" }?.id))
        let screen = Screen(window)
        await screen.settle()
        let hits = { (name: String) in
            AccessWalk.check(screen.host, screen: name, secrets: ["alex-dev"]).filter { $0.what.contains("secret") }
        }
        #expect(screen.strings().contains("github.com · alex-dev"), "off: the editor's Passkey row reads it")
        window.view.set("display.hide_usernames", true, window.session)
        await screen.settle()
        // APP-01.23's editor rule: its Username field stays in clear; nothing else.
        let field = ["AXTextField"]
        #expect(hits("masked editor").map(\.role) == field, "\(hits("masked editor"))")
        #expect(screen.strings().contains("github.com, hidden"), "the Passkey row reads the site, then hidden")
        main.dialog = .version(index: 2, try main.session.showVersion(vault: main.vault.id, index: 2))
        await screen.settle()
        // The sheet is modal: the walk reads it alone.
        #expect(hits("masked history").isEmpty, "\(hits("masked history"))")
        window.view.set("display.hide_usernames", false, window.session)
        await screen.settle()
        #expect(hits("history").map(\.role) == ["AXStaticText"], "off: the sheet reads it: \(hits("history"))")
    }

    @Test("APP-08.8 LD-219: the Wi-Fi join pop-up holds no network name, masked or not (FEA-10.11)")
    func maskWifiQrTitle() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let window = try ParityDemo.window("e5s11-mask-wifi")
        defer { window.lockAll() }
        defer { window.view.set("display.hide_usernames", false, window.session) }
        let main = try #require(window.main)
        main.select(try #require(main.rows.first { $0.title == "Home Wi-Fi" }?.id))
        main.showWifiJoin()
        let screen = Screen(window)
        await screen.settle()
        let network = "Morgan-Home 5G"
        #expect(screen.strings().contains(QrText.title))
        #expect(AccessWalk.check(screen.host, screen: "Wi-Fi join", secrets: [network]).isEmpty)
        window.view.set("display.hide_usernames", true, window.session)
        await screen.settle()
        #expect(AccessWalk.check(screen.host, screen: "masked Wi-Fi join", secrets: [network]).isEmpty)
    }
}

/// The test process's NSApp answers `keyWindow` and `mainWindow` with two
/// offscreen windows that are never shown or made key (AGENTS.md rule 10),
/// through a test subclass of this one instance until `detach()`.
@MainActor
private final class FrontWindows {
    private let base: AnyClass
    private static var made = 0

    init?(key: NSWindow, main: NSWindow) {
        let app = NSApplication.shared
        guard let base = object_getClass(app) else { return nil }
        Self.made += 1
        guard let front = objc_allocateClassPair(base, "E5S11FrontWindows\(Self.made)", 0) else { return nil }
        for (getter, window) in [
            (#selector(getter: NSApplication.keyWindow), key), (#selector(getter: NSApplication.mainWindow), main),
        ] {
            let answer: @convention(block) (NSApplication) -> NSWindow? = { [weak window] _ in window }
            class_addMethod(front, getter, imp_implementationWithBlock(answer), "@@:")
        }
        objc_registerClassPair(front)
        object_setClass(app, front)
        self.base = base
    }

    func detach() { object_setClass(NSApplication.shared, base) }
}
