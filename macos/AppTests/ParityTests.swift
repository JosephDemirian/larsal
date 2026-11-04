import AppCore
import AppKit
import SwiftUI
import Testing

// Design parity (Verify, 2026-10-28), check 6: the controls that the Option A
// mockup makes clickable do the same in the app. The real views render
// offscreen (never ordered front, AGENTS.md rule 10) and each control is
// pressed through the accessibility tree, as VoiceOver would. Controls that
// would leave the window (the open panel, the browser) are checked for being
// enabled but not pressed. Each test name starts "Parity <frame-id>:" so the
// parity report can cite it (design/parity/<section>/).

/// The demo vaults of testdata/README.md under their mockup names, copied
/// into a folder per suite (SnapshotTests uses target/option-a/Passwords).
@MainActor
enum ParityDemo {
    static let vaults = [
        ("option-a-personal.appvault", "Personal", "demo-pass-7"),
        ("option-a-work.appvault", "Work", "demo-pass-8"),
        ("option-a-family.appvault", "Family", "demo-pass-9"),
    ]
    static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appending(path: "../..")
        .standardizedFileURL

    static func setUp() {
        Fonts.register()
        // Never the owner's screen: attachment Open goes to a fake that
        // only records (the same one for every suite running side by side).
        FileOpener.open = { url in
            FakeOpener.opened.append(url)
            return true
        }
        Clock.now = { Date(timeIntervalSince1970: 1_793_093_400) }
    }

    static func path(_ index: Int, folder: String) throws -> String {
        let place = root.appending(path: "target/option-a/" + folder)
        try FileManager.default.createDirectory(at: place, withIntermediateDirectories: true)
        let (source, name, _) = vaults[index]
        let target = place.appending(path: name + ".appvault")
        try? FileManager.default.removeItem(at: target)
        try FileManager.default.copyItem(at: root.appending(path: "testdata/" + source), to: target)
        return target.path(percentEncoded: false)
    }

    /// A test session with the expiry notice off (S-START-11), so a first
    /// unlock of Personal (Zalando expired) shows All entries as the mockup
    /// draws it; the notice's own tests are in WindowFixesTests (F-077).
    static func session() throws -> Session {
        let session = Session()
        try session.saveSettings(changes: [AppSetting(key: "expiry.notice_on_unlock", value: .flag(on: false))])
        return session
    }

    /// The three demo vaults open; `unlocked` of them unlocked; `shown` shown.
    static func window(_ folder: String, unlocked: [Int] = [0], shown: Int = 0) throws -> MainWindowModel {
        let session = try Self.session()
        var ids: [UInt64] = []
        for index in 0..<3 { ids.append(try session.open(path: try path(index, folder: folder))) }
        for index in unlocked {
            #expect(try session.unlock(vault: ids[index], password: vaults[index].2, keyFile: nil) == .unlocked)
        }
        try session.switchTo(vault: ids[shown])
        let window = MainWindowModel(session: session)
        window.refresh()
        return window
    }

    /// Rates every password, as the main window does off the screen thread.
    static func rate(_ model: MainWindowModel) throws {
        let main = try #require(model.main)
        var done = false
        while !done { done = try model.session.rate(vault: main.vault.id, max: 100, utcOffset: 3600) }
        main.rated()
    }
}

@MainActor
@Suite(.serialized)
struct ParityLockTests {
    init() { ParityDemo.setUp() }

    @Test("Parity lock-locked-touch-id: Use password instead shows the password form; Touch ID waits for E6-S3")
    func touchID() async throws {
        let model = try ParityDemo.window("parity-lock", unlocked: [])
        let unlock = try #require(model.unlock)
        unlock.touchForm = true
        let screen = Screen(model)
        await screen.settle()
        #expect(screen.node("Unlock with Touch ID")?.isAccessibilityEnabled?() == false)
        try await screen.press("Use password instead")
        #expect(!unlock.touchForm)
        #expect(screen.node("Unlock") != nil, "the password form shows")
    }

    @Test("Parity lock-locked-password-key-file-security-key: Show password and Hide password switch")
    func revealPassword() async throws {
        let model = try ParityDemo.window("parity-lock", unlocked: [])
        let unlock = try #require(model.unlock)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Show password")
        #expect(unlock.reveal)
        try await screen.press("Hide password")
        #expect(!unlock.reveal)
    }

    @Test("Parity lock-locked-password-key-file-security-key: a wrong password shows M06-06, field cleared")
    func wrongPassword() async throws {
        let model = try ParityDemo.window("parity-lock", unlocked: [])
        let unlock = try #require(model.unlock)
        let screen = Screen(model)
        unlock.password = "wrong-demo-password"
        await screen.settle()
        try await screen.press("Unlock")
        try await screen.wait { unlock.message != nil }
        await screen.settle()
        #expect(unlock.message?.id == "M06-06")
        #expect(unlock.password.isEmpty)
        #expect(screen.strings().contains { $0.hasPrefix("Wrong password, key file or security key.") })
    }

    @Test("Parity lock-locked-password-key-file-security-key: the demo password opens the vault")
    func rightPassword() async throws {
        let model = try ParityDemo.window("parity-lock", unlocked: [])
        let unlock = try #require(model.unlock)
        let screen = Screen(model)
        unlock.password = "demo-pass-7"
        await screen.settle()
        try await screen.press("Unlock")
        try await screen.wait { model.main != nil }
        #expect(model.main?.vault.name == "Personal")
    }

    @Test("Parity lock-locked-password-key-file-security-key: Browse… and the security key enabled; Touch ID disabled")
    func laterControls() async throws {
        let model = try ParityDemo.window("parity-lock", unlocked: [])
        let screen = Screen(model)
        await screen.settle()
        // Browse… opens the Mac file panel, a window of its own: not pressed.
        #expect(screen.node("Key file")?.isAccessibilityEnabled?() == true)
        // F-107: the security key switch works (the test run reaches no USB key).
        #expect(screen.node("Use a security key")?.isAccessibilityEnabled?() == true)
        #expect(screen.node("Use Touch ID")?.isAccessibilityEnabled?() == false)
    }

    // Escape and a click outside close the menus (MenuLayer: onExitCommand,
    // onTapGesture); neither reaches an offscreen window that is not key, so
    // they wait for Mac QA.
    @Test("Parity lock-locked-vault-switcher: Switch vault opens the vault menu; Work in the menu shows Work")
    func lockSwitcher() async throws {
        let model = try ParityDemo.window("parity-lock", unlocked: [])
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Switch vault")
        #expect(model.vaultMenu && screen.node("Open vaults") != nil)
        try await screen.press("Work")
        #expect(model.shown?.name == "Work" && !model.vaultMenu)
    }

    @Test("Parity lock-welcome: a recent vault opens; Open vault… enabled; New vault opens the wizard; Import… waits")
    func welcome() async throws {
        let model = MainWindowModel(session: Session())
        let path = try ParityDemo.path(0, folder: "parity-lock")
        model.recents.append(.init(look: vaultLook(path: path), path: path, opened: Clock.now()))
        let screen = Screen(model, size: CGSize(width: 860, height: 540))
        await screen.settle()
        #expect(screen.node("Open vault…")?.isAccessibilityEnabled?() == true)
        // E5-S8: New vault opens the wizard in its own window, never shown
        // by a test (AGENTS.md rule 10).
        AuxWindows.present = { _ in }
        try await screen.press("New vault")
        #expect(AuxWindows.wizard != nil)
        AuxWindows.wizard?.model.cancel()
        #expect(AuxWindows.wizard == nil)
        #expect(screen.node("Import…")?.isAccessibilityEnabled?() == false)
        try await screen.press("Personal")
        // The open reads the file off the main thread (APP-05.24).
        for _ in 0..<400 where model.unlock == nil { try await Task.sleep(for: .milliseconds(25)) }
        #expect(model.unlock?.vault.name == "Personal")
    }
}

@MainActor
@Suite(.serialized)
struct ParityMainTests {
    init() { ParityDemo.setUp() }

    @Test("Parity main-main-window-light: sidebar items, tabs and rows select; the detail follows")
    func selecting() async throws {
        let model = try ParityDemo.window("parity-main")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Favorites")
        #expect(main.place == .favorites && main.title == "Favorites")
        try await screen.press("All entries")
        try await screen.press("Two-step codes")
        #expect(main.tab == .codes && main.rows.allSatisfy(\.hasTotp))
        try await screen.press("All")
        try await screen.press("Google")
        #expect(main.detail?.title == "Google")
        #expect(screen.node("Google", role: "AXHeading") != nil)
    }

    @Test("Parity main-main-window-light: Show password reveals the password and Hide password hides it")
    func reveal() async throws {
        let model = try ParityDemo.window("parity-main")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Show password")
        try await screen.wait { main.shown["Password"] != nil }
        await screen.settle()
        #expect(main.shown["Password"]?.isEmpty == false)
        try await screen.press("Hide password")
        #expect(main.shown.isEmpty)
    }

    @Test("Parity main-main-window-light: More actions opens the entry menu")
    func moreMenu() async throws {
        let model = try ParityDemo.window("parity-main")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("More actions")
        #expect(main.overlay == .more)
        #expect(screen.node("Clone Entry…") != nil)
    }

    @Test("Parity main-main-window-light: the sort menu sorts by title and the month headers go away")
    func sortMenu() async throws {
        let model = try ParityDemo.window("parity-main")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Sort by Modified")
        #expect(main.overlay == .sort)
        try await screen.press("Title")
        #expect(main.sort == .title && main.overlay == nil && main.sections.allSatisfy { $0.title == nil })
        #expect(main.rows.first?.title == "Amazon")
    }

    @Test("Parity main-main-window-light: Tags opens the tag list; Hide sidebar hides it; Lock locks the vault")
    func chrome() async throws {
        let model = try ParityDemo.window("parity-main")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Tags")
        #expect(main.tagsOpen)
        try await screen.press("2fa")
        #expect(main.place == .tag("2fa"))
        try await screen.press("Hide sidebar (⌃⌘S)")
        #expect(screen.node("Sidebar") == nil && screen.node("Show sidebar (⌃⌘S)") != nil)
        try await screen.press("Show sidebar (⌃⌘S)")
        try await screen.press("Lock")
        #expect(model.unlock?.vault.name == "Personal" && model.main == nil)
    }

    @Test("Parity main-main-window-light: later-story controls are drawn and disabled")
    func laterMain() async throws {
        let model = try ParityDemo.window("parity-main")
        let screen = Screen(model)
        await screen.settle()
        for name in ["Type login"] {
            #expect(screen.node(name)?.isAccessibilityEnabled?() == false, "\(name)")
        }
        // The editor works since E5-S5 (ParityEditorTests), the generator
        // since E5-S6 (ParityGeneratorTests).
        for name in ["Edit entry (⌘E)", "New Entry", "Generator"] {
            #expect(screen.node(name)?.isAccessibilityEnabled?() == true, "\(name)")
        }
        // Copy works since E6-S1 (states-copied); Open site and the link
        // open the browser: enabled, not pressed.
        for name in ["Copy password", "Copy username", "Copy one-time code", "Open site"] {
            #expect(screen.node(name)?.isAccessibilityEnabled?() == true, "\(name)")
        }
    }
}

/// The real main window view, offscreen, read and pressed through the
/// accessibility tree.
@MainActor
final class Screen {
    let host: NSHostingView<AnyView>
    let window: NSWindow

    init(_ model: MainWindowModel, size: CGSize = CGSize(width: 1320, height: 820)) {
        host = NSHostingView(rootView: AnyView(MainWindow(model: model).frame(width: size.width, height: size.height)))
        host.frame = NSRect(origin: .zero, size: size)
        window = NSWindow(
            contentRect: NSRect(origin: CGPoint(x: -20_000, y: -20_000), size: size), styleMask: [.borderless],
            backing: .buffered, defer: false
        )
        // The reference images are sRGB, whatever the Mac's screen uses.
        window.colorSpace = .sRGB
        window.contentView = host
        // SwiftUI builds its accessibility nodes only while an assistive
        // client is present; this process-local flag stands in for one. It
        // stays on: suites run side by side (SnapshotTests sets it too).
        NSApplication.shared.setValue(true, forKey: "accessibilityEnhancedUserInterface")
    }

    isolated deinit {
        window.contentView = nil
    }

    func settle() async {
        host.layoutSubtreeIfNeeded()
        try? await Task.sleep(for: .milliseconds(150))
        host.layoutSubtreeIfNeeded()
    }

    func wait(_ done: () -> Bool) async throws {
        for _ in 0..<400 where !done() { try await Task.sleep(for: .milliseconds(25)) }
    }

    /// An element's frame in points from the view's top-left corner.
    func box(_ element: AnyObject) -> CGRect {
        let frame = element.accessibilityFrame?() ?? .zero
        let origin = window.frame
        return CGRect(
            x: frame.minX - origin.minX, y: origin.maxY - frame.maxY, width: frame.width, height: frame.height)
    }

    func nodes() -> [AnyObject] {
        var out: [AnyObject] = []
        func walk(_ any: Any, _ depth: Int) {
            let element = any as AnyObject
            guard depth < 80 else { return }
            out.append(element)
            for child in element.accessibilityChildren?() ?? [] { walk(child, depth + 1) }
        }
        walk(host, 0)
        return out
    }

    /// The first element whose label (or its first part before ", ") is
    /// `name`.
    func node(_ name: String, role: String? = nil) -> AnyObject? {
        nodes().first { element in
            let label = (element.accessibilityLabel?() ?? nil) ?? ""
            let matches = label == name || label.hasPrefix(name + ", ")
            return matches && (role == nil || element.accessibilityRole?()?.rawValue == role)
        }
    }

    /// Every label and text value on screen.
    func strings() -> [String] {
        nodes().flatMap { element -> [String] in
            let value: Any? = element.accessibilityValue?() ?? nil
            return [(element.accessibilityLabel?() ?? nil) ?? "", (value as? String) ?? ""].filter { !$0.isEmpty }
        }
    }

    /// Types `text` into the text field named `name`, as its field editor
    /// would: the value changes and the field tells its delegate.
    func type(_ text: String, into name: String) async throws {
        let element = try #require(node(name), "\(name) is on screen")
        let field = try #require((element as? NSCell)?.controlView as? NSTextField ?? element as? NSTextField)
        let editor = NSTextView()
        editor.string = text
        field.stringValue = text
        NotificationCenter.default.post(
            name: NSControl.textDidChangeNotification, object: field, userInfo: ["NSFieldEditor": editor])
        await settle()
    }

    func press(_ name: String) async throws {
        let element = try #require(node(name), "\(name) is on screen")
        #expect(element.isAccessibilityEnabled?() != false, "\(name) is enabled")
        #expect(element.accessibilityPerformPress?() == true, "\(name) takes a press")
        await settle()
    }
}
