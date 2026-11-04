import AppCore
import AppKit
import SwiftUI
import Testing

// AT-K06 offscreen (APP-08.25, E5-S11): every built screen is rendered
// offscreen and its accessibility tree walked in the test process, as
// VoiceOver would read it. Every control must have a role and a name, sit
// inside the window or a list that scrolls to it, and be one the focus can
// reach (a control role macOS moves the focus to, never a bare clickable
// picture); a disabled one says so (APP-08.25). No value may show a hidden
// secret. Real VoiceOver listening and the Tab order on a key window are Mac
// QA with the owner's go (AGENTS.md rule 10).

/// One problem the walk found on a screen.
struct WalkFailure: CustomStringConvertible {
    let screen: String
    let role: String
    let what: String
    let frame: CGRect

    var description: String { "\(screen): \(role) at \(frame.integral): \(what)" }
}

@MainActor
enum AccessWalk {
    /// The roles of controls: what a keyboard user must reach and VoiceOver
    /// must name.
    static let controls: Set<String> = [
        "AXButton", "AXCheckBox", "AXRadioButton", "AXTextField", "AXTextArea", "AXPopUpButton", "AXMenuButton",
        "AXSlider", "AXLink", "AXDisclosureTriangle", "AXComboBox", "AXIncrementor", "AXMenuItem", "AXSearchField",
        "AXSegmentedControl", "AXColorWell", "AXDateField",
    ]

    /// Walks `host` and returns every unnamed, misplaced or unreachable
    /// control, and every value that holds `secrets`.
    static func check(_ host: NSView, screen: String, secrets: [String] = []) -> [WalkFailure] {
        NSApplication.shared.setValue(true, forKey: "accessibilityEnhancedUserInterface")
        UserDefaults.standard.setVolatileDomain(["AppleKeyboardUIMode": 2], forName: UserDefaults.argumentDomain)
        let window = host.window?.frame ?? .zero
        var out: [WalkFailure] = []
        let whole = CGRect(origin: .zero, size: window.size)
        func walk(_ any: Any, _ depth: Int, scrolled: Bool) {
            let element = any as AnyObject
            guard depth < 80 else { return }
            let role = element.accessibilityRole?()?.rawValue ?? ""
            let box = element.accessibilityFrame?() ?? .zero
            let frame = CGRect(
                x: box.minX - window.minX, y: window.maxY - box.maxY, width: box.width, height: box.height)
            let label = (element.accessibilityLabel?() ?? nil) ?? ""
            let title = (element.accessibilityTitle?() ?? nil) ?? ""
            let value: Any? = element.accessibilityValue?() ?? nil
            let text = [label, title, (value as? String) ?? ""]
            func fail(_ what: String) { out.append(WalkFailure(screen: screen, role: role, what: what, frame: frame)) }
            // F-135: not AppKit's own Caps Lock picture in a secure field.
            // AppKit draws it while the key is down and names it "caps lock
            // down"; App cannot change it, and App's own note is text (M06-37).
            let appKitCapsLock = role == "AXImage" && (element.accessibilityParent?() ?? nil) is NSSecureTextFieldCell
            for secret in secrets where text.contains(where: { $0.contains(secret) }) {
                fail("shows a hidden secret")
            }
            if controls.contains(role) {
                // A name VoiceOver can read: a glyph's private-use character
                // (U+E000 to U+F8FF) alone is no name.
                let readable = (label + title).unicodeScalars.contains {
                    !CharacterSet.whitespacesAndNewlines.contains($0) && !(0xE000...0xF8FF).contains($0.value)
                }
                if !readable { fail("no name") }
                // In the window, or in a list the keyboard scrolls to it.
                if frame.width < 1 || frame.height < 1 || !scrolled && !whole.insetBy(dx: -1, dy: -1).contains(frame) {
                    fail("outside the window (\(label))")
                }
                // The focus can move to it (Tab with keyboard navigation on,
                // VoiceOver's cursor).
                let focus = #selector(NSAccessibilityElement.setAccessibilityFocused(_:))
                if element.isAccessibilityEnabled?() != false, element.isAccessibilitySelectorAllowed?(focus) == false {
                    fail("the focus cannot reach it (\(label))")
                }
            } else if frame != whole, ["AXImage", "AXGroup", "AXStaticText"].contains(role), !appKitCapsLock {
                // A picture or group that acts on a click but is no control:
                // the keyboard and VoiceOver cannot use it.
                let press = #selector(NSAccessibilityButton.accessibilityPerformPress)
                if element.isAccessibilitySelectorAllowed?(press) == true {
                    fail("clickable but not a control (\(label))")
                }
            }
            for child in element.accessibilityChildren?() ?? [] {
                walk(child, depth + 1, scrolled: scrolled || role == "AXScrollArea")
            }
        }
        walk(host, 0, scrolled: false)
        return out
    }

    /// The first node, depth first, whose name `matches`.
    static func find(_ any: Any, _ matches: (String) -> Bool) -> AnyObject? {
        let element = any as AnyObject
        if matches((element.accessibilityLabel?() ?? nil) ?? "") { return element }
        for child in element.accessibilityChildren?() ?? [] {
            if let hit = find(child, matches) { return hit }
        }
        return nil
    }
}

@MainActor
@Suite(.serialized)
struct AccessibilityWalkTests {
    init() {
        ParityDemo.setUp()
    }

    /// The screen states the walk covers, each named as it reads.
    nonisolated static let screens = [
        "welcome", "unlock", "unlock vault switcher", "unlock typed, shown", "list and detail",
        "detail shown password", "editor", "editor pages", "more actions", "vault switcher", "sort menu", "search tips",
        "generator", "reports", "recycle bin", "dialog", "empty vault", "settings", "vault settings", "new vault",
        "totp setup", "search none", "empty tab", "preview",
    ]

    /// F-135: each screen with Caps Lock up and down, from the fake
    /// (`capsLockFake`), never the Mac's key.
    @Test("AT-K06: every control on every built screen is named and reachable", arguments: screens, [false, true])
    func walk(_ name: String, capsLock: Bool) async throws {
        let failures = try await Self.failures(name, capsLock: capsLock)
        #expect(failures.isEmpty, "\(failures.map(\.description).joined(separator: "\n"))")
    }

    @Test("F-135: AppKit's Caps Lock picture in a secure field is not App's clickable picture; others still are")
    func f135SecureFieldCapsLockPicture() {
        let frame = NSRect(x: -20_000, y: -20_000, width: 300, height: 80)
        // Never ordered front (AGENTS.md rule 10).
        let window = NSWindow(contentRect: frame, styleMask: [.borderless], backing: .buffered, defer: true)
        let root = PictureHost(frame: NSRect(origin: .zero, size: frame.size))
        root.pictures = [
            WalkPicture(under: root.secure, "caps lock down", at: frame.origin),
            WalkPicture(under: root.plain, "a picture", at: frame.origin),
        ]
        window.contentView = root
        defer { window.contentView = nil }
        let failures = AccessWalk.check(root, screen: "f135")
        #expect(failures.map(\.what) == ["clickable but not a control (a picture)"], "only the plain cell's")
    }

    /// Two pictures that take a press: one in a secure field's cell, as
    /// AppKit draws its Caps Lock picture, one in a plain field's cell.
    private final class PictureHost: NSView {
        let secure = NSSecureTextFieldCell()
        let plain = NSTextFieldCell()
        var pictures: [WalkPicture] = []
        override func accessibilityChildren() -> [Any]? { pictures }
    }

    @Test("AT-K06: the walk finds a password on screen once Show was chosen, and never before")
    func secretCheck() async throws {
        let window = try ParityDemo.window("walk-secret")
        defer { window.lockAll() }
        let main = try #require(window.main)
        main.select(main.rows.first { $0.title == "Google" }?.id)
        let id = try #require(main.selection)
        let secret = try window.session.showField(vault: main.vault.id, entry: id, field: "Password")
        let screen = Screen(window)
        await screen.settle()
        #expect(AccessWalk.check(screen.host, screen: "hidden", secrets: [secret]).isEmpty)
        await main.toggleShow("Password")
        await screen.settle()
        let shown = AccessWalk.check(screen.host, screen: "shown", secrets: [secret])
        #expect(shown.contains { $0.what == "shows a hidden secret" })
    }

    static func failures(_ name: String, capsLock: Bool) async throws -> [WalkFailure] {
        if ["settings", "vault settings", "new vault"].contains(name) {
            return try await windows(name, capsLock: capsLock)
        }
        if name == "welcome" {
            let screen = Screen(MainWindowModel(session: Session()), size: CGSize(width: 860, height: 540))
            fake(capsLock, screen)
            await screen.settle()
            return AccessWalk.check(screen.host, screen: name)
        }
        let locked = name.hasPrefix("unlock")
        let window = try ParityDemo.window("walk", unlocked: locked ? [] : [0], shown: name == "empty vault" ? 2 : 0)
        if name == "empty vault" {
            _ = try window.session.unlock(vault: window.vaults[2].id, password: ParityDemo.vaults[2].2, keyFile: nil)
            window.refresh()
        }
        defer { window.lockAll() }
        let screen = Screen(window)
        fake(capsLock, screen)
        var secrets: [String] = []
        if let main = window.main, !main.rows.isEmpty {
            main.select(main.rows.first { $0.title == "Google" }?.id)
            // The demo password, read from Rust here only to prove that no
            // node shows it while it is hidden (demo data, AGENTS.md rule 5).
            let id = try #require(main.selection)
            secrets = [try window.session.showField(vault: main.vault.id, entry: id, field: "Password")]
            try await state(name, main, window)
        } else if name == "unlock vault switcher" {
            window.vaultMenu = true
        } else if name == "unlock typed, shown", let unlock = window.unlock {
            // A typed demo password after Show (APP-03.19): the shown field
            // is named too.
            unlock.password = "demo-typed-pass-11"
            unlock.reveal = true
        }
        await screen.settle()
        if name == "detail shown password" { secrets = [] }
        var failures = AccessWalk.check(screen.host, screen: name, secrets: secrets)
        if name == "editor pages", let editor = window.main?.editor {
            for page in EditorModel.Page.allCases {
                editor.page = page
                await screen.settle()
                failures += AccessWalk.check(screen.host, screen: "editor \(page)", secrets: secrets)
            }
        }
        if name == "search none", let main = window.main { failures += pressClear(screen.host, main) }
        return failures + note(name, capsLock, screen)
    }

    /// F-135: the screen reads Caps Lock from `capsLockFake`, never the key.
    private static func fake(_ capsLock: Bool, _ screen: Screen) {
        screen.host.rootView = AnyView(screen.host.rootView.environment(\.capsLockFake, capsLock))
    }

    /// F-135: the focused unlock password shows App's note only when the
    /// fake says Caps Lock is down, whatever the Mac's key is.
    private static func note(_ name: String, _ capsLock: Bool, _ screen: Screen) -> [WalkFailure] {
        if name != "unlock" || screen.strings().contains(CapsLock.note) == capsLock { return [] }
        return [WalkFailure(screen: "unlock", role: "AXStaticText", what: "the note is not the fake's", frame: .zero)]
    }

    /// "search none": the "clear the search" text is a button VoiceOver can
    /// press, and the press clears the search.
    private static func pressClear(_ host: NSView, _ main: VaultModel) -> [WalkFailure] {
        let node = AccessWalk.find(host) { $0.hasPrefix("No entries match") }
        if node?.accessibilityPerformPress?() == true, !main.searching { return [] }
        return [WalkFailure(screen: "search none", role: "AXButton", what: "a press keeps the search", frame: .zero)]
    }

    /// App's other windows, every page: the settings, the vault settings
    /// and the new vault wizard's first step.
    private static func windows(_ name: String, capsLock: Bool) async throws -> [WalkFailure] {
        var failures: [WalkFailure] = []
        func walk(_ view: some View, _ size: CGSize, _ page: String) async {
            let host = NSHostingView(
                rootView: AnyView(
                    view.environment(\.capsLockFake, capsLock).frame(width: size.width, height: size.height)))
            host.frame = NSRect(origin: .zero, size: size)
            // Never ordered front (AGENTS.md rule 10).
            let window = NSWindow(
                contentRect: NSRect(origin: CGPoint(x: -20_000, y: -20_000), size: size), styleMask: [.borderless],
                backing: .buffered, defer: false)
            window.contentView = host
            host.layoutSubtreeIfNeeded()
            try? await Task.sleep(for: .milliseconds(150))
            failures += AccessWalk.check(host, screen: page)
            window.contentView = nil
        }
        switch name {
        case "settings":
            let model = settingsModel()
            for page in AppSettingsPage.allCases {
                model.go(page)
                await walk(AppSettingsView(model: model), CGSize(width: 900, height: 680), "settings \(page)")
            }
        case "vault settings":
            let (window, model) = try SettingsDemo.model("walk-vault-settings")
            for page in VaultSettingsModel.Page.allCases {
                model.page = page
                await walk(VaultSettingsWindow(model: model), CGSize(width: 900, height: 640), "vault \(page)")
            }
            window.lockAll()
        default:
            await walk(NewVaultView(model: NewVaultModel(session: Session())), CGSize(width: 720, height: 720), name)
        }
        return failures
    }

    // One case per screen: a table, not logic.
    // swiftlint:disable:next cyclomatic_complexity
    private static func state(_ name: String, _ main: VaultModel, _ window: MainWindowModel) async throws {
        switch name {
        case "detail shown password": await main.toggleShow("Password")
        case "editor", "editor pages": main.edit()
        case "more actions": main.overlay = .more
        case "vault switcher": window.vaultMenu = true
        case "sort menu": main.overlay = .sort
        case "search tips": main.tips = true
        case "generator": main.toggleGenerator()
        case "reports": main.openReports()
        case "recycle bin":
            main.choose(.bin)
            main.select(main.rows.first?.id)
        case "dialog": main.dialog = .newGroup(name: "")
        case "totp setup":
            // An entry with no code in the editor, then "Add one-time code…"
            // (EditorEntryPage `setup`).
            main.edit(main.rows.first { $0.title == "Amazon" }?.id)
            main.dialog = .totpSetup(try window.session.totpSetup(vault: main.vault.id))
        case "search none": main.setSearch("zzzz-none")
        case "empty tab":
            // A list with no row and no search: its text is no button.
            main.choose(.favorites)
            main.chooseTab(.attention)
        case "preview":
            // MOD-05.9 (LD-239 (2)): a text long enough to scroll, with the
            // preview's Open, Save… and Done.
            let text = (1...80).map { "demo line \($0)" }.joined(separator: "\n")
            main.dialog = .preview(name: "notes.txt", .text(text: text))
        default: break
        }
    }
}

/// F-135: a picture that takes a press, as AppKit's Caps Lock picture does
/// (role image, the press allowed), whose parent is `cell`.
nonisolated private final class WalkPicture: NSAccessibilityElement {
    private let label: String

    init(under cell: NSCell, _ label: String, at origin: CGPoint) {
        self.label = label
        super.init()
        setAccessibilityParent(cell)
        setAccessibilityFrame(NSRect(x: origin.x + 20, y: origin.y + 20, width: 16, height: 16))
    }

    override func accessibilityRole() -> NSAccessibility.Role? { .image }
    override func accessibilityLabel() -> String? { label }
    override func accessibilityPerformPress() -> Bool { true }
    override func isAccessibilitySelectorAllowed(_ selector: Selector) -> Bool { true }
}
