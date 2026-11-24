import AppKit
import LarsalCore
import SwiftUI
import Testing

/// The project root, from this file's place in macos/LarsalTests.
private let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appending(path: "../..")
    .standardizedFileURL

/// The Option A demo vaults (testdata/README.md), copied under their
/// mockup names so the screens read "Personal", "Work" and "Family".
private enum Demo {
    static let vaults = [
        ("option-a-personal.larsalvault", "Personal.larsalvault", "demo-pass-7"),
        ("option-a-work.larsalvault", "Work.larsalvault", "demo-pass-8"),
        ("option-a-family.larsalvault", "Family.larsalvault", "demo-pass-9"),
    ]

    /// target/option-a/Passwords/<name>.larsalvault, fresh from testdata/.
    static func path(_ index: Int) throws -> String {
        let folder = root.appending(path: "target/option-a/Passwords")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let (source, name, _) = vaults[index]
        let target = folder.appending(path: name)
        try? FileManager.default.removeItem(at: target)
        try FileManager.default.copyItem(at: root.appending(path: "testdata/" + source), to: target)
        return target.path(percentEncoded: false)
    }

    /// The mockup's "now": 2026-10-27 10:30 in Central European time.
    static let now = Date(timeIntervalSince1970: 1_793_093_400)
}

/// Every frame of design/option-a/manifest.json that E5-S3, E5-S4 and E6-S1
/// build.
enum Frame: String, CaseIterable, CustomTestStringConvertible {
    case lockTouchID = "lock-locked-touch-id"
    case lockPassword = "lock-locked-password-key-file-security-key"
    case lockSwitcher = "lock-locked-vault-switcher"
    case welcome = "lock-welcome"
    case mainLight = "main-main-window-light"
    case mainDark = "main-main-window-dark"
    case attention = "states-needs-attention"
    case card = "states-card"
    case server = "states-server-with-ssh-key"
    case wifi = "states-wi-fi"
    case favorites = "states-favorites-tags-open"
    case tips = "states-search-tips"
    case noResult = "states-search-with-no-result"
    case more = "states-more-menu"
    case switcher = "states-vault-switcher"
    case sort = "states-sort-menu"
    case bin = "states-recycle-bin"
    case copied = "states-copied"
    case empty = "states-new-empty-vault"

    var testDescription: String { rawValue }
    var size: CGSize { self == .welcome ? CGSize(width: 860, height: 540) : CGSize(width: 1320, height: 820) }
    /// The two main window frames keep their own theme in both sets, as in
    /// the mockup (`theme: 'light'`, `theme: 'dark'`).
    var fixedTheme: NSAppearance.Name? {
        switch self {
        case .mainLight: .aqua
        case .mainDark: .darkAqua
        default: nil
        }
    }
}

@MainActor
@Suite(.serialized)
struct SnapshotTests {
    init() {
        Fonts.register()
        Clock.now = { Demo.now }
    }

    @Test("Option A frame, offscreen, light and dark", arguments: Frame.allCases)
    func frame(_ frame: Frame) async throws {
        let window = try await state(frame)
        let size = NSRect(origin: .zero, size: frame.size)
        let host = NSHostingView(rootView: MainWindow(model: window).frame(width: size.width, height: size.height))
        host.frame = size
        // Never ordered front: it only gives the view a backing store
        // (AGENTS.md rule 10).
        let offscreen = NSWindow(
            contentRect: size.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless], backing: .buffered,
            defer: false
        )
        // The reference images are sRGB, whatever the Mac's screen uses.
        offscreen.colorSpace = .sRGB
        offscreen.contentView = host
        for (folder, look) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            offscreen.appearance = NSAppearance(named: frame.fixedTheme ?? look)
            // The notice lasts 2.6 s: each theme gets a fresh copy (private
            // pasteboard of `Session()`, never the user's clipboard).
            if frame == .copied { window.main?.copy("Password") }
            let png = try await render(host)
            let out = ParityDemo.shotsDirectory.appending(path: "\(folder)/\(frame.rawValue).png")
            try FileManager.default.createDirectory(
                at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
            try png.write(to: out)
            #expect(png.count > 10_000, "\(out.path)")
            try accessibilityTree(host).write(to: out.deletingPathExtension().appendingPathExtension("ax.json"))
        }
        offscreen.contentView = nil
        window.lockAll()
    }

    /// The session and the screen state of `frame` (mockup.js `SECTIONS`).
    private func state(_ frame: Frame) async throws -> MainWindowModel {
        let session = try ParityDemo.session()
        let window = MainWindowModel(session: session)
        if frame == .welcome {
            for index in 0..<3 {
                let path = try Demo.path(index)
                window.recents.append(
                    .init(look: vaultLook(path: path), path: path, opened: Demo.now - [0, 86_400, 9 * 86_400][index])
                )
            }
            return window
        }
        var ids: [UInt64] = []
        for index in 0..<3 {
            ids.append(try session.open(path: try Demo.path(index)))
        }
        let shown = frame == .empty ? 2 : 0
        #expect(try session.unlock(vault: ids[shown], password: Demo.vaults[shown].2, keyFile: nil) == .unlocked)
        try session.switchTo(vault: ids[shown])
        if frame.rawValue.hasPrefix("lock-") {
            // Locked in this session, so the footer has its time.
            try session.lock(vault: ids[shown])
        }
        window.refresh()
        if let unlock = window.unlock {
            try await lockState(frame, unlock, window)
        } else if let main = window.main {
            let offset = Int32(TimeZone.current.secondsFromGMT())
            var done = false
            while !done { done = try session.rate(vault: main.vault.id, max: 100, utcOffset: offset) }
            main.rated()
            mainState(frame, main, window)
            // Show runs off the screen thread (LD-199 notes).
            if frame == .server { await main.toggleShow("Password") }
            main.tick()
        }
        return window
    }

    private func lockState(_ frame: Frame, _ unlock: UnlockModel, _ window: MainWindowModel) async throws {
        switch frame {
        case .lockTouchID:
            unlock.touchForm = true
        case .lockPassword:
            unlock.keyFile = root.appending(path: "testdata/key-hex64.larsalkey").path(percentEncoded: false)
            unlock.password = "wrong-demo-password"
            unlock.unlock()
            for _ in 0..<400 where unlock.message == nil {
                try await Task.sleep(for: .milliseconds(25))
            }
            #expect(unlock.message?.id == "M06-06")
        case .lockSwitcher:
            window.vaultMenu = true
        default:
            break
        }
    }

    // One case per frame: a table, not logic.
    // swiftlint:disable:next cyclomatic_complexity
    private func mainState(_ frame: Frame, _ main: VaultModel, _ window: MainWindowModel) {
        let group = { (name: String) in main.sidebar?.groups.first { $0.name == name }?.id ?? "" }
        let select = { (title: String) in main.select(main.rows.first { $0.title == title }?.id) }
        switch frame {
        case .attention:
            main.chooseTab(.attention)
            select("Amazon")
        case .card:
            main.choose(.group(group("Banking")))
            select("Visa Debit")
        case .server:
            main.choose(.group(group("Servers")))
            select("Server root · web-01")
        case .wifi:
            main.choose(.group(group("Devices")))
            select("Home Wi-Fi")
        case .favorites:
            main.choose(.favorites)
            select("Proton Mail")
            main.tagsOpen = true
        case .tips: main.tips = true
        case .noResult: main.setSearch("dropbox")
        case .more: main.overlay = .more
        case .switcher: window.vaultMenu = true
        case .sort:
            main.setSort(.title)
            main.overlay = .sort
        case .bin:
            main.choose(.bin)
            select("Twitter (old account)")
        case .copied: main.copy("Password")
        default:
            break
        }
    }

    /// Design parity (Verify, 2026-10-28): the accessibility tree of the
    /// rendered view, written next to its snapshot as `<frame-id>.ax.json`,
    /// so the strings, names and boxes can be checked against manifest.json.
    /// Frames are points from the view's top-left corner. SwiftUI builds its
    /// nodes only while an assistive client is present; the process-local
    /// enhanced user interface flag stands in for one.
    func accessibilityTree(_ host: NSView) throws -> Data {
        // Left on: suites run side by side, and turning it off would drop
        // the nodes another test is reading. It is local to the test process.
        NSApplication.shared.setValue(true, forKey: "accessibilityEnhancedUserInterface")
        let window = host.window?.frame ?? .zero
        func node(_ any: Any, _ depth: Int) -> [String: Any]? {
            let element = any as AnyObject
            guard depth < 80, let box = element.accessibilityFrame?() else { return nil }
            var out: [String: Any] = [
                "role": element.accessibilityRole?()?.rawValue ?? "",
                "frame": [box.minX - window.minX, window.maxY - box.maxY, box.width, box.height],
            ]
            // Typed as Any: the String overload would bridge a checkbox's
            // NSNumber value and raise.
            let value: Any? = element.accessibilityValue?() ?? nil
            let texts: [(String, String?)] = [
                ("subrole", element.accessibilitySubrole?()?.rawValue),
                ("label", element.accessibilityLabel?() ?? nil), ("title", element.accessibilityTitle?() ?? nil),
                ("value", value.map { "\($0)" }),
                ("placeholder", element.accessibilityPlaceholderValue?() ?? nil),
                ("help", element.accessibilityHelp?() ?? nil),
                ("identifier", element.accessibilityIdentifier?()),
            ]
            for (key, text) in texts where !(text ?? "").isEmpty { out[key] = text }
            if element.isAccessibilityEnabled?() == false { out["disabled"] = true }
            if element.isAccessibilitySelected?() == true { out["selected"] = true }
            if element.isAccessibilityFocused?() == true { out["focused"] = true }
            let kids = (element.accessibilityChildren?() ?? []).compactMap { node($0, depth + 1) }
            if !kids.isEmpty { out["children"] = kids }
            return out
        }
        return try JSONSerialization.data(withJSONObject: node(host, 0) ?? [:], options: [.prettyPrinted, .sortedKeys])
    }

    /// Lays the view out, lets the screen settle, and returns a PNG of it.
    func render(_ host: NSView) async throws -> Data {
        host.layoutSubtreeIfNeeded()
        try await Task.sleep(for: .milliseconds(300))
        host.layoutSubtreeIfNeeded()
        let rep = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: rep)
        return try #require(rep.representation(using: .png, properties: [:]))
    }
}
