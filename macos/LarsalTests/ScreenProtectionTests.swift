import AppKit
import LarsalCore
import QuartzCore
import SwiftUI
import Testing

/// SC-05, AT-D04, card APP-10.1 to APP-10.7 (E6-S5). Windows are made
/// offscreen and never ordered in (AGENTS.md rule 10). Each test has its own
/// `ScreenProtection` over its own windows, so none changes another's; real
/// capture attempts are Mac QA (V-A10-1).
@MainActor
struct ScreenProtectionTests {
    /// How protection reaches a kind of window.
    enum Way {
        /// `ScreenProtection.window(_:style:)` or `alert()`: at creation.
        case made
        /// The main window SwiftUI makes: `WindowChromeView` adopts it as
        /// its content moves in.
        case chrome
        /// A window subclass Larsal sets up in `file`: adopted before it is
        /// ordered in.
        case adoptedBeforeShown(file: String)
        /// Made by AppKit or SwiftUI for Larsal: each run loop pass, and the
        /// sheet and popover notices.
        case swept(@MainActor () -> NSWindow)
    }

    struct Kind {
        let name: String
        /// The source text (a regular expression) that makes this kind;
        /// `nil` for one AppKit makes with no source of Larsal's (About).
        let marker: String?
        /// Where it may be; `nil`: any file.
        let files: Set<String>?
        let way: Way
    }

    static let frame = NSRect(x: 0, y: 0, width: 240, height: 120)
    /// A window as AppKit or SwiftUI makes one. Deferred: in the test
    /// process (not a launched app) the window server keeps a window that
    /// has its device at "none" when it is set back to "read only" (seen on
    /// this Mac, 2026-10-28); the real app's toggle is Mac QA (APP-10.4-a).
    static func raw() -> NSWindow {
        NSWindow(contentRect: frame, styleMask: [.titled], backing: .buffered, defer: true)
    }
    static func panel() -> NSWindow {
        NSPanel(contentRect: frame, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: true)
    }

    /// Every kind of window Larsal can show (APP-10.3). Source that makes a
    /// window in a way not listed fails `listIsComplete`: add its kind here
    /// with the way protection reaches it.
    static let kinds: [Kind] = [
        Kind(name: "Main window (SwiftUI scene)", marker: #"\bWindow\("#, files: ["LarsalMain.swift"], way: .chrome),
        Kind(
            name: "Window constructors", marker: #"\bNS(Window|Panel|Alert)(\.init)?\("#,
            files: ["ScreenProtection.swift"],
            way: .made),
        Kind(
            name: "Settings, New Vault, Vault Settings, debug snapshot",
            marker: #"ScreenProtection\.shared\.window\("#,
            files: ["LarsalSettingsWindow.swift", "AuxWindows.swift", "Snapshot.swift"], way: .made),
        Kind(
            name: "Alerts Larsal runs (M09-06, MI05-10, MI05-30, MSG-08-2)",
            marker: #"ScreenProtection\.shared\.alert\(\)"#,
            files: ["main.swift", "AutoType.swift", "AutoTypeTyping.swift", "OpenURL.swift"], way: .made),
        Kind(
            name: "Window subclasses (the Auto-Type picker and unlock panels)",
            marker: #"contentRect:|\bclass\s+\w+\s*:\s*NS(Window|Panel)\b"#,
            files: ["ScreenProtection.swift", "AutoTypePicker.swift"],
            way: .adoptedBeforeShown(file: "AutoTypePicker.swift")),
        Kind(name: "Popovers", marker: #"\.popover\("#, files: nil, way: .swept(panel)),
        Kind(
            name: "SwiftUI alerts (a sheet)", marker: #"(?<!shared)\.alert\("#, files: nil,
            way: .swept({ NSAlert().window })),
        Kind(name: "Open and save panels", marker: #"\bNS(Open|Save)Panel\("#, files: nil, way: .swept(panel)),
        Kind(
            name: "Menus Larsal builds (menu bar, pop-up menus, pickers, calendars)",
            marker: #"\bNS(Hosting)?Menu\(|\.contextMenu\b|\bMenu\s*[({]|\bCommand(Menu|Group)\(|\b(Date)?Picker\("#,
            files: nil, way: .swept(panel)),
        Kind(name: "Tooltips", marker: #"\.help\(|toolTip"#, files: nil, way: .swept(panel)),
        Kind(
            name: "Share picker (only with a proved route, FEA-10.18)", marker: #"\bNSSharingServicePicker\("#,
            files: ["QrWiring.swift"], way: .swept(panel)),
        Kind(name: "Menu bar icon", marker: #"\bNSStatusBar\b"#, files: nil, way: .swept(raw)),
        Kind(name: "About panel (the Larsal menu's default About)", marker: nil, files: nil, way: .swept(panel)),
    ]

    /// Ways to make a window that no kind covers yet: one appearing fails.
    static let unlisted = [
        #"\bWindowGroup\b"#, #"(?m)^\s*Settings\s*\{"#, #"\bMenuBarExtra\b"#, #"\bDocumentGroup\b"#,
        #"\bUtilityWindow\b"#,
        #"\.sheet\("#, #"\.confirmationDialog\("#, #"\.fileImporter\("#, #"\.fileExporter\("#, #"\.inspector\("#,
        #"\bNSPopover(\.init)?\("#, #"contentViewController:"#, #"beginSheet"#,
        #"NS(Color|Font)Panel"#,
        #"orderFrontStandardAboutPanel"#, #"\bNSDrawer\b"#, #"\bNSWindowController\b"#, #"\bColorPicker\b"#,
        #"\bShareLink\b"#, #"\bNS(Print(Operation|Panel)|PageLayout)\b"#, #"\.fileMover\("#,
    ]

    @Test("APP-10.3, AT-D04: the window list is complete; every window Larsal makes is made or adopted as listed")
    func listIsComplete() throws {
        let sources = try Self.sources()
        #expect(sources.count > 50, "Larsal's sources found")
        for (file, code) in sources {
            for problem in Self.problems(file, code) { Issue.record("\(problem)") }
        }
        // Each listed file still makes its kind.
        for kind in Self.kinds {
            guard let marker = kind.marker, let files = kind.files else { continue }
            for file in files {
                let code = sources.first { $0.file == file }?.code ?? ""
                #expect(Self.found(marker, in: code), "\(file) no longer matches \(kind.name)")
            }
        }
    }

    @Test(
        "APP-10.1, APP-10.5: the launch starts protection with Rust's F07 before any window, with M10-01 in the banner")
    func startedAtLaunch() throws {
        let code = try #require(try Self.sources().first { $0.file == "AppDelegate.swift" }?.code)
        let after = try #require(code.components(separatedBy: "func applicationWillFinishLaunching").dropFirst().first)
        let launch = after.components(separatedBy: "\n    func ").first ?? ""
        #expect(launch.contains("ScreenProtection.shared.start(allowCapture: allowsScreenCapture())"))
        #expect(launch.contains("ScreenProtection.shared.refused = "))
        #expect(launch.contains("banner = ScreenProtection.refusedText"))
    }

    @Test("APP-10.1, APP-10.3, AT-D04: every kind of window in the list is protected, and read only when allowed")
    func everyKindIsProtected() throws {
        for kind in Self.kinds {
            for allowed in [false, true] {
                let protection = ScreenProtection()
                protection.allow(allowed)
                let wanted: NSWindow.SharingType = allowed ? .readOnly : .none
                switch kind.way {
                case .made:
                    #expect(protection.window(Self.frame, style: [.titled]).sharingType == wanted, "\(kind.name)")
                    #expect(protection.alert().window.sharingType == wanted, "\(kind.name)")
                case .chrome:
                    // WindowChromeView adopts for the shared protection.
                    guard !allowed else { continue }
                    #expect(try Self.firstFrame(Self.raw(), chrome: true) == NSWindow.SharingType.none, "\(kind.name)")
                case .adoptedBeforeShown(let file):
                    let code = try #require(try Self.sources().first { $0.file == file }?.code)
                    let shows = Self.shows(code)
                    #expect(!shows.isEmpty, "\(file) shows")
                    for show in shows where !show.adopted {
                        Issue.record("\(kind.name): \(file) shows \(show.window) before adopting it")
                    }
                case .swept(let make):
                    let window = make()
                    #expect(window.sharingType == .readOnly, "made by AppKit, not yet protected")
                    protection.windows = { [window] }
                    protection.sweep()
                    #expect(window.sharingType == wanted, "\(kind.name)")
                }
            }
        }
    }

    @Test("APP-10.1-c: before its first frame a window is protected: made by Larsal, and the main window SwiftUI makes")
    func beforeFirstFrame() throws {
        let protection = ScreenProtection()
        let none = NSWindow.SharingType.none
        #expect(try Self.firstFrame(protection.window(Self.frame, style: [.titled]), chrome: false) == none)
        #expect(protection.alert().window.sharingType == .none)
        // As SwiftUI makes the main window: capturable until WindowChromeView
        // adopts it, which is before anything in it draws.
        let window = Self.raw()
        #expect(window.sharingType == .readOnly)
        #expect(try Self.firstFrame(window, chrome: true) == none)
    }

    @Test("APP-10.3: a window AppKit or SwiftUI makes is protected on the next run loop pass, before CA commits")
    func runLoopPass() throws {
        let protection = ScreenProtection()
        protection.windows = { [] }
        protection.start(allowCapture: false, center: NotificationCenter())
        // Made after the start, as a tooltip or popover is.
        let later = Self.panel()
        protection.windows = { [later] }
        #expect(later.sharingType == .readOnly)
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        #expect(later.sharingType == .none)
        // The pass's order is below the commit that sends frames.
        CALayer().position = CGPoint(x: 1, y: 1)
        let loop = CFCopyDescription(CFRunLoopGetMain()) as String
        let commit = try #require(
            loop.split(separator: "\n").first { $0.contains("CA11Transaction17observer_callback") }, "CA's observer")
        let order = try #require(commit.firstMatch(of: /order = (\d+)/).flatMap { Int($0.1) })
        #expect(ScreenProtection.order < order)
        #expect(loop.contains("order = \(ScreenProtection.order),"), "the pass is on the main run loop")
    }

    @Test("APP-10.3: an alert or sheet about to begin and a popover about to show are protected before they show")
    func sheetAndPopover() {
        let center = NotificationCenter()
        let protection = ScreenProtection()
        protection.windows = { [] }
        protection.start(allowCapture: false, center: center)
        let alert = NSAlert()
        protection.windows = { [alert.window] }
        center.post(name: NSWindow.willBeginSheetNotification, object: Self.raw())
        #expect(alert.window.sharingType == .none)
        let popover = Self.panel()
        protection.windows = { [popover] }
        center.post(name: NSPopover.willShowNotification, object: NSPopover())
        #expect(popover.sharingType == .none)
    }

    @Test("APP-10.4-a, -b: allowing applies at once to every open window and popup; later ones follow; then protected")
    func allowAndBack() {
        let protection = ScreenProtection()
        let main = Self.raw()
        let popup = Self.panel()
        protection.windows = { [main, popup] }
        protection.sweep()
        #expect(main.sharingType == .none && popup.sharingType == .none)
        protection.allow(true)
        #expect(protection.allowed)
        #expect(main.sharingType == .readOnly)
        #expect(popup.sharingType == .readOnly)
        #expect(protection.window(Self.frame, style: []).sharingType == .readOnly, "a later window follows")
        protection.allow(false)
        #expect(main.sharingType == .none && popup.sharingType == .none)
        #expect(protection.window(Self.frame, style: []).sharingType == .none)
    }

    @Test("APP-10.5-a, APP-10.1-b: F07 starts every window allowed; without it, protected; no primary with F07 here")
    func startFlag() {
        // Rust: only the primary started with F07 says yes (APP-09.10).
        #expect(!allowsScreenCapture())
        #expect(!ScreenProtection().allowed, "a new start is protected")
        let open = Self.raw()
        let flagged = ScreenProtection()
        flagged.windows = { [open] }
        flagged.start(allowCapture: true, center: NotificationCenter())
        #expect(flagged.allowed && open.sharingType == .readOnly)
        #expect(flagged.window(Self.frame, style: []).sharingType == .readOnly)
        let plain = ScreenProtection()
        plain.windows = { [open] }
        plain.start(allowCapture: false, center: NotificationCenter())
        #expect(!plain.allowed && open.sharingType == .none)
    }

    @Test("APP-10.6-a: a window that reads back capturable shows M10-01 once; it stays; never while capture is allowed")
    func refusedBanner() {
        final class Stuck: NSWindow {
            override var sharingType: NSWindow.SharingType {
                get { .readOnly }
                set {}
            }
        }
        let protection = ScreenProtection()
        var banners = 0
        protection.refused = { banners += 1 }
        let stuck = Stuck(contentRect: Self.frame, styleMask: [.titled], backing: .buffered, defer: false)
        protection.windows = { [stuck] }
        protection.sweep()
        protection.sweep()
        #expect(banners == 1)
        protection.allow(true)
        #expect(banners == 1)
        protection.allow(false)
        #expect(banners == 2, "again once protection is back")
        #expect(
            ScreenProtection.refusedText == "Warning: screen capture could not be blocked for one of Larsal's windows.")
    }

    @Test("APP-10.4, APP-08.8 T17: View > Permit Screen Capture is checked exactly while capture is allowed")
    func menuAction() throws {
        guard #available(macOS 14.4, *) else { return }
        let shared = ScreenProtection.shared
        defer { shared.allow(false) }
        let window = MainWindowModel(session: Session())
        // A fresh menu as the menu bar builds it when it opens.
        let item = {
            let menu = NSHostingMenu(rootView: ViewMenuItems(window: window))
            menu.update()
            return menu.items.first { $0.title == "Permit Screen Capture" }
        }
        #expect(item()?.state == .off && !shared.allowed)
        shared.allow(true)
        #expect(item()?.state == .on)
        shared.allow(false)
        #expect(item()?.state == .off)
        // Choosing it allows capture.
        let choose = try #require(item())
        // `NSApp` is nil until something makes the app object.
        NSApplication.shared.sendAction(try #require(choose.action), to: choose.target, from: choose)
        #expect(shared.allowed)
    }
}

extension ScreenProtectionTests {
    /// The window's sharing type when something in it first draws: a view
    /// that records it, drawn offscreen, with `WindowChromeView` beside it
    /// as the main window has it.
    static func firstFrame(_ window: NSWindow, chrome: Bool) throws -> NSWindow.SharingType? {
        let probe = FirstFrame(frame: NSRect(x: 0, y: 0, width: 20, height: 20))
        if chrome {
            let host = NSHostingView(rootView: ProbeView(probe: probe).background(WindowChromeView()))
            host.frame = frame
            window.contentView = host
            host.layoutSubtreeIfNeeded()
        } else {
            window.contentView = probe
        }
        let view = try #require(window.contentView)
        let rep = try #require(view.bitmapImageRepForCachingDisplay(in: view.bounds))
        view.cacheDisplay(in: view.bounds, to: rep)
        return probe.seen
    }
}

/// Records its window's sharing type at its first draw.
final class FirstFrame: NSView {
    private(set) var seen: NSWindow.SharingType?

    override func draw(_ dirtyRect: NSRect) {
        if seen == nil { seen = window?.sharingType }
    }
}

private struct ProbeView: NSViewRepresentable {
    let probe: FirstFrame

    func makeNSView(context: Context) -> FirstFrame { probe }
    func updateNSView(_ view: FirstFrame, context: Context) {}
    func sizeThatFits(_ proposal: ProposedViewSize, nsView: FirstFrame, context: Context) -> CGSize? {
        CGSize(width: 20, height: 20)
    }
}
