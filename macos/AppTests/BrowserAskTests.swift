import AppCore
import AppKit
import SwiftUI
import Testing

/// The bridge's two dialogs E7-S2 builds (INT-02.4, INT-02.18): frames
/// `dialogs-connect-a-browser` and `dialogs-browser-asks-for-an-entry`,
/// drawn offscreen with Rust's words, and their answers through the window.
@MainActor
@Suite(.serialized)
struct BrowserAskTests {
    init() { ParityDemo.setUp() }

    static let connect = BrowserQuestion(
        id: 3, vault: 1, kind: "connect", title: "Connect a new browser?",
        text: "An App extension asks to connect to “Personal”. Name it so you know it later.",
        name: "Firefox on Test Mac", words: "Check that the extension shows: suspense bagginess crucial mongoose",
        rows: [], remember: nil, line: nil)
    static let access = BrowserQuestion(
        id: 4, vault: 1, kind: "access", title: "Firefox asks for a sign-in on github.com",
        text: "Choose the entries Firefox may use on this site.", name: "", words: "",
        rows: [BrowserQuestionRow(title: "GitHub", username: "alex"), BrowserQuestionRow(title: "Gist", username: "")],
        remember: "Remember for github.com", line: "This form sends what you type to collector.example.org.")

    private func render(_ root: some View, _ name: String) async throws {
        let host = NSHostingView(rootView: root.fixedSize().font(.sans(14)).foregroundStyle(Tok.text))
        host.frame = NSRect(origin: .zero, size: host.fittingSize)
        // Never ordered front (AGENTS.md rule 10).
        let offscreen = NSWindow(
            contentRect: host.frame.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless], backing: .buffered,
            defer: false)
        offscreen.colorSpace = .sRGB
        offscreen.backgroundColor = .clear
        offscreen.contentView = host
        let shots = SnapshotTests()
        for (folder, look) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            offscreen.appearance = NSAppearance(named: look)
            let png = try await shots.render(host)
            let out = ParityDemo.root.appending(path: "app-shots/\(folder)/\(name).png")
            try FileManager.default.createDirectory(
                at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
            try png.write(to: out)
            #expect(png.count > 5_000, "\(out.path)")
        }
        #expect(host.frame.width == 460)
        offscreen.contentView = nil
    }

    @Test("INT-02.4 dialogs-connect-a-browser, offscreen, light and dark")
    func connectFrame() async throws {
        let window = MainWindowModel(session: Session())
        try await render(BrowserConnectDialog(window: window, ask: Self.connect), "dialogs-connect-a-browser")
    }

    @Test("INT-02.18 dialogs-browser-asks-for-an-entry, offscreen, light and dark")
    func accessFrame() async throws {
        let window = MainWindowModel(session: Session())
        try await render(BrowserAccessDialog(window: window, ask: Self.access), "dialogs-browser-asks-for-an-entry")
    }

    @Test("An answer closes the dialog; a dialog Rust no longer shows closes on refresh")
    func answers() {
        let window = MainWindowModel(session: Session())
        window.browserAsk = Self.connect
        window.answerBrowserConnect(nil)
        #expect(window.browserAsk == nil)
        window.browserAsk = Self.access
        window.answerBrowserAccess(allow: true, checked: [true, false], remember: true)
        #expect(window.browserAsk == nil)
        // No bridge request waits in this session: refresh shows nothing.
        window.browserAsk = Self.access
        window.refreshBrowser()
        #expect(window.browserAsk == nil)
    }
}
