import AppKit
import LarsalCore
import SwiftUI
import Testing

/// The bridge's two dialogs E7-S2 builds (INT-02.4, INT-02.18). Each frame,
/// `dialogs-connect-a-browser` and `dialogs-browser-asks-for-an-entry`, is
/// drawn offscreen in Option A's state at its size, light and dark, with
/// the words Rust sends for a vault named “Personal”; W-07's pairing words
/// line and form line, which Option A does not draw yet, get shots of their
/// own. Then a value Rust hides, and the answers through the window.
@MainActor
@Suite(.serialized)
struct BrowserAskTests {
    init() { ParityDemo.setUp() }

    /// Rust's Connect question (vaults.rs `connect`; int02's `t01_t07_…`
    /// pins the text) with Option A's name and no words line.
    static let connect = BrowserQuestion(
        id: 3, vault: 1, kind: "connect", title: "Connect a new browser?",
        text: "A Larsal extension asks to connect to “Personal”. Name it so you know it later. "
            + "Only allow it if you just installed the extension.",
        name: "Firefox on MacBook", words: "", rows: [], remember: nil, line: nil)
    static let row = BrowserQuestionRow(
        title: "GitHub", username: "alex-dev", titleHidden: false, usernameHidden: false, host: "github.com", icon: 0,
        customIcon: nil)
    static let access = BrowserQuestion(
        id: 4, vault: 1, kind: "access", title: "Firefox asks for a sign-in on github.com",
        text: "Choose the entries Firefox may use on this site.", name: "", words: "",
        rows: [
            row,
            BrowserQuestionRow(
                title: "GitHub (work bot)", username: "morgan-labs-ci", titleHidden: false, usernameHidden: false,
                host: "github.com", icon: 0, customIcon: nil),
        ],
        remember: "Remember for github.com", line: nil)

    private func shot(_ root: some View, _ name: String) async throws -> CGSize {
        try await Shots.write(root.fixedSize().font(.sans(14)).foregroundStyle(Tok.text), size: nil, frame: name)
    }

    @Test("INT-02.4 dialogs-connect-a-browser, offscreen, light and dark, at 460 × 270")
    func connectFrame() async throws {
        let window = MainWindowModel(session: Session())
        let size = try await shot(BrowserConnectDialog(window: window, ask: Self.connect), "dialogs-connect-a-browser")
        #expect(size == CGSize(width: 460, height: 270))
        // W-07: MI02-01's words line under the field, as Rust sends it.
        var words = Self.connect
        words.words = "Check that the extension shows: nutshell speech regretful pretense"
        let more = try await shot(
            BrowserConnectDialog(window: window, ask: words), "w07-dialogs-connect-a-browser-words")
        #expect(more.width == 460 && more.height > 270)
    }

    @Test("INT-02.18 dialogs-browser-asks-for-an-entry, offscreen, light and dark, at 460 × 325")
    func accessFrame() async throws {
        let window = MainWindowModel(session: Session())
        let size = try await shot(
            BrowserAccessDialog(window: window, ask: Self.access, checked: [true, false], remember: true),
            "dialogs-browser-asks-for-an-entry")
        #expect(size == CGSize(width: 460, height: 325))
        // W-07: INT-02.19's form line above the rows; Remember hidden.
        var line = Self.access
        line.line = "This form sends what you type to collector.example.org."
        line.remember = nil
        let more = try await shot(
            BrowserAccessDialog(window: window, ask: line), "w07-dialogs-browser-asks-for-an-entry-form-line")
        #expect(more.width == 460)
    }

    /// One row drawn offscreen, light.
    private func rowImage(_ row: BrowserQuestionRow) async throws -> Data {
        let host = NSHostingView(
            rootView: BrowserAccessRow(row: row, isOn: .constant(true)).frame(width: 400).fixedSize()
                .font(.sans(14)).foregroundStyle(Tok.text))
        host.frame = NSRect(origin: .zero, size: host.fittingSize)
        let offscreen = NSWindow(
            contentRect: host.frame.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless], backing: .buffered,
            defer: false)
        offscreen.appearance = NSAppearance(named: .aqua)
        offscreen.contentView = host
        defer { offscreen.contentView = nil }
        return try await SnapshotTests().render(host)
    }

    @Test("V-1, INT-02.18: a title or user name Rust hides draws the mask, read “hidden”, never a value")
    func hiddenRowValues() async throws {
        var empty = Self.row
        empty.title = ""
        empty.username = ""
        var title = empty
        title.titleHidden = true
        var user = empty
        user.usernameHidden = true
        #expect(BrowserAccessRow.spoken(title, mask: false) == "hidden")
        #expect(BrowserAccessRow.spoken(user, mask: false) == "hidden")
        var both = title
        both.usernameHidden = true
        #expect(BrowserAccessRow.spoken(both, mask: false) == "hidden, hidden")
        #expect(BrowserAccessRow.spoken(Self.row, mask: false) == "GitHub, alex-dev")
        // S-VIEW-06 masks a user name here as everywhere (LD-219 (1)).
        #expect(BrowserAccessRow.spoken(Self.row, mask: true) == "GitHub, hidden")
        // The mask is drawn where an empty value draws nothing.
        let plain = try await rowImage(empty)
        #expect(try await rowImage(title) != plain)
        #expect(try await rowImage(user) != plain)
    }

    @Test("Parity dialogs-connect-a-browser: the dialog shows over the window; Deny and Connect answer and close it")
    func answers() async throws {
        let window = MainWindowModel(session: Session())
        let screen = Screen(window)
        for button in ["Deny", "Connect"] {
            window.browserAsk = Self.connect
            await screen.settle()
            #expect(screen.node(Self.connect.title) != nil)
            #expect(screen.strings().contains(Self.connect.text))
            try await screen.press(button)
            #expect(window.browserAsk == nil, "\(button) closes it")
        }
        // No bridge request waits in this session: refresh shows nothing.
        window.browserAsk = Self.connect
        window.refreshBrowser()
        #expect(window.browserAsk == nil)
    }

    @Test("Parity dialogs-browser-asks-for-an-entry: a row toggles; Deny and Allow Selected answer and close it")
    func accessAnswers() async throws {
        let window = MainWindowModel(session: Session())
        let screen = Screen(window)
        let first = BrowserAccessRow.spoken(Self.row, mask: false)
        func state() -> String? {
            guard let element = screen.node(first) else { return nil }
            let value: Any? = element.accessibilityValue?() ?? nil
            return value as? String
        }
        for button in ["Deny", "Allow Selected"] {
            window.browserAsk = Self.access
            await screen.settle()
            #expect(screen.node(Self.access.title) != nil)
            #expect(screen.strings().contains(Self.access.text))
            #expect(screen.node("GitHub (work bot), morgan-labs-ci") != nil)
            #expect(state() == "on")
            try await screen.press(first)
            #expect(state() == "off")
            #expect(screen.node("Remember for github.com") != nil)
            try await screen.press(button)
            #expect(window.browserAsk == nil, "\(button) closes it")
        }
        window.browserAsk = Self.access
        window.refreshBrowser()
        #expect(window.browserAsk == nil)
    }
}
