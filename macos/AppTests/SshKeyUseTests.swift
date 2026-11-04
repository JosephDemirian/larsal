import AppCore
import AppKit
import SwiftUI
import Testing

/// The frame E9-S2 builds: App's SSH agent asks before a key signs
/// (INT-06.34, frame `dialogs-ssh-key-use`), and R06-6's first second.
@MainActor
@Suite(.serialized)
struct SshKeyUseTests {
    init() { ParityDemo.setUp() }

    /// The mockup's question (mockup.js `sshConfirm`): MI06-29 and MI06-30
    /// for `ssh` signing in to 203.0.113.10, as Rust words them.
    static let drawn = SshQuestion(
        id: 7, heading: "Allow ssh to use “Server root · web-01”?",
        text: "ssh wants to sign in to 203.0.113.10 with this key.")
    static let start = Date(timeIntervalSince1970: 1_793_093_400)

    @Test("Option A dialogs-ssh-key-use, offscreen, light and dark")
    func frame() async throws {
        let window = MainWindowModel(session: Session())
        let ask = SshAsk(question: Self.drawn, shown: Self.start)
        window.sshAsk = ask
        let root = SshKeyUseDialog(window: window, ask: ask).fixedSize().font(.sans(14)).foregroundStyle(Tok.text)
        let host = NSHostingView(rootView: root)
        host.frame = NSRect(origin: .zero, size: host.fittingSize)
        // Never ordered front (AGENTS.md rule 10); sRGB as the references.
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
            let out = ParityDemo.root.appending(path: "app-shots/\(folder)/dialogs-ssh-key-use.png")
            try FileManager.default.createDirectory(
                at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
            try png.write(to: out)
            #expect(png.count > 5_000, "\(out.path)")
            try shots.accessibilityTree(host).write(to: out.deletingPathExtension().appendingPathExtension("ax.json"))
        }
        // The sheet alone: the reference's 920 by 304 pixels at 2x.
        #expect(host.frame.size == CGSize(width: 460, height: 152))
        offscreen.contentView = nil
    }

    @Test("R06-6: Return and Space do nothing for the first second; a click, Escape and Deny act at once")
    func firstSecond() throws {
        let ask = SshAsk(question: Self.drawn, shown: Self.start)
        // The fake clock of the card's test: Return at 0.5 s, then at 1.1 s.
        #expect(!ask.takes(allow: true, byKey: true, at: Self.start + 0.5))
        #expect(ask.takes(allow: true, byKey: true, at: Self.start + 1.1))
        #expect(ask.takes(allow: true, byKey: false, at: Self.start + 0.1), "a click on Allow Once")
        #expect(ask.takes(allow: false, byKey: true, at: Self.start), "Escape")
        #expect(ask.takes(allow: false, byKey: false, at: Self.start), "a click on Deny")
        // Return and Space arrive as key presses; a click does not.
        for key in ["\r", " "] {
            let event = NSEvent.keyEvent(
                with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0, windowNumber: 0, context: nil,
                characters: key, charactersIgnoringModifiers: key, isARepeat: false, keyCode: key == "\r" ? 36 : 49)
            #expect(SshAsk.byKey(event))
        }
        let click = NSEvent.mouseEvent(
            with: .leftMouseUp, location: .zero, modifierFlags: [], timestamp: 0, windowNumber: 0, context: nil,
            eventNumber: 0, clickCount: 1, pressure: 0)
        #expect(!SshAsk.byKey(click))
        // Through the window: Return at 0.5 s keeps the question, at 1.1 s
        // it answers and the dialog closes.
        let window = MainWindowModel(session: Session())
        window.sshAsk = ask
        window.answerSsh(allow: true, byKey: true, at: Self.start + 0.5)
        #expect(window.sshAsk == ask)
        window.answerSsh(allow: true, byKey: true, at: Self.start + 1.1)
        #expect(window.sshAsk == nil)
        window.sshAsk = ask
        window.answerSsh(allow: false, byKey: true, at: Self.start)
        #expect(window.sshAsk == nil, "Escape at once")
    }

    @Test("LD-213 (3): a held Return or Space never chooses Allow Once, also after the first second")
    func heldKey() {
        let window = MainWindowModel(session: Session())
        let ask = SshAsk(question: Self.drawn, shown: Self.start)
        func press(_ key: String, repeated: Bool) -> NSEvent? {
            NSEvent.keyEvent(
                with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0, windowNumber: 0, context: nil,
                characters: key, charactersIgnoringModifiers: key, isARepeat: repeated, keyCode: key == "\r" ? 36 : 49)
        }
        for key in ["\r", " "] {
            window.sshAsk = ask
            window.answerSsh(allow: true, from: press(key, repeated: true), at: Self.start + 1.1)
            window.answerSsh(allow: true, from: press(key, repeated: true), at: Self.start + 30)
            #expect(window.sshAsk == ask, "a repeat chose Allow Once")
            // A fresh press after the first second still answers.
            window.answerSsh(allow: true, from: press(key, repeated: false), at: Self.start + 1.1)
            #expect(window.sshAsk == nil)
        }
    }

    @Test("Parity dialogs-ssh-key-use: the question shows over the window; Deny and Allow Once answer and close it")
    func answers() async throws {
        let window = MainWindowModel(session: Session())
        let screen = Screen(window)
        for button in ["Deny", "Allow Once"] {
            window.sshAsk = SshAsk(question: Self.drawn, shown: Self.start)
            await screen.settle()
            #expect(screen.node(Self.drawn.heading) != nil)
            #expect(screen.strings().contains(Self.drawn.text))
            try await screen.press(button)
            #expect(window.sshAsk == nil, "\(button) closes it")
        }
        // A question Rust no longer asks closes on the next read.
        window.sshAsk = SshAsk(question: Self.drawn, shown: Self.start)
        window.refresh()
        #expect(window.sshAsk == nil)
    }
}
