import AppKit
import LarsalCore
import SwiftUI
import Testing

/// Every frame of design/option-a/manifest.json that E5-S6 builds.
enum GeneratorFrame: String, CaseIterable, CustomTestStringConvertible {
    case window = "generator-generator-in-the-window"
    case password = "generator-password"
    case passphrase = "generator-passphrase"

    var testDescription: String { rawValue }
}

@MainActor
@Suite(.serialized)
struct GeneratorSnapshotTests {
    init() { ParityDemo.setUp() }

    @Test("Option A generator frame, offscreen, light and dark", arguments: GeneratorFrame.allCases)
    func frame(_ frame: GeneratorFrame) async throws {
        let window = try ParityDemo.window("generator-shots")
        let main = try #require(window.main)
        try ParityDemo.rate(window)
        main.openGenerator(fromEditor: false)
        let generator = try #require(main.generator)
        if frame == .passphrase {
            generator.change {
                $0.passphrase = true
                $0.words = 5
                $0.separator = "-"
                $0.case = .lower
            }
        }
        try await Self.frameState(generator, phrase: frame == .passphrase)
        // The popover alone is the mockup's `card: true` frame.
        let root =
            frame == .window
            ? AnyView(MainWindow(model: window).frame(width: 1320, height: 820))
            : AnyView(GeneratorPanel(model: generator, vault: main).fixedSize())
        let host = NSHostingView(rootView: root)
        host.frame = NSRect(origin: .zero, size: frame == .window ? CGSize(width: 1320, height: 820) : host.fittingSize)
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
            let out = ParityDemo.shotsDirectory.appending(path: "\(folder)/\(frame.rawValue).png")
            try FileManager.default.createDirectory(
                at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
            try png.write(to: out)
            #expect(png.count > 5_000, "\(out.path)")
            try shots.accessibilityTree(host).write(to: out.deletingPathExtension().appendingPathExtension("ax.json"))
        }
        // The popover alone: the mockup's 404 by 340 (password), 404 by 368
        // (a phrase on two lines).
        if frame != .window { #expect(host.frame.size == CGSize(width: 404, height: frame == .password ? 340 : 368)) }
        offscreen.contentView = nil
        main.overlay = nil
        window.lockAll()
    }

    /// The frame's state, its live value of the mockup's form: an Excellent
    /// password (FEA-05), a passphrase that takes two lines.
    static func frameState(_ generator: GeneratorModel, phrase: Bool) async throws {
        for _ in 0..<200 {
            await generator.settled()
            // Five words, as drawn: a list word with a hyphen would make more parts.
            let words = generator.value.split(separator: "-", omittingEmptySubsequences: false).count
            let done =
                phrase
                ? words == 5 && (27...50).contains(generator.value.count) : generator.rating?.level == "Excellent"
            if done { return }
            generator.regenerate()
        }
        Issue.record("no value of the frame's form")
    }
}

/// Design parity (check 6) for the generator: its controls do what the
/// mockup and the cards make them do, pressed through the accessibility tree
/// offscreen. Every copy goes to the test session's private pasteboard.
@MainActor
@Suite(.serialized)
struct ParityGeneratorTests {
    init() { ParityDemo.setUp() }

    /// The test session's private pasteboard that holds `value`.
    private func board(holding value: String) -> NSPasteboard? {
        (0..<1000).lazy.map { NSPasteboard(name: .init("app.larsal.clipboard.\(getpid()).\($0)")) }
            .first { $0.string(forType: .string) == value }
    }

    @Test("Parity generator-generator-in-the-window: Generator opens the popover with a value; again closes it")
    func openClose() async throws {
        let model = try ParityDemo.window("parity-generator")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Generator")
        let generator = try #require(main.generator)
        await generator.settled()
        await screen.settle()
        #expect(main.generator === generator && !generator.fromEditor)
        #expect(screen.node("Password generator") != nil && screen.node("New entry with it") != nil)
        #expect(generator.value.count == 20 && generator.problem == nil)
        #expect(screen.strings().contains { $0.hasPrefix("Excellent") || $0.hasPrefix("Good") })
        try await screen.press("Generator")
        #expect(main.overlay == nil && main.generator == nil && generator.value.isEmpty)
        // FEA-02.23: Rust dropped it too; nothing is left to copy.
        #expect(try model.session.copyGenerated().empty)
    }

    @Test("Parity generator-generator-in-the-window: Copy copies the shown value in Rust and says so")
    func copy() async throws {
        let model = try ParityDemo.window("parity-generator")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Generator")
        let generator = try #require(main.generator)
        await generator.settled()
        let value = generator.value
        try await screen.press("Copy")
        try await screen.wait { main.toast != nil }
        #expect(main.toast == .init(glyph: "check", text: "Password copied.", note: "Clears in 10 s."))
        #expect(main.generator === generator, "the popover stays open")
        #expect(board(holding: value) != nil)
        // AGENTS.md rule 10: `Session()` copies to a private pasteboard (LD-206).
        PasteboardProof.expectOnlyPrivate(model.session)
    }

    @Test("Parity generator-generator-in-the-window: New entry with it opens a new entry holding the value")
    func newEntry() async throws {
        let model = try ParityDemo.window("parity-generator")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Generator")
        let generator = try #require(main.generator)
        await generator.settled()
        let value = generator.value
        try await screen.press("New entry with it")
        try await screen.wait { main.editor != nil && main.generator == nil }
        let editor = try #require(main.editor)
        #expect(editor.view.new && editor.view.passwordChars == 20)
        #expect(try model.session.draftPassword(vault: main.vault.id) == value)
        #expect(main.overlay == nil && generator.value.isEmpty)
        main.closeEditor()
    }

    @Test("Parity generator-generator-in-the-window: a lock closes the popover and drops the value (D-02-5)")
    func lock() async throws {
        let model = try ParityDemo.window("parity-generator")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Generator")
        let generator = try #require(main.generator)
        await generator.settled()
        #expect(!generator.value.isEmpty)
        try await screen.press("Lock")
        #expect(model.main == nil && generator.value.isEmpty)
        #expect(try model.session.copyGenerated().empty)
    }

    @Test("Parity generator-password: New password, the chips, the slider and look-alikes each make a new value")
    func passwordControls() async throws {
        let model = try ParityDemo.window("parity-generator")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Generator")
        let generator = try #require(main.generator)
        await generator.settled()
        let first = generator.value
        try await screen.press("New password")
        await generator.settled()
        #expect(generator.value != first && generator.value.count == 20)
        // FEA-02.1 through the chips; the last chip on stays on (D-02-3).
        for chip in ["A–Z", "a–z", "0–9"] { try await screen.press(chip) }
        await generator.settled()
        #expect(generator.value.allSatisfy { !$0.isLetter && !$0.isNumber })
        try await screen.press("!@#$")
        #expect(generator.options.special)
        try await screen.press("Äéß")
        await generator.settled()
        #expect(generator.options.extended && generator.value.contains { $0.unicodeScalars.first!.value > 0xA0 })
        // The slider: VoiceOver's adjust and the arrow keys step by one.
        let slider = try #require(screen.node("Length"))
        #expect(slider.accessibilityPerformIncrement?() == true)
        await screen.settle()
        await generator.settled()
        #expect(generator.options.length == 21 && generator.value.count == 21)
        try await screen.press("Leave out look-alikes l I 1 O 0")
        #expect(!generator.options.excludeLookalike)
    }

    @Test("Parity generator-password: the editor's generate button opens it with Use password at the field's length")
    func editorUse() async throws {
        let model = try ParityDemo.window("parity-generator")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        let stored = try model.session.draftPassword(vault: main.vault.id)
        try await screen.press("Open generator (⌥⌘G)")
        let generator = try #require(main.generator)
        await generator.settled()
        await screen.settle()
        // FEA-02.17: the field's length; the mockup's editor button "Use password".
        #expect(generator.fromEditor && Int(generator.options.length) == stored.count)
        #expect(screen.node("New entry with it") == nil)
        let value = generator.value
        try await screen.press("Use password")
        try await screen.wait { main.generator == nil }
        #expect(try model.session.draftPassword(vault: main.vault.id) == value)
        #expect(main.editor?.view.passwordChars == UInt32(value.count) && main.overlay == nil)
        main.closeEditor()
    }

    @Test("Parity generator-password: options that make nothing show the reason; Copy and Use are off (D-02-3)")
    func invalid() async throws {
        let model = try ParityDemo.window("parity-generator")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        main.editor?.passwordTyped("ab")
        try await screen.press("Open generator (⌥⌘G)")
        let generator = try #require(main.generator)
        await generator.settled()
        await screen.settle()
        #expect(generator.options.length == 2 && generator.value.isEmpty)
        #expect(generator.problem == "A character of every chosen type needs a length of at least 4.")
        #expect(screen.strings().contains(generator.problem ?? "-"))
        for name in ["Copy", "Use password"] {
            #expect(screen.node(name)?.isAccessibilityEnabled?() == false, "\(name)")
        }
        main.overlay = nil
        main.closeEditor()
    }

    @Test("Parity generator-passphrase: Passphrase, the separator, the case and the words slider make new phrases")
    func passphraseControls() async throws {
        let model = try ParityDemo.window("parity-generator")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Generator")
        let generator = try #require(main.generator)
        try await screen.press("Passphrase")
        await generator.settled()
        // FEA-03 defaults: 7 lower-case words, one space, 90.47 bits Good.
        #expect(generator.options.passphrase && generator.value.split(separator: " ").count == 7)
        #expect(generator.rating?.bits == 90 && generator.rating?.level == "Good")
        try await screen.press("-")
        try await screen.press("Title")
        await generator.settled()
        let words = generator.value.split(separator: "-")
        #expect(words.count >= 7 && words.allSatisfy { $0.first?.isUppercase == true || $0.first == nil })
        try await screen.press("UPPER")
        await generator.settled()
        #expect(generator.value == generator.value.uppercased())
        let slider = try #require(screen.node("Words"))
        #expect(slider.accessibilityPerformDecrement?() == true)
        await screen.settle()
        await generator.settled()
        #expect(generator.options.words == 6 && generator.rating?.bits == 78)
        try await screen.press("Password")
        await generator.settled()
        #expect(!generator.options.passphrase && generator.value.count == 20)
    }

    @Test("Parity generator-password: a refused paste over 64 KiB shows the reason; Copy and Use are off (FEA-02.16)")
    func refusedEdit() async throws {
        let model = try ParityDemo.window("parity-generator")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        try await screen.press("Open generator (⌥⌘G)")
        let generator = try #require(main.generator)
        await generator.settled()
        try await screen.type(String(repeating: "x", count: 64 * 1024 + 1), into: "Generated password")
        await generator.settled()
        await screen.settle()
        #expect(generator.value.isEmpty && generator.rating == nil && generator.problem == "The text is too long.")
        for name in ["Copy", "Use password"] {
            #expect(screen.node(name)?.isAccessibilityEnabled?() == false, "\(name)")
        }
        #expect(try model.session.copyGenerated().empty)
        main.overlay = nil
        main.closeEditor()
    }

    @Test("Parity generator-passphrase: typing over the value rates the text; Use takes the edit (FEA-02.16, D-03-7)")
    func edit() async throws {
        let model = try ParityDemo.window("parity-generator")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        try await screen.press("Open generator (⌥⌘G)")
        let generator = try #require(main.generator)
        try await screen.press("Passphrase")
        await generator.settled()
        #expect(generator.rating?.level == "Good")
        try await screen.type("demo", into: "Generated password")
        await generator.settled()
        // FEA-05's estimate of "demo", not the word formula.
        #expect(generator.value == "demo" && generator.rating?.level == "Poor")
        try await screen.press("Use password")
        try await screen.wait { main.generator == nil }
        #expect(try model.session.draftPassword(vault: main.vault.id) == "demo")
        main.closeEditor()
    }
}
