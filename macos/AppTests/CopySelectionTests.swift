import AppCore
import AppKit
import SwiftUI
import Testing

/// APP-03.7, APP-03.19 (LD-219 (4), F-081): text selected in the shown
/// vault's editor is copied by Rust's `copy.selection`, with the markers and
/// the countdown, never by AppKit's plain copy. Offscreen, never key or
/// shown (AGENTS.md rule 10); the copy goes to the session's private
/// pasteboard.
@MainActor
@Suite(.serialized)
struct CopySelectionTests {
    init() { ParityDemo.setUp() }

    @Test(
        "APP-03.7 LD-219 (4) F-081: ⌘C and ⌘X on text selected in the editor's Notes copy in Rust, marked and cleared"
    )
    func notesSelection() async throws {
        let before = PasteboardProof.count()
        let window = try ParityDemo.window("copy-selection")
        defer { window.lockAll() }
        try window.session.saveSettings(changes: [
            AppSetting(key: "clipboard.clear.seconds", value: .number(value: 1))
        ])
        let main = try #require(window.main)
        main.edit(main.rows.first { $0.title == "Google" }?.id)
        let editor = try #require(main.editor)
        editor.set(.notes, "keep demo-note-41 here")
        let screen = Screen(window)
        await screen.settle()
        let field = try #require(Self.textField("Notes", in: screen.host), "the editor's Notes")
        #expect(screen.window.makeFirstResponder(field))
        let text = try #require(screen.window.firstResponder as? NSTextView, "the field editor")
        #expect(text.string == "keep demo-note-41 here")
        let spy = try #require(CopySpy(text), "AppKit's copy must not run")
        defer { spy.detach() }
        let selected = (text.string as NSString).range(of: "demo-note-41")
        // The main window in front, the Notes field focused and the text
        // selected, set up again right before each synchronous command:
        // suites run side by side on the main actor, so nothing of this may
        // be left to them across an await, nor trusted after one (under
        // load the field lost its focus during the countdown, LD-249 (4)).
        func inFront(_ command: () -> Void) {
            let rules = WindowRules.shared
            let (saved, attached) = (rules.keyWindow, rules.window)
            rules.keyWindow = { screen.window }
            rules.attach(screen.window)
            if screen.window.firstResponder !== text { screen.window.makeFirstResponder(field) }
            #expect(screen.window.firstResponder === text, "the Notes field has the focus")
            text.setSelectedRange(selected)
            command()
            rules.keyWindow = saved
            if let attached, attached !== screen.window { rules.attach(attached) }
            text.setSelectedRange(NSRange(location: text.selectedRange().location, length: 0))
        }
        inFront { window.copyCommand() }
        #expect(spy.log.log.isEmpty, "\(spy.log.log)")
        #expect(main.toast == .init(glyph: "check", text: "Copied.", note: "Clears in 1 s."))
        let board = NSPasteboard(name: .init(try #require(window.session.pasteboardName())))
        #expect(board.string(forType: .string) == "demo-note-41")
        let types = Set((board.types ?? []).map(\.rawValue))
        #expect(types.isSuperset(of: ["org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType"]), "\(types)")
        // Nothing left to the other suites while this one waits.
        #expect(WindowRules.shared.keyWindow() !== screen.window && text.selectedRange().length == 0)
        // APP-03.11: the countdown clears it.
        for _ in 0..<100 where board.string(forType: .string) != nil { try await Task.sleep(for: .milliseconds(50)) }
        #expect(board.string(forType: .string) == nil, "cleared after 1 s")
        // Edit > Cut: copied the same way, then gone from the field.
        inFront { window.textCommand(#selector(NSText.cut(_:))) }
        #expect(spy.log.log.isEmpty, "\(spy.log.log)")
        #expect(board.string(forType: .string) == "demo-note-41")
        #expect(text.string == "keep  here")
        PasteboardProof.expectOnlyPrivate(window.session, before: before)
        screen.window.makeFirstResponder(nil)
    }

    /// The text field VoiceOver names `name`.
    private static func textField(_ name: String, in host: NSView) -> NSTextField? {
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
