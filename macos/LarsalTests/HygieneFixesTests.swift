import AppKit
import LarsalCore
import SwiftUI
import Testing

// E13-S6 part n (LD-244 (2)): the search clear minute per timer, Return in
// MSG-LOCK-DISCARD-EDIT, and UndoOff's already-editing branch. Offscreen
// only; keys go to the hidden window's own methods (AGENTS.md rule 10).

@MainActor
@Test("LD-244 (2): each search clear timer has its own minute, so suites running side by side never share one")
func ld244SearchClearMinuteIsPerTimer() {
    let shortened = SearchClearTimer()
    shortened.minute = .milliseconds(25)
    #expect(SearchClearTimer().minute == .seconds(60))
}

extension DataSafetyTests {
    @Test("LD-244 (2), APP-02.15 step 7: Return answers Cancel in MSG-LOCK-DISCARD-EDIT; Escape still does")
    func ld244ReturnAnswersCancelInLockDiscardEdit() async throws {
        let (model, screen) = try await window("ld244-return")
        let main = try #require(model.main)
        let id = main.vault.id
        let rows = try main.session.list(vault: id, view: .all).rows
        main.edit(try #require(rows.first { $0.title == "Wise" }?.id))
        try #require(main.editor).set(.title, "Wise (demo edit)")
        let unlocked = { model.session.vaults().first { $0.id == id }?.locked == false }
        for (code, key) in [(UInt16(36), "\r"), (53, "\u{1b}")] {
            model.lock(id)
            #expect(main.dialog == .lockDiscardEdit && main.afterLeave != nil)
            await screen.settle()
            let press = try #require(
                NSEvent.keyEvent(
                    with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0, windowNumber: 0, context: nil,
                    characters: key, charactersIgnoringModifiers: key, isARepeat: false, keyCode: code))
            #expect(screen.window.performKeyEquivalent(with: press), "a button's key: \(code)")
            await screen.settle()
            #expect(main.dialog == nil && main.afterLeave == nil, "Cancel: \(code)")
            #expect(main.editor != nil && unlocked(), "the vault and its edits stay: \(code)")
        }
    }
}

/// Its own suite, AppKit only: a SwiftUI field taking the focus here made
/// other suites' editing tests lose theirs while they waited.
@MainActor
@Suite(.serialized)
struct UndoOffEditingTests {
    @Test("F-127, LD-244 (2): a field already being edited when its value turns protected stops keeping undo copies")
    func f127FieldBeingEditedTurnsProtected() async throws {
        let frame = NSRect(x: 0, y: 0, width: 240, height: 24)
        let field = NSTextField(string: "first")
        field.frame = frame
        let probe = UndoOff.Probe(frame: frame)  // UndoOff's view behind the field
        let root = NSView(frame: frame)
        root.addSubview(field)
        root.addSubview(probe)
        let window = NSWindow(
            contentRect: frame.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless], backing: .buffered,
            defer: false)
        window.contentView = root
        defer { window.contentView = nil }
        #expect(window.makeFirstResponder(field))
        let editor = try #require(window.firstResponder as? NSTextView)
        #expect(editor.allowsUndo, "not protected yet: undo as usual")
        // What updateNSView does when the value turns protected.
        probe.off = true
        probe.apply()
        for _ in 0..<200 where editor.allowsUndo { try await Task.sleep(for: .milliseconds(25)) }
        #expect(field.cell?.allowsUndo == false && !editor.allowsUndo, "protected while editing")
        #expect(ProtectedUndoTests.textAfterUndo(editor) == "second", "the earlier value is not kept")
        window.makeFirstResponder(nil)
    }
}
