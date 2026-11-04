import AppKit
import SwiftUI
import Testing

// APP-03.19 (LD-181, Checker E6-S1): after Show, the unlock form's password
// is in a field whose editor lets it out no way at all, as the system's
// password editor. The editor is checked without taking focus: focus would
// turn on secure input for the whole Mac. Pasteboards are private (AGENTS.md
// rule 10).
@MainActor
@Suite(.serialized)
struct ShownPasswordFieldTests {
    init() { ParityDemo.setUp() }

    @Test(
        "Parity lock-locked-password-key-file-security-key: the shown password has no Copy or Cut, writes nothing out"
    )
    func shownPasswordNoCopy() async throws {
        let model = try ParityDemo.window("parity-lock", unlocked: [])
        let unlock = try #require(model.unlock)
        unlock.password = "typed-demo-password"
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Show password")
        let field = try #require(Self.find(NoCopyTextField.self, in: screen.host), "APP-03.19 field after Show")
        #expect(field.stringValue == "typed-demo-password")
        // Set up as editing does.
        let editor = try #require(field.cell?.fieldEditor(for: field) as? NoCopyEditor)
        _ = field.cell?.setUpFieldEditorAttributes(editor)
        editor.string = field.stringValue
        editor.selectAll(nil)
        try Self.expectNoWayOut(editor)
        try Self.expectNoHelp(editor, field)
        // Typing still reaches the model; Hide brings the secure field back.
        field.stringValue = "typed-again"
        NotificationCenter.default.post(name: NSControl.textDidChangeNotification, object: field)
        #expect(unlock.password == "typed-again")
        try await screen.press("Hide password")
        #expect(Self.find(NoCopyTextField.self, in: screen.host) == nil)
        #expect(Self.find(NSSecureTextField.self, in: screen.host) != nil)
    }

    /// F-069: typing in a shown secret leaves no earlier text with an undo
    /// manager, as the system's secure field; a plain text view with undo on
    /// keeps one. No window, no focus.
    @Test("F-069: the shown password's cell and field editor keep no undo copies")
    func shownPasswordNoUndo() throws {
        let field = NoCopyTextField(frame: NSRect(x: 0, y: 0, width: 200, height: 22))
        let cell = try #require(field.cell as? NoCopyCell)
        cell.allowsUndo = true
        let editor = try #require(cell.fieldEditor(for: field) as? NoCopyEditor)
        // Editing starts as a click starts it: the cell hands the editor its
        // undo setting here.
        cell.select(withFrame: field.bounds, in: field, editor: editor, delegate: field, start: 0, length: 0)
        #expect(!cell.allowsUndo && !editor.allowsUndo)
        let plain = NSTextView(frame: .zero)
        plain.allowsUndo = true
        #expect(Self.textAfterUndo(plain) == "first-demo-secret", "the control keeps the earlier text")
        #expect(Self.textAfterUndo(editor) == "second", "nothing kept to bring back")
        cell.endEditing(editor)
    }

    /// Types a demo secret into `view`, then types over it, with a private
    /// undo manager; the text one Undo then shows.
    private static func textAfterUndo(_ view: NSTextView) -> String {
        let source = UndoSource()
        source.undo.groupsByEvent = false
        view.delegate = source
        for text in ["first-demo-secret", "second"] {
            view.selectAll(nil)
            view.breakUndoCoalescing()
            source.undo.beginUndoGrouping()
            view.insertText(text, replacementRange: NSRange(location: NSNotFound, length: 0))
            source.undo.endUndoGrouping()
        }
        if source.undo.canUndo { source.undo.undo() }
        view.delegate = nil
        return view.string
    }

    @MainActor
    private final class UndoSource: NSObject, NSTextViewDelegate {
        let undo = UndoManager()
        func undoManager(for view: NSTextView) -> UndoManager? { undo }
    }

    static let legacy = NSPasteboard.PasteboardType("NSStringPboardType")
    static let click = NSEvent.mouseEvent(
        with: .rightMouseDown, location: .zero, modifierFlags: [], timestamp: 0, windowNumber: 0, context: nil,
        eventNumber: 0, clickCount: 1, pressure: 1)

    /// No way onto a pasteboard (copy, cut, drag, Services), against a
    /// plain text view with the same text that does write.
    private static func expectNoWayOut(_ editor: NoCopyEditor) throws {
        let plain = NSTextView(frame: .zero)
        plain.string = editor.string
        plain.selectAll(nil)
        let control = NSPasteboard(name: .init("app-test-\(UUID().uuidString)"))
        #expect(!plain.writablePasteboardTypes.isEmpty && plain.writeSelection(to: control, type: legacy))
        #expect(control.string(forType: .string) == editor.string, "the control writes")
        control.releaseGlobally()
        let board = NSPasteboard(name: .init("app-test-\(UUID().uuidString)"))
        #expect(editor.writablePasteboardTypes.isEmpty)
        #expect(!editor.writeSelection(to: board, type: legacy))
        #expect(!editor.writeSelection(to: board, types: [legacy, .string]))
        #expect(editor.validRequestor(forSendType: legacy, returnType: nil) == nil)
        #expect(editor.validRequestor(forSendType: .string, returnType: .string) == nil)
        let event = try #require(click)
        #expect(!editor.dragSelection(with: event, offset: .zero, slideBack: false))
        let text = editor.string
        editor.cut(nil)
        editor.copy(nil)
        #expect((board.types ?? []).isEmpty, "nothing written")
        #expect(editor.string == text, "Cut removes nothing")
        board.releaseGlobally()
        let item = { (action: Selector) in NSMenuItem(title: "", action: action, keyEquivalent: "") }
        #expect(!editor.validateUserInterfaceItem(item(#selector(NSText.copy(_:)))))
        #expect(!editor.validateUserInterfaceItem(item(#selector(NSText.cut(_:)))))
    }

    /// A menu of exactly Paste, Delete, Select All without plug-ins; no
    /// Writing Tools; no corrections, replacements, completion or smart
    /// quotes and dashes.
    private static func expectNoHelp(_ editor: NoCopyEditor, _ field: NSTextField) throws {
        let event = try #require(click)
        let menu = try #require(editor.menu(for: event))
        #expect(menu.items.map(\.action) == NoCopyEditor.allowed.map(\.1))
        #expect(menu.items.map(\.title) == ["Paste", "Delete", "Select All"] && !menu.allowsContextMenuPlugIns)
        if #available(macOS 15.0, *) { #expect(editor.writingToolsBehavior == .none) }
        #expect(!editor.isAutomaticSpellingCorrectionEnabled && !editor.isAutomaticTextReplacementEnabled)
        #expect(!editor.isAutomaticTextCompletionEnabled && !field.isAutomaticTextCompletionEnabled)
        #expect(!editor.isAutomaticQuoteSubstitutionEnabled && !editor.isAutomaticDashSubstitutionEnabled)
        #expect(!editor.isContinuousSpellCheckingEnabled && !editor.isGrammarCheckingEnabled)
        // Force-click Look Up and Speech are its own, never NSTextView's (not called: a
        // popover or speech would reach the owner's screen or speakers).
        for selector in [#selector(NSResponder.quickLook(with:)), #selector(NSTextView.startSpeaking(_:))] {
            #expect(
                class_getMethodImplementation(NoCopyEditor.self, selector)
                    != class_getMethodImplementation(NSTextView.self, selector)
            )
        }
    }

    private static func find<T: NSView>(_ type: T.Type, in view: NSView) -> T? {
        if let found = view as? T { return found }
        return view.subviews.lazy.compactMap { find(type, in: $0) }.first
    }
}
