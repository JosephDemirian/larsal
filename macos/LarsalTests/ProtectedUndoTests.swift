import AppKit
import LarsalCore
import SwiftUI
import Testing

/// F-127 (LD-237 (2)): a protected value shown in the editor keeps no undo
/// copies, as F-069's shown password. Offscreen, never ordered front
/// (AGENTS.md rule 10); the field takes focus only in that hidden window.
@MainActor
@Suite(.serialized)
struct ProtectedUndoTests {
    init() { ParityDemo.setUp() }

    static let secret = "demo-protected-7Kq2"

    static func label(_ field: EditText) -> String {
        switch field {
        case .title: "Title"
        case .userName: "Username"
        case .url: "Website"
        case .notes: "Notes"
        }
    }

    @Test("F-127: a shown protected custom field is drawn as text, never in a field that could keep undo copies")
    func f127ProtectedCustomFieldIsNeverEdited() async throws {
        let model = try ParityDemo.window("f127-custom")
        defer { model.lockAll() }
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        try await screen.press(EditorModel.Page.advanced.rawValue)
        try await screen.press("Add field")
        let editor = try #require(main.editor)
        let (session, id) = (main.session, main.vault.id)
        editor.run { try session.setField(vault: id, name: "New field", value: Self.secret) }
        try await screen.press("Protect New field")
        try await screen.press("Show New field")
        #expect(editor.shownFields["New field"] == Self.secret && screen.strings().contains(Self.secret), "shown")
        #expect(Self.field(holding: Self.secret, in: screen.host) == nil, "no text field holds it")
    }

    /// F-136: a Settings window closed and released while its search field
    /// is being edited, as Larsal drops a closed Settings window. That edit
    /// never ends, so the one field editor that SwiftUI gives every window
    /// keeps its undo on.
    static func closeInMidEdit() async throws {
        weak var closed: OtherWindow?
        do {
            let other = OtherWindow(AnyView(LarsalSettingsView(model: settingsModel()).frame(width: 900, height: 680)))
            other.isReleasedWhenClosed = false
            await other.settle()
            let search = try #require(other.field("Search settings"), "the Settings search field")
            #expect(other.makeFirstResponder(search))
            #expect((other.firstResponder as? NSTextView)?.allowsUndo == true, "that edit keeps undo")
            other.close()
            closed = other
        }
        try await Task.sleep(for: .milliseconds(50))
        #expect(closed == nil, "the closed window is released")
    }

    /// The AppKit text field under `view` that holds `text`.
    static func field(holding text: String, in view: NSView) -> NSTextField? {
        for sub in view.subviews {
            if let field = sub as? NSTextField, field.stringValue == text { return field }
            if let found = field(holding: text, in: sub) { return found }
        }
        return nil
    }

    /// Types over the field editor's text with a private undo manager (as
    /// the F-069 test), then undoes once: what it shows. The field does not
    /// hear the typing, so the binding (the test's protected view is a
    /// fake; Rust's draft is not protected) cannot put the value back.
    static func textAfterUndo(_ editor: NSTextView) -> String {
        let source = UndoSource()
        let delegate = editor.delegate
        editor.delegate = source
        defer { editor.delegate = delegate }
        source.undo.groupsByEvent = false
        source.undo.beginUndoGrouping()
        editor.selectAll(nil)
        editor.insertText("second", replacementRange: NSRange(location: NSNotFound, length: 0))
        source.undo.endUndoGrouping()
        if source.undo.canUndo { source.undo.undo() }
        return editor.string
    }

    private final class UndoSource: NSObject, NSTextViewDelegate {
        let undo = UndoManager()
        func undoManager(for view: NSTextView) -> UndoManager? { undo }
    }
}

// In MenuKeysTests' serialized group (LD-241 (1)): the edit takes SwiftUI's
// one field editor from any other window, so it never runs beside the
// APP-08.14 search field keys (three full runs of 2026-10-30, 22:14, failed
// there when it did).
private typealias Undo = ProtectedUndoTests

@MainActor
extension MenuKeysTests {
    @Test(
        "F-127 F-136: a shown protected Title, UserName, URL or Notes keeps no undo copies, also after a closed edit",
        arguments: [EditText.title, .userName, .url, .notes], [false, true])
    func f127ProtectedStandardFieldKeepsNoUndo(_ field: EditText, afterClosedEdit: Bool) async throws {
        let model = try ParityDemo.window("f127-\(field.name)")
        defer { model.lockAll() }
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        try #require(main.editor).set(field, Undo.secret)
        // What Rust sends for a protected field (as the F-060 test): the
        // flag and no value; Show gives the draft's value.
        var view = try main.session.editor(vault: main.vault.id)
        let other = field == .title ? view.user : view.title
        #expect(!other.isEmpty)
        view.protected = [field]
        switch field {
        case .title: view.title = ""
        case .userName: view.user = ""
        case .url: view.url = ""
        case .notes: view.notes = ""
        }
        let editor = EditorModel(session: main.session, vault: main.vault, view: view)
        main.editor = editor
        await screen.settle()
        try await screen.press("Show " + Undo.label(field))
        #expect(editor.shownFields[field.name] == Undo.secret)
        await screen.settle()
        let shown = try #require(Undo.field(holding: Undo.secret, in: screen.host), "the shown field")
        #expect(shown.cell?.allowsUndo == false, "its cell keeps no undo")
        #expect(Undo.field(holding: other, in: screen.host)?.cell?.allowsUndo == true, "an unprotected one does")
        if afterClosedEdit { try await Undo.closeInMidEdit() }
        // Editing starts as a click starts it: the field editor takes the
        // cell's setting; typing over the value leaves nothing to undo.
        // Larsal's own fix, not the test, turns the shared field editor's undo
        // off, whatever another window left it as (F-136; the full run of
        // 2026-10-30, 20:23).
        #expect(screen.window.makeFirstResponder(shown))
        let fieldEditor = try #require(screen.window.firstResponder as? NSTextView)
        #expect(!fieldEditor.allowsUndo)
        #expect(Undo.textAfterUndo(fieldEditor) == "second", "the earlier value is not kept")
        screen.window.makeFirstResponder(nil)
    }
}
