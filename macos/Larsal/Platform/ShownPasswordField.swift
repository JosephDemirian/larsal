import AppKit
import SwiftUI

/// UL-PW after Show (APP-03.19, APP-10): the typed password in clear, in a
/// field that never lets it out. The AppKit way: the field's cell supplies
/// its own field editor (`NoCopyEditor`), which allows what the system's
/// password editor allows, Copy and Cut refused. Paste and typing work. `focused` follows the field's first responder
/// state both ways, for the focus ring; the field turns on secure input itself.
struct ShownPasswordField: NSViewRepresentable {
    @Binding var text: String
    @Binding var focused: Bool
    let onSubmit: () -> Void

    func makeNSView(context: Context) -> NoCopyTextField {
        let field = NoCopyTextField()
        field.isBordered = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.usesSingleLineMode = true
        field.isAutomaticTextCompletionEnabled = false
        field.cell?.isScrollable = true
        field.font = NSFont(name: "IBMPlexSans-Regular", size: 15)
        field.textColor = NSColor(named: "text", bundle: appBundle)
        field.placeholderAttributedString = NSAttributedString(
            string: "Password",
            attributes: [
                .font: field.font ?? .systemFont(ofSize: 15),
                .foregroundColor: NSColor(named: "muted", bundle: appBundle) ?? .secondaryLabelColor,
            ])
        field.setAccessibilityLabel("Password")
        // VoiceOver reads the cell, not the field (AT-K06, APP-08.25).
        field.cell?.setAccessibilityLabel("Password")
        field.delegate = context.coordinator
        field.onFocus = { context.coordinator.parent.focused = $0 }
        return field
    }

    func updateNSView(_ field: NoCopyTextField, context: Context) {
        context.coordinator.parent = self
        if field.stringValue != text { field.stringValue = text }
        if focused, field.currentEditor() == nil, let window = field.window {
            // Not during SwiftUI's update: taking focus reports back.
            Task { window.makeFirstResponder(field) }
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: ShownPasswordField

        init(_ parent: ShownPasswordField) { self.parent = parent }

        func controlTextDidChange(_ note: Notification) {
            if let field = note.object as? NSTextField { parent.text = field.stringValue }
        }

        func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
            guard selector == #selector(NSResponder.insertNewline(_:)) else { return false }
            parent.onSubmit()
            return true
        }
    }
}

/// The editor's shown password while the user does not edit it (F-102,
/// AT-E07): drawn as the detail draws it, since an AppKit text field leaves
/// a copy of its value in Larsal's memory after Hide, lock and close. A click,
/// Tab or an accessibility press calls `edit`, which makes the field.
struct EditorShownPassword: View {
    let text: String
    let edit: () -> Void
    @FocusState private var focus: Bool

    var body: some View {
        PasswordText(text: text)
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
            .focusable(interactions: .edit)
            .focusEffectDisabled()
            .focused($focus)
            .onTapGesture(perform: edit)
            .onChange(of: focus) { _, now in if now { edit() } }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text(verbatim: "Password"))
            .accessibilityValue(Text(verbatim: text))
            .accessibilityAction(.default, edit)
    }
}

/// The shown password's text field: its cell hands out a `NoCopyEditor`.
/// Every password-kind field shown in clear is one (APP-10.9), so Larsal's own
/// secure input follows its focus here (SR-06, APP-10.11).
final class NoCopyTextField: NSTextField {
    var onFocus: ((Bool) -> Void)?
    var secureInput = SecureInput.shared

    override static var cellClass: AnyClass? {
        get { NoCopyCell.self }
        set {}
    }

    override func becomeFirstResponder() -> Bool {
        let taken = super.becomeFirstResponder()
        if taken {
            onFocus?(true)
            secureInput.focused(self)
        }
        return taken
    }

    /// Focus out, hidden, or removed from its window.
    override func textDidEndEditing(_ notification: Notification) {
        super.textDidEndEditing(notification)
        onFocus?(false)
        secureInput.left(self)
    }

    /// A new value replaced the text being typed: editing ends with no
    /// end-editing call.
    @discardableResult
    override func abortEditing() -> Bool {
        let aborted = super.abortEditing()
        secureInput.left(self)
        return aborted
    }

    /// Takes the focus once it is in a window: a field made when the user
    /// starts to edit a shown value (F-102).
    var focusOnWindow = false

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if window == nil {
            secureInput.left(self)
        } else if focusOnWindow {
            focusOnWindow = false
            // Not during SwiftUI's update: taking focus reports back.
            Task { [weak self] in
                if let self { self.window?.makeFirstResponder(self) }
            }
        }
    }
}

final class NoCopyCell: NSTextFieldCell {
    private let editor: NoCopyEditor = {
        let editor = NoCopyEditor(frame: .zero)
        editor.isFieldEditor = true
        editor.harden()
        return editor
    }()

    override func fieldEditor(for controlView: NSView) -> NSTextView? { editor }

    /// No undo, as the system's secure field: the window's undo manager
    /// would keep earlier texts of the shown secret (F-069).
    override var allowsUndo: Bool {
        get { false }
        set {}
    }

    /// Editing starts: the cell sets the editor up, then the hardening
    /// goes on again in case the cell turned anything back on.
    override func setUpFieldEditorAttributes(_ textObj: NSText) -> NSText {
        let text = super.setUpFieldEditorAttributes(textObj)
        (text as? NoCopyEditor)?.harden()
        return text
    }
}

/// A field editor that lets the text out no way at all, as the system's
/// password editor: no writable pasteboard types (so no Copy, Cut, drag or
/// Services), no Writing Tools, no text help that reads it, and a context
/// menu of Paste, Delete and Select All only.
final class NoCopyEditor: NSTextView {
    /// The context menu's only items.
    static let allowed: [(String, Selector)] = [
        ("Paste", #selector(NSText.paste(_:))), ("Delete", #selector(NSText.delete(_:))),
        ("Select All", #selector(NSText.selectAll(_:))),
    ]

    /// No spelling or grammar help, corrections, replacements, completion,
    /// smart quotes or dashes, data or link detection, Writing Tools; no undo
    /// copies of the text (F-069).
    func harden() {
        allowsUndo = false
        isContinuousSpellCheckingEnabled = false
        isGrammarCheckingEnabled = false
        isAutomaticSpellingCorrectionEnabled = false
        isAutomaticTextReplacementEnabled = false
        isAutomaticTextCompletionEnabled = false
        isAutomaticQuoteSubstitutionEnabled = false
        isAutomaticDashSubstitutionEnabled = false
        isAutomaticDataDetectionEnabled = false
        isAutomaticLinkDetectionEnabled = false
        if #available(macOS 15.0, *) { writingToolsBehavior = .none }
    }

    override var writablePasteboardTypes: [NSPasteboard.PasteboardType] { [] }
    override func writeSelection(to pboard: NSPasteboard, type: NSPasteboard.PasteboardType) -> Bool { false }
    override func writeSelection(to pboard: NSPasteboard, types: [NSPasteboard.PasteboardType]) -> Bool { false }
    override func dragSelection(with event: NSEvent, offset mouseOffset: NSSize, slideBack: Bool) -> Bool { false }
    override func copy(_ sender: Any?) {}
    override func cut(_ sender: Any?) {}
    /// No Look Up by force-click or three-finger tap: its popover can query
    /// the web (as the system's password editor does).
    override func quickLook(with event: NSEvent) {}
    override func startSpeaking(_ sender: Any?) {}

    /// Services may put text in, never take it.
    override func validRequestor(
        forSendType sendType: NSPasteboard.PasteboardType?, returnType: NSPasteboard.PasteboardType?
    ) -> Any? {
        sendType == nil ? super.validRequestor(forSendType: sendType, returnType: returnType) : nil
    }

    override func validateUserInterfaceItem(_ item: any NSValidatedUserInterfaceItem) -> Bool {
        let refused: [Selector] = [
            #selector(NSText.copy(_:)), #selector(NSText.cut(_:)), #selector(NSTextView.startSpeaking(_:)),
        ]
        if let action = item.action, refused.contains(action) { return false }
        return super.validateUserInterfaceItem(item)
    }

    /// A menu of its own (not the system's, so Look Up, Translate, search,
    /// Share and Speech never appear), with no plug-ins.
    override func menu(for event: NSEvent) -> NSMenu? {
        let menu = NSMenu()
        menu.allowsContextMenuPlugIns = false
        for (title, action) in Self.allowed {
            menu.addItem(NSMenuItem(title: title, action: action, keyEquivalent: ""))
        }
        return menu
    }
}
