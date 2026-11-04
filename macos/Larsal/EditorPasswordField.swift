import AppKit
import SwiftUI

/// The editor's shown password (E5-S5, mockup `.inp .pw`): the same no-copy
/// field as the unlock form's (`NoCopyTextField`, APP-03.19), in IBM Plex
/// Mono with digits and symbols coloured as `pwHtml` draws them. Each change
/// goes to Rust at once (`EditorModel.passwordTyped`); `focused` drives the
/// focus ring; the field turns on secure input itself (SR-06).
struct EditorPasswordField: NSViewRepresentable {
    @Binding var text: String
    @Binding var focused: Bool
    /// Digits and symbols coloured as `pwHtml` (off for the one-time secret).
    var coloured = true
    var placeholder = ""
    var label = "Password"
    /// Takes the focus when it appears (the editor makes it only to edit,
    /// F-102).
    var focusOnAppear = false

    func makeNSView(context: Context) -> NoCopyTextField {
        let field = NoCopyTextField()
        field.isBordered = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.usesSingleLineMode = true
        field.isAutomaticTextCompletionEnabled = false
        field.cell?.isScrollable = true
        field.cell?.lineBreakMode = .byClipping
        field.font = Self.font
        field.setAccessibilityLabel(label)
        field.cell?.setAccessibilityLabel(label)
        field.placeholderAttributedString = NSAttributedString(
            string: placeholder,
            attributes: [
                .font: Self.font, .foregroundColor: NSColor(named: "muted", bundle: appBundle) ?? .secondaryLabelColor,
            ])
        field.delegate = context.coordinator
        field.onFocus = { context.coordinator.parent.focused = $0 }
        field.focusOnWindow = focusOnAppear
        field.attributedStringValue = shown(text)
        return field
    }

    func updateNSView(_ field: NoCopyTextField, context: Context) {
        context.coordinator.parent = self
        if field.stringValue != text { field.attributedStringValue = shown(text) }
    }

    private func shown(_ text: String) -> NSAttributedString {
        coloured
            ? Self.coloured(text)
            : NSAttributedString(
                string: text,
                attributes: [
                    .font: Self.font, .foregroundColor: NSColor(named: "text", bundle: appBundle) ?? .labelColor,
                ])
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    static let font =
        NSFont(name: "IBMPlexMono-Regular", size: 14) ?? .monospacedSystemFont(ofSize: 14, weight: .regular)

    /// The text with `.d` and `.s` colours, 0.02 em apart (`.pw`).
    static func coloured(_ text: String) -> NSAttributedString {
        let out = NSMutableAttributedString()
        let ink = NSColor(named: "text", bundle: appBundle) ?? .labelColor
        let digit = NSColor(named: "digit", bundle: appBundle) ?? ink
        let symbol = NSColor(named: "symbol", bundle: appBundle) ?? ink
        for char in text {
            let color =
                char.isASCII && char.isNumber
                ? digit : (char.isASCII && char.isLetter) || char.isWhitespace ? ink : symbol
            out.append(
                NSAttributedString(
                    string: String(char), attributes: [.font: font, .foregroundColor: color, .kern: 0.28]))
        }
        return out
    }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: EditorPasswordField

        init(_ parent: EditorPasswordField) { self.parent = parent }

        func controlTextDidChange(_ note: Notification) {
            guard let field = note.object as? NSTextField else { return }
            parent.text = field.stringValue
            // Colour the text being typed in the field editor too.
            if parent.coloured, let editor = field.currentEditor() as? NSTextView, let storage = editor.textStorage {
                let selection = editor.selectedRanges
                storage.setAttributedString(EditorPasswordField.coloured(field.stringValue))
                editor.selectedRanges = selection
            }
        }
    }
}

/// The masked password (LD-199 (1)): a secure field (no copy, secure input
/// while focused, by AppKit) that starts empty with the stored length as
/// dots; what the user types goes straight to Rust (`typed`), and Swift keeps
/// no copy.
struct MaskedPasswordField: NSViewRepresentable {
    let dots: Int
    @Binding var focused: Bool
    var label = "Password"
    /// The muted placeholder while there is no password (the share one's).
    var empty = ""
    let typed: (String) -> Void

    func makeNSView(context: Context) -> FocusSecureField {
        let field = FocusSecureField()
        field.isBordered = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.cell?.isScrollable = true
        field.font = EditorPasswordField.font
        field.setAccessibilityLabel(label)
        let words = dots == 0 && !empty.isEmpty
        let sans = NSFont(name: "IBMPlexSans-Regular", size: 14) ?? .systemFont(ofSize: 14)
        field.placeholderAttributedString = NSAttributedString(
            string: words ? empty : String(repeating: "•", count: dots),
            attributes: [
                .font: words ? sans : EditorPasswordField.font,
                .foregroundColor: NSColor(named: words ? "muted" : "text", bundle: appBundle) ?? .labelColor,
            ])
        field.delegate = context.coordinator
        field.onFocus = { context.coordinator.parent.focused = $0 }
        return field
    }

    func updateNSView(_ field: FocusSecureField, context: Context) {
        context.coordinator.parent = self
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: MaskedPasswordField

        init(_ parent: MaskedPasswordField) { self.parent = parent }

        func controlTextDidChange(_ note: Notification) {
            guard let field = note.object as? NSTextField else { return }
            parent.typed(field.stringValue)
        }
    }
}

/// A secure text field that reports its focus.
final class FocusSecureField: NSSecureTextField {
    var onFocus: ((Bool) -> Void)?

    override func becomeFirstResponder() -> Bool {
        let taken = super.becomeFirstResponder()
        if taken { onFocus?(true) }
        return taken
    }

    override func textDidEndEditing(_ notification: Notification) {
        super.textDidEndEditing(notification)
        onFocus?(false)
    }
}
