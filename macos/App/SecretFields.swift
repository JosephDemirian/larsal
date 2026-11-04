import AppCore
import AppKit
import SwiftUI

/// A password field of the wizard (APP-07.11): masked and secure while
/// hidden, typing straight to Rust; in clear, mono, after Show. Swift keeps
/// no copy of what is typed while it is hidden: what Rust holds shows as
/// dots until the user types again.
struct SecretField: View {
    let shown: String?
    var dots = 0
    let label: String
    let turn: Int
    @Binding var focused: Bool
    let typed: (String) -> Void

    var body: some View {
        Group {
            if let shown {
                ShownSecret(text: shown, label: label, focused: $focused, typed: typed)
            } else {
                HiddenSecret(label: label, dots: dots, focused: $focused, typed: typed)
            }
        }
        .id(turn)
        .accessibilityLabel(Text(verbatim: label))
    }
}

private let secretFont =
    NSFont(name: "IBMPlexMono-Regular", size: 15) ?? .monospacedSystemFont(ofSize: 15, weight: .regular)

/// The masked field: AppKit's secure field (secure input while focused).
private struct HiddenSecret: NSViewRepresentable {
    let label: String
    let dots: Int
    @Binding var focused: Bool
    let typed: (String) -> Void

    func makeNSView(context: Context) -> FocusSecureField {
        let field = FocusSecureField()
        field.isBordered = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.cell?.isScrollable = true
        field.font = secretFont
        field.placeholderAttributedString = NSAttributedString(
            string: String(repeating: "•", count: min(dots, 18)),
            attributes: [.font: secretFont, .foregroundColor: NSColor(named: "text", bundle: appBundle) ?? .labelColor])
        field.setAccessibilityLabel(label)
        field.delegate = context.coordinator
        field.onFocus = { context.coordinator.parent.focused = $0 }
        return field
    }

    func updateNSView(_ field: FocusSecureField, context: Context) {
        context.coordinator.parent = self
        if focused, field.currentEditor() == nil, let window = field.window {
            Task { window.makeFirstResponder(field) }
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: HiddenSecret

        init(_ parent: HiddenSecret) { self.parent = parent }

        func controlTextDidChange(_ note: Notification) {
            guard let field = note.object as? NSTextField else { return }
            parent.typed(field.stringValue)
        }
    }
}

/// The shown field: the no-copy field (APP-03.19), digits and symbols
/// coloured as `pwHtml` draws them.
private struct ShownSecret: NSViewRepresentable {
    let text: String
    let label: String
    @Binding var focused: Bool
    let typed: (String) -> Void

    func makeNSView(context: Context) -> NoCopyTextField {
        let field = NoCopyTextField()
        field.isBordered = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.usesSingleLineMode = true
        field.isAutomaticTextCompletionEnabled = false
        field.cell?.isScrollable = true
        field.cell?.lineBreakMode = .byClipping
        field.font = secretFont
        field.setAccessibilityLabel(label)
        field.delegate = context.coordinator
        field.onFocus = { context.coordinator.parent.focused = $0 }
        field.attributedStringValue = Self.coloured(text)
        return field
    }

    func updateNSView(_ field: NoCopyTextField, context: Context) {
        context.coordinator.parent = self
        if field.stringValue != text { field.attributedStringValue = Self.coloured(text) }
        if focused, field.currentEditor() == nil, let window = field.window {
            Task { window.makeFirstResponder(field) }
        }
    }

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
                    string: String(char), attributes: [.font: secretFont, .foregroundColor: color, .kern: 0.3]))
        }
        return out
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: ShownSecret

        init(_ parent: ShownSecret) { self.parent = parent }

        func controlTextDidChange(_ note: Notification) {
            guard let field = note.object as? NSTextField else { return }
            parent.typed(field.stringValue)
            if let editor = field.currentEditor() as? NSTextView, let storage = editor.textStorage {
                let selection = editor.selectedRanges
                storage.setAttributedString(ShownSecret.coloured(field.stringValue))
                editor.selectedRanges = selection
            }
        }
    }
}
