import AppCore
import AppKit
import SwiftUI

extension EditText {
    /// The stored field name, as `show_draft_field` takes it.
    var name: String {
        switch self {
        case .title: "Title"
        case .userName: "UserName"
        case .url: "URL"
        case .notes: "Notes"
        }
    }
}

/// A standard text field of the Entry page that may be protected (F-060,
/// rule 4; by its own flag or the vault's, LD-207): unprotected, the field
/// itself; protected, dots and Show, as the protected custom fields. Rust
/// gives the value only on Show; while it is masked nothing can be typed,
/// so the stored value stays. Shown, the field edits it (it stays
/// protected) and Hide drops it. The field keeps its place in the tree, so
/// typing goes on when a vault flag masks it after the first key. With
/// S-CONV-05 the notes are hidden too, with a reveal button (APP-01.23,
/// F-082); the reveal is local, the text is already in the draft's view.
struct ProtectedText<Field: View>: View {
    let editor: EditorModel
    let field: EditText
    let label: String
    var boxed = false
    @ViewBuilder let content: () -> Field
    @Environment(\.detailOptions) private var options
    @State private var revealed = false

    var body: some View {
        let protected = editor.view.protected.contains(field)
        let shown = editor.shownFields[field.name] != nil
        let concealed = !protected && field == .notes && options.hideNotes
        let toggle = { if protected { editor.toggleShowField(field.name) } else { revealed.toggle() } }
        HStack(alignment: .top, spacing: 8) {
            if protected ? !shown : concealed && !revealed {
                let masked = MaskedRow(label: label, show: toggle)
                if boxed { InputBox { masked } } else { masked }
            } else {
                // F-127: shown, a protected value keeps no undo copies.
                content().background(UndoOff(off: protected).accessibilityHidden(true))
            }
            if protected ? shown : concealed && revealed {
                IconButton(glyph: "eye-slash", label: "Hide " + label, size: 28, action: toggle)
            }
        }
    }
}

/// F-127 (LD-237 (2)): a protected value shown in clear keeps no undo
/// copies, as F-069's shown password: the text field's cell gets
/// `allowsUndo` off, and the field editor takes it when editing starts.
/// SwiftUI gives no handle on its field's cell, so this empty view behind
/// the field finds the AppKit text field laid over its middle. A field being
/// edited when its value turns protected (a vault flag after the first key)
/// stops keeping copies at once. F-136: SwiftUI gives every window one field
/// editor, and a window released in the middle of an edit leaves its undo
/// on, which an edit in a cell that keeps none does not change; so the
/// probe also runs when its window's first responder changes, as the edit
/// starts. ponytail: a view-tree search after each frame change; an AppKit
/// field of App's own if SwiftUI ever draws text fields another way.
struct UndoOff: NSViewRepresentable {
    let off: Bool

    func makeNSView(context: Context) -> Probe { Probe() }

    func updateNSView(_ probe: Probe, context: Context) {
        probe.off = off
        probe.apply()
    }

    final class Probe: NSView {
        var off = false
        private var responder: NSKeyValueObservation?

        /// Never takes a click from the field.
        override func hitTest(_ point: NSPoint) -> NSView? { nil }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            responder = window?.observe(\.firstResponder) { [weak self] _, _ in
                MainActor.assumeIsolated { self?.set() }
            }
            apply()
        }

        override func setFrameSize(_ size: NSSize) {
            super.setFrameSize(size)
            apply()
        }

        override func setFrameOrigin(_ origin: NSPoint) {
            super.setFrameOrigin(origin)
            apply()
        }

        /// After SwiftUI's update and layout, when both views have their
        /// place in the window.
        func apply() {
            DispatchQueue.main.async { [weak self] in self?.set() }
        }

        private func set() {
            guard let root = window?.contentView, !bounds.isEmpty else { return }
            let area = convert(bounds, to: nil)
            for field in Self.fields(in: root) {
                let place = field.convert(field.bounds, to: nil)
                guard area.contains(NSPoint(x: place.midX, y: place.midY)) else { continue }
                field.cell?.allowsUndo = !off
                if off, let editor = field.currentEditor() as? NSTextView, editor.allowsUndo {
                    editor.breakUndoCoalescing()
                    editor.allowsUndo = false
                }
            }
        }

        private static func fields(in view: NSView) -> [NSTextField] {
            view.subviews.flatMap { [$0 as? NSTextField].compactMap { $0 } + fields(in: $0) }
        }
    }
}

/// A protected value not shown: dots and Show (F-060).
struct MaskedRow: View {
    let label: String
    let show: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            Text(verbatim: Self.dots)
                .font(.mono(13))
                .foregroundStyle(Tok.muted)
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityLabel(Text(verbatim: label))
                .accessibilityValue(Text(verbatim: Self.dots))
            IconButton(glyph: "eye", label: "Show " + label, size: 28, action: show)
        }
    }

    static let dots = String(repeating: "•", count: 12)
}

/// `.ta`: notes, at least 96 tall.
struct NotesBox: View {
    @Binding var text: String
    @FocusState private var focused: Bool

    var body: some View {
        TextField(
            "", text: $text,
            prompt: Text(verbatim: "Anything you want to keep with this entry").foregroundStyle(Tok.muted),
            axis: .vertical
        )
        .textFieldStyle(.plain)
        .font(.sans(14))
        .lineSpacing(2)
        .foregroundStyle(Tok.text)
        .focused($focused)
        .padding(.horizontal, 13)
        .padding(.vertical, 11)
        .frame(maxWidth: .infinity, minHeight: 96, alignment: .topLeading)
        .contentShape(Rectangle())
        .onTapGesture { focused = true }
        .background(Tok.field, in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(focused ? Tok.accent : Tok.control))
        .accessibilityLabel(Text(verbatim: "Notes"))
    }
}
