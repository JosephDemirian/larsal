import LarsalCore
import SwiftUI

/// Any other field: plain, or dots with Show and Show as QR Code for a
/// protected one.
struct CustomRow: View {
    let model: VaultModel
    let field: FieldView

    var body: some View {
        let shown = model.shown[field.name]
        Fld(label: field.name) {
            if field.protected {
                Text(verbatim: shown ?? String(repeating: "•", count: 8)).font(.mono(14)).lineLimit(1)
            } else {
                Text(verbatim: field.value).lineLimit(1)
            }
        } tools: {
            if field.protected {
                IconButton(
                    glyph: shown == nil ? "eye" : "eye-slash", label: (shown == nil ? "Show " : "Hide ") + field.name
                ) {
                    Task { await model.toggleShow(field.name) }
                }
                QrFieldButton(model: model, field: field.name)
            }
            IconButton(glyph: "copy", label: "Copy " + field.name) { model.copy(field.name) }
        }
        .qrField(model, field)
    }
}

/// The notes; behind Show while S-CONV-05 is on (APP-01.23, F-082), hidden
/// again on a new selection. Protected notes also take Show as QR Code.
struct NotesRow: View {
    let model: VaultModel
    let notes: FieldView
    let hidden: Bool
    @State private var revealed = false

    var body: some View {
        Fld(label: "Notes") {
            if hidden && !revealed {
                Masked.line().padding(.top, 2)
            } else {
                // `.v.wrap` inside `.v`: 2 more points down, as drawn.
                Text(verbatim: notes.value).lineBox(14, 20).fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 2)
            }
        } tools: {
            if hidden {
                IconButton(glyph: revealed ? "eye-slash" : "eye", label: revealed ? "Hide notes" : "Show notes") {
                    revealed.toggle()
                }
            }
            if notes.protected { QrFieldButton(model: model, field: notes.name) }
        }
        .qrField(model, notes)
    }
}

extension View {
    /// `qrField` for a card row that may not exist.
    func qrFieldOf(_ model: VaultModel, _ field: FieldView?) -> some View {
        Group {
            if let field { qrField(model, field) } else { self }
        }
    }
}
