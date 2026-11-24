import LarsalCore
import SwiftUI

/// FEA-04.22's setup screen in the mockup's look, with the card's title.
struct TotpSetupSheet: View {
    let model: VaultModel
    let setup: TotpSetup
    @State private var secret = ""
    @State private var digits = 6
    @State private var period: UInt32 = 30
    @State private var algorithm = "SHA-1"
    @State private var algorithms = false
    @State private var secretFocused = false
    @State private var problem: String?

    var body: some View {
        DialogCard(
            tint: "teal", glyph: "clock-countdown", title: "Set up one-time password",
            text: "Paste the secret key or the otpauth:// link the website shows when you turn on two-step sign-in."
        ) {
            DialogBody {
                // LD-199 (5): the secret in the no-copy field, secure input
                // while it has focus (NoCopyTextField).
                InputBox(focused: secretFocused) {
                    Glyph(name: "key").foregroundStyle(Tok.muted)
                    EditorPasswordField(
                        text: $secret, focused: $secretFocused, coloured: false, placeholder: "JBSW Y3DP EHPK 3PXP",
                        label: "Secret key")
                }
                .capsLockNote(focused: secretFocused)  // M06-37 (APP-06.6)
                Help(text: problem ?? "Spaces do not matter. Only letters A–Z and digits 2–7.")
                    .foregroundStyle(problem == nil ? Tok.muted : Tok.negative)
                RowBox(rows: [
                    AnyView(
                        SRow(title: "Digits") {
                            Segments(items: ["6", "7", "8"], selected: digits - 6) { digits = $0 + 6 }
                        }),
                    AnyView(
                        SRow(title: "New code every") {
                            StepBox(
                                value: "\(period) s", less: { period = max(1, period - 1) },
                                more: { period = min(86_400, period + 1) })
                        }),
                    AnyView(SRow(title: "Algorithm") { algorithmPicker }),
                ])
                .padding(.top, 16)
            }
            .onAppear {
                secret = setup.secret
                digits = min(max(Int(setup.digits), 6), 8)
                period = setup.period
                algorithm = setup.algorithm
            }
        } foot: {
            SheetButton(title: "Cancel", cancel: true) { model.dialog = nil }
            SheetButton(title: "Add Code", kind: .primary, action: add)
        }
    }

    private var algorithmPicker: some View {
        Button {
            algorithms.toggle()
        } label: {
            SelectBox(title: algorithm)
        }
        .buttonStyle(Bare())
        .accessibilityLabel(Text(verbatim: "Algorithm, " + algorithm))
        .popover(isPresented: $algorithms, arrowEdge: .bottom) {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(["SHA-1", "SHA-256", "SHA-512"], id: \.self) { name in
                    MenuItem(lead: .check(name == algorithm), title: name) {
                        algorithm = name
                        algorithms = false
                    }
                }
            }
            .padding(6)
            .frame(minWidth: 160)
        }
    }

    private func add() {
        do {
            try model.session.setTotp(
                vault: model.vault.id, secret: secret, digits: UInt32(digits), period: period, algorithm: algorithm)
            secret = ""
            model.editor?.refresh()
            model.editor?.tick()
            model.dialog = nil
        } catch {
            problem = message(error)
        }
    }
}

/// The one-time code as QR (FEA-04.23): the countdown from 44 seconds and
/// Copy come from the card; the symbol from Rust.
struct TotpQrSheet: View {
    let model: VaultModel
    let title: String
    let symbol: Qr
    let custom: Bool
    @State private var seconds = 44

    var body: some View {
        DialogCard(
            tint: "teal", glyph: "qr-code", title: "One-time code for “\(title)”",
            text: "Scan it with another authenticator app. Anyone who sees it can make sign-in codes, "
                + "so close it when you are done."
        ) {
            DialogBody {
                QrPanel(symbol: symbol, filled: true)
                if custom {
                    Help(
                        text: "Not every authenticator app can use these settings. "
                            + "Check that its codes match before you rely on it.")
                }
            }
        } foot: {
            Text(verbatim: "\(seconds) seconds until this window closes")
                .font(.sans(12)).num().foregroundStyle(Tok.muted)
                .frame(maxWidth: .infinity, alignment: .leading)
            SheetButton(title: "Copy", action: copyLink)
            SheetButton(title: "Done", kind: .primary) { model.dialog = nil }
        }
        .task {
            while seconds > 0 {
                try? await Task.sleep(for: .seconds(1))
                if Task.isCancelled { return }
                seconds -= 1
            }
            model.dialog = nil
        }
    }

    private func copyLink() {
        do {
            let copied = try model.session.copyTotpLink(vault: model.vault.id)
            model.notify(.init(glyph: "check", text: copied.label + " copied.", note: "Clears in \(copied.seconds) s."))
        } catch {
            model.notify(.init(glyph: "warning", text: message(error)))
        }
    }
}

/// New group (MOD-02.27): the name, where it goes, and a symbol and colour
/// stored as the group's custom icon (LD-192 (1)).
struct NewGroupSheet: View {
    let model: VaultModel
    @State var name: String
    @State private var colour = "cyan"
    @State private var glyph = "airplane"
    @State private var parent: GroupRow?
    @State private var choosing = false

    private static let colours = ["blue", "green", "orange", "pink", "purple", "cyan"]
    private static let symbols = [
        "airplane", "suitcase", "map-pin", "globe-simple", "house-line", "car", "train", "boat",
    ]

    var body: some View {
        DialogCard(
            tint: "brown", glyph: "folder-simple", title: "New group", text: "Groups sort entries, like folders."
        ) {
            DialogBody {
                VStack(alignment: .leading, spacing: 16) {
                    FieldCell(label: "Name") {
                        InputBox { PlainField(prompt: "", text: $name, label: "Name") }
                    }
                    TwoColumns {
                        FieldCell(label: "Inside") { inside }
                    } right: {
                        FieldCell(label: "Colour") {
                            HStack(spacing: 8) {
                                ForEach(Self.colours, id: \.self) { name in
                                    SwatchChoice(name: name, isOn: colour == name) { colour = name }
                                }
                            }
                            .frame(height: 36)
                        }
                    }
                }
                Lab(title: "Icon").padding(.top, 16)
                HStack(spacing: 6) {
                    ForEach(Self.symbols, id: \.self) { symbol in
                        IconChoice(glyph: symbol, isOn: glyph == symbol, size: 47) { glyph = symbol }
                    }
                }
            }
        } foot: {
            SheetButton(title: "Cancel", cancel: true) { model.dialog = nil }
            SheetButton(title: "Create Group", kind: .primary) {
                model.addGroup(name: name, parent: parent?.id, glyph: glyph, colour: colour)
            }
            .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
        }
    }

    /// The parent: the top level or a group, from a pop-up list.
    private var inside: some View {
        Button {
            choosing.toggle()
        } label: {
            InputBox {
                Text(verbatim: parent?.name ?? "Top level").frame(maxWidth: .infinity, alignment: .leading)
                Glyph(name: "caret-up-down").foregroundStyle(Tok.muted)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .accessibilityLabel(Text(verbatim: "Inside, " + (parent?.name ?? "Top level")))
        .popover(isPresented: $choosing, arrowEdge: .bottom) {
            VStack(alignment: .leading, spacing: 0) {
                MenuItem(lead: .check(parent == nil), title: "Top level") {
                    parent = nil
                    choosing = false
                }
                ForEach(model.sidebar?.groups ?? [], id: \.id) { group in
                    MenuItem(
                        lead: .check(parent?.id == group.id),
                        title: String(repeating: "   ", count: Int(group.depth) + 1) + group.name
                    ) {
                        parent = group
                        choosing = false
                    }
                }
            }
            .padding(6)
            .frame(minWidth: 220)
        }
    }
}

/// A QR symbol from Rust's module matrix, 176 points, in the light text
/// colour on a light 12-point panel (mockup `qr()`, LD-192 (4)).
struct QrPanel: View {
    let symbol: Qr
    let filled: Bool

    var body: some View {
        Canvas { context, size in
            let side = Int(symbol.size)
            guard side > 0 else { return }
            let cell = size.width / CGFloat(side)
            var path = Path()
            for row in 0..<side {
                for column in 0..<side where symbol.modules[row * side + column] == 1 {
                    path.addRect(
                        CGRect(x: CGFloat(column) * cell, y: CGFloat(row) * cell, width: cell, height: cell))
                }
            }
            context.fill(path, with: .color(Tok.text))
        }
        .frame(width: 176, height: 176)
        .padding(13)
        .frame(maxWidth: .infinity)
        .background(filled ? Tok.surface : .clear, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
        // LD-192 (4): dark modules on a light quiet zone in both themes, as
        // scanners need (ISO/IEC 18004); a light panel in the dark sheet.
        .environment(\.colorScheme, .light)
        .accessibilityElement()
        .accessibilityLabel(Text(verbatim: "QR code"))
        .accessibilityAddTraits(.isImage)
    }
}

/// A shown password with digits and symbols coloured (`pwHtml`).
struct PasswordText: View {
    let text: String

    var body: some View {
        text.reduce(Text(verbatim: "")) { line, char in
            let piece = Text(verbatim: String(char))
            if char.isASCII, char.isNumber { return line + piece.foregroundColor(Tok.digit) }
            if (char.isASCII && char.isLetter) || char.isWhitespace { return line + piece }
            return line + piece.foregroundColor(Tok.symbol)
        }
        .font(.mono(14))
        .tracking(0.28)
        .lineLimit(1)
    }
}

/// The attachment questions (MOD-05.5, MOD-05.11, MOD-05.12 rule 3,
/// MOD-05.14): a title, the consequence, the default (No or Cancel) and the
/// action.
struct FileQuestion: View {
    let model: VaultModel
    let dialog: VaultModel.Dialog

    var body: some View {
        let ask = words
        DialogCard(tint: "orange", glyph: "paperclip", title: ask.title, text: ask.text) {
            SheetButton(title: ask.cancel, cancel: true, action: decline)
            SheetButton(title: ask.action, kind: .danger, action: accept)
        }
    }

    /// A question's words: title, consequence, the default and the action.
    private struct Words {
        let title: String
        let text: String
        let cancel: String
        let action: String
    }

    private var words: Words {
        switch dialog {
        case .removeAttachment(let name):
            Words(
                title: "Remove the attachment “\(name)”?", text: "It leaves this entry. Earlier versions keep it.",
                cancel: "Cancel", action: "Remove")
        case .overwriteAttachment(let name):
            Words(
                title: "Overwrite the attachment “\(name)”?",
                text: "The entry already has an attachment with this name.",
                cancel: "No", action: "Overwrite")
        case .bigFile(let name, let megabytes):
            Words(
                title: "Add a big file?",
                text: "“\(name)” is \(megabytes) MB. The vault may become very large and slow.",
                cancel: "No", action: "Yes")
        case .openRisky(let name):
            Words(
                title: "Open “\(name)”?",
                text: "Files of this type can run programs or commands on this Mac when opened.",
                cancel: "Cancel", action: "Open")
        case .replaceFile(let name, _):
            Words(
                title: "Overwrite “\(name)” in that folder?", text: "A file with this name is already there.",
                cancel: "Cancel", action: "Overwrite")
        default: Words(title: "", text: "", cancel: "Cancel", action: "OK")
        }
    }

    private func decline() {
        switch dialog {
        case .overwriteAttachment, .bigFile: model.answerFile(false, overwrite: false)
        default: model.dialog = nil
        }
    }

    private func accept() {
        switch dialog {
        case .removeAttachment(let name):
            let (session, vault) = (model.session, model.vault.id)
            model.editor?.run { try session.removeAttachment(vault: vault, name: name) }
            model.dialog = nil
        case .overwriteAttachment: model.answerFile(true, overwrite: true)
        case .bigFile: model.answerFile(true, overwrite: false)
        case .openRisky(let name): model.openAttachment(name, confirmed: true)
        case .replaceFile(let name, let folder): model.saveAttachment(name, to: folder, overwrite: true)
        default: model.dialog = nil
        }
    }
}
