import AppCore
import SwiftUI

/// The rail's first panel by entry kind: user name, password with its
/// strength line, Wi-Fi security, the live code, the passkey, the SSH key;
/// or the card. Show fetches one value from Rust; Hide drops it (AT-E07).
struct EntryFields {
    let model: VaultModel
    let entry: EntryDetail
    var options = DetailOptions()

    /// Custom fields the layout shows in its own way.
    private static let placed: Set<String> = [
        "Cardholder", "Card number", "Expires", "Security code", "PIN", "Security",
    ]

    var rows: [AnyView] {
        var out: [AnyView] = []
        let wifi = entry.kind == .wiFi
        if entry.kind == .card {
            out += card
        } else {
            if let user = field(.userName) {
                out.append(AnyView(UserRow(model: model, field: user, label: wifi ? "Network name" : "Username")))
            }
            if let password = field(.password) {
                out.append(
                    AnyView(
                        PasswordRow(
                            model: model, field: password, label: wifi ? "Wi-Fi password" : "Password",
                            rating: entry.rating)))
            } else if options.dotsForEmpty {
                // S-CONV-01 (APP-01.23, F-084): an empty password shows as a filled one.
                out.append(
                    AnyView(Fld(label: wifi ? "Wi-Fi password" : "Password") { Masked.line().font(.mono(14)) }))
            }
            if wifi, let security = custom("Security") {
                out.append(
                    AnyView(
                        Fld(label: "Security") {
                            Text(verbatim: security.value).lineLimit(1)
                        } tools: {
                            IconButton(glyph: "qr-code", label: "Show as QR code") { model.showWifiQr() }
                        }))
            }
            if entry.hasTotp {
                out.append(
                    AnyView(
                        CodeRow(code: model.codes[entry.id], hidden: options.hideCodes) { model.copyCode() }
                            .id(entry.id)))
            }
            if let passkey = entry.passkey {
                // LD-219 (1): its user name is masked with the Username row
                // and shows with that row's Show. ponytail: a passkey user on
                // an entry with no user name has no Show here; the editor
                // shows it.
                let shown = field(.userName).map { model.shown[$0.name] != nil } ?? false
                out.append(
                    AnyView(
                        Fld(label: "Passkey") {
                            MaskedUser(user: passkey.user, site: passkey.site, shown: shown).lineLimit(1)
                        } tools: {
                            Glyph(name: "fingerprint").foregroundStyle(Tok.muted).frame(width: 32, height: 32)
                        }))
            }
            if let key = entry.ssh {
                out.append(
                    AnyView(
                        Fld(label: "SSH key · " + key.kind) {
                            Text(verbatim: key.fingerprint).font(.mono(13)).tracking(0.26).lineLimit(1)
                        } tools: {
                            IconButton(glyph: "copy", label: "Copy fingerprint") { model.copyFingerprint() }
                        }))
            }
        }
        for item in entry.fields
        where item.kind == .custom && !(Self.placed.contains(item.name) && placedHere(item.name)) {
            out.append(AnyView(CustomRow(model: model, field: item)))
        }
        return out
    }

    private func placedHere(_ name: String) -> Bool {
        name == "Security" ? entry.kind == .wiFi : entry.kind == .card
    }

    private func field(_ kind: FieldKind) -> FieldView? { entry.fields.first { $0.kind == kind } }
    private func custom(_ name: String) -> FieldView? { entry.fields.first { $0.kind == .custom && $0.name == name } }

    /// A field's Copy (APP-03.1 `copy.field`): the value stays in Rust.
    private func copyButton(_ what: String, field: String) -> some View {
        IconButton(glyph: "copy", label: "Copy " + what) { model.copy(field) }
    }

    /// The card layout: holder, number, then expiry, security code and PIN.
    private var card: [AnyView] {
        let shownNumber = model.shown["Card number"]
        let secret = { (name: String, dots: String) -> String in model.shown[name] ?? dots }
        var out: [AnyView] = []
        if let holder = custom("Cardholder") {
            out.append(AnyView(Fld(label: "Cardholder") { Text(verbatim: holder.value).lineLimit(1) }))
        }
        if custom("Card number") != nil {
            out.append(
                AnyView(
                    Fld(label: "Card number") {
                        Text(verbatim: shownNumber ?? "•••• •••• •••• ••••").font(.mono(14)).tracking(0.28).lineLimit(1)
                    } tools: {
                        IconButton(
                            glyph: shownNumber == nil ? "eye" : "eye-slash",
                            label: shownNumber == nil ? "Show card number" : "Hide card number"
                        ) {
                            Task { await model.toggleShow("Card number") }
                        }
                        copyButton("card number", field: "Card number")
                    }))
        }
        out.append(
            AnyView(
                HStack(spacing: 12) {
                    gridCell("Expires", Text(verbatim: custom("Expires")?.value ?? "—").num())
                    gridCell("Security code", Text(verbatim: secret("Security code", "•••")).font(.mono(14)))
                    gridCell("PIN", Text(verbatim: secret("PIN", "••••")).font(.mono(14)))
                }
                .padding(.leading, 16).padding(.trailing, 8).padding(.vertical, 9).frame(minHeight: 58)))
        return out
    }

    private func gridCell(_ label: String, _ value: some View) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(verbatim: label).font(.sans(12)).foregroundStyle(Tok.muted).frame(height: 16)
            value.frame(minHeight: 20)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}

/// The second panel: group, address, tags, attachments, notes.
struct MoreFields {
    let model: VaultModel
    let entry: EntryDetail
    var options = DetailOptions()

    var rows: [AnyView] {
        var out: [AnyView] = []
        out.append(
            AnyView(
                Fld(label: "Group") {
                    let shown = entry.groupIcon >= 0 || entry.groupCustomIcon != nil
                    if shown, let look = SymbolIcon.look(entry.groupIcon, entry.groupCustomIcon) {
                        HStack(spacing: 8) {
                            Tile(color: look.color, glyph: look.glyph).shareMark(model.sharing.marks[entry.groupId])
                            Text(verbatim: entry.group)
                        }
                    } else {
                        Text(verbatim: entry.group)
                    }
                }))
        let url = entry.fields.first { $0.kind == .url }?.value ?? ""
        if !url.isEmpty && entry.kind != .login {
            out.append(AnyView(Fld(label: "Address") { Text(verbatim: url).lineLimit(1) }))
        }
        if !entry.tags.isEmpty {
            out.append(
                AnyView(
                    Fld(label: "Tags") {
                        Flow {
                            ForEach(entry.tags, id: \.self) { tag in
                                Text(verbatim: "#" + tag)
                                    .font(.sans(12))
                                    .foregroundStyle(Tok.chipInk)
                                    .padding(.horizontal, 8)
                                    .frame(height: 22)
                                    .background(Tok.chipBg, in: RoundedRectangle(cornerRadius: 5))
                            }
                        }
                        .padding(.top, 4)
                    }))
        }
        if !entry.attachments.isEmpty {
            out.append(
                AnyView(
                    Fld(label: "Attachments") {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(Array(entry.attachments.enumerated()), id: \.offset) { _, file in
                                // MOD-05.9 Preview (SD-13): a click on the file.
                                Button {
                                    model.previewAttachment(file.name)
                                } label: {
                                    HStack(spacing: 8) {
                                        Glyph(name: "paperclip")
                                        Text(verbatim: file.name).lineLimit(1)
                                        Text(verbatim: Formats.size(file.size)).font(.sans(12)).num().foregroundStyle(
                                            Tok.muted)
                                    }
                                }
                                .buttonStyle(Bare())
                                .help("Preview")
                                .accessibilityHint(Text(verbatim: "Preview"))
                                .frame(height: 20)
                                .padding(.top, 4)
                            }
                        }
                    }))
        }
        if let notes = entry.fields.first(where: { $0.kind == .notes }) {
            out.append(AnyView(NotesRow(notes: notes, hidden: options.hideNotes).id(entry.id)))
        }
        return out
    }
}

/// The password row: dots or the shown value with digits and symbols
/// coloured (`pwHtml`), the strength line, Show and Copy.
struct PasswordRow: View {
    let model: VaultModel
    let field: FieldView
    let label: String
    let rating: Rating?
    @Environment(\.colourPasswords) private var colour

    var body: some View {
        let shown = model.shown[field.name]
        Fld(label: label) {
            VStack(alignment: .leading, spacing: 2) {
                if let shown {
                    Self.secret(shown, coloured: colour).font(.mono(14)).tracking(0.28).lineLimit(1)
                        .frame(height: 20)
                } else {
                    Text(verbatim: String(repeating: "•", count: min(Int(rating?.chars ?? 12), 18)))
                        .font(.mono(14))
                        .frame(height: 20)
                }
                if let rating {
                    Text(verbatim: "\(rating.word) · \(rating.chars) characters · about \(rating.bits) bits")
                        .font(.sans(12))
                        .num()
                        .foregroundStyle(rating.attention && !rating.expired ? Tok.negative : Tok.muted)
                        .frame(height: 20)
                }
            }
        } tools: {
            IconButton(
                glyph: shown == nil ? "eye" : "eye-slash", label: shown == nil ? "Show password" : "Hide password"
            ) {
                Task { await model.toggleShow(field.name) }
            }
            IconButton(glyph: "copy", label: "Copy password") { model.copy(field.name) }
        }
    }

    /// The shown value: digits and symbols in colour while S-UI-07 is on
    /// (APP-01.24, LD-212 (5)), else plain.
    static func secret(_ text: String, coloured: Bool) -> Text {
        guard coloured else { return Text(verbatim: text) }
        return text.reduce(Text(verbatim: "")) { line, char in
            let piece = Text(verbatim: String(char))
            if char.isASCII, char.isNumber { return line + piece.foregroundColor(Tok.digit) }
            if (char.isASCII && char.isLetter) || char.isWhitespace { return line + piece }
            return line + piece.foregroundColor(Tok.symbol)
        }
    }
}

/// The user name: plain, or masked behind Show while S-VIEW-06 is on
/// (APP-01.23); Show reads it from Rust as the other Show buttons do, and a
/// new selection or a lock drops it. Masked, the buttons name the row:
/// "username", or "network name" for Wi-Fi (LD-219 (3)); unmasked, Copy
/// keeps the frame's "Copy username" (states-wi-fi).
private struct UserRow: View {
    let model: VaultModel
    let field: FieldView
    let label: String
    @Environment(\.maskUserNames) private var mask

    var body: some View {
        let masked = mask && !field.value.isEmpty
        let shown = model.shown[field.name]
        let name = masked ? label.lowercased() : "username"
        Fld(label: label) {
            MaskedUser(user: masked ? shown ?? field.value : field.value, shown: shown != nil).lineLimit(1)
        } tools: {
            if masked {
                IconButton(
                    glyph: shown == nil ? "eye" : "eye-slash", label: (shown == nil ? "Show " : "Hide ") + name
                ) {
                    Task { await model.toggleShow(field.name) }
                }
            }
            IconButton(glyph: "copy", label: "Copy " + name) { model.copy(field.name) }
        }
    }
}

/// Any other field: plain, or dots with Show for a protected one.
private struct CustomRow: View {
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
            }
            IconButton(glyph: "copy", label: "Copy " + field.name) { model.copy(field.name) }
        }
    }
}

/// The notes; behind Show while S-CONV-05 is on (APP-01.23, F-082), hidden
/// again on a new selection.
private struct NotesRow: View {
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
        }
    }
}

/// The live one-time code (`.fld.otp`, FEA-04.14, FEA-04.15); hidden until
/// its button while S-CONV-04 is on (APP-01.23, F-082).
private struct CodeRow: View {
    let code: TotpView?
    var hidden = false
    let copy: () -> Void
    @State private var revealed = false

    var body: some View {
        Fld(label: "One-time code") {
            if hidden && !revealed {
                Masked.line().font(.mono(28, .medium)).frame(height: 34)
            } else if let code, code.problem == nil, code.period > 0 {
                VStack(alignment: .leading, spacing: 0) {
                    Text(verbatim: Codes.shown(code.code))
                        .font(.mono(28, .medium))
                        .tracking(1.12)
                        .frame(height: 34)
                    Capsule()
                        .fill(Tok.active)
                        .frame(height: 4)
                        .overlay(alignment: .leading) {
                            GeometryReader { box in
                                Capsule()
                                    .fill(Tok.accent)
                                    .frame(width: box.size.width * CGFloat(code.secondsLeft) / CGFloat(code.period))
                            }
                        }
                        .padding(.top, 10)
                        .accessibilityHidden(true)
                    Text(verbatim: "New code in \(code.secondsLeft) s")
                        .font(.sans(12))
                        .num()
                        .foregroundStyle(Tok.muted)
                        .frame(height: 20)
                        .padding(.top, 6)
                }
            } else {
                Text(verbatim: code?.problem ?? " ").foregroundStyle(Tok.warning)
            }
        } tools: {
            if hidden {
                IconButton(
                    glyph: revealed ? "eye-slash" : "eye",
                    label: revealed ? "Hide one-time code" : "Show one-time code"
                ) { revealed.toggle() }
            }
            IconButton(glyph: "copy", label: "Copy one-time code", action: copy)
        }
    }
}
