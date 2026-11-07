import LarsalCore
import SwiftUI

// MARK: Entry

/// The Entry page: sign-in, two-step sign-in, organize, notes.
struct EntryPage: View {
    let model: VaultModel
    let editor: EditorModel
    @State private var tagText = ""
    @State private var urlText = ""
    @State private var addingURL = false
    @State private var groupMenu = false
    @State private var presets = false
    @FocusState private var focus: EditText?

    var body: some View {
        let view = editor.view
        EdSection(title: "Sign-in") {
            VStack(alignment: .leading, spacing: 16) {
                FieldCell(label: "Title") {
                    InputBox(focused: focus == .title) {
                        ProtectedText(editor: editor, field: .title, label: "Title") {
                            PlainField(prompt: "GitHub, Bank, Home Wi-Fi…", text: text(.title), label: "Title")
                                .focused($focus, equals: .title)
                        }
                    }
                }
                TwoColumns {
                    FieldCell(label: "Username") {
                        InputBox(focused: focus == .userName) {
                            Glyph(name: "user").foregroundStyle(Tok.muted)
                            ProtectedText(editor: editor, field: .userName, label: "Username") {
                                PlainField(prompt: "name@example…", text: text(.userName), label: "Username")
                                    .focused($focus, equals: .userName)
                            }
                        }
                    }
                } right: {
                    PasswordCell(model: model, editor: editor)
                }
                website(view)
            }
        }
        EdSection(title: "Two-step sign-in") { TwoStepPanel(model: model, editor: editor) }
        EdSection(title: "Organize") {
            VStack(alignment: .leading, spacing: 16) {
                TwoColumns {
                    FieldCell(label: "Group") { groupBox(view) }
                } right: {
                    FieldCell(label: "Tags") { tagBox(view) }
                }
                FieldCell(label: "Expires") { expiry(view) }
            }
        }
        EdSection(title: "Notes") {
            ProtectedText(editor: editor, field: .notes, label: "Notes", boxed: true) { NotesBox(text: text(.notes)) }
        }
    }

    private func text(_ field: EditText) -> Binding<String> {
        Binding(
            get: {
                if let shown = editor.shownFields[field.name] { return shown }  // a protected one, shown (F-060)
                return switch field {
                case .title: editor.view.title
                case .userName: editor.view.user
                case .url: editor.view.url
                case .notes: editor.view.notes
                }
            },
            set: { editor.set(field, $0) })
    }

    private func website(_ view: EditorView) -> some View {
        FieldCell(label: "Website") {
            InputBox(focused: focus == .url) {
                Glyph(name: "globe-simple").foregroundStyle(Tok.muted)
                ProtectedText(editor: editor, field: .url, label: "Website") {
                    PlainField(prompt: "https://…", text: text(.url), label: "Website").focused($focus, equals: .url)
                }
                if !view.new {
                    IconButton(glyph: "arrow-square-out", label: "Open website", size: 28) { model.openURL() }
                        .disabled(view.url.isEmpty)
                }
            }
        } help: {
            WebsiteRows(view: view)
            if !view.new { urlHelp(view) }
        }
    }

    /// "+ Add another website · gist.github.com is also allowed": the Allow hosts (INT-03.18, INT-02.29).
    @ViewBuilder
    private func urlHelp(_ view: EditorView) -> some View {
        HStack(spacing: 0) {
            LinkButton(title: "+ Add another website") { addingURL.toggle() }
                .popover(isPresented: $addingURL, arrowEdge: .bottom) {
                    HStack(spacing: 8) {
                        InputBox { PlainField(prompt: "https://…", text: $urlText, label: "Another website") }
                            .frame(width: 280)
                            .onSubmit(addURL)
                        Button("Add", action: addURL).buttonStyle(Btn())
                    }
                    .padding(12)
                }
            if !view.allow.isEmpty {
                Text(verbatim: " · " + view.allow.joined(separator: ", ") + " is also allowed")
                    .font(.sans(12)).foregroundStyle(Tok.muted)
            }
        }
        .frame(height: 16)
        .padding(.top, 6)
    }

    private func addURL() {
        let url = urlText
        editor.run { try editor.session.addUrl(vault: editor.vault.id, url: url) }
        urlText = ""
        addingURL = false
    }

    private func groupBox(_ view: EditorView) -> some View {
        Button {
            groupMenu.toggle()
        } label: {
            InputBox {
                if let look = SymbolIcon.look(view.groupIcon, view.groupCustomIcon) {
                    Tile(color: look.color, glyph: look.glyph)
                }
                Text(verbatim: view.groupName).frame(maxWidth: .infinity, alignment: .leading)
                Glyph(name: "caret-up-down").foregroundStyle(Tok.muted)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .accessibilityLabel(Text(verbatim: "Group, " + view.groupName))
        .popover(isPresented: $groupMenu, arrowEdge: .bottom) {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(view.groups, id: \.id) { group in
                    MenuItem(
                        lead: .check(group.id == view.group),
                        title: String(repeating: "   ", count: Int(group.depth)) + group.name
                    ) {
                        editor.run { try editor.session.setGroup(vault: editor.vault.id, group: group.id) }
                        groupMenu = false
                    }
                }
            }
            .padding(6)
            .frame(minWidth: 232)
        }
    }

    private func tagBox(_ view: EditorView) -> some View {
        InputBox(focused: focus == .notes && false, gap: 6) {
            ForEach(view.tags, id: \.self) { tag in
                Chip(text: "#" + tag) { setTags(view.tags.filter { $0 != tag }) }
            }
            PlainField(prompt: "Add a tag…", text: $tagText, label: "Add a tag")
                .onSubmit {
                    let typed = tagText.trimmingCharacters(in: .whitespaces)
                    if !typed.isEmpty {
                        setTags(view.tags + [typed.hasPrefix("#") ? String(typed.dropFirst()) : typed])
                    }
                    tagText = ""
                }
        }
    }

    private func setTags(_ tags: [String]) {
        editor.run { try editor.session.setTags(vault: editor.vault.id, chips: tags) }
    }

    /// Expires (MOD-09): the switch, the date and the presets.
    private func expiry(_ view: EditorView) -> some View {
        HStack(spacing: 8) {
            Switch(
                label: "Expires",
                isOn: Binding(
                    get: { view.expires },
                    set: { value in
                        editor.run { try editor.session.setExpiry(vault: editor.vault.id, on: value, at: nil) }
                    }))
            dateBox(view)
            Button {
                presets.toggle()
            } label: {
                HStack(spacing: 6) {
                    Text(verbatim: "In 3 months")
                    Glyph(name: "caret-down")
                }
            }
            .buttonStyle(Btn())
            .disabled(!view.expires)
            .opacity(view.expires ? 1 : 0.55)
            .popover(isPresented: $presets, arrowEdge: .bottom) {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(Self.presets.enumerated()), id: \.offset) { index, title in
                        MenuItem(lead: .glyph("calendar-blank"), title: title) {
                            let offset = Int32(TimeZone.current.secondsFromGMT())
                            editor.run {
                                _ = try editor.session.expiryPreset(
                                    vault: editor.vault.id, index: UInt32(index), utcOffset: offset)
                            }
                            presets = false
                        }
                    }
                }
                .padding(6)
                .frame(minWidth: 200)
            }
        }
    }

    /// MOD-09.10: a date-time field in local time while Expires is on;
    /// "Never" while off.
    private func dateBox(_ view: EditorView) -> some View {
        InputBox(off: !view.expires) {
            Glyph(name: "calendar-blank").foregroundStyle(Tok.muted)
            if view.expires {
                DatePicker(
                    "Expiry date",
                    selection: Binding(
                        get: { Formats.date(view.expiry) },
                        set: { date in
                            let time = Int64(date.timeIntervalSince1970)
                            editor.run { try editor.session.setExpiry(vault: editor.vault.id, on: true, at: time) }
                        }),
                    displayedComponents: [.date, .hourAndMinute]
                )
                .datePickerStyle(.field)
                .labelsHidden()
                .font(.sans(14))
                .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                PlainField(prompt: "Never", text: .constant(""), label: "Expiry date").disabled(true)
            }
        }
        .frame(maxWidth: view.expires ? 260 : 200)
    }

    /// MOD-09.11's presets, in menu order.
    static let presets = [
        "In 12 hours", "In 24 hours", "In 1 week", "In 2 weeks", "In 3 weeks", "In 1 month", "In 2 months",
        "In 3 months", "In 6 months", "In 1 year", "In 2 years", "In 3 years",
    ]
}

/// The password cell: the label with its strength, the field (shown or dots),
/// Show or Hide, Show as QR Code, the generator (E5-S6) and the strength bar.
private struct PasswordCell: View {
    let model: VaultModel
    let editor: EditorModel
    @State private var focused = false
    /// The shown password is in the text field (F-102).
    @State private var editing = false

    var body: some View {
        let rating = editor.rating
        FieldCell(label: "Password", small: rating.map { "· \($0.level), about \($0.bits) bits" }) {
            InputBox(focused: focused) {
                if let shown = editor.shownPassword, editing {
                    EditorPasswordField(
                        text: Binding(get: { shown }, set: { editor.passwordTyped($0) }), focused: $focused,
                        focusOnAppear: true
                    )
                    .accessibilityLabel(Text(verbatim: "Password"))
                } else if let shown = editor.shownPassword {
                    EditorShownPassword(text: shown) { editing = true }  // F-102
                } else {
                    // LD-199 (1): masked, a secure field; typing goes to Rust.
                    MaskedPasswordField(dots: min(Int(editor.view.passwordChars), 18), focused: $focused) {
                        editor.maskedTyped($0)
                    }
                    .id(editor.applied)
                    .accessibilityLabel(Text(verbatim: "Password"))
                }
                IconButton(
                    glyph: editor.shownPassword == nil ? "eye" : "eye-slash",
                    label: editor.shownPassword == nil ? "Show password" : "Hide password", size: 28
                ) { editor.toggleShowPassword() }
                // APP-08.14: ⌃H shows or hides the text, ⌃G opens the generator.
                .keyboardShortcut("h", modifiers: .control)
                IconButton(glyph: "qr-code", label: QrText.title, size: 28) { editor.showQr("Password") }.qrInvoker()
                IconButton(glyph: "password", label: "Open generator (⌥⌘G)", size: 28) {
                    model.openGenerator(fromEditor: true)
                }
                .keyboardShortcut("g", modifiers: [.option, .command])
                .background {
                    Button("") { model.openGenerator(fromEditor: true) }
                        .keyboardShortcut("g", modifiers: .control)
                        .opacity(0)
                        .focusable(false)
                        .accessibilityHidden(true)
                }
            }
            // F-102: out of the field, or Hide, the shown text comes back.
            .onChange(of: focused) { _, now in if !now { editing = false } }
            .onChange(of: editor.shownPassword == nil) { _, hidden in if hidden { editing = false } }
            .capsLockNote(focused: focused)  // M06-37 (APP-06.6)
        } help: {
            Capsule()
                .fill(Tok.active)
                .frame(height: 3)
                .overlay(alignment: .leading) {
                    GeometryReader { box in
                        Capsule()
                            .fill(color(rating))
                            .frame(width: box.size.width * min(1, CGFloat(rating?.bits ?? 0) / 128))
                    }
                }
                .clipShape(Capsule())
                .padding(.top, 8)
                .accessibilityHidden(true)
        }
    }

    private func color(_ rating: Rating?) -> Color {
        guard let rating else { return Tok.positive }
        return rating.segments >= 3 ? Tok.positive : rating.segments == 2 ? Tok.warning : Tok.negative
    }
}

/// Two-step sign-in: the one-time code and the passkey (FEA-04, INT-04.51).
private struct TwoStepPanel: View {
    let model: VaultModel
    let editor: EditorModel

    var body: some View {
        let view = editor.view
        var rows: [AnyView] = [view.totp.map { AnyView(codeRow($0)) } ?? AnyView(addRow)]
        if let passkey = view.passkey {
            rows.append(AnyView(passkeyRow(passkey)))
        } else if !view.new {
            rows.append(
                AnyView(
                    Fld(label: "Passkey") {
                        Text(verbatim: "None. The browser extension saves passkeys here.").foregroundStyle(Tok.muted)
                    }))
        }
        return Panel(rows: rows)
    }

    private func codeRow(_ totp: TotpInfo) -> some View {
        let every = totp.steam ? "5 characters every \(totp.period) s" : "\(totp.digits) digits every \(totp.period) s"
        return Fld(label: "One-time code · " + every) {
            Text(verbatim: editor.code.map { Codes.shown($0.code) } ?? " ")
                .font(.mono(18, .medium))
                .tracking(0.36)
                .frame(height: 20)
        } tools: {
            Button(action: showQr) { BtnLabel(glyph: "qr-code", title: "Show QR") }
                .buttonStyle(Btn(size: .small))
            Button("Change…", action: setup).buttonStyle(Btn(size: .small))
        }
    }

    private var addRow: some View {
        HStack(spacing: 4) {
            VStack(alignment: .leading, spacing: 0) {
                Text(verbatim: "One-time code").frame(height: 20).padding(.top, 2)
                Text(verbatim: "Paste the secret key a website shows when you turn on two-step sign-in.")
                    .font(.sans(12)).foregroundStyle(Tok.muted).frame(height: 16)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Button(action: setup) { BtnLabel(glyph: "plus", title: "Add one-time code…") }
                .buttonStyle(Btn())
        }
        .padding(.leading, 16).padding(.trailing, 8).padding(.vertical, 9)
    }

    private func passkeyRow(_ passkey: PasskeyView) -> some View {
        Fld(label: "Passkey") {
            // LD-219 addendum: masked while S-VIEW-06 is on.
            MaskedUser(user: passkey.user, site: passkey.site).lineLimit(1)
        } tools: {
            Button {
                model.dialog = .removePasskey(site: passkey.site)
            } label: {
                Text(verbatim: "Remove").foregroundStyle(Tok.negative)
            }
            .buttonStyle(Btn(size: .small))
        }
    }

    private func setup() {
        if let setup = try? editor.session.totpSetup(vault: editor.vault.id) { model.dialog = .totpSetup(setup) }
    }

    private func showQr() {
        do {
            let symbol = try editor.session.totpQr(vault: editor.vault.id)
            model.dialog = .totpQr(title: editor.view.title, symbol: symbol, custom: editor.view.totp?.custom == true)
        } catch {
            editor.problem = message(error)
        }
    }
}
