import LarsalCore
import SwiftUI

// MARK: Advanced

/// Custom fields and attachments (MOD-01.2 to MOD-01.6, MOD-05).
struct AdvancedPage: View {
    let model: VaultModel
    let editor: EditorModel
    @State private var dropping = false

    var body: some View {
        let view = editor.view
        EdSection(
            title: "Custom fields",
            lead: "Extra values kept with the entry. Protected values stay hidden and encrypted in memory."
        ) {
            if !view.custom.isEmpty {
                MiniTable(
                    header: Self.fieldColumns, rows: view.custom.map { row($0) }, columns: Self.fieldColumns)
            }
            Button {
                editor.run { _ = try editor.session.addField(vault: editor.vault.id) }
            } label: {
                BtnLabel(glyph: "plus", title: "Add field")
            }
            .buttonStyle(Btn())
            .padding(.top, view.custom.isEmpty ? 0 : 12)
        }
        EdSection(title: "Attachments") {
            if !view.attachments.isEmpty {
                MiniTable(
                    header: Self.fileColumns, rows: view.attachments.map { file($0) }, columns: Self.fileColumns,
                    cellHeight: 32)
            }
            dropZone.padding(.top, view.attachments.isEmpty ? 0 : 12)
        }
    }

    static let fieldColumns = [
        MiniColumn(title: "Name", width: 230), MiniColumn(title: "Value"), MiniColumn(title: "Protected", width: 119),
        MiniColumn(width: 76, trailing: true),
    ]
    static let fileColumns = [
        MiniColumn(title: "File"), MiniColumn(title: "Size", width: 64, trailing: true),
        MiniColumn(width: 170, trailing: true),
    ]

    private func row(_ field: CustomFieldView) -> [AnyView] {
        let id = editor.vault.id
        let session = editor.session
        return [
            AnyView(
                CellField(text: field.name, weight: .medium, label: "Name of " + field.name) { name in
                    editor.run { try session.renameField(vault: id, old: field.name, name: name) }
                }),
            field.protected
                ? AnyView(
                    HStack(spacing: 4) {
                        Button {
                            editor.toggleShowField(field.name)
                        } label: {
                            Text(verbatim: editor.shownFields[field.name] ?? String(repeating: "•", count: 20))
                                .font(.mono(13))
                        }
                        .buttonStyle(Bare())
                        .accessibilityLabel(
                            Text(verbatim: (editor.shownFields[field.name] == nil ? "Show " : "Hide ") + field.name)
                        )
                        // What it draws: dots while protected (rule 4).
                        .accessibilityValue(
                            Text(verbatim: editor.shownFields[field.name] ?? String(repeating: "•", count: 20)))
                        Spacer(minLength: 0)
                        IconButton(glyph: "qr-code", label: QrText.title, size: 28) { editor.showQr(field.name) }
                            .qrInvoker()
                    }
                    .focusedValue(\.qrField, field.name))
                : AnyView(
                    CellField(text: field.value, label: "Value of " + field.name) { value in
                        editor.run { try session.setField(vault: id, name: field.name, value: value) }
                    }),
            AnyView(
                Switch(
                    label: "Protect " + field.name,
                    isOn: Binding(
                        get: { field.protected },
                        set: { value in editor.run { try session.protectField(vault: id, name: field.name, on: value) }
                        }))),
            AnyView(
                HStack(spacing: 0) {
                    IconButton(glyph: "copy", label: "Copy", size: 28) { model.copy(field.name) }
                        .disabled(editor.view.new)
                    IconButton(glyph: "trash", label: "Remove field", size: 28) {
                        model.dialog = .removeField(name: field.name)
                    }
                }),
        ]
    }

    private func file(_ file: AttachmentView) -> [AnyView] {
        [
            AnyView(
                HStack(spacing: 0) {
                    Glyph(name: "file-text")
                    Text(verbatim: file.name)
                }),
            AnyView(Text(verbatim: Formats.size(file.size)).num()),
            AnyView(
                // Inline buttons a space apart, as the mockup's `td.act`.
                HStack(spacing: 3) {
                    Button("Open") { model.openAttachment(file.name) }
                        .buttonStyle(Btn(size: .small))
                        .fixedSize()
                        // MOD-05.12 rule 5.
                        .help("The file is decrypted on disk while it is open.")
                    Button("Save…") { saveAttachment(file.name) }.buttonStyle(Btn(size: .small)).fixedSize()
                    IconButton(glyph: "trash", label: "Remove", size: 28) {
                        model.dialog = .removeAttachment(name: file.name)
                    }
                }
                .padding(.top, 4)),
        ]
    }

    /// Save… (MOD-05.14): a folder, not a file name.
    private func saveAttachment(_ name: String) {
        guard let url = VaultModel.attachmentFolderPanel() else { return }
        model.saveAttachment(name, to: url.path(percentEncoded: false))
    }

    /// `.empty`: the attachment drop target, the only drop target of the
    /// editor (AT-E06, LD-153): file URLs only.
    private var dropZone: some View {
        HStack(spacing: 0) {
            Glyph(name: "upload-simple")
            Text(verbatim: " Drop files here, or ")
            Button {
                chooseFiles()
            } label: {
                Text(verbatim: "choose files…").font(.sans(14, .medium)).foregroundStyle(Tok.accent)
            }
            .buttonStyle(Bare())
            // LD-192 (3): MOD-05.16's limit.
            Text(verbatim: " · up to 1 GB each")
        }
        .foregroundStyle(Tok.muted)
        .frame(height: 20)
        .frame(maxWidth: .infinity)
        .padding(21)
        .background(dropping ? Tok.accentSoft : .clear, in: RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10).strokeBorder(
                dropping ? Tok.accent : Tok.control, style: StrokeStyle(lineWidth: 1, dash: [4, 3]))
        )
        .dropDestination(for: URL.self) { urls, _ in
            let files = urls.filter(\.isFileURL)
            add(files)
            return !files.isEmpty
        } isTargeted: {
            dropping = $0
        }
    }

    private func chooseFiles() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        guard panel.runModal() == .OK else { return }
        add(panel.urls)
    }

    /// Adds files one by one, asking about a same name and a big file first
    /// (MOD-05.5, MOD-05.6).
    private func add(_ urls: [URL]) {
        editor.pending += urls.map { EditorModel.PendingFile(url: $0) }
        Task { model.dialog = await editor.nextFile() }
    }
}

/// A table cell that reads as text and edits in place; the change goes to
/// Rust when typing ends.
private struct CellField: View {
    let text: String
    var weight = Font.Weight.regular
    let label: String
    let commit: (String) -> Void
    @State private var typed: String?

    var body: some View {
        TextField("", text: Binding(get: { typed ?? text }, set: { typed = $0 }))
            .textFieldStyle(.plain)
            .font(.sans(13, weight))
            .foregroundStyle(Tok.text)
            .autocorrectionDisabled()
            .accessibilityLabel(Text(verbatim: label))
            .onSubmit(done)
            .onChange(of: text) { typed = nil }
            .onDisappear(perform: done)
    }

    private func done() {
        if let typed, typed != text { commit(typed) }
        typed = nil
    }
}

// MARK: Icon

/// The icon page (MOD-06): the website logo, a symbol and colour (stored as
/// a custom icon, LD-192 (1)), or the group's icon.
struct IconPage: View {
    let editor: EditorModel

    static let symbols = [
        "key", "lock-simple", "globe-simple", "envelope-simple", "bank", "credit-card", "shopping-bag", "briefcase",
        "house-line", "wifi-high", "hard-drives", "terminal-window", "database", "cloud", "device-mobile", "desktop",
        "game-controller", "film-strip", "music-notes", "airplane", "car", "heart", "student", "certificate",
        "identification-card", "shield-check", "users-three", "chat-circle", "printer", "star",
    ]
    static let colours = ["blue", "teal", "green", "orange", "pink", "red", "purple", "brown", "slate", "gray"]

    var body: some View {
        let view = editor.view
        let symbol = SymbolIcon.parse(view.customIcon)
        let current = symbol ?? Self.standard(view.icon) ?? ("key", "blue")
        let groupCustom = view.groupCustomIcon != nil && view.customIcon == view.groupCustomIcon
        let brand = view.icon == 0 && symbol == nil && Brands.match(host: view.host) != nil
        let group = !brand && (groupCustom || (symbol == nil && view.icon == view.groupIcon && view.groupIcon >= 0))
        EdSection(title: "Icon", lead: "The icon shows in the list and the sidebar.") {
            VStack(spacing: 8) {
                Choice(
                    isOn: brand, title: "Website logo",
                    note: "The \(view.title) logo, stored in the vault. Fetched once from the logo set that ships "
                        + "with Larsal: nothing is downloaded.",
                    trailing: AnyView(EntryLogo(title: view.title, host: view.host, icon: 0, size: .large))
                ) { set(0) }
                .disabled(Brands.match(host: view.host) == nil)
                Choice(isOn: !brand && !group, title: "Symbol and colour", note: "Pick one below.") {
                    editor.chooseSymbol(current.0, current.1)
                }
                Choice(
                    isOn: group, title: "The group's icon", note: "Follows the \(view.groupName) group.",
                    trailing: SymbolIcon.look(view.groupIcon, view.groupCustomIcon).map {
                        AnyView(Tile(color: $0.color, glyph: $0.glyph, size: 44))
                    }
                ) {
                    if let mark = SymbolIcon.parse(view.groupCustomIcon) {
                        editor.chooseSymbol(mark.glyph, mark.color)
                    } else {
                        set(view.groupIcon)
                    }
                }
            }
        }
        EdSection(title: "Symbols") {
            VStack(alignment: .leading, spacing: 16) {
                Flow(spacing: 6) {
                    ForEach(Self.symbols, id: \.self) { glyph in
                        IconChoice(glyph: glyph, isOn: glyph == current.0) { editor.chooseSymbol(glyph, current.1) }
                    }
                }
                HStack(spacing: 16) {
                    Text(verbatim: "Colour").font(.sans(13, .medium))
                    HStack(spacing: 8) {
                        ForEach(Self.colours, id: \.self) { name in
                            SwatchChoice(name: name, isOn: current.1 == name) { editor.chooseSymbol(current.0, name) }
                        }
                    }
                }
            }
            .padding(17)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
        }
    }

    /// A standard icon's glyph and colour names.
    static func standard(_ number: Int32) -> (String, String)? {
        guard number >= 0, Int(number) < StandardIcons.table.count else { return nil }
        let item = StandardIcons.table[Int(number)]
        return (item.glyph, item.color)
    }

    private func set(_ number: Int32) {
        editor.run { try editor.session.setIcon(vault: editor.vault.id, number: number) }
    }
}

// MARK: Auto-Type

/// Auto-Type (MOD-01.18, INT-05): the switch, the sequence and the windows.
struct AutoTypePage: View {
    let editor: EditorModel
    @State private var sequence: String?

    var body: some View {
        let auto = editor.view.autoType
        let custom = !auto.sequence.isEmpty || sequence != nil
        EdSection {
            VStack(spacing: 0) {
                // LD-167: the card's words.
                SRow(
                    title: "Let Auto-Type use this entry",
                    detail: "Types the sign-in into the window in front when you press ⌃⌥V."
                ) {
                    Switch(label: "Auto-Type", isOn: Binding(get: { auto.enabled }, set: { set($0, auto.sequence) }))
                }
            }
            // `.panel`: the row inside its 1-point border.
            .padding(1)
            .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
        }
        EdSection(title: "Sequence") {
            VStack(spacing: 8) {
                Choice(isOn: !custom, title: "Use the group's sequence", note: auto.groupSequence, mono: true) {
                    sequence = nil
                    set(auto.enabled, "")
                }
                Choice(isOn: custom, title: "Custom sequence", extra: AnyView(customSequence(auto))) {
                    if !custom { sequence = auto.groupSequence }
                }
            }
        }
        EdSection(title: "Windows", lead: "Auto-Type also offers this entry in windows whose title matches.") {
            if !auto.windows.isEmpty {
                let columns = [
                    MiniColumn(title: "Window title", width: 388), MiniColumn(title: "Sequence"),
                    MiniColumn(width: 48, trailing: true),
                ]
                MiniTable(
                    header: columns,
                    rows: auto.windows.enumerated().map { index, window in
                        [
                            AnyView(Text(verbatim: window.window).font(.mono(13))),
                            window.sequence.isEmpty
                                ? AnyView(Text(verbatim: "Entry sequence").foregroundStyle(Tok.muted))
                                : AnyView(Text(verbatim: window.sequence).font(.mono(12))),
                            AnyView(
                                IconButton(glyph: "trash", label: "Remove", size: 28) {
                                    editor.run {
                                        try editor.session.removeWindow(vault: editor.vault.id, index: UInt32(index))
                                    }
                                }),
                        ]
                    }, columns: columns)
            }
            Button {
            } label: {
                BtnLabel(glyph: "plus", title: "Add window")
            }
            .buttonStyle(Btn())
            .later(Later.autoTypeWindows)
            .padding(.top, auto.windows.isEmpty ? 0 : 12)
        }
    }

    private func set(_ enabled: Bool, _ sequence: String) {
        editor.run { try editor.session.setAutoType(vault: editor.vault.id, enabled: enabled, sequence: sequence) }
    }

    /// The custom sequence box and the placeholder hint.
    private func customSequence(_ auto: AutoTypeView) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            InputBox {
                PlainField(
                    prompt: "", text: Binding(get: { sequence ?? auto.sequence }, set: { sequence = $0 }), mono: true,
                    label: "Custom sequence"
                )
                .onSubmit { set(auto.enabled, sequence ?? auto.sequence) }
            }
            ChoiceNote(text: "Placeholders: {USERNAME} {PASSWORD} {TOTP} {TAB} {ENTER} {DELAY 500}").padding(.top, 4)
        }
    }
}
