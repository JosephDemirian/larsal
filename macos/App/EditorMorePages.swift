import AppCore
import SwiftUI

// MARK: Browser

/// The Browser page (INT-02.29): the site access lists and the three
/// options are stored with the editor; the browser bridge uses them (E7).
struct BrowserPage: View {
    let editor: EditorModel
    @State private var allowText = ""
    @State private var denyText = ""
    @State private var problem: String?

    /// An option's title, subline and switch name.
    struct Words {
        let title: String
        let detail: String
        let name: String
    }

    static let labels: [String: Words] = [
        // LD-167: the card's words for the first option.
        "BrowserHideEntry": Words(
            title: "Never offer this entry to browsers", detail: "The extension never sees it.",
            name: "Hide from browser"),
        "BrowserSkipAutoSubmit": Words(
            title: "Fill, but do not submit", detail: "You press the sign-in button yourself.", name: "Do not submit"),
        "BrowserOnlyHttpAuth": Words(
            title: "Only for sign-in pop-ups (HTTP)", detail: "For routers and old intranet pages.", name: "HTTP only"),
    ]

    var body: some View {
        let view = editor.view
        EdSection(title: "Sites", lead: "The browser extension fills this entry on its website and on these sites.") {
            TwoColumns(leftWidth: 400) {
                FieldCell(label: "Also allowed on") { sites(view.allow, text: $allowText, deny: false) }
            } right: {
                FieldCell(label: "Never on") { sites(view.deny, text: $denyText, deny: true) }
            }
            if let problem { Help(text: problem).foregroundStyle(Tok.negative) }
        }
        EdSection(title: "Options") {
            RowBox(rows: view.browserOptions.map { AnyView(row($0)) })
        }
        EdSection(title: "Browsers that used this entry") { browsers(view.browsers) }
    }

    /// A list as chips, then "Add a site…" (Return adds the typed host).
    private func sites(_ hosts: [String], text: Binding<String>, deny: Bool) -> some View {
        InputBox(gap: 6) {
            ForEach(hosts, id: \.self) { host in
                Chip(text: host) {
                    editor.run { try editor.session.removeSite(vault: editor.vault.id, host: host, deny: deny) }
                }
            }
            PlainField(prompt: "Add a site…", text: text, label: deny ? "Never on" : "Also allowed on")
                .onSubmit {
                    let typed = text.wrappedValue
                    do {
                        try editor.session.addSite(vault: editor.vault.id, typed: typed, deny: deny)
                        problem = nil
                        text.wrappedValue = ""
                    } catch {
                        problem = message(error)
                    }
                    editor.refresh()
                }
        }
    }

    /// One option; a group that decides it shows its value, disabled,
    /// with MI02-11 (INT-02.14).
    private func row(_ option: BrowserOptionView) -> some View {
        let words = Self.labels[option.key] ?? Words(title: option.key, detail: "", name: option.key)
        let note = option.group.map { "Set by the group “\($0)”." }
        return SRow(title: words.title, detail: note ?? words.detail) {
            Switch(
                label: words.name,
                isOn: Binding(
                    get: { option.on },
                    set: { value in
                        editor.run {
                            try editor.session.setBrowserOption(vault: editor.vault.id, key: option.key, on: value)
                        }
                    })
            )
            .disabled(option.group != nil)
        }
    }

    /// `BrowserLastUse`, newest first (INT-02.29).
    @ViewBuilder
    private func browsers(_ list: [BrowserUseView]) -> some View {
        if list.isEmpty {
            Text(verbatim: "No browser has used this entry yet.")
                .font(.sans(13))
                .foregroundStyle(Tok.muted)
                .padding(.horizontal, 17)
                .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
        } else {
            let columns = [MiniColumn(), MiniColumn(width: 160, trailing: true)]
            MiniTable(
                header: nil,
                rows: list.map { use in
                    [
                        AnyView(
                            HStack(spacing: 10) {
                                BrowserLogo(name: use.name)
                                Text(verbatim: use.name)
                            }),
                        AnyView(Text(verbatim: Self.when(use.used)).num().foregroundStyle(Tok.muted)),
                    ]
                }, columns: columns)
        }
    }

    /// "Today, 09:12", or "Oct 20" (this year), or "Oct 20, 2025".
    static func when(_ unix: Int64) -> String {
        guard unix > 0 else { return "—" }
        return Formats.modified(unix) == "Today" ? "Today, " + Formats.time(unix) : Formats.modified(unix)
    }
}

// MARK: SSH Agent

/// The SSH Agent page (INT-06): the key's public parts from the entry's
/// attachments; the agent settings come with E9-S2.
struct SshPage: View {
    let editor: EditorModel

    var body: some View {
        let view = editor.view
        let publicFile = view.attachments.first { $0.name.hasSuffix(".pub") }
        let privateFile = view.attachments.first { publicFile.map { "\($0.name)" } == $0.name + ".pub" }
        EdSection {
            VStack(spacing: 0) {
                SRow(
                    title: "Use this entry's key with the SSH agent",
                    detail: "\(view.title) · the entry's password unlocks the key"
                ) {
                    Switch(label: "SSH agent", isOn: .constant(view.ssh != nil)).later(Later.sshAgent)
                }
            }
            // `.panel`: the row inside its 1-point border.
            .padding(1)
            .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
        }
        EdSection(title: "Private key") {
            VStack(spacing: 8) {
                Choice(
                    isOn: true, title: "From an attachment",
                    extra: AnyView(
                        SelectBox(
                            title: privateFile.map { "\($0.name) · \(Formats.size($0.size))" } ?? "Choose an attachment"
                        ) {
                            Glyph(name: "paperclip", size: 12).foregroundStyle(Tok.muted)
                        }
                        .padding(.top, 8))
                ) {}
                Choice(isOn: false, title: "From a file on this Mac", note: "~/.ssh/id_ed25519", mono: true) {}
                    .later(Later.sshAgent)
            }
            if let key = view.ssh {
                let parts = (view.sshPublicKey ?? "").split(separator: " ", maxSplits: 2).map(String.init)
                VStack(alignment: .leading, spacing: 10) {
                    keyValue("Type") { Text(verbatim: key.kind) }
                    keyValue("Fingerprint") { Text(verbatim: key.fingerprint).font(.mono(13)) }
                    keyValue("Comment") {
                        Text(verbatim: parts.count > 2 ? parts[2].trimmingCharacters(in: .newlines) : "—")
                    }
                    keyValue("Public key") {
                        VStack(alignment: .leading, spacing: 8) {
                            // `.keybox`: `word-break: break-all`, so a line breaks
                            // anywhere (a zero-width space after each character).
                            Text(
                                verbatim: Self.breakAnywhere(
                                    (view.sshPublicKey ?? "").trimmingCharacters(in: .newlines))
                            )
                            .accessibilityLabel(Text(verbatim: view.sshPublicKey ?? ""))
                            .font(.mono(12))
                            .lineBox(12, 18)
                            .fixedSize(horizontal: false, vertical: true)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 10)
                            .background(Tok.raised, in: RoundedRectangle(cornerRadius: 8))
                            Button {
                            } label: {
                                BtnLabel(glyph: "copy", title: "Copy public key")
                            }
                            .buttonStyle(Btn(size: .small))
                            .later(Later.sshAgent)
                        }
                    }
                }
                .font(.sans(13))
                // `dl.kv` keeps the browser's 1 em (13) above and below.
                .padding(.horizontal, 17)
                .padding(.vertical, 30)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
                .padding(.top, 12)
            }
        }
        EdSection(title: "Agent") {
            RowBox(rows: [
                AnyView(
                    SRow(title: "Add the key when the vault unlocks") {
                        Switch(label: "Add on unlock", isOn: .constant(true)).later(Later.sshAgent)
                    }),
                AnyView(
                    SRow(title: "Remove the key when the vault locks") {
                        Switch(label: "Remove on lock", isOn: .constant(true)).later(Later.sshAgent)
                    }),
                AnyView(
                    SRow(
                        title: "Ask before each use",
                        detail: "App shows a question every time a program wants to sign with the key."
                    ) {
                        Switch(label: "Confirm", isOn: .constant(false)).later(Later.sshAgent)
                    }),
                AnyView(
                    SRow(title: "Remove the key after") {
                        HStack(spacing: 8) {
                            StepBox(value: "10 min", less: {}, more: {})
                            Switch(label: "Lifetime", isOn: .constant(false))
                        }
                        .later(Later.sshAgent)
                    }),
            ])
            HStack(spacing: 8) {
                Button {
                } label: {
                    BtnLabel(glyph: "plus-circle", title: "Add to agent now")
                }.buttonStyle(Btn())
                Button {
                } label: {
                    BtnLabel(glyph: "minus-circle", title: "Remove from agent")
                }.buttonStyle(Btn())
            }
            .later(Later.sshAgent)
            .padding(.top, 12)
        }
    }

    static func breakAnywhere(_ text: String) -> String {
        text.map { String($0) + "\u{200B}" }.joined()
    }

    private func keyValue<Value: View>(_ key: String, @ViewBuilder value: () -> Value) -> some View {
        HStack(alignment: .top, spacing: 16) {
            Text(verbatim: key).foregroundStyle(Tok.muted).frame(
                minWidth: 160, maxWidth: 160, minHeight: 20, alignment: .topLeading)
            value().frame(maxWidth: .infinity, minHeight: 20, alignment: .topLeading)
        }
        .accessibilityElement(children: .contain)  // `dt` and `dd`: two texts
    }
}

// MARK: Properties

/// Properties (MOD-01 table) and custom data (MOD-01.20).
struct PropertiesPage: View {
    let model: VaultModel
    let editor: EditorModel

    var body: some View {
        let view = editor.view
        EdSection(title: "Properties") {
            VStack(alignment: .leading, spacing: 10) {
                pair("Identifier") { Text(verbatim: view.identifier).font(.mono(13)) }
                if !view.new {
                    pair("Created") { Text(verbatim: Formats.dateTime(view.created)).num() }
                    pair("Modified") { Text(verbatim: Formats.dateTime(view.modified)).num() }
                    pair("Last used") { Text(verbatim: Formats.used(view.accessed)).num() }
                }
                pair("Expires") { Text(verbatim: view.expires ? Formats.longDate(view.expiry) : "Never") }
                pair("Times used") { Text(verbatim: "\(view.usage)").num() }
                pair("History") {
                    Text(
                        verbatim: Formats.count(Int(view.historyItems), "version", "versions") + " · "
                            + Formats.size(view.historySize)
                    )
                    .num()
                }
            }
            .font(.sans(13))
            // `dl.kv` keeps the browser's 1 em (13) above and below.
            .padding(.horizontal, 19)
            .padding(.vertical, 32)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
        }
        EdSection(title: "Custom data", lead: "Values other apps and the browser extension store with this entry.") {
            if !view.customData.isEmpty {
                let columns = [
                    MiniColumn(title: "Key", width: 388), MiniColumn(title: "Value"),
                    MiniColumn(width: 48, trailing: true),
                ]
                MiniTable(
                    header: columns,
                    rows: view.customData.map { item in
                        [
                            AnyView(Text(verbatim: item.key).font(.mono(13))),
                            AnyView(Text(verbatim: item.value).num()),
                            AnyView(
                                IconButton(glyph: "trash", label: "Remove", size: 28) {
                                    model.dialog = .removeCustomData(key: item.key)
                                }),
                        ]
                    }, columns: columns)
            }
        }
    }

    private func pair<Value: View>(_ key: String, @ViewBuilder value: () -> Value) -> some View {
        HStack(alignment: .top, spacing: 16) {
            Text(verbatim: key).foregroundStyle(Tok.muted).frame(width: 160, alignment: .leading)
            value().frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(minHeight: 20)
        .accessibilityElement(children: .contain)  // `dt` and `dd`: two texts
    }
}

// MARK: History

/// Earlier versions (MOD-03.11 to MOD-03.13): Show, Restore, Delete; the
/// changes take effect at Save.
struct HistoryPage: View {
    let model: VaultModel
    let editor: EditorModel

    var body: some View {
        let view = editor.view
        let mib = Int(view.historyMaxSize) / 1_048_576
        let bytes =
            mib * 1_048_576 == Int(view.historyMaxSize)
            ? "\(mib) MB" : Formats.size(UInt64(max(view.historyMaxSize, 0)))
        let size = view.historyMaxSize < 0 ? "" : ", up to " + bytes
        let items = view.historyMaxItems < 0 ? "every version" : "the last \(view.historyMaxItems) versions"
        EdSection(title: "Earlier versions", lead: "App keeps \(items) of each entry\(size) per entry.") {
            if !view.history.isEmpty {
                let columns = [
                    MiniColumn(title: "Saved", width: 233), MiniColumn(title: "Change"),
                    MiniColumn(title: "Password", width: 140),
                    MiniColumn(width: 177, trailing: true),
                ]
                MiniTable(header: columns, rows: view.history.map { row($0) }, columns: columns, cellHeight: 32)
            }
            Button {
                editor.run { try editor.session.deleteVersion(vault: editor.vault.id, index: nil) }
            } label: {
                BtnLabel(glyph: "trash", title: "Delete all history").foregroundStyle(Tok.negative)
            }
            .buttonStyle(Btn())
            .disabled(view.historyItems == 0)
            .padding(.top, 12)
        }
    }

    private func row(_ row: HistoryRow) -> [AnyView] {
        let session = editor.session
        let id = editor.vault.id
        return [
            AnyView(Text(verbatim: Formats.dateTime(row.saved)).num()),
            AnyView(Text(verbatim: row.change)),
            row.passwordChanged
                ? AnyView(Pill(text: "changed")) : AnyView(Text(verbatim: "same").foregroundStyle(Tok.muted)),
            AnyView(
                // Inline buttons a space apart, as the mockup's `td.act`.
                HStack(spacing: 3) {
                    Button("Show") {
                        if let index = row.index, let version = try? session.showVersion(vault: id, index: index) {
                            model.dialog = .version(index: index, version)
                        }
                    }
                    .buttonStyle(Btn(size: .small))
                    .fixedSize()
                    .disabled(row.index == nil)
                    Button("Restore") {
                        if let index = row.index { editor.run { try session.restoreVersion(vault: id, index: index) } }
                    }
                    .buttonStyle(Btn(size: .small))
                    .fixedSize()
                    .disabled(row.index == nil)
                    IconButton(glyph: "trash", label: "Delete version", size: 28) {
                        if let index = row.index { editor.run { try session.deleteVersion(vault: id, index: index) } }
                    }
                    .disabled(row.index == nil)
                }),
        ]
    }
}
