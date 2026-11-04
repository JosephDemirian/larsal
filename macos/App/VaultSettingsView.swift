import AppCore
import AppKit
import SwiftUI

/// The vault settings window (mockup `settingsWin(s, VSET, VSETP, 'vault')`,
/// 900 × 640): the vault and its six pages on the left, the page on the
/// sheet. Behaviour from MOD-12.
struct VaultSettingsWindow: View {
    let model: VaultSettingsModel

    var body: some View {
        HStack(spacing: 0) {
            nav.frame(width: 232)
            VStack(spacing: 0) {
                // `.shead`.
                HStack(spacing: 8) {
                    Glyph(name: "caret-left").foregroundStyle(Tok.muted)
                    Glyph(name: "caret-right").foregroundStyle(Tok.muted)
                    Text(verbatim: model.page.title).font(.sans(15, .semibold)).accessibilityAddTraits(.isHeader)
                }
                .padding(.horizontal, 20)
                .frame(maxWidth: .infinity, minHeight: 52, maxHeight: 52, alignment: .leading)
                .overlay(alignment: .bottom) { Rectangle().fill(Tok.rule).frame(height: 1) }
                ScrollView(.vertical) {
                    Group {
                        switch model.page {
                        case .general: SettingsGeneral(model: model)
                        case .security: SettingsSecurity(model: model)
                        case .bin: SettingsBin(model: model)
                        case .history: SettingsHistory(model: model)
                        case .browser: SettingsBrowser(model: model)
                        case .shares: SettingsShares(model: model)
                        }
                    }
                    .padding(.horizontal, 24)
                    .padding(.top, 20)
                    .padding(.bottom, 32)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .scrollIndicators(.never)
            }
            .background(Tok.surface, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Tok.border))
            .padding([.top, .trailing, .bottom], 8)
        }
        .font(.sans(14))
        .foregroundStyle(Tok.text)
        .background(Tok.ground)
        .overlay { SettingsSheet(model: model) }
        .background(WindowChromeView())
    }

    /// `.snav` with the vault's title block (`title` set).
    private var nav: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Tile(color: model.vault.tileColor, glyph: model.vault.tileGlyph, size: 32)
                VStack(alignment: .leading, spacing: 0) {
                    Text(verbatim: model.vault.name).font(.sans(14, .semibold)).frame(height: 20)
                    Text(verbatim: "Vault settings").font(.sans(12)).foregroundStyle(Tok.muted).frame(height: 20)
                }
                .lineLimit(1)
            }
            .padding(.horizontal, 8)
            .padding(.bottom, 14)
            .accessibilityElement(children: .combine)
            ForEach(VaultSettingsModel.Page.allCases) { page in
                SidebarItem(
                    title: page.title, current: model.page == page,
                    lead: AnyView(Tile(color: Tok.tileColor(page.tile.color), glyph: page.tile.glyph))
                ) {
                    EmptyView()
                } action: {
                    model.page = page
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10)
        .padding(.top, 48)
        .padding(.bottom, 12)
    }
}

/// `.grp`: the heading (13/18 semibold) over its rows.
struct SetGroup<Content: View>: View {
    var title: String?
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let title {
                Text(verbatim: title).font(.sans(13, .semibold)).frame(height: 18).padding(.leading, 2)
                    .padding(.bottom, 8).accessibilityAddTraits(.isHeader)
            }
            content
        }
    }
}

/// `.srow` whose second line is any view.
struct DetailRow<Detail: View, Control: View>: View {
    let title: String
    @ViewBuilder let detail: Detail
    @ViewBuilder let control: Control
    @Environment(\.titleGap) private var gap

    var body: some View {
        HStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: title).frame(minHeight: 20, alignment: .leading).padding(.bottom, gap)
                detail.font(.sans(12)).foregroundStyle(Tok.muted).frame(minHeight: 16, alignment: .leading)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: 8) { control }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(minHeight: 46)
        .accessibilityElement(children: .contain)
    }
}

extension EnvironmentValues {
    /// Extra room under a row's title line (an inline logo's line box).
    @Entry var titleGap: CGFloat = 0
}

/// A `btn sm` in the negative colour (mockup `style="color:var(--negative)"`).
struct RedButton: View {
    let title: String
    let action: () -> Void

    var body: some View {
        Button(action: action) { Text(verbatim: title).foregroundStyle(Tok.negative) }
            .buttonStyle(Btn(size: .small))
            .accessibilityLabel(Text(verbatim: title))
    }
}

// MARK: General (MOD-12.3, MOD-12.4)

private struct SettingsGeneral: View {
    @Bindable var model: VaultSettingsModel
    @FocusState private var focus: Field?

    enum Field { case name, user, description }

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .top, spacing: 16) {
                    field("Name", $model.name, .name)
                    field("Default username", $model.defaultUserName, .user)
                }
                VStack(alignment: .leading, spacing: 0) {
                    Lab(title: "Description")
                    TextField("", text: $model.description, axis: .vertical)
                        .textFieldStyle(.plain)
                        .lineLimit(2...)
                        .focused($focus, equals: .description)
                        .accessibilityLabel(Text(verbatim: "Description"))
                        .padding(.horizontal, 13)
                        .padding(.vertical, 11)
                        .frame(minHeight: 72, alignment: .topLeading)
                        .background(Tok.field, in: RoundedRectangle(cornerRadius: 8))
                        .overlay(
                            RoundedRectangle(cornerRadius: 8).strokeBorder(
                                focus == .description ? Tok.accent : Tok.control)
                        )
                        // CSS: the inline textarea sits on a line box 5.5 taller.
                        .padding(.bottom, 5.5)
                }
            }
            SetGroup(title: "Colour and icon") {
                let swatches = AnyView(
                    SRow(title: "Shown in the sidebar and on the lock screen") {
                        HStack(spacing: 8) {
                            ForEach(VaultLooks.swatches, id: \.self) { name in
                                SwatchChoice(name: name, isOn: model.swatch == name) { model.setColour(name) }
                            }
                        }
                    })
                RowBox(rows: [swatches])
            }
            SetGroup(title: "File") {
                let view = model.view
                RowBox(rows: [
                    AnyView(
                        DetailRow(title: "Location") {
                            Text(verbatim: view?.path ?? "").font(.mono(12)).lineLimit(1).truncationMode(.middle)
                        } control: {
                            Button("Show in Finder", action: model.showInFinder).buttonStyle(Btn(size: .small))
                        }),
                    AnyView(
                        DetailRow(title: "Format") {
                            Text(verbatim: "Version \(view?.version ?? "4.0") · \(Formats.size(view?.size ?? 0))").num()
                        } control: {
                            EmptyView()
                        }),
                ])
            }
        }
    }

    private func field(_ title: String, _ text: Binding<String>, _ which: Field) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Lab(title: title)
            InputBox(focused: focus == which) {
                TextField("", text: text)
                    .textFieldStyle(.plain)
                    .autocorrectionDisabled()
                    .focused($focus, equals: which)
                    .accessibilityLabel(Text(verbatim: title))
            }
        }
        .frame(maxWidth: .infinity)
    }
}

// MARK: Security (MOD-12.10 to MOD-12.14)

/// The Security page's credentials (MOD-12.10): password, key file and
/// security key rows. The forced key change prompt shows them too
/// (MOD-13.8, F-074).
struct CredentialRows: View {
    let model: VaultSettingsModel

    var body: some View {
        let view = model.view
        RowBox(rows: [
            AnyView(
                SRow(
                    title: "Password",
                    detail: view.map {
                        $0.hasPassword ? "Changed " + Formats.longDate($0.passwordChanged) : "No password"
                    }
                ) {
                    Button("Change…", action: model.askPassword).buttonStyle(Btn(size: .small))
                }),
            AnyView(
                SRow(title: "Key file", detail: view?.keyFile ?? "No key file") {
                    HStack(spacing: 8) {
                        Button("Change…") { model.keyMenu.toggle() }.buttonStyle(Btn(size: .small))
                            .popover(isPresented: Bindable(model).keyMenu, arrowEdge: .bottom) {
                                VStack(alignment: .leading, spacing: 0) {
                                    MenuItem(
                                        lead: .glyph("file-plus"), title: "New Key File…",
                                        action: model.askCreateKeyFile)
                                    MenuItem(
                                        lead: .glyph("folder-open"), title: "Choose Key File…",
                                        action: model.pickKeyFile)
                                }
                                .padding(6)
                                .frame(minWidth: 200)
                            }
                        RedButton(title: "Remove", action: model.removeKeyFile).disabled(view?.keyFile == nil)
                    }
                }),
            AnyView(
                MarkRow(title: "Security key", detail: model.securityKeyText) {
                    BrandMark(brand: "yubico")
                } control: {
                    // F-126: Option A's Change… (Add… without a key) opens the
                    // key menu; Remove is in the menu (W-19).
                    Button(view?.securityKey == nil ? "Add…" : "Change…") { model.securityKeyMenu.toggle() }
                        .buttonStyle(Btn(size: .small))
                        .popover(isPresented: Bindable(model).securityKeyMenu, arrowEdge: .bottom) {
                            KeyMenu(
                                picker: model.keyPicker, chosen: view?.securityKey,
                                choose: { model.setSecurityKey($0.pick) },
                                remove: view?.securityKey == nil ? nil : { model.setSecurityKey(nil) })
                        }
                }),
            AnyView(
                SRow(title: "Touch ID for this vault") {
                    Switch(label: "Touch ID", isOn: .constant(true)).later(Later.touchID)
                }),
        ])
    }
}

private struct SettingsSecurity: View {
    let model: VaultSettingsModel

    /// "Argon2id resists guessing on graphics cards." (mockup); none for AES-KDF.
    private var kdfNote: String? {
        switch model.encryption.kdf {
        case .argon2id: "Argon2id resists guessing on graphics cards."
        case .argon2d: "Argon2d resists guessing on graphics cards."
        case .aesKdf: nil
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            SetGroup(title: "Credentials") { CredentialRows(model: model) }
            SetGroup(title: "Encryption") {
                VStack(alignment: .leading, spacing: 0) {
                    EncryptionRows(
                        choice: model.encryption, editable: true,
                        kdfNote: kdfNote,
                        memoryNote: model.memoryNote, timeLabel: "Unlock time on this Mac",
                        timeNote: "Higher means slower guessing for an attacker.", showLanes: true
                    ) { edit in
                        var next = model.encryption
                        edit(&next)
                        if next.cipher != model.encryption.cipher {
                            model.setCipher(next.cipher)
                        } else {
                            model.setEncryption(edit)
                        }
                    }
                    .disabled(model.measuring)
                    Text(
                        verbatim: "Changes take effect the next time App saves. Older apps may not open a vault "
                            + "that uses ChaCha20 or more than 1 GiB of memory."
                    )
                    .font(.sans(12)).foregroundStyle(Tok.muted).lineBox(12, 16)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 2)
                    .padding(.top, 10)
                }
            }
        }
    }
}
