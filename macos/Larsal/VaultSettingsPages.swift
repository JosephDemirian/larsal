import AppKit
import LarsalCore
import SwiftUI

// The vault settings' Recycle Bin, History and Browser Keys pages and the
// sheets (MOD-12.5, MOD-12.6, MOD-12.18).

// MARK: Recycle Bin (MOD-12.6)

struct SettingsBin: View {
    let model: VaultSettingsModel

    var body: some View {
        RowBox(rows: [
            AnyView(
                SRow(title: "Use a Recycle Bin", detail: "Deleted entries wait here until you empty it.") {
                    Switch(
                        label: "Bin",
                        isOn: Binding(get: { model.view?.recycleBin ?? true }, set: { model.setBin($0) }))
                }),
            AnyView(
                SRow(title: "Empty entries older than") {
                    HStack(spacing: 8) {
                        StepBox(value: "90 days", less: {}, more: {}).later(Later.autoEmpty)
                        Switch(label: "Auto empty", isOn: .constant(false)).later(Later.autoEmpty)
                    }
                }),
        ])
    }
}

// MARK: History (MOD-12.5)

struct SettingsHistory: View {
    let model: VaultSettingsModel

    var body: some View {
        let view = model.view
        let keeping = (view?.historyItems ?? 10) != 0
        let items = view?.historyItems ?? 10
        let mib = view?.historyMib ?? 6
        RowBox(rows: [
            AnyView(
                SRow(title: "Keep earlier versions of entries") {
                    Switch(label: "History", isOn: Binding(get: { keeping }, set: { model.setHistory($0) }))
                }),
            AnyView(
                SRow(title: "Versions per entry") {
                    StepBox(
                        value: items < 0 ? "No limit" : "\(items)", less: { model.stepItems(-1) },
                        more: { model.stepItems(1) }
                    )
                    .disabled(!keeping)
                }),
            AnyView(
                SRow(title: "History size per entry") {
                    StepBox(
                        value: mib < 0 ? "No limit" : "\(mib) MB", less: { model.stepSize(-1) },
                        more: { model.stepSize(1) })
                }),
            AnyView(
                SRow(
                    title: "Space used now",
                    detail: Formats.size(view?.historyBytes ?? 0) + " in "
                        + Formats.count(Int(view?.historyVersions ?? 0), "version", "versions")
                ) {
                    RedButton(title: "Delete all history…") { model.sheet = .confirm(.deleteHistory) }
                        .disabled((view?.historyVersions ?? 0) == 0)
                }),
        ])
    }
}

// MARK: Browser Keys (MOD-12.18, INT-02.8)

struct SettingsBrowser: View {
    let model: VaultSettingsModel

    var body: some View {
        let view = model.view
        VStack(alignment: .leading, spacing: 24) {
            SetGroup(title: "Connected browsers") {
                let browsers = view?.browsers ?? []
                RowBox(
                    rows: browsers.isEmpty
                        ? [AnyView(SRow(title: "No browser is connected.") { EmptyView() }.foregroundStyle(Tok.muted))]
                        : browsers.map { browser in
                            AnyView(
                                DetailRow(title: "") {
                                    Text(
                                        verbatim: browser.created.map { "Connected " + Formats.day($0) } ?? "Connected")
                                } control: {
                                    RedButton(title: "Disconnect") { model.sheet = .confirm(.disconnect(browser.name)) }
                                        .accessibilityLabel(Text(verbatim: "Disconnect " + browser.name))
                                }
                                .overlay(alignment: .topLeading) {
                                    HStack(spacing: 10) {
                                        BrowserLogo(name: browser.name)
                                        Text(verbatim: browser.name)
                                    }
                                    .frame(height: 20)
                                    .padding(.leading, 14)
                                    .padding(.top, 10)
                                }
                                // CSS: the 18-point logo's inline-flex line box is 3.5 taller.
                                .environment(\.titleGap, 3.5))
                        })
            }
            SetGroup(title: "Stored permissions") {
                let count = Int(view?.siteAccess ?? 0)
                let row = AnyView(
                    SRow(
                        title: "Site permissions kept in entries",
                        detail: Formats.count(count, "entry holds", "entries hold") + " allowed or blocked sites"
                    ) {
                        Button("Remove all…") { model.sheet = .confirm(.forgetSites) }
                            .buttonStyle(Btn(size: .small))
                            .disabled(count == 0)
                    })
                RowBox(rows: [row])
            }
        }
    }
}

// MARK: Sheets

struct SettingsSheet: View {
    let model: VaultSettingsModel

    var body: some View {
        if let sheet = model.sheet {
            ZStack(alignment: .top) {
                Tok.scrim.contentShape(Rectangle()).accessibilityHidden(true)
                Group {
                    switch sheet {
                    case .question(let question, let then):
                        QuestionCard(question: question, cancel: model.dismiss) { model.answer(question, then: then) }
                    case .notice(let text):
                        NoticeCard(text: text) { model.sheet = nil }
                    case .confirm(let what):
                        ConfirmCard(model: model, what: what)
                    case .changePassword:
                        PasswordCard(model: model)
                    case .createKeyFile:
                        CreateKeyFileCard(
                            fileName: model.keyFilePath.lastPathComponent, change: model.changeKeyFilePath,
                            cancel: { model.sheet = nil }, create: model.createKeyFile)
                    }
                }
                .padding(.top, 52)
            }
            .onExitCommand { model.dismiss() }
        }
    }
}

/// The screen's confirmations before an action that acts at once
/// (MOD-04.12, MOD-03, MOD-12.18): the destructive button red, never the
/// default.
private struct ConfirmCard: View {
    typealias Confirm = VaultSettingsModel.Confirm
    let model: VaultSettingsModel
    let what: Confirm

    var body: some View {
        switch what {
        case .binOff:
            DialogCard(
                tint: "red", glyph: "trash", title: "Delete the Recycle Bin and everything in it?",
                text: "You cannot undo this. With No, the bin stays as a normal group with “ (old)” after its name."
            ) {
                SheetButton(title: "No", kind: .primary) { model.confirmed(.binOff, yes: false) }
                Button("Delete") { model.confirmed(.binOff) }.buttonStyle(Btn(kind: .danger, size: .large))
            }
        case .historyOff:
            card(
                "Stop keeping earlier versions?",
                "Every entry's earlier versions leave the vault now. You cannot undo this.",
                "Stop Keeping", .historyOff)
        case .deleteHistory:
            card(
                "Delete all history?", "Every entry's earlier versions leave the vault. You cannot undo this.",
                "Delete All History", .deleteHistory)
        case .forgetSites:
            card(
                "Remove the stored site permissions?",
                "The entries forget which sites they allowed or blocked. Browsers ask again next time.", "Remove All",
                .forgetSites)
        case .disconnect(let name):
            card(
                "Disconnect “\(name)”?", "It can no longer use this vault until you connect it again.", "Disconnect",
                .disconnect(name))
        }
    }

    private func card(_ title: String, _ text: String, _ button: String, _ what: Confirm) -> some View {
        DialogCard(tint: "red", glyph: "warning", title: title, text: text) {
            SheetButton(title: "Cancel", cancel: true) { model.sheet = nil }
            Button(button) { model.confirmed(what) }.buttonStyle(Btn(kind: .danger, size: .large))
        }
    }
}

/// The password's Change… (MOD-12.10 with the wizard's password part,
/// APP-07.20).
private struct PasswordCard: View {
    let model: VaultSettingsModel
    @State private var passwordFocused = false
    @State private var repeatFocused = false

    var body: some View {
        DialogCard(
            tint: "blue", glyph: "password", title: "Change the password",
            text: "The next save locks the vault with the new password. Copies made before still open with the old one."
        ) {
            DialogBody {
                Lab(title: "Password", small: model.rating.map { "· \($0.level), about \($0.bits) bits" })
                InputBox(focused: passwordFocused) {
                    SecretField(
                        shown: model.shownPassword, dots: model.passwordLength, label: "Password",
                        turn: model.fieldTurn, focused: $passwordFocused, typed: model.passwordTyped)
                    IconButton(
                        glyph: model.shownPassword == nil ? "eye" : "eye-slash",
                        label: model.shownPassword == nil ? "Show password" : "Hide password", size: 28,
                        action: model.toggleShow
                    )
                    .keyboardShortcut("h", modifiers: .control)
                }
                .capsLockNote(focused: passwordFocused)  // M06-37, not on Verify (APP-06.6)
                Meter(rating: model.rating).padding(.top, 8)
                Lab(title: "Verify password").padding(.top, 16)
                InputBox(focused: repeatFocused) {
                    SecretField(
                        shown: model.shownRepeat, dots: model.repeatLength, label: "Verify password",
                        turn: model.fieldTurn, focused: $repeatFocused, typed: model.repeatTyped)
                    if model.match == true {
                        Glyph(name: "check-circle", size: 18, fill: true).foregroundStyle(Tok.positive)
                    }
                }
                Text(verbatim: model.mismatch ? "The two passwords are different." : " ")
                    .font(.sans(12)).foregroundStyle(Tok.negative).frame(height: 16).padding(.top, 6)
                    .accessibilityHidden(!model.mismatch)
                    .accessibilityAddTraits(.updatesFrequently)
            }
        } foot: {
            SheetButton(title: "Cancel", cancel: true, action: model.clearPassword)
            SheetButton(title: "Change Password", kind: .primary, action: model.changePassword)
        }
        .onAppear { passwordFocused = true }
    }
}
