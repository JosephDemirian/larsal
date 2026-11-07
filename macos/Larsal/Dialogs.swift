import LarsalCore
import SwiftUI

/// The mockup's `.dlg`: a sheet that drops from the window top. The tile,
/// the question and its consequence, the body, and the buttons; the
/// destructive button is red and never the default (Return does not press
/// it), Escape is Cancel.
struct DialogCard<Body: View, Foot: View>: View {
    let tint: String
    let glyph: String
    let title: String
    var text: String?
    var wide = false
    /// FEA-10.12: the dense code's width, when neither of the two fits it.
    var width: CGFloat?
    /// A user name `title` holds (the Wi-Fi network's): masked as every
    /// other one while S-VIEW-06 is on, read "hidden" (LD-219 addendum).
    var user: String?
    @ViewBuilder let content: Body
    @ViewBuilder let foot: Foot
    @Environment(\.colorScheme) private var scheme
    @Environment(\.maskUserNames) private var maskUser

    var body: some View {
        let user = maskUser ? self.user ?? "" : ""
        let shown = user.isEmpty ? title : title.replacingOccurrences(of: user, with: Masked.text)
        let spoken = user.isEmpty ? title : title.replacingOccurrences(of: user, with: Masked.spoken)
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .top, spacing: 14) {
                Tile(color: Tok.tileColor(tint), glyph: glyph, size: 44)
                VStack(alignment: .leading, spacing: 6) {
                    // 22-point lines (IBM Plex's own line is 20 at 16).
                    Text(verbatim: shown)
                        .accessibilityLabel(Text(verbatim: spoken))
                        .font(.sans(16, .semibold))
                        .lineSpacing(2)
                        .padding(.vertical, 1)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityAddTraits(.isHeader)
                    if let text {
                        Text(verbatim: text)
                            .foregroundStyle(Tok.muted)
                            .lineSpacing(2)
                            .padding(.vertical, 1)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(.top, 6)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            content
            HStack(spacing: 8) { foot }
                .frame(maxWidth: .infinity, alignment: .trailing)
                .padding(.top, 22)
        }
        .padding(.horizontal, 22)
        .padding(.top, 22)
        .padding(.bottom, 18)
        .frame(width: width ?? (wide ? 560 : 460))
        .background(Tok.dialog, in: RoundedRectangle(cornerRadius: 12))
        // The sheet's own box, before its shadow draws outside it.
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text(verbatim: spoken))
        .accessibilityAddTraits(.isModal)
        .background {
            let dark = scheme == .dark
            // `--pop-shadow`: the soft drop, and the hairline ring outside
            // the sheet's edge (CSS's 0 0 0 1px spread), not inside it.
            BoxShadow(radius: 12, drop: dark ? 16 : 12, blur: dark ? 40 : 32, alpha: dark ? 0.6 : 0.16)
            RoundedRectangle(cornerRadius: 13)
                .strokeBorder(dark ? Color.white.opacity(0.08) : Color.black.opacity(0.06))
                .padding(-1)
        }
    }
}

extension DialogCard where Body == EmptyView {
    init(
        tint: String, glyph: String, title: String, text: String? = nil, @ViewBuilder foot: () -> Foot
    ) {
        self.init(tint: tint, glyph: glyph, title: title, text: text, content: { EmptyView() }, foot: foot)
    }
}

/// `.dlg .db`: the body, 18 below the head.
struct DialogBody<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }.padding(.top, 18)
    }
}

/// A `btn lg` of a sheet.
struct SheetButton: View {
    let title: String
    var kind = Btn.Kind.plain
    var cancel = false
    let action: () -> Void

    var body: some View {
        let button = Button(title, action: action).buttonStyle(Btn(kind: kind, size: .large))
        if cancel {
            button.keyboardShortcut(.cancelAction)
        } else if kind == .primary {
            button.keyboardShortcut(.defaultAction)
        } else {
            button
        }
    }
}

/// The sheet for `dialog` (mockup `DIALOGS`), wired to the vault and the
/// editor. Behaviour from the cards; their words where they differ.
/// The sheet for `dialog` (mockup `DIALOGS`), wired to the vault and the
/// editor. Behaviour from the cards; their words where they differ.
struct DialogView: View {
    let model: VaultModel
    let dialog: VaultModel.Dialog

    var body: some View {
        switch dialog {
        case .moveToBin(let id, let title): MoveToBinSheet(model: model, id: id, title: title)
        case .clone(let id, let title): CloneSheet(model: model, id: id, title: title)
        case .totpSetup(let setup): TotpSetupSheet(model: model, setup: setup)
        case .totpQr(let title, let symbol, let custom):
            TotpQrSheet(model: model, title: title, symbol: symbol, custom: custom)
        case .qrCode(let popup): QrPopupView(popup: popup)
        case .newGroup(let start): NewGroupSheet(model: model, name: start)
        case .version(let index, let version): VersionSheet(model: model, index: index, version: version)
        case .removeAttachment, .overwriteAttachment, .bigFile, .openRisky, .replaceFile:
            FileQuestion(model: model, dialog: dialog)
        case .preview(let name, let preview): PreviewSheet(model: model, name: name, preview: preview)
        case .export(let step): ExportSheet(model: model, step: step)
        case .approveShare(let label): ApproveShareSheet(model: model, label: label)
        case .leaveEditor:
            // LD-199 (2): the unsaved-changes question (mockup `closeUnsaved`).
            DialogCard(
                tint: "teal", glyph: "floppy-disk", title: "Save changes to “\(model.editor?.view.title ?? "")”?",
                text: model.editor?.changeSentence
            ) {
                Button("Discard") { model.answerLeave(save: false) }
                    .buttonStyle(Btn(size: .large))
                    .frame(maxWidth: .infinity, alignment: .leading)
                SheetButton(title: "Cancel", cancel: true) {
                    model.afterLeave = nil
                    model.dialog = nil
                }
                SheetButton(title: "Save", kind: .primary) { model.answerLeave(save: true) }
            }
        case .lockDiscardEdit:
            // APP-02.15 step 7 (F-122): MSG-LOCK-DISCARD-EDIT; Cancel keeps
            // the vault unlocked, Discard drops the edits and goes on. Cancel
            // is the default, as Apple's HIG has for a destructive question:
            // Return answers it as Escape does (LD-244 (2)).
            let changes = model.editor?.changeSentence ?? ""
            let keep = {
                model.afterLeave = nil
                model.dialog = nil
            }
            DialogCard(
                tint: "orange", glyph: "pencil-simple", title: "Lock now and lose your unsaved edits?",
                text: changes.isEmpty ? nil : changes
            ) {
                SheetButton(title: "Cancel", cancel: true, action: keep)
                    .background {
                        Button("", action: keep).keyboardShortcut(.defaultAction).opacity(0).accessibilityHidden(true)
                    }
                SheetButton(title: "Discard", kind: .danger) { model.answerLeave(save: false) }
            }
        case .changedOnDisk, .closeUnsaved, .saveFailed, .formatNotice, .diskNewKey, .askUnsafe, .oldCopies,
            .changedAttachment, .diskOldKey, .copies:
            SavingSheet(model: model, dialog: dialog)
        default: Confirm(model: model, dialog: dialog)
        }
    }
}

/// The question sheets: a title, its consequence, Cancel and the red button.
private struct Confirm: View {
    let model: VaultModel
    let dialog: VaultModel.Dialog

    var body: some View {
        let say = words
        DialogCard(tint: say.tint, glyph: say.glyph, title: say.title, text: say.text) {
            SheetButton(title: dialog == .discard ? "Keep Editing" : "Cancel", cancel: true) { model.dialog = nil }
            SheetButton(title: say.action, kind: .danger, action: confirm)
        }
    }

    /// A question's tile colour, glyph, title, text and red button.
    private struct Words {
        let tint: String
        let glyph: String
        let title: String
        let text: String?
        let action: String

        init(_ tint: String, _ glyph: String, _ title: String, _ text: String?, _ action: String) {
            (self.tint, self.glyph, self.title, self.text, self.action) = (tint, glyph, title, text, action)
        }
    }

    private var words: Words {
        switch dialog {
        case .deleteForever(_, let title):
            return Words(
                "red", "trash", "Delete “\(title)” forever?",
                "The entry and its history leave the vault. You cannot undo this.", "Delete Forever"
            )
        case .emptyBin(let titles):
            let text = Formats.count(titles.count, "entry is", "entries are") + " deleted for good: "
            return Words(
                "red", "trash", "Empty the Recycle Bin?", text + DialogView.list(titles) + ".", "Empty Recycle Bin")
        case .discard:
            let title = model.editor?.view.title ?? ""
            return Words(
                "orange", "pencil-simple", "Discard your changes to “\(title)”?", model.editor?.changeSentence,
                "Discard Changes"
            )
        case .removePasskey(let site):
            // INT-04.46: MI04-34, the card's words.
            return Words(
                "purple", "fingerprint", "Remove the passkey?",
                "You can no longer sign in to \(site) with it. The password stays.", "Remove Passkey"
            )
        case .removeField(let name): return Words("red", "trash", "Remove the field “\(name)”?", nil, "Remove")
        case .removeCustomData(let key): return Words("red", "trash", "Delete the custom data “\(key)”?", nil, "Delete")
        default: return Words("red", "trash", "", nil, "OK")
        }
    }

    private func confirm() {
        let session = model.session
        let vault = model.vault.id
        let editor = model.editor
        switch dialog {
        case .deleteForever(let id, _): model.delete(id)
        case .emptyBin: model.emptyBin()
        case .discard: model.closeEditor()
        case .removePasskey:
            if let editor {
                editor.run { try session.removePasskey(vault: vault) }
            } else {
                model.removeReportPasskey()  // the Passkeys report's Remove (INT-04.46)
            }
        case .removeField(let name): editor?.run { try session.removeField(vault: vault, name: name) }
        case .removeCustomData(let key): editor?.run { try session.removeCustomData(vault: vault, key: key) }
        default: break
        }
        if dialog != .discard { model.dialog = nil }
    }
}

extension DialogView {
    /// "Twitter (old account) and MySpace".
    static func list(_ titles: [String]) -> String {
        guard let last = titles.last else { return "" }
        let head = titles.dropLast().joined(separator: ", ")
        return head.isEmpty ? last : head + " and " + last
    }
}

/// Move to the Recycle Bin (MOD-04.3, with S-ENTRY-02 on).
private struct MoveToBinSheet: View {
    let model: VaultModel
    let id: String
    let title: String
    @State private var dontAsk = false

    var body: some View {
        DialogCard(
            tint: "red", glyph: "trash", title: "Move “\(title)” to the Recycle Bin?",
            text: "You can restore it until you empty the Recycle Bin."
        ) {
            DialogBody { CheckRow(title: "Do not ask again", isOn: $dontAsk) }
        } foot: {
            SheetButton(title: "Cancel", cancel: true) { model.dialog = nil }
            SheetButton(title: "Move to Recycle Bin", kind: .danger) {
                if dontAsk { model.askBeforeBin = false }
                model.delete(id)
            }
        }
    }
}

/// Clone entry (MOD-10.1): the card's labels and defaults.
private struct CloneSheet: View {
    let model: VaultModel
    let id: String
    let title: String
    @State private var suffix = true
    @State private var refs = false
    @State private var history = true

    var body: some View {
        DialogCard(
            tint: "blue", glyph: "copy-simple", title: "Clone “\(title)”", text: "Makes a copy in the same group."
        ) {
            DialogBody {
                CheckRow(title: "Mark the copy's title with ' - Clone'", isOn: $suffix)
                CheckRow(
                    title: "Link user name and password to the original",
                    detail: "The copy changes when the original changes.", isOn: $refs)
                CheckRow(title: "Copy the history", isOn: $history)
            }
        } foot: {
            SheetButton(title: "Cancel", cancel: true) { model.dialog = nil }
            SheetButton(title: "Clone", kind: .primary) {
                model.clone(id, suffix: suffix, refs: refs, history: history)
            }
        }
    }
}

/// An earlier version (MOD-03.12): its password is the sheet's Show value,
/// gone when the sheet closes. A protected title, user name or URL comes
/// empty and shows masked with Show (F-060).
private struct VersionSheet: View {
    let model: VaultModel
    let index: UInt32
    let version: VersionView

    var body: some View {
        let masked = version.protected.contains(.title)
        DialogCard(
            tint: "orange", glyph: "clock-counter-clockwise",
            title: "\(masked ? MaskedRow.dots : version.title), \(Formats.dateAt(version.saved))",
            text: "How the entry looked before \(version.before)."
        ) {
            DialogBody {
                Panel(
                    rows: (masked ? [AnyView(Fld(label: "Title") { text(.title, "Title", version.title) })] : []) + [
                        AnyView(Fld(label: "Username") { text(.userName, "Username", version.user) }),
                        AnyView(Fld(label: "Password") { PasswordText(text: version.password) }),
                        AnyView(Fld(label: "Website") { text(.url, "Website", version.url) }),
                    ])
            }
        } foot: {
            SheetButton(title: "Close", cancel: true) { model.dialog = nil }
            SheetButton(title: "Restore This Version", kind: .primary) {
                let (session, vault) = (model.session, model.vault.id)
                model.editor?.run { try session.restoreVersion(vault: vault, index: index) }
                model.dialog = nil
            }
        }
    }

    private func text(_ field: EditText, _ label: String, _ value: String) -> some View {
        VersionText(
            model: model, index: index, field: field, label: label, value: value,
            protected: version.protected.contains(field))
    }
}

/// One text of an earlier version: as stored, or masked with Show and
/// Hide when protected (F-060). The shown value goes with the sheet.
private struct VersionText: View {
    let model: VaultModel
    let index: UInt32
    let field: EditText
    let label: String
    let value: String
    let protected: Bool
    @State private var shown: String?

    var body: some View {
        if !protected && field == .userName {
            // LD-219 addendum: an earlier user name, masked by S-VIEW-06.
            MaskedUser(user: value).lineLimit(1)
        } else if !protected {
            Text(verbatim: value).lineLimit(1)
        } else if let shown {
            HStack(spacing: 8) {
                Text(verbatim: shown).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityLabel(Text(verbatim: label)).accessibilityValue(Text(verbatim: shown))
                IconButton(glyph: "eye-slash", label: "Hide " + label, size: 28) { self.shown = nil }
            }
        } else {
            MaskedRow(label: label) {
                shown = try? model.session.showVersionField(vault: model.vault.id, index: index, name: field.name)
            }
        }
    }
}
