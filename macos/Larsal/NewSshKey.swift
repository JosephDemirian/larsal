import LarsalCore
import SwiftUI

// New SSH Key (E24-S2; spec INT-06.E24.01 to .06; Option A frames
// `e24-s1-new-ssh` to `e24-s1-ssh-save-error`). Rust makes the key, adds it
// to the open entry and commits the editor; its private half never comes
// here (AGENTS rule 4): Swift gets the type, the public line and the
// fingerprint. The vault then saves the normal way, and "SSH key saved"
// shows only after that save (INT-06.E24.04).

extension SshPage {
    /// `.keybox`: `word-break: break-all`, so a line breaks anywhere (a
    /// zero-width space after each character).
    static func breakAnywhere(_ text: String) -> String {
        text.map { String($0) + "\u{200B}" }.joined()
    }
}

/// The SSH page's New SSH Key… (INT-06.E24.01), on an entry without a key.
struct NewSshKeyButton: View {
    let model: VaultModel

    var body: some View {
        Button {
            model.dialog = .newSshKey
        } label: {
            BtnLabel(glyph: "plus-circle", title: "New SSH Key…")
        }
        .buttonStyle(Btn())
    }
}

/// The choices (INT-06.E24.01): Ed25519 by default, with no size; ECDSA on
/// three curves, P-256 first; RSA in two sizes, 3072 first. Nothing else.
struct SshKeyChoice: Equatable {
    var family = 0
    var curve = 0
    var bits = 0

    static let families = ["Ed25519", "ECDSA", "RSA"]
    static let curves = ["P-256", "P-384", "P-521"]
    static let sizes = ["3072", "4096"]

    var kind: SshKeyKind {
        switch family {
        case 1: [SshKeyKind.ecdsaP256, .ecdsaP384, .ecdsaP521][min(curve, 2)]
        case 2: [SshKeyKind.rsa3072, .rsa4096][min(bits, 1)]
        default: .ed25519
        }
    }
}

/// One key being made: the sheet's state, kept by the task that waits for
/// Rust even after the sheet went away.
@MainActor
@Observable
final class SshKeyJob {
    var making = false
    var cancelled = false
    var problem: String?
}

/// `e24Note`: a `.help` line 14 below what is above it.
private struct Note: View {
    let text: String
    var top: CGFloat = 14

    var body: some View {
        Text(verbatim: text).font(.sans(12)).foregroundStyle(Tok.muted).lineBox(12, 16)
            .fixedSize(horizontal: false, vertical: true).padding(.top, top)
    }
}

/// `.panel` with `padding: 14px 16px`.
private struct KeyPanel<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
    }
}

/// New SSH Key, then "Making your SSH key" while Rust makes it.
struct NewSshKeySheet: View {
    let model: VaultModel
    @State var choice: SshKeyChoice
    @State var title: String
    @State var comment = ""
    @State var job: SshKeyJob

    init(model: VaultModel, choice: SshKeyChoice = .init(), job: SshKeyJob = .init()) {
        self.model = model
        _choice = State(initialValue: choice)
        _title = State(initialValue: model.editor?.view.title ?? "")
        _job = State(initialValue: job)
    }

    var body: some View {
        if job.making { making } else { choosing }
    }

    private var heading: (String, String) {
        switch choice.family {
        case 1: ("New SSH Key · ECDSA", "Choose a standard curve.")
        case 2: ("New SSH Key · RSA", "Choose the key size explicitly.")
        default: ("New SSH Key", "Add a new key to this entry.")
        }
    }

    private var choosing: some View {
        DialogCard(tint: "teal", glyph: "key", title: heading.0, text: heading.1, width: 600) {
            DialogBody {
                segments("Key type", SshKeyChoice.families, $choice.family)
                switch choice.family {
                case 1: segments("ECDSA curve", SshKeyChoice.curves, $choice.curve).padding(.top, 16)
                case 2: segments("RSA bits", SshKeyChoice.sizes, $choice.bits).padding(.top, 16)
                default: Note(text: "Fixed key size · Ed25519 is the default.")
                }
                FieldCell(label: "Entry title") {
                    InputBox { PlainField(prompt: "", text: $title, label: "Entry title") }
                }
                .padding(.top, choice.family == 0 ? 14 : 16)
                FieldCell(label: "Public comment") {
                    InputBox { PlainField(prompt: "", text: $comment, label: "Public comment") }
                } help: {
                    Help(text: "Optional. Programs and sites can see this label.")
                }
                .padding(.top, 14)
                Note(text: "The private key stays protected in your vault. Only its public key can be copied or saved.")
                if let problem = job.problem {
                    Text(verbatim: problem).font(.sans(12)).foregroundStyle(Tok.negative).lineBox(12, 16)
                        .fixedSize(horizontal: false, vertical: true).padding(.top, 6)
                }
            }
        } foot: {
            SheetButton(title: "Cancel", cancel: true) { model.dialog = nil }
            SheetButton(title: "Generate and Add Key", kind: .primary, action: generate)
        }
    }

    private var making: some View {
        DialogCard(
            tint: "teal", glyph: "clock", title: "Making your SSH key",
            text: "The private key stays protected in Larsal.", width: 600
        ) {
            DialogBody {
                KeyPanel { Text(verbatim: "Working · finish time unknown") }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(Text(verbatim: "Making SSH key"))
                    .accessibilityValue(Text(verbatim: "Working · finish time unknown"))
                    .accessibilityAddTraits(.updatesFrequently)
                Note(text: "Cancelling discards the draft. Nothing is copied or written as a private-key file.")
            }
        } foot: {
            SheetButton(title: "Cancel", cancel: true, action: cancel)
        }
    }

    /// A labelled `.segc` (the frame's `fieldset` and `legend`).
    private func segments(_ label: String, _ items: [String], _ selected: Binding<Int>) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Lab(title: label)
            Segments(items: items, selected: selected.wrappedValue) { selected.wrappedValue = $0 }
                .accessibilityElement(children: .contain)
                .accessibilityLabel(Text(verbatim: label))
        }
    }

    /// Generate and Add Key: the title goes to the draft, Rust makes the
    /// key off the screen thread and commits it with the editor.
    private func generate() {
        guard let editor = model.editor, !job.making else { return }
        if title != editor.view.title { editor.set(.title, title) }
        let view = editor.view
        let group = view.groupName == model.vault.name ? view.groupName : "\(model.vault.name) › \(view.groupName)"
        let line = "\(view.title) · \(group)"
        let (session, vault, kind, comment, job) = (model.session, model.vault.id, choice.kind, comment, job)
        (job.problem, job.making) = (nil, true)
        Task { [model] in
            let made = await Task.detached {
                Result { try session.newSshKey(vault: vault, kind: kind, comment: comment) }
            }.value
            switch made {
            case .success(let key):
                // Committed before any Cancel reached Rust: it is in the entry.
                await model.sshKeyAdded(key, line: line)
            case .failure(let error):
                guard !job.cancelled else { return }  // Rust wiped it
                (job.making, job.problem) = (false, message(error))
            }
        }
    }

    /// Cancel while the key is made (INT-06.E24.04): Rust drops that key
    /// when it is done; the editor stays as it was.
    private func cancel() {
        job.cancelled = true
        model.session.cancelNewSshKey(vault: model.vault.id)
        model.dialog = nil
    }
}

/// "SSH key saved": the type, the public line and the fingerprint, with
/// Copy Public Key and Save Public Key… (INT-06.E24.05). Nothing is copied
/// or written before a press.
struct SshKeySavedSheet: View {
    let model: VaultModel
    let key: NewSshKeyView
    let line: String
    /// The folder where the public key file is already there: ask first.
    @State var replace: String?

    var body: some View {
        DialogCard(tint: "teal", glyph: "check-circle", title: "SSH key saved", text: line, width: 600) {
            DialogBody {
                KeyPanel {
                    Lab(title: "Public key · \(key.kind)")
                    Text(verbatim: SshPage.breakAnywhere(key.publicKey)).font(.mono(14))
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityLabel(Text(verbatim: key.publicKey))
                    Lab(title: "Fingerprint").padding(.top, 14)
                    Text(verbatim: key.fingerprint).font(.mono(14)).fixedSize(horizontal: false, vertical: true)
                }
                HStack(spacing: 8) {
                    SheetButton(title: "Copy Public Key", action: copy)
                    SheetButton(title: "Save Public Key…") { save() }
                }
                .padding(.top, 14)
                if let folder = replace { ask(folder) }
            }
        } foot: {
            SheetButton(title: "Done", kind: .primary) { model.dialog = nil }
        }
    }

    /// The file is there already: Overwrite, or Cancel (the default).
    private func ask(_ folder: String) -> some View {
        HStack(spacing: 8) {
            Text(verbatim: "Overwrite “\(key.attachment).pub” in that folder? A file with this name is there.")
                .font(.sans(12)).foregroundStyle(Tok.warning)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button("Cancel") { replace = nil }.buttonStyle(Btn(size: .small))
            Button("Overwrite") { save(folder, overwrite: true) }.buttonStyle(Btn(kind: .danger, size: .small))
        }
        .padding(.top, 10)
    }

    /// Copy Public Key: APP-03's copy, of the public line only.
    private func copy() {
        let (session, vault, entry) = (model.session, model.vault.id, key.entry)
        model.notifyCopy("Public key") { try session.copySshPublicKey(vault: vault, entry: entry) }
    }

    /// Save Public Key…: a folder (the panel never shows in tests, rule
    /// 10), then the `.pub` file; one already there asks first.
    private func save(_ chosen: String? = nil, overwrite: Bool = false) {
        guard let folder = chosen ?? VaultModel.attachmentFolderPanel()?.path(percentEncoded: false) else { return }
        do {
            let saved = try model.session.saveSshPublicKey(
                vault: model.vault.id, entry: key.entry, folder: folder, overwrite: overwrite)
            replace = saved ? nil : folder
            if saved { model.notify(VaultModel.Toast(glyph: "check", text: "Public key saved.")) }
        } catch {
            replace = nil
            model.notify(VaultModel.Toast(glyph: "warning", text: message(error)))
        }
    }
}

/// "Key not saved": the key joined the entry but the save failed, so the
/// vault file is unchanged and the key stays in the open vault as an unsaved
/// change (APP-05). Try Again saves again through the same save queue;
/// Cancel leaves the unsaved change (INT-06.E24.04, .29; lead ruling (5)).
struct SshKeyNotSavedSheet: View {
    let model: VaultModel
    let key: NewSshKeyView
    let line: String

    var body: some View {
        DialogCard(
            tint: "teal", glyph: "warning-circle", title: "Key not saved", text: "The vault file is unchanged.",
            width: 600
        ) {
            DialogBody {
                Note(
                    text: "The new key stays in this entry as an unsaved change. "
                        + "Check that the vault is writable, then try again.", top: 0)
            }
        } foot: {
            SheetButton(title: "Cancel", cancel: true) { model.dialog = nil }
            SheetButton(title: "Try Again", kind: .primary) {
                Task { await model.saveSshKey(key, line: line) }
            }
        }
    }
}

extension VaultModel {
    /// The key joined its entry and Rust closed the editor: the window
    /// follows, as after Save, and the vault saves now.
    func sshKeyAdded(_ key: NewSshKeyView, line: String) async {
        editor?.close()
        editor = nil
        dialog = nil
        afterChange(select: key.entry)
        await saveSshKey(key, line: line)
    }

    /// Saves now. Only a save that wrote every change says "SSH key saved";
    /// a failed one says "Key not saved"; a save that asks a question first
    /// (APP-05) leaves its sheet up.
    func saveSshKey(_ key: NewSshKeyView, line: String) async {
        dialog = nil
        let status = await saveNow(failureSheet: false)
        guard dialog == nil else { return }
        let saved = status.map { $0.failure == nil && $0.changes == 0 } ?? false
        dialog = saved ? .sshKeySaved(key, line: line) : .sshKeyNotSaved(key, line: line)
    }
}
