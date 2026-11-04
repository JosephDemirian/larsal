import AppCore
import SwiftUI

/// The saving sheets (E5-S10): mockup `DIALOGS.disk`, `closeUnsaved` and
/// `saveFailed` in the dialog look, with the cards' words where they
/// differ (APP-05, APP-02.15), and APP-05.32's notice in the same look.
struct SavingSheet: View {
    let model: VaultModel
    let dialog: VaultModel.Dialog

    var body: some View {
        switch dialog {
        case .changedOnDisk(let ask, let changes):
            ChangedOnDiskSheet(model: model, ask: ask, changes: changes, older: model.disk.older)
        case .closeUnsaved(let changes):
            // APP-02.15 step 8, `MSG-LOCK-SAVE`: Save (default), Discard,
            // Cancel. The frame `dialogs-close-with-unsaved-changes`.
            DialogCard(
                tint: "teal", glyph: "floppy-disk", title: "\(model.vault.name) was changed. Save the changes?",
                text: "You have \(Formats.count(Int(changes), "change", "changes")) that are not saved yet."
            ) {
                Button("Discard") { model.answerUnsaved(save: false) }
                    .buttonStyle(Btn(size: .large))
                    .frame(maxWidth: .infinity, alignment: .leading)
                SheetButton(title: "Cancel", cancel: true) { model.answerUnsaved(save: nil) }
                SheetButton(title: "Save", kind: .primary) { model.answerUnsaved(save: true) }
            }
        case .saveFailed(let reason):
            // APP-05.13 `MSG-SAVE-FAILED`: the vault and the system's reason.
            DialogCard(
                tint: "red", glyph: "warning-circle", title: "App could not save “\(model.vault.name)”",
                text: reason + " Your changes are safe in memory until you quit."
            ) {
                Button("Save As…") { model.saveAs() }
                    .buttonStyle(Btn(size: .large))
                    .frame(maxWidth: .infinity, alignment: .leading)
                SheetButton(title: "Close", cancel: true) { model.dialog = nil }
                SheetButton(title: "Try Again", kind: .primary) {
                    model.dialog = nil
                    model.saving = Task { _ = await model.saveNow(asks: true) }
                }
            }
        case .formatNotice:
            // APP-05.32 `MSG-SAVE-V4-NOTICE` (LD-07): OK only, then the save.
            let backups = model.session.settings().flag(key: "backup.enabled")
            DialogCard(
                tint: "blue", glyph: "info", title: "From now on this vault is saved in the newer file format",
                text: "Apps that only read the older format cannot open it any more. The unlock time stays the same."
                    + (backups ? " The old file is kept as the backup." : "")
            ) {
                SheetButton(title: "OK", kind: .primary) { model.confirmFormatNotice() }
            }
        case .diskNewKey(let choice): DiskNewKeySheet(model: model, choice: choice)
        case .askUnsafe:
            // APP-05.14 `MSG-SAVE-UNSAFE-ASK` (LD-52): Cancel the default.
            DialogCard(
                tint: "orange", glyph: "warning", title: "Saving “\(model.vault.name)” failed several times",
                text: "A sync service may be holding the file. Turn off safe saving for this vault and try again?"
            ) {
                SheetButton(title: "Turn off") { model.turnOffSafeSave() }
                SheetButton(title: "Cancel", kind: .primary) { model.dialog = nil }
            }
        case .oldCopies(let paths): OldCopiesSheet(model: model, paths: paths)
        case .diskOldKey:
            // APP-05.29 `MSG-DISK-OLD-KEY` (MOD-11.31): Skip the default.
            DialogCard(
                tint: "orange", glyph: "lock-key", title: OldKeyWords.title(model.fileName), text: OldKeyWords.text
            ) {
                SheetButton(title: "Merge anyway") { model.resolveOldKey(mergeAnyway: true) }
                SheetButton(title: "Skip", kind: .primary) { model.resolveOldKey(mergeAnyway: false) }
            }
        case .copies: CopiesSheet(model: model, rows: model.disk.conflicts)
        case .changedAttachment(let name):
            // MOD-05.13: Save the default.
            DialogCard(
                tint: "orange", glyph: "paperclip", title: "Save the changes to “\(name)”?",
                text: "Another app changed the open copy of this attachment. Save the changed file into this entry?"
            ) {
                SheetButton(title: "Discard", cancel: true) { model.answerChangedCopy(name, save: false) }
                SheetButton(title: "Save", kind: .primary) { model.answerChangedCopy(name, save: true) }
            }
        default: EmptyView()
        }
    }
}

/// `dialogs-changed-on-disk` (APP-05.26 to APP-05.28, APP-05.30): the
/// file's name, the card's message, the choices as the mockup's `.choice`
/// rows (Merge the default), Cancel, and the chosen action. Up and down
/// arrows move the choice; Return runs it, Escape cancels.
private struct ChangedOnDiskSheet: View {
    let model: VaultModel
    let ask: DiskAsk
    let changes: UInt32
    /// APP-05.26 (LD-267 (3)): the "went back in time" line.
    let older: Bool
    @State private var chosen: DiskChoice?

    private struct Option {
        let choice: DiskChoice
        let title: String
        let note: String
    }

    var body: some View {
        let file = model.fileName
        let current = chosen ?? options.first?.choice ?? .later
        DialogCard(
            tint: "blue", glyph: "arrows-clockwise", title: "\(file) changed on disk", text: text(file), wide: true
        ) {
            DialogBody {
                VStack(spacing: 8) {
                    ForEach(options, id: \.title) { option in
                        Choice(isOn: current == option.choice, title: option.title, note: option.note) {
                            chosen = option.choice
                        }
                    }
                }
                .focusable()
                .onKeyPress(.downArrow) { move(1, from: current) }
                .onKeyPress(.upArrow) { move(-1, from: current) }
            }
        } foot: {
            SheetButton(title: ask == .reload ? "Keep" : "Cancel", cancel: true) {
                model.resolveDisk(.later, ask: ask)
            }
            SheetButton(title: options.first { $0.choice == current }?.title ?? "OK", kind: .primary) {
                model.resolveDisk(current, ask: ask)
            }
        }
    }

    private func move(_ step: Int, from current: DiskChoice) -> KeyPress.Result {
        guard let index = options.firstIndex(where: { $0.choice == current }) else { return .ignored }
        chosen = options[min(max(index + step, 0), options.count - 1)].choice
        return .handled
    }

    /// The card's message (`MSG-DISK-UNSAVED`, `-ON-SAVE`, `-UNREADABLE`,
    /// `-ASK-RELOAD`), with the rollback guard's line for an older version.
    private func text(_ file: String) -> String {
        let line = older ? " “\(file)” went back in time: it is older than a version App has seen." : ""
        return words(file) + line
    }

    private func words(_ file: String) -> String {
        switch ask {
        case .unsaved: "“\(file)” was changed by another program, and this vault has unsaved changes."
        case .onSave: "“\(file)” was changed by another program since it was opened."
        case .overwriteOnly:
            "App could not read the file on disk. Your open copy is unchanged. It may still be syncing."
        case .reload: "“\(file)” was changed by another program. Load the changes?"
        }
    }

    /// The card's buttons as the mockup's choices, in the mockup's order.
    private var options: [Option] {
        let merge = Option(
            choice: .merge, title: ask == .onSave ? "Merge then save" : "Merge",
            note: "Keep both. For an entry changed in both places, the newer version wins and the other goes to its "
                + "history.")
        let lost = Formats.count(Int(changes), "change is", "changes are")
        let discard = Option(choice: .reload, title: "Discard", note: "Open the version on disk. Your \(lost) lost.")
        let keep = Option(
            choice: .keepMine, title: ask == .unsaved ? "Ignore" : "Overwrite", note: "Save over the file on disk.")
        switch ask {
        case .unsaved, .onSave: return [merge, discard, keep]
        case .overwriteOnly: return [keep]
        case .reload: return [Option(choice: .reload, title: "Load", note: "Open the version on disk.")]
        }
    }
}

/// APP-05.29 (F-085), `MSG-DISK-NEW-KEY`: the unlock sheet for the changed
/// file, in the dialog look. Unlock goes on with the chosen Merge or
/// Discard (or the silent reload); Cancel acts as Cancel in APP-05.27.
private struct DiskNewKeySheet: View {
    let model: VaultModel
    let choice: DiskChoice
    @State private var password = ""
    @State private var keyFile = ""
    @State private var problem: String?
    @State private var busy = false
    @FocusState private var passwordFocused: Bool

    var body: some View {
        DialogCard(
            tint: "orange", glyph: "lock-key", title: "Unlock the changed “\(model.fileName)”",
            text: problem
                ?? "This copy of “\(model.fileName)” opens with another password or key. Enter the password or key "
                + "this copy opens with."
        ) {
            DialogBody {
                VStack(alignment: .leading, spacing: 10) {
                    InputBox {
                        Glyph(name: "key").foregroundStyle(Tok.muted)
                        SecureField("", text: $password, prompt: Text(verbatim: "Password"))
                            .textFieldStyle(.plain)
                            .accessibilityLabel(Text(verbatim: "Password"))
                            .focused($passwordFocused)
                            .onSubmit(unlock)
                    }
                    .capsLockNote(focused: passwordFocused)  // M06-37 (APP-06.6, F-076)
                    HStack(spacing: 8) {
                        InputBox { PlainField(prompt: "Key file (optional)", text: $keyFile, label: "Key file") }
                        // APP-06's Browse… (F-085); tests stub the panel (rule 10).
                        Button("Browse…") {
                            if let picked = NewVaultModel.openKeyFile() { keyFile = picked.path(percentEncoded: false) }
                        }
                        .buttonStyle(Btn(size: .large))
                    }
                }
            }
        } foot: {
            SheetButton(title: "Cancel", cancel: true) { model.resolveDisk(.later, ask: .unsaved) }
            SheetButton(title: "Unlock", kind: .primary, action: unlock).disabled(busy)
        }
    }

    private func unlock() {
        busy = true
        model.unlockDisk(
            choice, password: password.isEmpty ? nil : password, keyFile: keyFile.isEmpty ? nil : keyFile
        ) { text in
            busy = false
            problem = text
        }
    }
}

/// APP-05.33 (F-088), `MSG-KEY-OLD-COPIES`: the copies App made before the
/// key change, all checked; Delete checked and Keep (the default); OK
/// only when none is listed.
private struct OldCopiesSheet: View {
    let model: VaultModel
    let paths: [String]
    @State private var kept: Set<String> = []

    var body: some View {
        DialogCard(
            tint: "orange", glyph: "copy", title: "Old copies still open with the old credentials",
            text: "Backups and recovery copies made before this change still open with the old credentials, and so do "
                + "copies outside App (Time Machine, sync history)."
                + (paths.isEmpty ? "" : " Delete the copies App made of this vault?")
        ) {
            DialogBody {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(paths, id: \.self) { path in
                        CheckRow(
                            title: (path as NSString).lastPathComponent, detail: path,
                            isOn: Binding(
                                get: { !kept.contains(path) },
                                set: { checked in
                                    if checked { kept.remove(path) } else { kept.insert(path) }
                                })
                        )
                    }
                }
            }
        } foot: {
            if paths.isEmpty {
                SheetButton(title: "OK", kind: .primary) { model.dialog = nil }
            } else {
                SheetButton(title: "Delete checked", kind: .danger) {
                    model.deleteOldCopies(paths.filter { !kept.contains($0) })
                }
                SheetButton(title: "Keep", kind: .primary) { model.dialog = nil }
            }
        }
    }
}

/// `MSG-DISK-OLD-KEY` (APP-05.29, APP-05.17, MOD-11.31), one text for the
/// vault's own file and the listed copies.
enum OldKeyWords {
    static func title(_ file: String) -> String { "This copy of “\(file)” uses a replaced password" }

    static let text =
        "It uses a password or key that was replaced on this Mac. It may be an old copy, or come from someone who "
        + "knows the old password. App has not merged it. Merge anyway adds its entries and changes, but never its "
        + "password or key and never its deletions. For the vault's own file, Skip keeps your vault as it is and saves "
        + "it over this copy; for any other copy, Skip leaves it alone."
}

/// APP-05.17 `MSG-DISK-COPIES`: each listed copy with its state, a check box
/// (checked) on each merged one; Unlock… asks a copy's password with the
/// `MSG-DISK-NEW-KEY` words; a replaced-password copy shows
/// `MSG-DISK-OLD-KEY` with Skip (the default: it leaves the copy alone) and
/// Merge anyway (its content merge); Keep (the default) and Move to Trash.
private struct CopiesSheet: View {
    let model: VaultModel
    let rows: [CopyRow]
    @State private var unchecked: Set<String> = []
    @State private var skipped: Set<String> = []
    @State private var unlocking: String?
    @State private var password = ""
    @State private var keyFile = ""
    @State private var problem: String?
    @State private var busy = false

    var body: some View {
        DialogCard(
            tint: "blue", glyph: "copy", title: "Other copies of “\(model.fileName)”",
            text: problem
                ?? "A sync service made other copies of “\(model.fileName)”. App merged the ones it could open into "
                + "this vault. Move them to the Trash?", wide: true
        ) {
            DialogBody {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(rows, id: \.path) { row in HStack(spacing: 8) { line(row) } }
                    if let unlocking { form(unlocking) }
                }
            }
        } foot: {
            SheetButton(title: "Move to Trash", kind: .danger) { model.copiesDone(trash: true, unchecked: unchecked) }
            SheetButton(title: "Keep", kind: .primary) { model.copiesDone(trash: false) }
        }
        // A copy's state changed: its form is done.
        .onChange(of: rows) {
            unlocking = nil
            busy = false
            problem = nil
        }
    }

    /// A merged copy's check box, or a copy's state and its button.
    @ViewBuilder private func line(_ row: CopyRow) -> some View {
        if row.state == .merged {
            CheckRow(title: name(row), detail: "Merged", isOn: checked(row.path))
        } else {
            let old = row.state == .oldKey
            VStack(alignment: .leading, spacing: 0) {
                Text(verbatim: name(row)).frame(minHeight: 20, alignment: .leading)
                Text(verbatim: old ? "Uses a replaced password" : "Needs its password")
                    .font(.sans(12)).foregroundStyle(Tok.muted)
                // MOD-11.31: the warning before any merge; Skip, the default, leaves the copy alone.
                if old, !skipped.contains(row.path) {
                    Text(verbatim: OldKeyWords.text).font(.sans(12)).foregroundStyle(Tok.muted).padding(.vertical, 6)
                    HStack(spacing: 8) {
                        Button("Merge anyway") { merge(row.path, anyway: true) }.buttonStyle(Btn(size: .large))
                        Button("Skip") { skipped.insert(row.path) }.buttonStyle(Btn(kind: .primary, size: .large))
                    }
                    .disabled(busy)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if !old {
                Button("Unlock…") { (unlocking, problem) = (row.path, nil) }
                    .buttonStyle(Btn(size: .large))
                    .disabled(busy)
            }
        }
    }

    /// Unlock…'s form, with the `MSG-DISK-NEW-KEY` words.
    @ViewBuilder private func form(_ path: String) -> some View {
        Text(
            verbatim: "This copy of “\((path as NSString).lastPathComponent)” opens with another password or key. "
                + "Enter the password or key this copy opens with."
        )
        .font(.sans(12)).foregroundStyle(Tok.muted)
        InputBox {
            Glyph(name: "key").foregroundStyle(Tok.muted)
            SecureField("", text: $password, prompt: Text(verbatim: "Password"))
                .textFieldStyle(.plain)
                .accessibilityLabel(Text(verbatim: "Password"))
                .onSubmit { merge(path, anyway: false) }
        }
        HStack(spacing: 8) {
            InputBox { PlainField(prompt: "Key file (optional)", text: $keyFile, label: "Key file") }
            Button("Unlock") { merge(path, anyway: false) }
                .buttonStyle(Btn(size: .large))
                .disabled(busy)
        }
    }

    private func checked(_ path: String) -> Binding<Bool> {
        Binding(
            get: { !unchecked.contains(path) },
            set: { isOn in
                if isOn { unchecked.remove(path) } else { unchecked.insert(path) }
            })
    }

    private func name(_ row: CopyRow) -> String {
        row.version ? "iCloud version of “\(model.fileName)”" : (row.path as NSString).lastPathComponent
    }

    private func merge(_ path: String, anyway: Bool) {
        busy = true
        let typed = anyway || password.isEmpty ? nil : password
        let key = anyway || keyFile.isEmpty ? nil : keyFile
        password = ""
        model.mergeCopy(path, password: typed, keyFile: key, anyway: anyway) { text in
            busy = false
            problem = text
        }
    }
}
