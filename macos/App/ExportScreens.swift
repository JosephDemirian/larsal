import AppCore
import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// One step of a plain export from the window (FEA-09, INT-04.50, SD-07):
/// every export shows Rust's warning before any file is written. Rust
/// builds and writes the file; Swift sends only the path and the options.
enum ExportStep: Hashable {
    /// MSG-EXP-CONFIRM before the save panel (CSV and XML, FEA-09.2).
    case ask(ExportFormat, ExportWarning)
    /// The HTML dialog (FEA-09.7): the warning stays on it as its banner.
    case html(ExportWarning)
    /// MI04-30 before the list of passkeys (INT-04.50 step 1).
    case passkeyWarning(text: String, rows: [PasskeyRow])
    /// The entries to export, all chosen at first (step 2, MI04-31).
    case passkeys([PasskeyRow])
    /// MI04-32 for `file` in `folder`; the entries in `rest` follow.
    case passkeyExists(file: String, entry: String, folder: String, rest: [String])
}

extension VaultModel {
    /// File > Export ▸ CSV…, HTML… or XML… (FEA-09.1): Rust's warning first.
    func askExport(_ format: ExportFormat) {
        let warning = exportWarning(format: format)
        dialog = .export(warning.asksFirst ? .ask(format, warning) : .html(warning))
    }

    /// Yes under MSG-EXP-CONFIRM, or OK on the HTML dialog: the save panel,
    /// then Rust writes the file off the screen thread (FEA-09.15).
    func export(_ format: ExportFormat, type: String, sort: ExportSort = .nameAscending) {
        dialog = nil
        guard let url = Self.exportPanel(type, vault.name) else { return }
        let (session, id, path) = (session, vault.id, url.path(percentEncoded: false))
        Task {
            let result = await Task.detached {
                Result { try session.exportVault(vault: id, format: format, path: path, sort: sort, warned: true) }
            }.value
            if case .failure(let error) = result { notify(Toast(glyph: "warning", text: message(error))) }
        }
    }

    /// The export save panel (FEA-09.15; never shown by tests, AGENTS.md
    /// rule 10): the format in its title and filter, named after the vault.
    static var exportPanel: (_ type: String, _ name: String) -> URL? = { type, name in
        // ponytail: starts in the home folder, APP-01.15's fallback; keep a
        // last folder per format once S-STATE-06 has its Swift call.
        let panel = NSSavePanel()
        panel.title = "Export " + type.uppercased()
        panel.nameFieldStringValue = name + "." + type
        panel.allowedContentTypes = [UTType(filenameExtension: type) ?? .data]
        panel.directoryURL = URL(fileURLWithPath: NSHomeDirectory())
        panel.canCreateDirectories = true
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// The Passkeys report's Export Passkeys… (INT-04.50): MI04-30 first.
    func askPasskeyExport() {
        guard let rows = reports?.passkeys, !rows.isEmpty else { return }
        dialog = .export(.passkeyWarning(text: passkeyExportWarning(), rows: rows))
    }

    /// Export Selected (steps 3 and 4): the folder, then one file each.
    func exportPasskeys(_ entries: [String]) {
        dialog = nil
        guard let folder = Self.passkeyFolderPanel() else { return }
        exportPasskeys(entries, to: folder.path(percentEncoded: false))
    }

    /// Step 4: one `.passkey` file per entry, 0600; a file already there
    /// asks MI04-32 (`replace` is its Yes for the first entry), a failed
    /// write says MI04-33 and the next entry follows.
    func exportPasskeys(_ entries: [String], to folder: String, replace: Bool = false) {
        for (index, entry) in entries.enumerated() {
            do {
                let done = try session.exportPasskey(
                    vault: vault.id, entry: entry, folder: folder, warned: true, replace: replace && index == 0)
                if case .exists(let file) = done {
                    let rest = Array(entries.dropFirst(index + 1))
                    dialog = .export(.passkeyExists(file: file, entry: entry, folder: folder, rest: rest))
                    return
                }
            } catch {
                notify(Toast(glyph: "warning", text: message(error)))
            }
        }
        dialog = nil
    }

    /// INT-04.50 step 3: the passkey folder (never shown by tests).
    static var passkeyFolderPanel: () -> URL? = {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.directoryURL = URL(fileURLWithPath: NSHomeDirectory())
        panel.prompt = "Export"
        return panel.runModal() == .OK ? panel.url : nil
    }
}

/// The export sheets (mockup `dialogs-export-warning`), with the cards'
/// words: Yes and No where the card asks, No the default: Return answers
/// it as Escape does (FEA-09.2, INT-04.50, LD-244 (2)).
struct ExportSheet: View {
    let model: VaultModel
    let step: ExportStep

    var body: some View {
        switch step {
        case .ask(let format, let warning):
            DialogCard(tint: "orange", glyph: "warning", title: warning.title, text: warning.text) {
                no { model.dialog = nil }
                SheetButton(title: "Yes", kind: .danger) { model.export(format, type: warning.extension) }
            }
        case .html(let warning): HtmlExportSheet(model: model, warning: warning)
        case .passkeyWarning(let text, let rows):
            DialogCard(tint: "orange", glyph: "warning", title: "Export without encryption?", text: text) {
                no { model.dialog = nil }
                SheetButton(title: "Yes", kind: .danger) { model.dialog = .export(.passkeys(rows)) }
            }
        case .passkeys(let rows): PasskeyListSheet(model: model, rows: rows)
        case .passkeyExists(let file, let entry, let folder, let rest):
            DialogCard(
                tint: "orange", glyph: "warning",
                title: "A file named \(file) is already in this folder. Replace it?"
            ) {
                no { model.exportPasskeys(rest, to: folder) }
                SheetButton(title: "Yes", kind: .danger) {
                    model.exportPasskeys([entry] + rest, to: folder, replace: true)
                }
            }
        }
    }
}

extension ExportSheet {
    /// No, answered by Escape and by Return (the hidden default button).
    private func no(_ action: @escaping () -> Void) -> some View {
        SheetButton(title: "No", cancel: true, action: action)
            .background {
                Button("", action: action).keyboardShortcut(.defaultAction).opacity(0).accessibilityHidden(true)
            }
    }
}

/// FEA-09.7: the warning as the dialog's banner, and "sort entries by".
private struct HtmlExportSheet: View {
    let model: VaultModel
    let warning: ExportWarning
    @State private var sort = ExportSort.nameAscending

    var body: some View {
        DialogCard(tint: "orange", glyph: "warning", title: warning.title, text: warning.text) {
            DialogBody {
                Lab(title: "Sort entries by")
                VStack(spacing: 8) {
                    choice(.nameAscending, "Name, A to Z")
                    choice(.nameDescending, "Name, Z to A")
                    choice(.vaultOrder, "Order in the vault")
                }
            }
        } foot: {
            SheetButton(title: "Cancel", cancel: true) { model.dialog = nil }
            SheetButton(title: "OK", kind: .primary) { model.export(.html, type: warning.extension, sort: sort) }
        }
    }

    private func choice(_ value: ExportSort, _ title: String) -> some View {
        Choice(isOn: sort == value, title: title) { sort = value }
    }
}

/// INT-04.50 step 2: "‹title› - ‹user name›" for each entry, all chosen.
private struct PasskeyListSheet: View {
    let model: VaultModel
    let rows: [PasskeyRow]
    @State private var off: Set<String> = []
    @State private var listHeight: CGFloat = 0
    @Environment(\.maskUserNames) private var maskUser

    var body: some View {
        let chosen = rows.map(\.entry.id).filter { !off.contains($0) }
        DialogCard(
            tint: "purple", glyph: "fingerprint", title: "Export passkeys",
            text: "Each file is named after its entry's title."
        ) {
            DialogBody {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(rows, id: \.entry.id) { row in
                            CheckRow(
                                title: row.entry.title + " - " + (maskUser ? Masked.text : row.user), isOn: on(row))
                        }
                    }
                    .onGeometryChange(for: CGFloat.self) {
                        $0.size.height
                    } action: {
                        listHeight = $0
                    }
                }
                .scrollIndicators(.never)
                // As tall as the list, scrolling past 260 points.
                .frame(height: min(listHeight, 260))
            }
        } foot: {
            SheetButton(title: "Cancel", cancel: true) { model.dialog = nil }
            SheetButton(title: "Export Selected", kind: .primary) { model.exportPasskeys(chosen) }
                .disabled(chosen.isEmpty)
        }
    }

    private func on(_ row: PasskeyRow) -> Binding<Bool> {
        Binding(
            get: { !off.contains(row.entry.id) },
            set: { if $0 { off.remove(row.entry.id) } else { off.insert(row.entry.id) } })
    }
}
