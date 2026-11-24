import AppKit
import Foundation
import LarsalCore

/// The window's vault changes (E5-S5): the editor, the sheets that change
/// the vault, and the save after each change (APP-05). Every change is one
/// Rust call; values never come back except the one Show value a sheet was
/// opened for.
extension VaultModel {
    /// A sheet dropped from the window top (mockup `DIALOGS`).
    enum Dialog: Hashable {
        case moveToBin(id: String, title: String)
        case deleteForever(id: String, title: String)
        case emptyBin(titles: [String])
        case discard
        case clone(id: String, title: String)
        case totpSetup(TotpSetup)
        case totpQr(title: String, symbol: Qr, custom: Bool)
        case wifiQr(network: String, symbol: Qr)
        case newGroup(name: String)
        case removePasskey(site: String)
        case version(index: UInt32, VersionView)
        case removeField(name: String)
        case removeCustomData(key: String)
        case removeAttachment(name: String)
        case overwriteAttachment(name: String)
        case bigFile(name: String, megabytes: String)
        case openRisky(name: String)
        case replaceFile(name: String, folder: String)
        case preview(name: String, AttachmentPreview)
        case leaveEditor
        /// APP-02.15 step 7 (F-122): `MSG-LOCK-DISCARD-EDIT` before a
        /// manual lock or a quit.
        case lockDiscardEdit
        /// The saving sheets (E5-S10, SavingSheets.swift).
        case changedOnDisk(ask: DiskAsk, changes: UInt32)
        case closeUnsaved(changes: UInt32)
        case saveFailed(reason: String)
        case formatNotice
        /// APP-05.29 (F-085): the unlock sheet for the changed file; the
        /// chosen Merge or Reload goes on after it.
        case diskNewKey(choice: DiskChoice)
        /// APP-05.14 (F-087): `MSG-SAVE-UNSAFE-ASK`.
        case askUnsafe
        /// APP-05.33 (F-088): `MSG-KEY-OLD-COPIES` with the copies' paths.
        case oldCopies([String])
        /// MOD-05.13 (F-086): another app changed an open copy.
        case changedAttachment(name: String)
        case diskOldKey, copies  // E15-S4: `MSG-DISK-OLD-KEY` (APP-05.29), `MSG-DISK-COPIES` (APP-05.17)
        /// A plain export's sheets (ExportScreens.swift, SD-07).
        case export(ExportStep)
        /// INT-08.31: the Approve sheet of a share made elsewhere.
        case approveShare(ShareLabel)
    }

    // MARK: The editor

    /// Edit entry (⌘E): the editor takes the sheet.
    func edit(_ id: String? = nil) {
        guard let id = id ?? selection else { return }
        overlay = nil
        do {
            let view = try session.beginEdit(vault: vault.id, entry: id)
            editor = EditorModel(session: session, vault: vault, view: view)
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    /// New Entry: a new entry in the group on screen, else the root group.
    func newEntry(in group: String? = nil) {
        overlay = nil
        var target = group
        if target == nil, case .group(let id) = place { target = id }
        do {
            let view = try session.beginNew(vault: vault.id, group: target)
            editor = EditorModel(session: session, vault: vault, view: view)
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    /// Cancel: with changes, the Discard sheet asks first (the unsaved
    /// changes check); without, the editor closes.
    func cancelEditor() {
        guard let editor else { return }
        if untouched(editor) {
            // F-122: a changed open copy asks before the close wipes it.
            if askChangedCopy() { return }
            closeEditor()
        } else {
            dialog = .discard
        }
    }

    /// The draft has no change (a new entry: nothing typed or added).
    func untouched(_ editor: EditorModel) -> Bool {
        let draft = editor.view
        guard draft.new else { return draft.changed.isEmpty }
        let blank = [draft.title, draft.url, draft.notes].allSatisfy(\.isEmpty) && draft.passwordChars == 0
        return blank && draft.custom.isEmpty && draft.tags.isEmpty && draft.attachments.isEmpty && draft.totp == nil
    }

    /// Leaving this vault (a switch or a close) with the editor open
    /// (LD-199 (2)): without changes the editor closes; with changes the
    /// unsaved-changes question shows (Save, Discard, Cancel) and `then`
    /// runs after Save or Discard. True when it asked.
    func askLeave(then: @escaping () -> Void) -> Bool {
        guard let editor else { return false }
        if untouched(editor) {
            // MOD-05.13 (F-086): a changed open copy asks before the close
            // wipes it; the leave waits.
            if askChangedCopy() { return true }
            closeEditor()
            return false
        }
        afterLeave = then
        dialog = .leaveEditor
        return true
    }

    /// The answer to the unsaved-changes question.
    func answerLeave(save: Bool) {
        if save {
            // F-086: the sheet is free for Save's changed-copy question;
            // while it shows, the editor stays open and the leave waits.
            dialog = nil
            saveEditor()
            guard editor == nil else {
                if dialog == nil { dialog = .leaveEditor }  // refused: the question stays
                return
            }
        } else {
            closeEditor()
        }
        dialog = nil
        let next = afterLeave
        afterLeave = nil
        next?()
    }

    /// Drops the draft; nothing changed (MOD-01.25).
    func closeEditor() {
        editor?.close()
        try? session.cancelEdit(vault: vault.id)
        editor = nil
        dialog = nil
    }

    /// Save (⌘S): the draft is committed in one edit session and the vault
    /// saves. A refusal keeps the editor open with its reason.
    func saveEditor() {
        guard let editor else { return }
        // MOD-05.13 (F-086): an open copy changed by another app asks
        // before the editor closes and wipes it.
        if askChangedCopy() { return }
        let passwordChanged = editor.view.changed.contains("Password")
        do {
            let id = try session.commitEdit(vault: vault.id)
            editor.close()
            self.editor = nil
            afterChange(select: id)
            reports?.edited(id, passwordChanged: passwordChanged)  // FEA-06.11
        } catch {
            editor.problem = message(error)
        }
    }

    // MARK: Sheets that change the vault

    /// Delete (⌘⌫): asks only while S-ENTRY-02 is on or for good (MOD-04.3).
    func askDelete(_ id: String? = nil) {
        overlay = nil
        guard let id = id ?? selection,
            let title = rows.first(where: { $0.id == id })?.title ?? detail.map({ $0.title })
        else { return }
        if place == .bin || detail?.inBin == true {
            dialog = .deleteForever(id: id, title: title)
        } else if askBeforeBin {
            dialog = .moveToBin(id: id, title: title)
        } else {
            delete(id)
        }
    }

    func delete(_ id: String) {
        dialog = nil
        do {
            _ = try session.deleteEntry(vault: vault.id, entry: id)
            afterChange(select: nil)
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    func restore(_ id: String) {
        do {
            let toRoot = try session.restoreEntry(vault: vault.id, entry: id)
            afterChange(select: nil)
            if toRoot { notify(Toast(glyph: "info", text: "1 entry restored to the root group")) }
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    func askEmptyBin() {
        let titles = (try? session.list(vault: vault.id, view: .bin))?.rows.map(\.title) ?? []
        dialog = .emptyBin(titles: titles)
    }

    func emptyBin() {
        dialog = nil
        do {
            _ = try session.emptyBin(vault: vault.id)
            afterChange(select: nil)
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    func askClone() {
        overlay = nil
        guard let id = selection, let title = detail?.title, detail?.inBin == false else { return }
        dialog = .clone(id: id, title: title)
    }

    func clone(_ id: String, suffix: Bool, refs: Bool, history: Bool) {
        dialog = nil
        do {
            let new = try session.cloneEntry(vault: vault.id, entry: id, suffix: suffix, refs: refs, history: history)
            afterChange(select: new)
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    /// New group with a symbol and colour as its custom icon (LD-192 (1)).
    func addGroup(name: String, parent: String?, glyph: String, colour: String) {
        do {
            var icon: String?
            if let png = SymbolIcon.png(glyph, colour) {
                icon = try session.addCustomIcon(vault: vault.id, png: png, name: SymbolIcon.name(glyph, colour))
            }
            _ = try session.addGroup(vault: vault.id, parent: parent, name: name, icon: 48, customIcon: icon)
            dialog = nil
            afterChange(select: nil)
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    /// The Wi-Fi entry's QR button: the symbol is made in Rust.
    func showWifiQr() {
        guard let id = selection, let detail else { return }
        let network = detail.fields.first { $0.kind == .userName }?.value ?? detail.title
        if let symbol = try? session.wifiQr(vault: vault.id, entry: id) {
            dialog = .wifiQr(network: network, symbol: symbol)
        }
    }

    /// After a vault change: the sidebar, the list and the detail are read
    /// again with `id` selected, the passwords are rated again (LD-139), and
    /// the vault saves (APP-05).
    func afterChange(select id: String?) {
        rating?.cancel()
        ratingWorker?.cancel()
        rating = nil
        ratingWorker = nil
        rated()
        if let id, rows.contains(where: { $0.id == id }) { select(id) }
        rateAll()
        reports?.refresh()  // FEA-05.18: recomputed after each action
        saveSoon()
    }

    // MARK: Attachments (MOD-05)

    /// Open (MOD-05.12): Rust writes the private copy; the default app gets
    /// its path through `FileOpener`.
    func openAttachment(_ name: String, confirmed: Bool = false) {
        do {
            switch try session.openAttachment(vault: vault.id, name: name, confirmed: confirmed) {
            case .askFirst:
                dialog = .openRisky(name: name)
            case .opened(let path):
                dialog = nil
                if !FileOpener.open(URL(fileURLWithPath: path)) {
                    notify(Toast(glyph: "warning", text: "Cannot open “\(name)”."))
                }
                watchOpenCopies(path)
            }
        } catch {
            dialog = nil
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    /// Preview (MOD-05.9, SD-13) of an attachment of the selected entry,
    /// from Rust: an image it decoded, or plain text.
    func previewAttachment(_ name: String) {
        guard let selection else { return }
        do {
            dialog = .preview(name: name, try session.previewAttachment(vault: vault.id, entry: selection, name: name))
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    /// Save… into `folder` (MOD-05.14); an existing file asks first.
    func saveAttachment(_ name: String, to folder: String, overwrite: Bool = false) {
        do {
            let saved = try session.saveAttachment(vault: vault.id, name: name, folder: folder, overwrite: overwrite)
            dialog = saved ? nil : .replaceFile(name: name, folder: folder)
        } catch {
            dialog = nil
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    /// MOD-05.13 (F-086): while the editor is open, the open copy at `path`
    /// is watched with file events (DiskWatch, joined over 500 ms) plus a
    /// check every 5 seconds.
    func watchOpenCopies(_ path: String) {
        disk.copyWatches.append(
            DiskWatch(path: path) { [weak self] _ in
                Task { @MainActor in await self?.lookAtCopies() }
            })
        guard disk.copies == nil else { return }
        disk.copies = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                guard let self, self.editor != nil else { break }
                await self.lookAtCopies()
            }
            self?.disk.copies = nil
            self?.disk.copyWatches = []  // the editor closed: its copies are gone
        }
    }

    /// Rust compares each open copy with what it wrote (SHA-256), off the
    /// main thread (a copy may be as large as the attachment limit); a
    /// changed one asks Save or Discard, one question at a time.
    func lookAtCopies() async {
        guard editor != nil else { return }
        let (session, id) = (session, vault.id)
        let changed = await Task.detached { try? session.changedAttachments(vault: id) }.value
        if dialog == nil, editor != nil, let name = changed?.first {
            dialog = .changedAttachment(name: name)
        }
    }

    /// Asks about the first changed open copy; true when it asked.
    func askChangedCopy() -> Bool {
        guard dialog == nil, let name = (try? session.changedAttachments(vault: vault.id))?.first else { return false }
        dialog = .changedAttachment(name: name)
        return true
    }

    /// Save puts the changed copy into the draft; Discard keeps the draft.
    func answerChangedCopy(_ name: String, save: Bool) {
        dialog = nil
        let (session, id) = (session, vault.id)
        editor?.run { try session.takeChangedAttachment(vault: id, name: name, save: save) }
    }

    /// The answer to a file question (MOD-05.5), then the next file.
    func answerFile(_ yes: Bool, overwrite: Bool) {
        editor?.answer(yes, overwrite: overwrite)
        dialog = nil
        Task { [weak self] in self?.dialog = await self?.editor?.nextFile() }
    }

    // MARK: Saving (APP-05)

    /// Saves off the screen thread after a change (APP-05.2, APP-05.3,
    /// Saving.swift); the footer follows.
    func saveSoon() {
        scheduleSave()
    }

    /// The footer's words (mockup `.saved`).
    var savedWords: (dirty: Bool, text: String) {
        // M06-35 while a save's security key challenge waits (INT-07.19).
        if KeyTouch.shared.waits { return (true, KeyTouch.words) }
        if let status = saveStatus, status.changes > 0 {
            let changes = Formats.count(Int(status.changes), "change", "changes")
            return (true, changes + " not saved yet")
        }
        if let time = saveStatus?.savedAt ?? sidebar?.savedAt {
            return (false, "Saved at \(Formats.time(time)) · encrypted")
        }
        return (false, "Saved just now · encrypted")
    }
}

/// Hands a file to its default app (MOD-05.12). Tests put a fake here, so
/// nothing opens on the owner's screen (AGENTS.md rule 10).
enum FileOpener {
    static var open: (URL) -> Bool = { NSWorkspace.shared.open($0) }
}
