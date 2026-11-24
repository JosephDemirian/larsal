import AppKit
import Foundation
import LarsalCore
import UniformTypeIdentifiers
import os

/// APP-02.15 step 8 for a quit, Lock Everything and the automatic locks:
/// each changed vault saves first, in a coordinated write off the main
/// thread (APP-05.24), or asks, or goes to a recovery copy (APP-02.16).
extension MainWindowModel {
    /// Each changed vault saves first and the quit waits; a vault that is
    /// not saved by the settings, or whose save fails, asks on its screen
    /// and the quit stops. Save or Discard there quits again. With `asks`
    /// off (a quit signal, logout, restart or shut down) it never asks: a
    /// vault it cannot save goes to a recovery copy (APP-02.16).
    func mayQuit(asks: Bool) async -> Bool {
        await saveAll(asks: asks) { NSApp?.terminate(nil) }
    }

    /// APP-02.15 step 8 for every unlocked vault, before a quit or the
    /// menu's Lock Everything: true when they may go. Each save runs off the
    /// main thread (LD-228 (1)). A vault that asks is locked after its Save
    /// or Discard, then `then` goes on. With `asks` off a vault not saved
    /// goes to a recovery copy (APP-02.16).
    func saveAll(asks: Bool, then: @escaping () -> Void) async -> Bool {
        let saveFirst = savesFirst
        for vault in vaults where !vault.locked {
            let (session, id, screen) = (session, vault.id, opened[vault.id])
            guard let status = try? session.saveStatus(vault: id), status.changes > 0 else { continue }
            // A quit signal or a logout never waits for a download: a
            // dataless file goes to a recovery copy at once (APP-02.16). The
            // user's quit and Lock Everything wait, with "Still downloading"
            // on the vault (APP-05.30).
            let dataless = await FileAccess.dataless(vault.path)
            let shows: (Bool) -> Void = { screen?.downloading = $0 }
            let save: @Sendable () -> Bool = { (try? session.save(vault: id))?.changes == 0 }
            if saveFirst, asks || !dataless, await FileAccess.run(.replace, vault.path, downloading: shows, save) {
                continue
            }
            guard asks else {
                await Task.detached { _ = try? session.writeRecoveryCopy(vault: id) }.value
                continue
            }
            switchTo(id)
            // In front, as askEditor (F-122): the icon's Lock Everything and
            // Quit run while the window may be hidden.
            rules.bring()
            guard let main, main.vault.id == id, main.dialog == nil else { return false }
            main.afterLeave = { [weak self] in self?.lockNow(id, then: then) }
            main.dialog = .closeUnsaved(changes: (try? session.saveStatus(vault: id))?.changes ?? status.changes)
            return false
        }
        return true
    }

    /// The automatic locks' step 8 (APP-02.16, F-101): never asks. Each
    /// changed vault's save runs on another thread and the lock goes on
    /// once it has waited `deadline`; a save still running then keeps its
    /// change in the recovery copy itself if it does not write (saving.rs).
    /// A vault not saved goes to a recovery copy. ponytail: one wait per
    /// vault, so N stalled vaults wait N deadlines; one shared deadline if
    /// that ever matters.
    func saveBeforeLock(within deadline: DispatchTimeInterval) {
        let saveFirst = savesFirst
        for vault in vaults where !vault.locked {
            guard ((try? session.saveStatus(vault: vault.id))?.changes ?? 0) > 0 else { continue }
            // nil: still saving when the deadline passed.
            if saveFirst, Self.saved(session, vault.id, vault.path, within: deadline) != false { continue }
            _ = try? session.writeRecoveryCopy(vault: vault.id)
        }
    }

    /// `save.after_every_change` or `save.on_lock` (APP-02.15 step 8).
    private var savesFirst: Bool {
        session.settings().flag(key: "save.after_every_change") || session.settings().flag(key: "save.on_lock")
    }

    /// F-101 (LD-225 (1)): vault `id`'s save at `path` in a coordinated
    /// write on another thread, waited for at most `wait`: whether it saved
    /// every change; nil when it still runs. A save that has not started
    /// by then (another process holds the file, APP-05.24) never starts:
    /// false, so the lock keeps the change in the recovery copy.
    nonisolated static func saved(
        _ session: Session, _ id: UInt64, _ path: String, within wait: DispatchTimeInterval
    ) -> Bool? {
        let done = DispatchSemaphore(value: 0)
        // The save started; the lock gave up on it; it saved every change.
        let state = OSAllocatedUnfairLock(initialState: (started: false, gaveUp: false, saved: false))
        FileAccess.coordinate(.replace, path) {
            let begins = state.withLock { now in
                now.started = !now.gaveUp
                return now.started
            }
            guard begins else { return }
            let all = (try? session.save(vault: id))?.changes == 0
            state.withLock { $0.saved = all }
            done.signal()
        }
        if done.wait(timeout: .now() + wait) == .success { return state.withLock { $0.saved } }
        return state.withLock { now in
            now.gaveUp = !now.started
            return now.started ? nil : false
        }
    }
}

// MARK: Save As (APP-05.6), the guard's answers and the conflict copies (E15-S4)

/// One copy `MSG-DISK-COPIES` lists (APP-05.17 step 6): its file and its
/// state; `version`: an iCloud conflict version of the vault's file,
/// resolved rather than moved to the Trash.
struct CopyRow: Hashable, Sendable {
    let path: String
    var state: CopyState
    let version: Bool
}

extension VaultModel {
    /// The save-failed sheet's Save As… (APP-05.6): a save panel in the
    /// vault's folder; after a good write the vault lives there.
    func saveAs() {
        let current = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
        guard let target = Self.saveAsPanel(current) else { return }
        dialog = nil
        let (session, id) = (session, vault.id)
        let chosen = target.path(percentEncoded: false)
        saving = Task { [weak self] in
            guard let self else { return }
            let status = await self.onFile(.replace, at: chosen) {
                try? session.saveAs(vault: id, path: chosen)
            }
            guard let status else { return }
            self.saved(status, asks: true)
            if status.failure == nil { self.watchDisk() }
        }
    }

    /// The save panel (never shown by tests, AGENTS.md rule 10).
    static var saveAsPanel: (URL) -> URL? = { current in
        let panel = NSSavePanel()
        panel.directoryURL = current.deletingLastPathComponent()
        panel.nameFieldStringValue = current.lastPathComponent
        panel.allowedContentTypes = [UTType(filenameExtension: "larsalvault") ?? .data]
        panel.canCreateDirectories = true
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// The rollback guard's and the retired-key check's answers (APP-05.26,
    /// APP-05.29, MOD-11.31; E15-S4).
    func guardEvent(_ event: DiskEvent) {
        switch event {
        case .oldKey:
            // APP-05.29, MOD-11.31: nothing merged; Skip is the default.
            dialog = .diskOldKey
        case .rollback:
            // APP-05.26 (LD-267 (3)): merged, never loaded; saved at once,
            // whatever S-FILE-01 says, and said once that save is done.
            afterChange(select: selection)
            saving = Task { [weak self] in
                guard let self, let status = await self.saveNow(asks: true), status.changes == 0 else { return }
                self.notify(
                    Toast(
                        glyph: "clock-counter-clockwise", text: "“\(self.fileName)” went back in time.",
                        note:
                            "It is older than a version Larsal has seen. Larsal merged it into your vault, so nothing "
                            + "newer was lost, and saved the result. A sync service, an old backup or another Mac "
                            + "may have put it back."))
            }
        case .weaker(let settings):
            // APP-05.26 `MSG-DISK-WEAKER`: the names, never a value.
            afterChange(select: selection)
            notify(Self.weakerToast(fileName, settings))
        default:
            break
        }
    }

    /// `MSG-DISK-WEAKER` (APP-05.26).
    static func weakerToast(_ file: String, _ settings: String) -> Toast {
        Toast(
            glyph: "warning",
            text: "“\(file)” is saved with weaker settings than Larsal has seen for this vault: "
                + "\(settings).", note: "Check them in Vault Settings.")
    }

    /// APP-05.29 `MSG-DISK-OLD-KEY` for the vault's own file: Skip takes
    /// nothing, Merge anyway the content merge only; either way the vault
    /// keeps this Mac's key and is saved over the copy at once, as
    /// Overwrite.
    func resolveOldKey(mergeAnyway: Bool) {
        dialog = nil
        guard let event = try? session.resolveOldKey(vault: vault.id, mergeAnyway: mergeAnyway) else { return }
        if event == .reloaded { afterChange(select: selection) }
        saving = Task { [weak self] in _ = await self?.saveNow(asks: true) }
    }
}

extension VaultModel {
    /// APP-05.17: after each unlock, and after a watch event or tick that
    /// found the vault's own file unchanged, at a time APP-05.25 allows.
    /// Rust lists the sibling candidates, the seam the iCloud conflict
    /// versions; each copy is read in a coordinated read off the main
    /// thread and merged when it opens with the current key and has the
    /// vault's root group id. After the merges the vault saves, then
    /// `MSG-DISK-COPIES` lists the copies.
    func findCopies() {
        guard editor == nil, sharing.editor == nil, dialog == nil, !disk.checking, !disk.pending, !disk.finding else {
            return
        }
        disk.finding = true
        let (session, id, file) = (session, vault.id, (path as NSString).expandingTildeInPath)
        let cloud = FileAccess.cloud.withLock { $0 }
        Task { [weak self] in
            let (siblings, versions) = await Task.detached {
                ((try? session.conflictCopies(vault: id)) ?? [], cloud.unresolved(file))
            }.value
            var rows: [CopyRow] = []
            for (copy, version) in siblings.map({ ($0, false) }) + versions.map({ ($0, true) }) {
                let state = await FileAccess.run(.read, copy) {
                    (try? session.mergeCopy(vault: id, path: copy, password: nil, keyFile: nil, anyway: false))
                        ?? .skipped
                }
                if state != .skipped { rows.append(CopyRow(path: copy, state: state, version: version)) }
            }
            guard let self else { return }
            self.disk.finding = false
            guard !rows.isEmpty else { return }
            if rows.contains(where: { $0.state == .merged }) {
                self.afterChange(select: self.selection)
                guard await self.saveNow(asks: true)?.changes == 0 else { return }
            }
            self.disk.conflicts = rows
            if self.dialog == nil { self.dialog = .copies }
        }
    }

    /// `MSG-DISK-COPIES`' Unlock… (with `password` and `keyFile`, the
    /// `MSG-DISK-NEW-KEY` words) or Merge anyway (`anyway`) on one listed
    /// copy; a merge saves at once. `failed` gets the form's message.
    func mergeCopy(
        _ copy: String, password: String?, keyFile: String?, anyway: Bool, failed: @escaping (String) -> Void
    ) {
        let (session, id) = (session, vault.id)
        Task { [weak self] in
            let result = await FileAccess.run(.read, copy) {
                Result {
                    try session.mergeCopy(vault: id, path: copy, password: password, keyFile: keyFile, anyway: anyway)
                }
            }
            guard let self else { return }
            switch result {
            case .success(.needsPassword):
                failed("That password or key file does not open this copy.")
            case .success(.skipped):
                // APP-05.17 step 5: another root group id, or unreadable: not listed.
                self.disk.conflicts.removeAll { $0.path == copy }
                if self.disk.conflicts.isEmpty { self.copiesDone(trash: false) } else { self.dialog = .copies }
            case .success(let state):
                if let index = self.disk.conflicts.firstIndex(where: { $0.path == copy }) {
                    self.disk.conflicts[index].state = state
                }
                if state == .merged {
                    self.dialog = nil
                    self.afterChange(select: self.selection)
                    await self.saveNow(asks: true)
                    if self.dialog != nil { return }
                }
                self.dialog = .copies
            case .failure(let error):
                failed(message(error))
            }
        }
    }

    /// `MSG-DISK-COPIES`' Keep (`trash` false) moves nothing; Move to Trash
    /// moves the merged sibling copies not in `unchecked` to the Trash
    /// (never deleted outright) and marks those iCloud versions resolved,
    /// then removes the other versions once none is left unresolved. Either
    /// way the listed copies are not merged or listed again this session
    /// until they change.
    func copiesDone(trash: Bool, unchecked: Set<String> = []) {
        let rows = disk.conflicts
        disk.conflicts = []
        dialog = nil
        let (session, id, file) = (session, vault.id, (path as NSString).expandingTildeInPath)
        let cloud = FileAccess.cloud.withLock { $0 }
        Task.detached {
            try? session.copiesDone(vault: id, paths: rows.map(\.path))
            guard trash else { return }
            let checked = rows.filter { $0.state == .merged && !unchecked.contains($0.path) }
            for row in checked where !row.version { _ = cloud.trash(row.path) }
            let versions = checked.filter(\.version).map(\.path)
            if !versions.isEmpty { cloud.resolve(file, versions) }
        }
    }
}
