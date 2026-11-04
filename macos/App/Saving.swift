import AppCore
import AppKit
import Foundation
import os

/// The window's saving (E5-S10, APP-05): the save after each change, the
/// questions a save or the disk watch raises, and the unsaved-changes
/// question of a close, lock or quit. Rust decides and writes (saving.rs);
/// this holds no vault data.
final class DiskState {
    /// A test's override of S-FILE-01; `nil` reads the setting live.
    var autosave: Bool?
    /// APP-05.24: the watch of this vault's file.
    var watch: DiskWatch?
    /// APP-05.2, APP-05.3: the change window or the autosave delay.
    var window: Task<Void, Never>?
    /// A change on disk waits for the editor, a sheet, a save or a
    /// download (APP-05.25); `pendingEvent`: a watch event waits, not only
    /// a tick (a tick never fetches a dataless file).
    var pending = false
    var pendingEvent = false
    var checking = false
    /// The save-failed sheet showed for this run of failures.
    var failureShown = false
    /// MOD-05.13: the 5-second check of the open attachment copies, and
    /// the file event watch of each.
    var copies: Task<Void, Never>?
    var copyWatches: [DiskWatch] = []
    /// INT-08.15 (LD-216): one watch per share container path Rust names.
    var shareWatches: [String: DiskWatch] = [:]
    /// INT-08.20: the last share pass's banner, for E11-S5's banner view.
    var shareBanner: ShareBanner?
    /// APP-05.17: a conflict-copy look runs; the copies `MSG-DISK-COPIES`
    /// lists.
    var finding = false
    var conflicts: [CopyRow] = []
    /// APP-05.26 (LD-267 (3)): the shown `MSG-DISK-CHANGED` adds the "went
    /// back in time" line.
    var older = false
}

extension VaultModel {
    /// APP-05.2: each change is saved (S-FILE-01), read when a save is
    /// decided, so a change in Settings counts at once (APP-05.3 T06).
    var autosave: Bool {
        get { disk.autosave ?? session.settings().flag(key: "save.after_every_change") }
        set { disk.autosave = newValue }
    }

    /// The vault's file name, as the questions name it.
    var fileName: String { (path as NSString).lastPathComponent }

    /// `body` (Rust's file I/O) in a coordinated access of the vault file,
    /// or of `file`, once it is on this Mac; "Still downloading" shows
    /// meanwhile (APP-05.24, APP-05.30).
    func onFile<T: Sendable>(
        _ kind: FileAccess.Kind = .read, at file: String? = nil, _ body: @escaping @Sendable () -> T
    ) async -> T {
        await FileAccess.run(kind, file ?? path, downloading: { self.downloading = $0 }, body)
    }

    /// `MSG-DISK-DOWNLOADING` (APP-05.30), where `MSG-DISK-UNREADABLE` shows.
    var downloadingToast: Toast {
        Toast(
            glyph: "cloud", text: "Still downloading.",
            note: "“\(fileName)” is not on this Mac yet. App reads it when the download ends; "
                + "your open copy is unchanged.")
    }

    /// The vault's path now (Save As moves it); `~` is the home folder.
    var path: String { session.vaults().first { $0.id == vault.id }?.path ?? vault.path }

    /// `save.on_lock` or `save.after_every_change` (APP-02.15 step 8).
    var savesOnLock: Bool { autosave || session.settings().flag(key: "save.on_lock") }

    // MARK: Saving (APP-05.2, APP-05.3; Save As, APP-05.6: SavingQuit.swift)

    /// After a change: with `save.after_every_change` on, one save 150 ms
    /// after the first change of a window (later changes join it), or N
    /// minutes after the last change when the vault's autosave delay is N.
    func scheduleSave() {
        saveStatus = try? session.saveStatus(vault: vault.id)
        guard autosave, (saveStatus?.changes ?? 0) > 0 else { return }
        let minutes = saveStatus?.autosaveMinutes ?? 0
        if minutes == 0, disk.window != nil { return }
        disk.window?.cancel()
        let wait: Duration = minutes > 0 ? .seconds(Int(minutes) * 60) : .milliseconds(150)
        disk.window = Task { [weak self] in
            try? await Task.sleep(for: wait)
            guard !Task.isCancelled, let self else { return }
            self.disk.window = nil
            // Turned off meanwhile, or saved already: nothing (APP-05.3).
            let changes = (try? self.session.saveStatus(vault: self.vault.id))?.changes ?? 0
            guard self.autosave, changes > 0 else { return }
            self.saving = Task { _ = await self.saveNow() }
        }
    }

    /// Saves at once, ending a waiting window or delay; saves of a vault
    /// run one at a time in Rust. `asks`: a failure shows its sheet even
    /// when one showed for this run of failures (Try Again).
    @discardableResult
    func saveNow(asks: Bool = false, failureSheet: Bool = true) async -> SaveStatus? {
        disk.window?.cancel()
        disk.window = nil
        let (session, id) = (session, vault.id)
        let status = await onFile(.replace) {
            try? session.save(vault: id)
        }
        if let status { saved(status, asks: asks, failureSheet: failureSheet) }
        return status
    }

    /// A save's answer: the footer, its notice, and the question it raises.
    func saved(_ status: SaveStatus, asks: Bool = false, failureSheet: Bool = true) {
        saveStatus = status
        if let notice = status.notice { notify(Toast(glyph: "info", text: notice)) }
        if status.failure == nil { disk.failureShown = false }
        guard dialog == nil else { return }
        if status.formatNotice {
            dialog = .formatNotice
        } else if let ask = status.onDisk {
            (disk.older, dialog) = (status.older, .changedOnDisk(ask: ask, changes: status.changes))
        } else if let copies = status.oldCopies {
            dialog = .oldCopies(copies)
        } else if status.askUnsafe {
            dialog = .askUnsafe
        } else if let failure = status.failure, failureSheet, asks || !disk.failureShown {
            disk.failureShown = true
            dialog = .saveFailed(reason: failure)
        } else {
            diskResume()
        }
    }

    /// APP-05.32: OK on the format notice; the save goes on.
    func confirmFormatNotice() {
        dialog = nil
        try? session.confirmFormatNotice(vault: vault.id)
        saving = Task { [weak self] in _ = await self?.saveNow() }
    }

    // MARK: Changes on disk (APP-05.24 to APP-05.31)

    /// Starts (or moves) the watch of this vault's file.
    func watchDisk() {
        disk.watch = DiskWatch(path: path) { [weak self] tick in
            Task { @MainActor in self?.checkDisk(tick: tick) }
        }
        findCopies()  // APP-05.17 step 1: after each unlock, in the vault's folder now
    }

    /// The watch says "look": Rust compares and decides, in a coordinated
    /// read off the screen thread (a silent reload runs the KDF). While the
    /// entry editor, the group editor (LD-310 (7)), a sheet or a check is
    /// open, or the file downloads, the event waits (APP-05.25). A watch
    /// event on a dataless file shows "Still downloading" and starts the
    /// download (APP-05.30); a `tick` never does: a dataless file is no
    /// change then (APP-05.24).
    func checkDisk(tick: Bool = false) {
        guard editor == nil, sharing.editor == nil, dialog == nil, !disk.checking else {
            disk.pending = true
            disk.pendingEvent = disk.pendingEvent || !tick
            return
        }
        disk.pending = false
        disk.pendingEvent = false
        disk.checking = true
        let (session, id, file) = (session, vault.id, path)
        Task { [weak self] in
            let check: @Sendable () -> DiskEvent? = { try? session.checkDisk(vault: id) }
            let event: DiskEvent?
            if tick {
                event = await FileAccess.tick(file, check) ?? nil
            } else if let self {
                event = await self.onFile(.read, check)
            } else {
                return
            }
            self?.disk.checking = false
            // Busy: a watch event waits as an event (APP-05.25).
            if event == .busy, !tick { self?.disk.pendingEvent = true }
            if let event { self?.handle(event) }
            // APP-05.17 step 1: the copies, once the vault's own file is done.
            if event == DiskEvent.none { self?.findCopies() }
        }
    }

    /// A waiting change on disk is handled once the editor or sheet closes;
    /// as a tick when only ticks waited.
    func diskResume() {
        if disk.pending { checkDisk(tick: !disk.pendingEvent) }
    }

    /// `choice`: what the user chose, for the unlock sheet of `NewKey`
    /// (the silent reload's is Merge, APP-05.29: the open vault may hold
    /// edits made under the other key).
    private func handle(_ event: DiskEvent, choice: DiskChoice = .merge) {
        switch event {
        case .none:
            break
        case .busy:
            disk.pending = true
        case .reloaded:
            // APP-05.31: the views read again; the selection stays when it
            // is still there.
            afterChange(select: selection)
            notify(Toast(glyph: "arrows-clockwise", text: "Reloaded."))
        case .ask(let ask, let changes), .askOlder(let ask, let changes):
            if dialog == nil {
                disk.older = event == .askOlder(ask: ask, changes: changes)
                dialog = .changedOnDisk(ask: ask, changes: changes)
            } else {
                disk.pending = true
            }
        case .newKey:
            // APP-05.29 (F-085): the unlock sheet for the changed file;
            // the open vault stays as it is until it succeeds.
            if dialog == nil {
                dialog = .diskNewKey(choice: choice == .merge ? .merge : .reload)
            } else {
                disk.pending = true
            }
        case .unreadable:
            notify(Toast(glyph: "warning", text: "App could not read the file on disk. Your open copy is unchanged."))
        case .oldKey, .rollback, .weaker:
            guardEvent(event)
        }
    }

    /// The answer to a changed-on-disk question. Merge and Keep mine save
    /// after: at once when a save found the change (APP-05.28), else as
    /// after any change (APP-05.27).
    func resolveDisk(_ choice: DiskChoice, ask: DiskAsk) {
        dialog = nil
        let (session, id) = (session, vault.id)
        let atOnce = ask == .onSave || ask == .overwriteOnly
        saving = Task { [weak self] in
            guard let self else { return }
            let event = await self.onFile {
                try? session.resolveDisk(vault: id, choice: choice)
            }
            guard let event else { return }
            self.handle(event, choice: choice)
            switch choice {
            case .merge where event == .reloaded, .keepMine:
                if atOnce { await self.saveNow(asks: true) } else { self.scheduleSave() }
            case .later:
                self.saveStatus = try? session.saveStatus(vault: id)
                self.notify(Toast(glyph: "info", text: "Reload cancelled."))
            default:
                break
            }
        }
    }

    /// APP-05.29 (F-085): the unlock sheet's Unlock. Rust opens the changed
    /// file with these key parts and goes on with `choice`; a Merge saves at
    /// once with the new key. `failed` gets the sheet's message.
    func unlockDisk(
        _ choice: DiskChoice, password: String?, keyFile: String?, failed: @escaping (String) -> Void
    ) {
        let (session, id) = (session, vault.id)
        Task { [weak self] in
            guard let self else { return }
            let result = await self.onFile {
                Result {
                    try session.resolveDiskWithKey(vault: id, choice: choice, password: password, keyFile: keyFile)
                }
            }
            switch result {
            case .success(.newKey):
                failed("That password or key file does not open the changed file.")
            case .success(let event):
                self.dialog = nil
                self.handle(event, choice: choice)
                if choice == .merge, event == .reloaded { await self.saveNow(asks: true) }
            case .failure(let error):
                failed(message(error))
            }
        }
    }

    /// APP-05.14 (F-087) Turn off: this vault saves with the unsafe method
    /// while it stays open, and saves again at once.
    func turnOffSafeSave() {
        dialog = nil
        try? session.turnOffSafeSave(vault: vault.id)
        saving = Task { [weak self] in _ = await self?.saveNow(asks: true) }
    }

    /// APP-05.33 (F-088) Delete checked: Rust removes the listed copies
    /// among `paths` and names the ones it could not remove.
    func deleteOldCopies(_ paths: [String]) {
        dialog = nil
        guard !paths.isEmpty else { return }
        let left = (try? session.deleteOldCopies(vault: vault.id, paths: paths)) ?? paths
        if !left.isEmpty {
            let names = left.map { ($0 as NSString).lastPathComponent }.joined(separator: ", ")
            notify(Toast(glyph: "warning", text: "App could not delete \(names)."))
        }
    }

    // MARK: Close, lock and quit with unsaved changes (APP-02.15 step 8)

    /// A manual close or lock of this vault: with unsaved changes it saves
    /// first when the settings say so; when that is not done or fails, it
    /// asks Save, Discard or Cancel. `then` runs once the vault may go.
    /// True when it took over (the leave waits). `asked` runs when a
    /// question shows (the lock brings the window forward, F-122).
    func askUnsaved(asked: @escaping () -> Void = {}, then: @escaping () -> Void) -> Bool {
        guard let status = try? session.saveStatus(vault: vault.id), status.changes > 0 else { return false }
        let saveFirst = savesOnLock
        Task { [weak self] in
            guard let self else { return }
            if saveFirst {
                let after = await self.saveNow(failureSheet: false)
                if after?.changes == 0 {
                    then()
                    return
                }
                // A change on disk asked its own question: the leave fails.
                if self.dialog != nil { return asked() }
            }
            self.afterLeave = then
            let changes = (try? self.session.saveStatus(vault: self.vault.id))?.changes ?? status.changes
            self.dialog = .closeUnsaved(changes: changes)
            asked()
        }
        return true
    }

    /// The unsaved-changes question's answer: Save saves again and the
    /// leave fails when that fails; Discard lets the vault go with its
    /// changes; Cancel (`nil`) keeps it.
    func answerUnsaved(save: Bool?) {
        dialog = nil
        let next = afterLeave
        afterLeave = nil
        guard let save else { return }
        guard save else {
            next?()
            return
        }
        saving = Task { [weak self] in
            if await self?.saveNow(asks: true)?.changes == 0 { next?() }
        }
    }
}

// MARK: Shared groups (INT-08, E11-S3)

extension VaultModel {
    /// INT-08.15: watches the container paths Rust names now, read off the
    /// main thread (Rust's path check reads the disk). A watch only says
    /// "look": Rust compares the first 5 KiB and imports (share.rs).
    func watchShares() {
        let (session, id) = (session, vault.id)
        Task { [weak self] in
            let paths = await Task.detached { (try? session.sharePaths(vault: id)) ?? [] }.value
            self?.watch(sharePaths: paths)
        }
    }

    /// One `DiskWatch` per path (LD-216): a new path gets its own, a path
    /// still named keeps its watch, a path no longer named stops it.
    func watch(sharePaths paths: [String]) {
        let (session, id) = (session, vault.id)
        disk.shareWatches = disk.shareWatches.filter { paths.contains($0.key) }
        for path in paths where disk.shareWatches[path] == nil {
            disk.shareWatches[path] = DiskWatch(path: path) { _ in
                try? session.shareLook(vault: id, path: path)
            }
        }
    }

    /// What the share passes did since the last look (INT-08.20): an
    /// import that changed the vault reads the views again and is saved
    /// as any change (APP-05.2); the banner waits for E11-S5's view.
    func takeShareNews() {
        guard let news = try? session.takeShareNews(vault: vault.id) else { return }
        if news.changed { afterChange(select: selection) }
        if let banner = news.banner { disk.shareBanner = banner }
    }
}
