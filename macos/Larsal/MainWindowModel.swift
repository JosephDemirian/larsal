import AppKit
import LarsalCore
import Observation
import os

/// View data of the main window: the open vaults and which screen shows.
/// The vaults themselves live in the Rust session; this holds names, ids
/// and the per-screen view models only (Swift rule 5).
@Observable
final class MainWindowModel {
    let session: Session
    private(set) var vaults: [VaultInfo] = []
    /// M09-07 or another open error, shown as a banner.
    var banner: String?
    /// The unlock screen of the shown vault while it is locked. One whose
    /// unlock still waits for its file when its screen goes (a vault switch,
    /// an open) goes on (APP-05.30), and its screen comes back with it
    /// (APP-06.10, APP-06.17); Lock Everything still stops it.
    private(set) var unlock: UnlockModel? {
        didSet {
            waiting.removeAll { !$0.busy || $0 === unlock }
            if let oldValue, oldValue !== unlock, oldValue.busy { waiting.append(oldValue) }
        }
    }
    @ObservationIgnored private var waiting: [UnlockModel] = []
    /// The main screens of the unlocked vaults; dropped on lock (AT-E07).
    private(set) var opened: [UInt64: VaultModel] = [:]
    /// MOD-13.8 (F-074): the shown vault's forced key change prompt, in place
    /// of its screen (KeyChange.swift).
    private(set) var keyChange: KeyChangeModel?
    /// The vault menu (mockup `overlay === 'vault'`) is open.
    var vaultMenu = false
    /// The welcome screen's recent vaults, newest first (APP-01.14). Empty
    /// until the recent list is kept (E5-S9).
    var recents: [Recent] = []
    /// The question of Larsal's SSH agent while it waits (INT-06.34,
    /// SshKeyUse.swift).
    var sshAsk: SshAsk?
    var browserAsk: BrowserQuestion?  // the bridge's dialog (INT-02.15, BrowserAsk.swift)
    var files: FileFlow?  // Encrypt File and Decrypt File (FIL-02, FileFlow.swift)
    /// The View menu's settings (APP-08.8, ViewOptions.swift).
    let view = ViewOptions()
    /// Brings the window forward when a lock or a quit asks (F-122); tests
    /// put recording rules here.
    @ObservationIgnored var rules = WindowRules.shared
    /// The last open asked for (APP-09.23, FileOpen.swift).
    @ObservationIgnored var opening: Task<Void, Never>?

    /// One recent vault of the welcome screen.
    struct Recent: Identifiable {
        let look: VaultLook
        /// The full path, for opening.
        let path: String
        let opened: Date
        var id: String { path }
    }

    init(session: Session = .shared()) {
        self.session = session
        // The version only, no vault data.
        // swiftlint:disable:next no_public_log_or_print
        Logger.app.notice("Main window opened: Larsal \(LarsalCore.coreVersion(), privacy: .public)")
        view.load(session.settings())
        refresh()
    }

    var shown: VaultInfo? { vaults.first { $0.shown } }
    var main: VaultModel? { shown.flatMap { opened[$0.id] } }

    /// Reads the session again: after any change made here, and when Rust
    /// says it changed (a Finder or channel open, a passed-in unlock).
    func refresh() {
        let before = Set(vaults.filter { !$0.locked }.map(\.id))
        vaults = session.vaults()
        AuxWindows.sessionChanged(self)
        refreshAsks()
        if let text = session.takeBanner() {
            banner = text
        }
        let unlocked = Set(vaults.filter { !$0.locked }.map(\.id))
        // APP-06.5: a lock from outside Swift (the channel's `lock`,
        // APP-09.12) also clears a typed password.
        if !before.isSubset(of: unlocked) {
            unlock?.clear()
            // APP-10.8, APP-10.11: a lock checks Larsal's secure input call
            // again; a field that no longer edits ends it.
            SecureInput.shared.update()
        }
        for (id, model) in opened where !unlocked.contains(id) {
            model.clear()
            opened[id] = nil
        }
        // Only the shown vault keeps a Show value or a live code (AT-E07).
        for (id, model) in opened where id != shown?.id {
            model.leave()
        }
        // INT-08: a share pass ended, or a share was set up again.
        for model in opened.values {
            model.shareRefresh()
        }
        followKeyChange(shown)
        guard let shown else {
            unlock?.clear()
            unlock = nil
            return
        }
        if shown.locked {
            if unlock?.vault.id == shown.id {
                unlock?.update(shown)
            } else {
                unlock?.clear()
                let back = waiting.first { $0.vault.id == shown.id }
                back?.update(shown)
                unlock = back ?? UnlockModel(session: session, vault: shown) { [weak self] in self?.refresh() }
            }
        } else if shown.keyChange != nil {
            unlock?.clear()
            unlock = nil
        } else {
            unlock?.clear()
            unlock = nil
            if opened[shown.id] == nil { opened[shown.id] = screen(shown) }
        }
    }

    /// MOD-13.8 (F-074): the prompt shows while the shown vault's change is
    /// forced, in place of its screen.
    private func followKeyChange(_ shown: VaultInfo?) {
        guard let shown, let words = shown.keyChange else {
            keyChange = nil
            return
        }
        if keyChange?.vault.id != shown.id { keyChange = KeyChangeModel(window: self, vault: shown, words: words) }
    }

    /// The screen of a vault that just opened.
    private func screen(_ shown: VaultInfo) -> VaultModel {
        let model = VaultModel(session: session, vault: shown)
        // MOD-09.7, MOD-13.10 (F-077, F-074): once after the unlock.
        let offset = Int32(TimeZone.current.secondsFromGMT())
        if let after = try? session.afterUnlock(vault: shown.id, utcOffset: offset) { model.afterUnlock(after) }
        // S-ENTRY-02 (APP-01.26), read when the vault opens.
        model.askBeforeBin = session.settings().flag(key: "entry.confirm_recycle")
        // The disk watch (APP-05.24) and the share containers' (INT-08.15).
        model.watchDisk()
        model.watchShares()
        #if DEBUG
            DebugUI.apply(to: model)
        #endif
        return model
    }

    /// "Open vault…": any file; format detection decides at unlock.
    func chooseVault() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Open"
        panel.message = "Choose a vault file."
        guard panel.runModal() == .OK else { return }
        open(panel.urls.map { $0.path(percentEncoded: false) })
    }

    func switchTo(_ id: UInt64) {
        vaultMenu = false
        // LD-199 (2): an open editor with changes asks first.
        if let main, main.vault.id != id, main.askLeave(then: { [weak self] in self?.switchTo(id) }) { return }
        if main?.vault.id != id { files?.revoke() }  // FIL-02.14
        try? session.switchTo(vault: id)
        refresh()
    }

    func lock(_ id: UInt64) {
        opened[id]?.qrPopup?.revoke()  // FEA-10.15: before any wait or question
        files?.revoke()  // FIL-02.14
        vaultMenu = false
        // APP-02.15 step 7 (F-122): editor edits or a changed open copy ask
        // MSG-LOCK-DISCARD-EDIT first.
        if askEditor(id, then: { [weak self] in self?.lock(id) }) { return }
        // APP-02.15 step 8 (E5-S10): unsaved changes save or ask first, in
        // front (an Auto-Type relock runs behind another app, INT-05.32).
        let front: () -> Void = { [weak self] in self?.rules.bring() }
        if let main, main.vault.id == id, main.askUnsaved(asked: front, then: { [weak self] in self?.lockNow(id) }) {
            return
        }
        lockNow(id)
    }

    /// Locks `id`, then `then` goes on. The window stays live during a
    /// save before the lock, so an editor edit made meanwhile asks step 7
    /// here first (F-122), also after Discard of the unsaved-changes question.
    func lockNow(_ id: UInt64, then: @escaping () -> Void = {}) {
        opened[id]?.qrPopup?.revoke()
        files?.revoke()
        if askEditor(id, then: { [weak self] in self?.lockNow(id, then: then) }) { return }
        try? session.lock(vault: id)
        refresh()
        then()
    }

    /// Lock Everything and every automatic lock (APP-02.15, APP-02.16):
    /// changed vaults save first (step 8). An automatic lock never asks:
    /// editor edits go, and it waits for each save at most a second
    /// (F-101). `asks` (the menu's Lock Everything): editor edits ask first
    /// (step 7, F-122); the saves run off the main thread, then a vault
    /// whose save fails asks and the lock waits, or all lock here
    /// (LD-228 (1)). The window stays live during the saves, so after them
    /// it checks again: an edit made meanwhile asks too.
    func lockAll(asks: Bool = false) {
        for model in opened.values { model.qrPopup?.revoke() }
        files?.revoke()
        vaultMenu = false
        guard asks else {
            saveBeforeLock(within: .seconds(1))
            return lockEverything()
        }
        if askEditors(then: { [weak self] in self?.lockAll(asks: true) }) { return }
        guard unsaved else { return lockEverything() }
        Task { [weak self] in
            let saved = await self?.saveAll(asks: true) { [weak self] in self?.lockAll(asks: true) }
            if saved == true { self?.lockAll(asks: true) }
        }
    }

    private func lockEverything() {
        session.lockAll()
        // APP-06.5, APP-06.16: a lock event also clears a typed password and
        // stops every unlock that still waits for its file.
        for model in waiting { model.stop() }
        waiting = []
        unlock?.stop()
        // APP-06.27: and closes Auto-Type's unlock panel as a cancel.
        NotificationCenter.default.post(name: .appLockedEverything, object: session)
        refresh()
    }

    func close(_ id: UInt64) {
        opened[id]?.qrPopup?.revoke()
        files?.revoke()
        if let main, main.vault.id == id, main.askLeave(then: { [weak self] in self?.close(id) }) { return }
        // APP-02.15 step 8 (E5-S10): unsaved changes save or ask first.
        if let main, main.vault.id == id, main.askUnsaved(then: { [weak self] in self?.closeNow(id) }) { return }
        closeNow(id)
    }

    func closeNow(_ id: UInt64) {
        opened[id]?.qrPopup?.revoke()
        files?.revoke()
        // As lockNow (F-122, LD-199 (2)): an editor opened during the save
        // asks; after its Save or Discard the close starts again.
        if let main, main.vault.id == id, main.askLeave(then: { [weak self] in self?.close(id) }) { return }
        for model in waiting + [unlock].compactMap({ $0 }) where model.vault.id == id { model.stop() }  // LD-285 (3)
        try? session.close(vault: id)
        refresh()
    }

    /// Edit > Copy, ⌘C (APP-03.7, APP-08.4): text selected in the shown
    /// vault's window goes to Rust's `copy.selection` (`vaultSelection`);
    /// with no selection, the selected entry's password, in Rust, but only
    /// while Copy Password could run and the main window is in front. In a
    /// dialog, another of Larsal's windows or while the shown vault is locked
    /// it is the plain copy (APP-08.12, LD-219 (2)).
    func copyCommand() {
        let key = WindowRules.shared.keyWindow()
        let selected = ((key?.firstResponder as? NSTextView)?.selectedRange().length ?? 0) > 0
        if !selected, MenuState(window: self).copyEntry != nil, key == nil || key === WindowRules.shared.window {
            main?.copy("Password")
        } else if !vaultSelection(cut: false) {
            textCommand(#selector(NSText.copy(_:)))
        }
    }

    /// APP-03.7, APP-03.19 (LD-219 (4), F-081): text selected in the main
    /// window while its vault is unlocked (the editor's Title, Username,
    /// Website, Notes, any text field there) is copied by Rust's
    /// `copy.selection`, with the markers and the countdown, never by the
    /// plain AppKit copy; Cut then deletes it. False, and nothing done, in
    /// another window, while the vault is locked, with nothing selected or
    /// in a field that refuses the copy (the no-copy field). ponytail: the
    /// first selected range only; context menus, drags and Services of
    /// these fields still use AppKit's copy, a field editor of Larsal's own if
    /// they must go through Rust too.
    func vaultSelection(cut: Bool) -> Bool {
        let action = cut ? #selector(NSText.cut(_:)) : #selector(NSText.copy(_:))
        guard let main, let key = WindowRules.shared.keyWindow(), key === WindowRules.shared.window,
            let text = key.firstResponder as? NSTextView, text.selectedRange().length > 0,
            text.validateUserInterfaceItem(NSMenuItem(title: "", action: action, keyEquivalent: ""))
        else { return false }
        if main.copySelection((text.string as NSString).substring(with: text.selectedRange())), cut {
            text.delete(nil)
        }
        return true
    }

    /// Edit's Cut and plain Copy act on the focused text of Larsal's window in
    /// front, as on every Mac (APP-08.4); with none, on the target AppKit's
    /// responder chain gives (the main window's field behind a window in
    /// front). As a Mac's menu does, that target is asked first: a password
    /// field refuses Cut and Copy (APP-03.19, LD-219 (2)).
    func textCommand(_ action: Selector) {
        if action == #selector(NSText.cut(_:)), vaultSelection(cut: true) { return }
        let focused = WindowRules.shared.keyWindow()?.firstResponder
        let target: Any? =
            focused?.responds(to: action) == true ? focused : NSApp?.target(forAction: action, to: nil, from: nil)
        let item = NSMenuItem(title: "", action: action, keyEquivalent: "")
        if let field = target as? NSUserInterfaceValidations, !field.validateUserInterfaceItem(item) { return }
        NSApp?.sendAction(action, to: target, from: nil)
    }

    /// Quit (APP-03.15, SC-03): every vault locks, then Larsal's clipboard
    /// copy is cleared if it is still there.
    func quit() {
        // APP-01.17: the open vaults are kept for the next start (APP-09.20).
        session.rememberOpenVaults()
        session.lockAll()
        session.clearClipboard()
        // INT-06.25, INT-06.32: Larsal's SSH agent and its socket go.
        session.stopSshAgent()
    }
}

// MARK: APP-02.15 step 7 (F-122): editor edits ask before a manual lock or a quit

extension MainWindowModel {
    /// Quit (APP-02.15 steps 7 and 8, APP-05.4). The user's quit (`asks`)
    /// with editor edits asks first and stops (F-122). With no unsaved
    /// change it quits now; else each changed vault saves off the main
    /// thread while AppKit waits, the window live (`.terminateLater`,
    /// LD-228 (1)), and `reply` gets whether Larsal may quit (`mayQuit`).
    /// The user's quit checks again after the saves: an edit made in the
    /// live window meanwhile asks too.
    func quitReply(asks: Bool, reply: @escaping (Bool) -> Void) -> NSApplication.TerminateReply {
        for model in opened.values { model.qrPopup?.revoke() }
        if quitAfterFiles(asks: asks, reply: reply) { return .terminateLater }
        files?.revoke()
        if asks, askEditors(then: { NSApp?.terminate(nil) }) { return .terminateCancel }
        guard unsaved else { return .terminateNow }
        Task { [weak self] in
            guard let self else { return reply(true) }
            let may = await self.mayQuit(asks: asks)
            guard may, asks else { return reply(may) }
            switch self.quitReply(asks: true, reply: reply) {
            case .terminateNow: reply(true)
            case .terminateCancel: reply(false)
            default: break  // saving again; that run replies
            }
        }
        return .terminateLater
    }

    /// An unlocked vault has changes not saved yet.
    var unsaved: Bool {
        vaults.contains { !$0.locked && ((try? session.saveStatus(vault: $0.id))?.changes ?? 0) > 0 }
    }

    /// APP-02.15 step 7 (F-122) for vault `id`: with editor edits or a
    /// changed open copy it shows and asks `MSG-LOCK-DISCARD-EDIT`; `then`
    /// goes on after Discard. True when it asked.
    func askEditor(_ id: UInt64, then: @escaping () -> Void) -> Bool {
        guard opened[id]?.editorEdits == true else { return false }
        if shown?.id != id {
            try? session.switchTo(vault: id)
            refresh()
        }
        guard main?.askLock(then: then) == true else { return false }
        // In front: the window may be hidden to the menu bar icon or behind
        // another app (the icon's Lock Everything and Quit, INT-05.32).
        rules.bring()
        return true
    }

    /// Step 7 for every unlocked vault, before Lock Everything or a quit.
    func askEditors(then: @escaping () -> Void) -> Bool {
        guard let id = opened.first(where: { $0.value.editorEdits })?.key else { return false }
        return askEditor(id, then: then)
    }
}

extension VaultModel {
    /// The editor is open with a change in its draft or an open copy that
    /// another app changed (F-122).
    var editorEdits: Bool {
        guard let editor else { return false }
        return !untouched(editor) || (try? session.changedAttachments(vault: vault.id).isEmpty) == false
    }

    /// APP-02.15 step 7 (F-122, LD-227 (2)): a manual lock or a quit with
    /// `editorEdits` asks `MSG-LOCK-DISCARD-EDIT`; Discard drops them and
    /// `then` goes on (`answerLeave(save: false)`), Cancel keeps the vault
    /// unlocked. True when it asked. An automatic lock never asks
    /// (APP-02.16).
    func askLock(then: @escaping () -> Void) -> Bool {
        guard editorEdits else { return false }
        afterLeave = then
        dialog = .lockDiscardEdit
        return true
    }
}
