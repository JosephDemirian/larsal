import AppCore
import AppKit
import Foundation
import Testing

/// E13-S6 part i: the lock and leave questions (F-122, APP-02.15 step 7)
/// and the menu's Lock Everything and the quit saving off the main thread
/// (LD-228 (1)), through the window model, offscreen (never ordered front,
/// AGENTS.md rule 10). Demo vaults only, copied to target/. No test answers
/// a quit's question: that would end the test run.
@MainActor
private func locked(_ model: MainWindowModel, _ id: UInt64) -> Bool {
    model.session.vaults().first { $0.id == id }?.locked == true
}

/// The editor on Wise with its title typed over.
@MainActor
private func editWise(_ main: VaultModel) throws {
    let rows = try main.session.list(vault: main.vault.id, view: .all).rows
    main.edit(try #require(rows.first { $0.title == "Wise" }?.id))
    try #require(main.editor).set(.title, "Wise (demo edit)")
    #expect(main.editor?.view.changed.isEmpty == false)
}

extension DataSafetyTests {

    @Test("F-122, APP-02.15 step 7: a manual lock with editor edits asks; Cancel keeps it unlocked, Discard locks")
    func f122ManualLockAsksAboutEditorEdits() async throws {
        let (model, screen) = try await window("f122-lock")
        let main = try #require(model.main)
        let id = main.vault.id
        try editWise(main)
        model.lock(id)
        #expect(main.dialog == .lockDiscardEdit && !locked(model, id), "MSG-LOCK-DISCARD-EDIT, not locked")
        await screen.settle()
        #expect(screen.strings().contains("Lock now and lose your unsaved edits?"))
        try await screen.press("Cancel")
        #expect(main.dialog == nil && main.editor != nil && !locked(model, id), "Cancel: the vault stays unlocked")
        model.lock(id)
        await screen.settle()
        try await screen.press("Discard")
        #expect(locked(model, id), "Discard: the edits go, the vault locks")
        // APP-02.16: an automatic lock never asks; the edits go.
        #expect(try model.session.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        model.refresh()
        let again = try #require(model.main)
        try editWise(again)
        model.lockAll()
        #expect(locked(model, id) && again.dialog == nil)
    }

    @Test("F-122: a changed open copy asks before Cancel closes an unchanged editor and before a manual lock")
    func f122ChangedCopyAsksBeforeCancelAndLock() async throws {
        let (model, _) = try await window("f122-copy")
        let main = try #require(model.main)
        let id = main.vault.id
        let (entry, _) = try openCopy(main, "f122-copy")
        main.saveEditor()
        #expect(main.editor == nil, "codes.txt is in the entry")
        main.edit(entry)
        let before = FakeOpener.opened.count  // shared with suites running side by side
        main.openAttachment("codes.txt")
        let copy = try #require(FakeOpener.opened.dropFirst(before).first)
        try Data("second edit".utf8).write(to: copy)
        // At once, before the watch's 500 ms join: Cancel asks.
        main.cancelEditor()
        #expect(main.dialog == .changedAttachment(name: "codes.txt") && main.editor != nil, "Cancel asks first")
        main.dialog = nil
        model.lock(id)
        #expect(main.dialog == .lockDiscardEdit && !locked(model, id), "the lock asks, the draft has no change")
        #expect(FileManager.default.fileExists(atPath: copy.path(percentEncoded: false)), "the copy is kept")
        main.answerLeave(save: false)  // Discard
        for _ in 0..<400 where !locked(model, id) { try await Task.sleep(for: .milliseconds(25)) }
        #expect(locked(model, id), "Discard: the lock goes on (the saved entry first)")
        #expect(!FileManager.default.fileExists(atPath: copy.path(percentEncoded: false)), "the copy is wiped")
    }

    @Test("F-122: a quit and the menu's Lock Everything with editor edits ask first; Discard goes on")
    func f122QuitAndLockEverythingAsk() async throws {
        let (model, _) = try await window("f122-quit")
        let main = try #require(model.main)
        let id = main.vault.id
        try editWise(main)
        var replies: [Bool] = []
        #expect(model.quitReply(asks: true) { replies.append($0) } == .terminateCancel, "the quit stops")
        #expect(main.dialog == .lockDiscardEdit && replies.isEmpty)
        main.afterLeave = nil  // Cancel
        main.dialog = nil
        model.lockAll(asks: true)
        #expect(main.dialog == .lockDiscardEdit && !locked(model, id), "Lock Everything asks")
        main.answerLeave(save: false)  // Discard
        #expect(locked(model, id), "Discard: Lock Everything goes on")
    }
}

/// LD-228 (1): the menu's Lock Everything and the quit never wait on a
/// save on the main thread.
extension ParitySavingTests {
    /// Waits up to 40 s for `done`.
    func wait(until done: () -> Bool) async throws {
        for _ in 0..<1600 where !done() { try await Task.sleep(for: .milliseconds(25)) }
    }

    /// The Personal demo vault in `folder`, saved on lock only, with a
    /// 3-second key derivation: from now on each save takes that long. The
    /// caller puts the saving settings back.
    func slowSaves(_ folder: String) async throws -> MainWindowModel {
        let (model, vaultSettings) = try SettingsDemo.model(folder)
        try setSaving(model.session, autosave: false, onLock: true)
        vaultSettings.page = .security
        await vaultSettings.settled()
        vaultSettings.setEncryption {
            $0.memoryMib = 64
            $0.lanes = 2
            $0.unlockMs = 3_000
        }
        await vaultSettings.settled()
        for _ in 0..<3 {
            guard case .question(let question, let then) = vaultSettings.sheet else { break }
            vaultSettings.answer(question, then: then)
        }
        #expect(vaultSettings.view?.encryption.unlockMs == 3_000 && vaultSettings.sheet == nil)
        return model
    }

    @Test("LD-228 (1): Lock Everything and the quit keep the main thread free behind a 3 s save; an edit then asks")
    func ld228SavesLeaveTheMainThreadFree() async throws {
        let model = try await slowSaves("saving-ld228")
        defer { try? setSaving(model.session, autosave: true, onLock: true) }
        let id = try #require(model.shown?.id)
        let main = try #require(model.main)
        let saved = { (try? model.session.saveStatus(vault: id))?.changes == 0 }
        let allLocked = { model.vaults.allSatisfy(\.locked) }
        #expect(!saved())
        // Quit: AppKit waits for the reply; the save runs off the main
        // thread. An editor edit made after the first check asks once the
        // save is done (F-122), and the quit stops.
        var replies: [Bool] = []
        #expect(model.quitReply(asks: true) { replies.append($0) } == .terminateLater)
        try editWise(main)
        // The main thread is free during the save: this test's next turn,
        // queued after the call's Task, runs before the save ends. A save on
        // the main actor would end inside that Task's first turn. Unlike a
        // timing, this order holds under any load.
        try await Task.sleep(for: .milliseconds(1))
        #expect(replies.isEmpty, "the quit's save does not run on the main thread")
        try await wait { !replies.isEmpty }
        #expect(replies == [false] && main.dialog == .lockDiscardEdit && saved(), "saved, then the edit asks")
        main.afterLeave = nil  // Cancel
        main.dialog = nil
        main.closeEditor()
        // Lock Everything: the same, then Discard locks.
        try add(model.session, id, "Demo Shop")
        #expect(!saved())
        model.lockAll(asks: true)
        try editWise(main)
        try await Task.sleep(for: .milliseconds(1))
        #expect(main.dialog == nil && !allLocked(), "Lock Everything's save does not run on the main thread")
        try await wait { main.dialog != nil || allLocked() }
        #expect(main.dialog == .lockDiscardEdit && !allLocked() && saved(), "saved, then the edit asks")
        main.answerLeave(save: false)  // Discard
        #expect(allLocked(), "Discard: Lock Everything goes on")
        #expect(try onDisk(file("saving-ld228")).contains("Demo Shop"), "saved before the lock")
    }

    @Test("F-122: an editor edit made while a manual lock's or a close's own 3 s save runs asks once it is done")
    func f122EditDuringLockOrCloseSaveAsks() async throws {
        let model = try await slowSaves("saving-f122-during")
        defer { try? setSaving(model.session, autosave: true, onLock: true) }
        let id = try #require(model.shown?.id)
        let main = try #require(model.main)
        let saved = { (try? model.session.saveStatus(vault: id))?.changes == 0 }
        #expect(!saved())
        // The manual lock (Lock button, menu, key change prompt, INT-05.32).
        model.lock(id)
        try await Task.sleep(for: .milliseconds(300))
        try editWise(main)
        try await wait { main.dialog != nil || locked(model, id) }
        #expect(main.dialog == .lockDiscardEdit && !locked(model, id) && saved(), "saved, then the edit asks")
        main.afterLeave = nil  // Cancel
        main.dialog = nil
        #expect(main.editor != nil && !locked(model, id), "Cancel: the vault stays unlocked")
        model.lock(id)
        #expect(main.dialog == .lockDiscardEdit)
        main.answerLeave(save: false)  // Discard
        #expect(locked(model, id), "Discard: the edits go, the vault locks")
        // The close: an editor opened during the save asks (LD-199 (2)).
        #expect(try model.session.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        model.refresh()
        let again = try #require(model.main)
        try add(model.session, id, "Demo Shop")
        model.close(id)
        try await Task.sleep(for: .milliseconds(300))
        try editWise(again)
        let open = { model.session.vaults().contains { $0.id == id } }
        try await wait { again.dialog != nil || !open() }
        #expect(again.dialog == .leaveEditor && open() && saved(), "saved, then the edit asks")
        again.answerLeave(save: false)  // Discard: the close starts again
        try await wait { !open() }
        #expect(!open(), "Discard: the vault closes")
        #expect(try onDisk(file("saving-f122-during")).contains("Demo Shop"), "saved before the close")
    }

    @Test("F-122: Discard of Lock Everything's unsaved-changes question asks about an editor edit, then goes on")
    func f122DiscardUnsavedThenEditorAsks() async throws {
        let model = try ParityDemo.window("saving-f122-discard")
        defer { try? setSaving(model.session, autosave: true, onLock: true) }
        let main = try #require(model.main)
        let id = main.vault.id
        main.autosave = false
        main.disk.watch = nil
        try setSaving(model.session, autosave: false, onLock: false)
        try add(model.session, id, "Demo Shop")
        model.lockAll(asks: true)
        try await wait { main.dialog != nil }
        #expect(main.dialog == .closeUnsaved(changes: try model.session.saveStatus(vault: id).changes))
        // As an edit made while a failed save ran, before the question.
        try editWise(main)
        main.answerUnsaved(save: false)  // Discard
        #expect(main.dialog == .lockDiscardEdit && !locked(model, id), "step 7 asks before the lock")
        main.answerLeave(save: false)  // Discard
        #expect(main.dialog == nil && model.vaults.allSatisfy(\.locked), "Discard: Lock Everything goes on")
    }
}

/// F-122 follow-on: a lock or quit question shows in front, even while the
/// window hides behind the menu bar icon (recorded window and NSApp calls).
extension MenuBarIconTests {
    @Test("F-122: hidden to the icon, its Lock Everything and a manual lock ask in front, not in the hidden window")
    func f122AsksInFront() async throws {
        let setup = try demo("f122-icon")
        let (model, icon) = (setup.model, setup.icon)
        model.rules = rules
        let main = try #require(model.main)
        let id = main.vault.id
        main.autosave = false
        main.disk.watch = nil
        try model.session.saveSettings(changes: [
            AppSetting(key: "save.after_every_change", value: .flag(on: false)),
            AppSetting(key: "save.on_lock", value: .flag(on: false)),
        ])
        _ = try model.session.beginNew(vault: id, group: nil)
        try model.session.setText(vault: id, field: .title, value: "Demo Shop")
        _ = try model.session.commitEdit(vault: id)
        let unsaved = VaultModel.Dialog.closeUnsaved(changes: try model.session.saveStatus(vault: id).changes)
        try editWise(main)
        // Step 7 from the icon: the editor's question.
        rules.hideToIcon()
        icon.build()
        let lock = try #require(icon.menu.items.firstIndex { $0.title == "Lock Everything" })
        icon.menu.performActionForItem(at: lock)
        #expect(main.dialog == .lockDiscardEdit && !locked(model, id), "MSG-LOCK-DISCARD-EDIT")
        #expect(window.log == ["hide", "front"] && !rules.hidden, "asked in front")
        // Step 8 of Lock Everything: after Discard the unsaved change asks.
        rules.hideToIcon()
        main.answerLeave(save: false)
        for _ in 0..<400 where main.dialog == nil { try await Task.sleep(for: .milliseconds(25)) }
        #expect(main.dialog == unsaved && window.log.last == "front", "Lock Everything's step 8 in front")
        // Step 8 of a manual lock (an Auto-Type relock, INT-05.32).
        main.answerUnsaved(save: nil)  // Cancel
        rules.hideToIcon()
        model.lock(id)
        for _ in 0..<400 where main.dialog == nil { try await Task.sleep(for: .milliseconds(25)) }
        #expect(main.dialog == unsaved && window.log.last == "front", "the manual lock's step 8 in front")
        main.answerUnsaved(save: false)  // Discard
        #expect(locked(model, id))
        #expect(window.log == ["hide", "front", "hide", "front", "hide", "front"])
    }
}
