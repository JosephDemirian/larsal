import AppCore
import Foundation
import Testing

/// The Verify probes of E5-S10 (security/parity/E5-S10-saving.md, V-B1 to
/// V-B6, R-OFF) and the lock request (LD-217 (4)), kept as the builder's
/// tests: the disk watch, "Merge then save", and what an automatic lock
/// keeps. Demo vaults only; settings and recovery copies in a temp folder.
extension ParitySavingTests {
    /// A fresh settings folder in the temp folder, never App's own.
    private func settingsFolder(_ name: String) -> String {
        let folder = FileManager.default.temporaryDirectory.appending(path: "app-saving-\(name)-\(getpid())")
        try? FileManager.default.removeItem(at: folder)
        return folder.path(percentEncoded: false)
    }

    /// Waits up to 10 s for `done`.
    private func until(_ done: () -> Bool) async throws {
        for _ in 0..<400 where !done() { try await Task.sleep(for: .milliseconds(25)) }
    }

    private func attribute(_ path: String, _ key: FileAttributeKey) -> Int? {
        (try? FileManager.default.attributesOfItem(atPath: path))?[key] as? Int
    }

    /// Another program edits the vault file in place (the same inode, so
    /// the folder does not change): it writes the bytes of a version with
    /// `title` added, made in a folder of its own.
    private func inPlace(_ path: String, adds title: String) throws {
        let manager = FileManager.default
        let side = manager.temporaryDirectory.appending(path: "app-saving-side-\(getpid())")
        try? manager.removeItem(at: side)
        try manager.createDirectory(at: side, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: side) }
        let copy = side.appending(path: "Personal.appvault")
        try manager.copyItem(at: URL(fileURLWithPath: path), to: copy)
        try otherWriter(copy.path(percentEncoded: false), adds: title)
        let bytes = try Data(contentsOf: copy)
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
        try handle.truncate(atOffset: 0)
        try handle.write(contentsOf: bytes)
        try handle.synchronize()
        try handle.close()
    }

    @Test("APP-09.12, APP-02.16 (LD-217 (4), R-OFF): a lock request saves the change, or keeps it in a recovery copy")
    func lockRequestSavesOrKeepsACopy() async throws {
        let model = try ParityDemo.window("saving-lock-request")
        let main = try #require(model.main)
        let id = main.vault.id
        let path = file("saving-lock-request")
        let settings = settingsFolder("lock-request")
        defer { try? FileManager.default.removeItem(atPath: settings) }
        model.session.settings().useFolder(folder: settings)
        try setSaving(model.session, autosave: false, onLock: true)
        try add(main.session, id, "Demo Shop")
        main.afterChange(select: nil)
        // What Rust's answer to `app --lock` calls; it returns at once.
        let events = WindowEvents(window: model)
        events.lockAll()
        try await until { model.vaults.allSatisfy { $0.locked } }
        #expect(model.vaults.allSatisfy { $0.locked })
        #expect(try onDisk(path).contains("Demo Shop"), "saved before the lock")
        // R-OFF: both save settings off; the file stays, the copy keeps it.
        #expect(try model.session.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        model.refresh()
        let again = try #require(model.main)
        try setSaving(model.session, autosave: false, onLock: false)
        let before = try Data(contentsOf: URL(fileURLWithPath: path))
        try add(again.session, id, "Demo Shop 2")
        again.afterChange(select: nil)
        events.lockAll()
        try await until { model.vaults.allSatisfy { $0.locked } }
        #expect(model.vaults.allSatisfy { $0.locked })
        #expect(try Data(contentsOf: URL(fileURLWithPath: path)) == before, "the file is not written")
        let copies = try FileManager.default.contentsOfDirectory(atPath: settings + "/recovery")
        #expect(copies.count == 1)
        let copy = settings + "/recovery/" + (copies.first ?? "")
        #expect(attribute(copy, .posixPermissions) == 0o600)
        #expect(try onDisk(copy).contains("Demo Shop 2"), "the change is kept")
    }

    @Test("APP-05.10, APP-05.28 T17, T49 (V-B1): a save that finds another writer's change asks; Merge then save saves")
    func mergeThenSave() async throws {
        let model = try ParityDemo.window("saving-merge-then-save")
        let main = try #require(model.main)
        main.autosave = false
        main.disk.watch = nil  // a share whose events are lost: the save finds it
        let screen = Screen(model)
        await screen.settle()
        let path = file("saving-merge-then-save")
        try otherWriter(path, adds: "Demo Bank 2")
        try add(main.session, main.vault.id, "Demo Shop")
        main.afterChange(select: nil)
        await main.saveNow(asks: true)
        #expect(main.dialog == .changedOnDisk(ask: .onSave, changes: 1))
        #expect(try !onDisk(path).contains("Demo Shop"), "nothing written before the answer")
        await screen.settle()
        try await pressLast(screen, "Merge then save")
        try await until { main.saveStatus?.changes == 0 }
        #expect(main.saveStatus?.changes == 0, "saved at once")
        #expect(try onDisk(path).isSuperset(of: ["Demo Shop", "Demo Bank 2", "GitHub"]), "both sides kept")
        model.lockAll()
    }

    @Test("APP-05.24, APP-05.26, APP-05.27 T44, T45, T48 (V-B3): an edit in place reloads, or asks: Discard, Keep")
    func inPlaceEdits() async throws {
        let model = try ParityDemo.window("saving-in-place")
        let main = try #require(model.main)
        main.autosave = false
        let path = file("saving-in-place")
        // No unsaved change: a silent reload.
        try inPlace(path, adds: "In Place 1")
        try await until { titles(main).contains("In Place 1") }
        #expect(titles(main).contains("In Place 1") && main.dialog == nil, "reloaded")
        // An unsaved change: it asks; Discard opens the disk version.
        try add(main.session, main.vault.id, "Local Lost")
        main.afterChange(select: nil)
        try inPlace(path, adds: "In Place 2")
        try await until { main.dialog != nil }
        #expect(main.dialog == .changedOnDisk(ask: .unsaved, changes: 1))
        main.resolveDisk(.reload, ask: .unsaved)
        _ = await main.saving?.value
        #expect(titles(main).contains("In Place 2") && !titles(main).contains("Local Lost"), "discarded")
        // Reload on change off: it asks; Keep keeps the open vault, changed.
        try model.session.saveSettings(changes: [AppSetting(key: "save.reload_on_change", value: .flag(on: false))])
        try inPlace(path, adds: "In Place 3")
        try await until { main.dialog != nil }
        #expect(main.dialog == .changedOnDisk(ask: .reload, changes: 0))
        main.resolveDisk(.later, ask: .reload)
        _ = await main.saving?.value
        #expect(!titles(main).contains("In Place 3") && main.saveStatus?.changes == 1, "kept")
        await main.saveNow(asks: true)
        #expect(main.dialog == .changedOnDisk(ask: .onSave, changes: 1), "the save asks again")
        #expect(try onDisk(path).contains("In Place 3"), "nothing written")
        main.dialog = nil
        model.lockAll()
    }

    @Test("APP-05.24 T42, APP-05.11 T18 (V-B4): deleted or moved: no question; a save writes the file anew, watched")
    func deletedOrMoved() async throws {
        let model = try ParityDemo.window("saving-deleted")
        let main = try #require(model.main)
        main.autosave = false
        let path = file("saving-deleted")
        try FileManager.default.removeItem(atPath: path)
        try await Task.sleep(for: .milliseconds(1_500))
        #expect(main.dialog == nil, "no question")
        try add(main.session, main.vault.id, "After Delete")
        main.afterChange(select: nil)
        #expect(await main.saveNow()?.changes == 0)
        #expect(attribute(path, .posixPermissions) == 0o600, "written anew, 0600")
        // The watch follows the new file: an edit in place is seen.
        try await Task.sleep(for: .milliseconds(1_500))
        try inPlace(path, adds: "After Recreate Remote")
        try await until { titles(main).contains("After Recreate Remote") }
        #expect(titles(main).contains("After Recreate Remote"), "the new file is watched")
        // Moved away: no question; the next save writes the old path anew.
        let moved = (path as NSString).deletingLastPathComponent + "/Moved.appvault"
        try? FileManager.default.removeItem(atPath: moved)
        try FileManager.default.moveItem(atPath: path, toPath: moved)
        let movedBytes = try Data(contentsOf: URL(fileURLWithPath: moved))
        try await Task.sleep(for: .milliseconds(1_500))
        #expect(main.dialog == nil, "no question")
        try add(main.session, main.vault.id, "After Move")
        main.afterChange(select: nil)
        #expect(await main.saveNow()?.changes == 0)
        #expect(try onDisk(path).contains("After Move"))
        #expect(try Data(contentsOf: URL(fileURLWithPath: moved)) == movedBytes, "the moved file is not touched")
        model.lockAll()
    }

    @Test("APP-05.24 T40 (V-B6): after App's own save (a rename) an edit in place is still seen")
    func watchFollowsOwnSave() async throws {
        let model = try ParityDemo.window("saving-rearm")
        let main = try #require(model.main)
        main.autosave = false
        let path = file("saving-rearm")
        let inode = attribute(path, .systemFileNumber)
        try add(main.session, main.vault.id, "Demo Shop")
        main.afterChange(select: nil)
        #expect(await main.saveNow()?.changes == 0)
        #expect(attribute(path, .systemFileNumber) != inode, "App saves by a rename")
        try await Task.sleep(for: .milliseconds(1_500))
        try inPlace(path, adds: "In Place After Save")
        try await until { titles(main).contains("In Place After Save") }
        #expect(titles(main).contains("In Place After Save"), "the watch moved to the new file")
        model.lockAll()
    }
}

/// F-101 (LD-225 (1), E13-S2 AT-E03): an automatic lock never waits long
/// on a save on the main thread.
extension ParitySavingTests {
    @Test("F-101: a FIFO at the vault's path: an automatic lock returns at once, locked, the change in a copy")
    func f101FifoAtTheVaultPathDoesNotHoldTheLock() async throws {
        let model = try ParityDemo.window("saving-f101-fifo")
        let main = try #require(model.main)
        let path = file("saving-f101-fifo")
        let settings = (path as NSString).deletingLastPathComponent + "/settings"
        try? FileManager.default.removeItem(atPath: settings)
        defer { try? FileManager.default.removeItem(atPath: settings) }
        model.session.settings().useFolder(folder: settings)
        try setSaving(model.session, autosave: false, onLock: true)
        try add(main.session, main.vault.id, "Demo Shop")
        main.afterChange(select: nil)
        try FileManager.default.removeItem(atPath: path)
        #expect(mkfifo(path, 0o600) == 0)
        defer { try? FileManager.default.removeItem(atPath: path) }
        let took = ContinuousClock().measure { model.lockAll() }  // as LockSignals does
        #expect(took < .seconds(2), "lockAll on the main thread took \(took)")
        #expect(model.vaults.allSatisfy { $0.locked })
        let copies = try FileManager.default.contentsOfDirectory(atPath: settings + "/recovery")
        #expect(copies.count == 1, "the change is kept")
    }

    @Test("F-101: an automatic lock waits a second at most for a slow save, which still writes after the lock")
    func f101SlowSaveDoesNotHoldTheLock() async throws {
        let (model, vaultSettings) = try SettingsDemo.model("saving-f101-slow")
        try setSaving(model.session, autosave: false, onLock: true)
        // A 3-second key derivation: from now on each save takes that long.
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
        let url = URL(fileURLWithPath: try #require(vaultSettings.view?.fullPath))
        let before = try Data(contentsOf: url)
        let took = ContinuousClock().measure { model.lockAll() }  // as LockSignals does
        #expect(took < .seconds(2), "lockAll on the main thread took \(took)")
        #expect(model.vaults.allSatisfy { $0.locked })
        for _ in 0..<400 where (try? Data(contentsOf: url)) == before { try await Task.sleep(for: .milliseconds(50)) }
        #expect(try Data(contentsOf: url) != before, "the save went on after the lock and wrote the change")
    }
}
