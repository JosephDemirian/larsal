import AppCore
import Foundation
import Testing
import os

/// The conflict-copy calls a test sees: the seam answers the vault's iCloud
/// conflict versions with `versions` and records what would be resolved or
/// moved to the Trash, so no test touches the owner's Trash or iCloud
/// (real iCloud: E15-S5).
nonisolated final class FakeCloud: Sendable {
    struct Seen {
        var trashed: [String] = []
        var resolved: [[String]] = []
    }

    let seen = OSAllocatedUnfairLock(initialState: Seen())

    init(versions: [String] = [], of vault: String = "") {
        let seen = seen
        FileAccess.cloud.withLock {
            $0 = FileAccess.Cloud(
                unresolved: { path in !vault.isEmpty && path.hasSuffix(vault) ? versions : [] },
                resolve: { _, done in seen.withLock { $0.resolved.append(done) } },
                trash: { path in
                    seen.withLock { $0.trashed.append(path) }
                    return true
                })
        }
    }

    func remove() { FileAccess.cloud.withLock { $0 = .system } }
}

/// E15-S4 (APP-05.17): the conflict-copy finder through the window model,
/// offscreen (never ordered front, AGENTS.md rule 10). Demo vaults only,
/// copied to target/.
extension ParitySavingTests {
    /// Waits up to 10 s for `done`.
    private func until(_ done: () -> Bool) async throws {
        for _ in 0..<400 where !done() { try await Task.sleep(for: .milliseconds(25)) }
    }

    /// Another Mac's save of the copy at `path` with `title` added; its own
    /// backup off, so no backup of the copy lands next to the vault.
    private func copyWriter(_ path: String, adds title: String) throws {
        let other = Session()
        try other.saveSettings(changes: [AppSetting(key: "backup.enabled", value: .flag(on: false))])
        let id = try other.open(path: path)
        #expect(try other.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        try add(other, id, title)
        #expect(try other.save(vault: id).changes == 0)
        try other.close(vault: id)
    }

    private func name(_ path: String) -> String { (path as NSString).lastPathComponent }

    /// The rows of `MSG-DISK-COPIES` once it shows.
    private func copiesSheet(_ main: VaultModel) async throws -> [CopyRow] {
        try await until { main.dialog != nil }
        guard main.dialog == .copies else {
            Issue.record("MSG-DISK-COPIES did not show: \(String(describing: main.dialog))")
            return []
        }
        return main.disk.conflicts
    }

    @Test("APP-05.17 T65: sibling copies merge after the unlock and save; Move to Trash moves them, Keep none")
    func t65SiblingCopies() async throws {
        let names = ["Personal (Demo User's conflicted copy 2026-10-31).appvault", "Personal-DemoMac.appvault"]
        for trash in [true, false] {
            let folder = "copies-siblings-\(trash ? "trash" : "keep")"
            let dir = (try ParityDemo.path(0, folder: folder) as NSString).deletingLastPathComponent
            let manager = FileManager.default
            for file in try manager.contentsOfDirectory(atPath: dir) where file.hasPrefix("Personal") {
                try? manager.removeItem(atPath: dir + "/" + file)
            }
            let path = try ParityDemo.path(0, folder: folder)
            for (copy, title) in zip(names, ["Demo Dropbox", "Demo OneDrive"]) {
                try manager.copyItem(atPath: path, toPath: dir + "/" + copy)
                try copyWriter(dir + "/" + copy, adds: title)
            }
            let cloud = FakeCloud()
            defer { cloud.remove() }
            let model = try ParityDemo.window(folder)
            let main = try #require(model.main)
            let rows = try await copiesSheet(main)
            #expect(rows.map { name($0.path) } == names)
            #expect(rows.allSatisfy { $0.state == .merged && !$0.version })
            #expect(try onDisk(path).isSuperset(of: ["Demo Dropbox", "Demo OneDrive"]), "merged and saved first")
            if trash {
                let screen = Screen(model)
                await screen.settle()
                let words = "A sync service made other copies of “Personal.appvault”"
                #expect(screen.strings().contains { $0.hasPrefix(words) })
            }
            main.copiesDone(trash: trash)
            try await until { !trash || cloud.seen.withLock { $0.trashed.count } == 2 }
            try await Task.sleep(for: .milliseconds(300))
            let trashed = cloud.seen.withLock { $0.trashed }.map { name($0) }
            #expect(trashed == (trash ? names : []))
            #expect(names.allSatisfy { manager.fileExists(atPath: dir + "/" + $0) }, "none deleted outright")
            // Kept or moved: not listed again until it changes.
            main.findCopies()
            try await Task.sleep(for: .milliseconds(800))
            #expect(main.dialog == nil, "not listed again")
            model.lockAll()
            for copy in names { try? manager.removeItem(atPath: dir + "/" + copy) }
        }
    }

    @Test("APP-05.17 T68: two iCloud conflict versions merge; Move to Trash resolves both once, Keep nothing")
    func t68ICloudVersions() async throws {
        for trash in [true, false] {
            let folder = "copies-icloud-\(trash ? "trash" : "keep")"
            let path = try ParityDemo.path(0, folder: folder)
            let side = ParityDemo.root.appending(path: "target/option-a/\(folder)-versions")
            try? FileManager.default.removeItem(at: side)
            try FileManager.default.createDirectory(at: side, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: side) }
            var versions: [String] = []
            for title in ["Demo Version 1", "Demo Version 2"] {
                let copy = side.appending(path: "\(title).appvault").path(percentEncoded: false)
                try FileManager.default.copyItem(atPath: path, toPath: copy)
                try copyWriter(copy, adds: title)
                versions.append(copy)
            }
            let cloud = FakeCloud(versions: versions, of: "/\(folder)/Personal.appvault")
            defer { cloud.remove() }
            let model = try ParityDemo.window(folder)
            let main = try #require(model.main)
            let rows = try await copiesSheet(main)
            #expect(rows.map(\.path) == versions && rows.allSatisfy { $0.state == .merged && $0.version })
            #expect(try onDisk(path).isSuperset(of: ["Demo Version 1", "Demo Version 2"]), "merged and saved")
            main.copiesDone(trash: trash)
            try await until { !trash || !cloud.seen.withLock { $0.resolved.isEmpty } }
            try await Task.sleep(for: .milliseconds(300))
            let seen = cloud.seen.withLock { $0 }
            #expect(seen.resolved == (trash ? [versions] : []), "resolved, then the others removed, once")
            #expect(seen.trashed.isEmpty, "a version is resolved, never moved to the Trash")
            model.lockAll()
        }
    }
    @Test("APP-05.29 T64: a copy under the replaced password asks MSG-DISK-OLD-KEY first; Skip saves over it at once")
    func t64ReplacedPasswordSkip() async throws {
        let folder = "copies-old-key"
        let model = try ParityDemo.window(folder)
        let main = try #require(model.main)
        main.autosave = false
        main.disk.watch = nil
        let path = file(folder)
        let old = (path as NSString).deletingLastPathComponent + "/old-copy.keep"
        try? FileManager.default.removeItem(atPath: old)
        try FileManager.default.copyItem(atPath: path, toPath: old)
        defer { try? FileManager.default.removeItem(atPath: old) }
        let settings = VaultSettings(session: main.session, vault: main.vault.id)
        _ = try settings.setPassword(text: Self.newPassword)
        _ = try settings.setRepeat(text: Self.newPassword)
        #expect(try settings.changePassword(answers: []) == .done)
        #expect(await main.saveNow(asks: true)?.changes == 0)
        guard case .oldCopies? = main.dialog else {
            Issue.record("MSG-KEY-OLD-COPIES after the key change")
            return
        }
        main.dialog = nil  // its Keep
        try copyWriter(old, adds: "Demo Old")
        try FileManager.default.removeItem(atPath: path)
        try FileManager.default.copyItem(atPath: old, toPath: path)
        main.checkDisk()
        try await until { main.dialog != nil }
        #expect(main.dialog == .diskNewKey(choice: .merge), "a silent reload goes on as Merge (APP-05.29)")
        main.unlockDisk(.merge, password: "demo-pass-7", keyFile: nil) { _ in }
        try await until { main.dialog == .diskOldKey }
        let screen = Screen(model)
        await screen.settle()
        #expect(screen.strings().contains("This copy of “Personal.appvault” uses a replaced password"))
        #expect(!titles(main).contains("Demo Old"), "nothing merged before the answer")
        main.resolveOldKey(mergeAnyway: false)
        _ = await main.saving?.value
        #expect(main.saveStatus?.changes == 0, "saved over the copy at once")
        let reader = Session()
        let id = try reader.open(path: path)
        #expect(try reader.unlock(vault: id, password: "demo-pass-7", keyFile: nil) != .unlocked)
        #expect(try reader.unlock(vault: id, password: Self.newPassword, keyFile: nil) == .unlocked)
        #expect(!Set(try reader.list(vault: id, view: .all).rows.map(\.title)).contains("Demo Old"))
        model.lockAll()
    }

    @Test("APP-05.17 step 5, MOD-11.31: a replaced-password copy in MSG-DISK-COPIES warns first; Skip leaves it alone")
    func f182OldKeyCopyWarnsAndSkips() async throws {
        let model = try ParityDemo.window("copies-old-key-row")
        let main = try #require(model.main)
        main.autosave = false
        main.disk.watch = nil
        let before = titles(main)
        main.disk.conflicts = [CopyRow(path: "/nowhere/Personal (old).appvault", state: .oldKey, version: false)]
        main.dialog = .copies
        let screen = Screen(model)
        await screen.settle()
        let strings = screen.strings()
        #expect(strings.contains("Uses a replaced password") && strings.contains(OldKeyWords.text))
        #expect(strings.contains("Merge anyway") && strings.contains("Skip"))
        try await screen.press("Skip")
        #expect(!screen.strings().contains(OldKeyWords.text), "answered")
        #expect(main.dialog == .copies && titles(main) == before, "nothing merged")
        model.lockAll()
    }

    @Test("APP-05.17 step 5 (F-201): a copy with another root id, opened with its own password, is not listed")
    func c1r2StrangerAfterUnlock() async throws {
        let folder = "copies-c1r2-stranger"
        let path = try ParityDemo.path(0, folder: folder)
        let stranger = (path as NSString).deletingLastPathComponent + "/Personal 2.appvault"
        try? FileManager.default.removeItem(atPath: stranger)
        try FileManager.default.copyItem(
            at: ParityDemo.root.appending(path: "testdata/option-a-work.appvault"),
            to: URL(fileURLWithPath: stranger))
        defer { try? FileManager.default.removeItem(atPath: stranger) }
        let cloud = FakeCloud()
        defer { cloud.remove() }
        let model = try ParityDemo.window(folder)
        let main = try #require(model.main)
        let rows = try await copiesSheet(main)
        #expect(rows.map(\.state) == [.needsPassword], "its root id is known only once it opens")
        let row = try #require(rows.first)
        var problem: String?
        main.mergeCopy(row.path, password: "demo-pass-8", keyFile: nil, anyway: false) { problem = $0 }
        try await until { main.disk.conflicts.first?.state != .needsPassword || problem != nil }
        #expect(main.disk.conflicts.isEmpty && problem == nil, "not merged, not listed")
        #expect(main.dialog == nil, "no copy left: the sheet closes")
        model.lockAll()
    }

    @Test("APP-05.17 step 6 (F-213): Move to Trash moves only the merged copies, never an unmerged one")
    func c1r3TrashOnlyMerged() async throws {
        let cloud = FakeCloud()
        defer { cloud.remove() }
        let model = try ParityDemo.window("copies-c1r3-trash")
        let main = try #require(model.main)
        main.autosave = false
        main.disk.watch = nil
        main.disk.conflicts = [
            CopyRow(path: "/nowhere/Personal-DemoMac.appvault", state: .merged, version: false),
            CopyRow(path: "/nowhere/Personal (copy).appvault", state: .needsPassword, version: false),
            CopyRow(path: "/nowhere/Personal (old).appvault", state: .oldKey, version: false),
        ]
        main.dialog = .copies
        main.copiesDone(trash: true)
        try await until { !cloud.seen.withLock { $0.trashed.isEmpty } }
        try await Task.sleep(for: .milliseconds(300))
        #expect(cloud.seen.withLock { $0.trashed } == ["/nowhere/Personal-DemoMac.appvault"])
        model.lockAll()
    }

    static let newPassword = "4v8Nq2LmZ7rT1xKc9WbP"

    @Test("APP-05.26 T70: an older file put back is merged, never loaded, saved at once, then MSG-DISK-ROLLBACK shows")
    func t70RollbackIsMergedAndSaved() async throws {
        let folder = "copies-rollback"
        let path = try ParityDemo.path(0, folder: folder)
        let first = try Data(contentsOf: URL(fileURLWithPath: path))
        let model = try ParityDemo.window(folder)
        let main = try #require(model.main)
        main.autosave = false
        main.disk.watch = nil
        try add(main.session, main.vault.id, "Demo Shop")
        main.afterChange(select: nil)
        #expect(await main.saveNow(asks: true)?.changes == 0)
        try first.write(to: URL(fileURLWithPath: path))
        main.checkDisk()
        try await until { main.toast?.text.contains("went back in time") == true }
        #expect(main.toast?.text == "“Personal.appvault” went back in time.")
        #expect(main.saveStatus?.changes == 0, "saved at once, S-FILE-01 off")
        #expect(titles(main).contains("Demo Shop") && main.dialog == nil, "merged, never loaded")
        #expect(try onDisk(path).contains("Demo Shop"), "the file holds the merge")
        model.lockAll()
    }
}
