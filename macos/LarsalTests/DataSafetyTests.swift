import AppKit
import LarsalCore
import SwiftUI
import Testing

/// E13-S6 part e: the saving and attachment questions of F-085 to F-088
/// through the window model, offscreen (never ordered front, AGENTS.md
/// rule 10). Demo vaults only, copied to target/.
@MainActor
@Suite(.serialized)
struct DataSafetyTests {
    init() { ParityDemo.setUp() }

    static let newPassword = "4v8Nq2LmZ7rT1xKc9WbP"

    func file(_ folder: String) -> String {
        ParityDemo.root.appending(path: "target/option-a/\(folder)/Personal.larsalvault").path(percentEncoded: false)
    }

    func add(_ session: Session, _ vault: UInt64, _ title: String) throws {
        _ = try session.beginNew(vault: vault, group: nil)
        try session.setText(vault: vault, field: .title, value: title)
        _ = try session.commitEdit(vault: vault)
    }

    /// MOD-12.10 through the vault settings: the next save writes the new
    /// password.
    func changePassword(_ session: Session, _ vault: UInt64) throws {
        let settings = VaultSettings(session: session, vault: vault)
        _ = try settings.setPassword(text: Self.newPassword)
        _ = try settings.setRepeat(text: Self.newPassword)
        #expect(try settings.changePassword(answers: []) == .done)
    }

    /// What a fresh reader finds in the file with `password`.
    func titles(_ path: String, _ password: String) throws -> Set<String> {
        let reader = Session()
        let id = try reader.open(path: path)
        #expect(try reader.unlock(vault: id, password: password, keyFile: nil) == .unlocked)
        return Set(try reader.list(vault: id, view: .all).rows.map(\.title))
    }

    /// A window on the Personal demo vault: no autosave, no folder watch
    /// (each test drives its own path).
    func window(_ folder: String) async throws -> (MainWindowModel, Screen) {
        let model = try ParityDemo.window(folder)
        let main = try #require(model.main)
        main.autosave = false
        main.disk.watch = nil
        let screen = Screen(model)
        await screen.settle()
        return (model, screen)
    }

    @Test("F-085 APP-05.29: a file re-keyed elsewhere asks for its new password; Merge then keeps both and saves")
    func f085RekeyedFileUnlocksAndMerges() async throws {
        let (model, screen) = try await window("data-safety-rekey")
        let main = try #require(model.main)
        let path = file("data-safety-rekey")
        try add(main.session, main.vault.id, "Mine unsaved")
        main.afterChange(select: nil)
        let other = Session()
        let id = try other.open(path: path)
        #expect(try other.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        try add(other, id, "Theirs")
        try changePassword(other, id)
        #expect(try other.save(vault: id).changes == 0)
        try other.close(vault: id)
        main.resolveDisk(.merge, ask: .unsaved)
        try await screen.wait { main.dialog != nil }
        #expect(main.dialog == .diskNewKey(choice: .merge), "the unlock sheet, not only a notice")
        await screen.settle()
        #expect(screen.strings().contains("Unlock the changed “Personal.larsalvault”"))
        var problem: String?
        main.unlockDisk(.merge, password: "wrong", keyFile: nil) { problem = $0 }
        try await screen.wait { problem != nil }
        #expect(problem == "That password or key file does not open the changed file.")
        #expect(main.dialog == .diskNewKey(choice: .merge), "a wrong password keeps the sheet")
        main.unlockDisk(.merge, password: Self.newPassword, keyFile: nil) { problem = $0 }
        try await screen.wait { main.dialog == nil && main.saveStatus?.changes == 0 }
        #expect(try titles(path, Self.newPassword).isSuperset(of: ["Mine unsaved", "Theirs"]), "both sides kept")
        model.lockAll()
    }

    @Test("F-087 APP-05.14: the third failed safe save asks to turn it off; Turn off saves this vault")
    func f087ThirdFailureAsksToTurnOffSafeSaving() async throws {
        let (model, screen) = try await window("data-safety-unsafe")
        let main = try #require(model.main)
        let path = file("data-safety-unsafe")
        let folder = URL(fileURLWithPath: path).deletingLastPathComponent()
        let away = folder.deletingLastPathComponent().appending(path: "data-safety-unsafe-away")
        try? FileManager.default.removeItem(at: away)
        try add(main.session, main.vault.id, "Demo Shop")
        main.afterChange(select: nil)
        // The folder is gone: a reason another method can help with.
        try FileManager.default.moveItem(at: folder, to: away)
        var asked: [Bool] = []
        for _ in 0..<3 {
            main.dialog = nil
            await main.saveNow()
            asked.append(main.dialog == .askUnsafe)
        }
        try FileManager.default.moveItem(at: away, to: folder)
        #expect(asked == [false, false, true])
        await screen.settle()
        try await screen.press("Turn off")
        try await screen.wait { main.saveStatus?.changes == 0 }
        #expect(try titles(path, "demo-pass-7").contains("Demo Shop"))
        #expect(!main.session.settings().flag(key: "save.alternative"), "the app setting stays")
        model.lockAll()
    }

    @Test("F-088 APP-05.33: the save after a password change lists the old backup; Delete checked removes it")
    func f088OldCopiesAfterAKeyChange() async throws {
        let (model, screen) = try await window("data-safety-old-copies")
        let main = try #require(model.main)
        let backup = URL(fileURLWithPath: file("data-safety-old-copies")).deletingLastPathComponent()
            .appending(path: "Personal.old.larsalvault")
        try? FileManager.default.removeItem(at: backup)
        try changePassword(main.session, main.vault.id)
        await main.saveNow()
        guard case .oldCopies(let paths) = main.dialog else {
            Issue.record("no old copies question: \(String(describing: main.dialog))")
            return
        }
        #expect(paths.map { ($0 as NSString).lastPathComponent } == ["Personal.old.larsalvault"])
        await screen.settle()
        try await screen.press("Delete checked")
        #expect(main.dialog == nil && !FileManager.default.fileExists(atPath: backup.path(percentEncoded: false)))
        await main.saveNow()
        #expect(main.dialog == nil, "only the key-change save asks")
        model.lockAll()
    }

    @Test("F-086 MOD-05.13: an outside edit of an open attachment copy asks within 5 seconds; Save keeps it")
    func f086ChangedCopyAsksAndSaves() async throws {
        let (model, _) = try await window("data-safety-open-copy")
        let main = try #require(model.main)
        let folder = URL(fileURLWithPath: file("data-safety-open-copy")).deletingLastPathComponent()
        let source = folder.appending(path: "codes.txt")
        try Data("first".utf8).write(to: source)
        let session = main.session
        let id = main.vault.id
        let entry = try #require(try session.list(vault: id, view: .all).rows.first { $0.title == "Wise" }?.id)
        main.edit(entry)
        try session.attachFile(vault: id, path: source.path(percentEncoded: false))
        let before = FakeOpener.opened.count  // shared with suites running side by side
        main.openAttachment("codes.txt")
        let copy = try #require(FakeOpener.opened.dropFirst(before).first)
        try Data("second edit".utf8).write(to: copy)
        for _ in 0..<160 where main.dialog == nil { try await Task.sleep(for: .milliseconds(50)) }
        #expect(main.dialog == .changedAttachment(name: "codes.txt"), "the 5-second watch asks")
        main.answerChangedCopy("codes.txt", save: true)
        main.saveEditor()
        #expect(main.editor == nil, "committed")
        #expect(!FileManager.default.fileExists(atPath: copy.path(percentEncoded: false)), "the copy is wiped")
        _ = try session.beginEdit(vault: id, entry: entry)
        let out = folder.appending(path: "out")
        _ = try session.saveAttachment(
            vault: id, name: "codes.txt", folder: out.path(percentEncoded: false), overwrite: true)
        try session.cancelEdit(vault: id)
        #expect(try Data(contentsOf: out.appending(path: "codes.txt")) == Data("second edit".utf8))
        model.lockAll()
    }

    /// The editor on Wise with codes.txt ("first") attached, then opened:
    /// the entry and the open copy's path, as the fake opener got it.
    func openCopy(_ main: VaultModel, _ folder: String) throws -> (entry: String, copy: URL) {
        let source = URL(fileURLWithPath: file(folder)).deletingLastPathComponent().appending(path: "codes.txt")
        try Data("first".utf8).write(to: source)
        let rows = try main.session.list(vault: main.vault.id, view: .all).rows
        let entry = try #require(rows.first { $0.title == "Wise" }?.id)
        main.edit(entry)
        try main.session.attachFile(vault: main.vault.id, path: source.path(percentEncoded: false))
        main.editor?.refresh()
        let before = FakeOpener.opened.count  // shared with suites running side by side
        main.openAttachment("codes.txt")
        return (entry, try #require(FakeOpener.opened.dropFirst(before).first))
    }

    @Test("F-086 MOD-05.13: Save in the leave question asks about a changed open copy first; the leave waits")
    func f086LeaveSaveAsksAboutTheChangedCopy() async throws {
        let (model, _) = try await window("data-safety-leave-save")
        let main = try #require(model.main)
        let (_, copy) = try openCopy(main, "data-safety-leave-save")
        try Data("second edit".utf8).write(to: copy)
        var left = false
        #expect(main.askLeave { left = true }, "the draft has a change")
        #expect(main.dialog == .leaveEditor)
        main.answerLeave(save: true)
        #expect(main.dialog == .changedAttachment(name: "codes.txt"), "asked before the commit")
        #expect(main.editor != nil && !left, "the leave waits")
        #expect(FileManager.default.fileExists(atPath: copy.path(percentEncoded: false)), "the copy is kept")
        model.lockAll()
    }

    @Test("F-086 MOD-05.13: leaving an editor without changes asks about a changed open copy first")
    func f086LeaveWithoutChangesAsksAboutTheChangedCopy() async throws {
        let (model, _) = try await window("data-safety-leave-plain")
        let main = try #require(model.main)
        let (entry, _) = try openCopy(main, "data-safety-leave-plain")
        main.saveEditor()
        #expect(main.editor == nil, "codes.txt is in the entry")
        main.edit(entry)
        let before = FakeOpener.opened.count
        main.openAttachment("codes.txt")
        let copy = try #require(FakeOpener.opened.dropFirst(before).first)
        try Data("second edit".utf8).write(to: copy)
        #expect(main.askLeave {}, "asked, though the draft has no change")
        #expect(main.dialog == .changedAttachment(name: "codes.txt"))
        #expect(main.editor != nil && FileManager.default.fileExists(atPath: copy.path(percentEncoded: false)))
        model.lockAll()
    }

    @Test("F-086 MOD-05.13: a file event on the open copy asks before the 5-second check")
    func f086FileEventAsksBeforeTheCheck() async throws {
        let (model, _) = try await window("data-safety-copy-event")
        let main = try #require(model.main)
        let (_, copy) = try openCopy(main, "data-safety-copy-event")
        try await Task.sleep(for: .milliseconds(300))  // the watch is armed
        try Data("second edit".utf8).write(to: copy)
        // 3 s: the 5-second check comes 5 s after the open at the earliest.
        for _ in 0..<60 where main.dialog == nil { try await Task.sleep(for: .milliseconds(50)) }
        #expect(main.dialog == .changedAttachment(name: "codes.txt"), "the file event asks")
        model.lockAll()
    }

    @Test("F-085 APP-05.29: the unlock sheet's Browse… picks the key file of a file re-keyed with one")
    func f085BrowsePicksTheKeyFile() async throws {
        let (model, screen) = try await window("data-safety-rekey-file")
        let main = try #require(model.main)
        let path = file("data-safety-rekey-file")
        let key = URL(fileURLWithPath: path).deletingLastPathComponent().appending(path: "personal.larsalkey")
        try? FileManager.default.removeItem(at: key)
        try add(main.session, main.vault.id, "Mine unsaved")
        main.afterChange(select: nil)
        // Elsewhere: a key file only, no password.
        let other = Session()
        let id = try other.open(path: path)
        #expect(try other.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        try add(other, id, "Theirs")
        let settings = VaultSettings(session: other, vault: id)
        let made = try settings.newKeyFile(path: key.path(percentEncoded: false), answers: [])
        #expect(made == .then(outcome: .done))
        _ = try settings.setPassword(text: "")
        _ = try settings.setRepeat(text: "")
        #expect(try settings.changePassword(answers: [.noPassword]) == .done)
        #expect(try other.save(vault: id).changes == 0)
        try other.close(vault: id)
        main.resolveDisk(.merge, ask: .unsaved)
        try await screen.wait { main.dialog != nil }
        #expect(main.dialog == .diskNewKey(choice: .merge))
        await screen.settle()
        let browse = try #require(screen.node("Browse…"), "the sheet has Browse…")
        let panel = NewVaultModel.openKeyFile  // shared with suites running side by side
        NewVaultModel.openKeyFile = { key }
        #expect(browse.accessibilityPerformPress?() == true)
        NewVaultModel.openKeyFile = panel
        await screen.settle()
        try await screen.press("Unlock")
        try await screen.wait { main.dialog == nil && main.saveStatus?.changes == 0 }
        #expect(main.dialog == nil, "the picked key file opened the changed file")
        let reader = Session()
        let again = try reader.open(path: path)
        #expect(try reader.unlock(vault: again, password: nil, keyFile: key.path(percentEncoded: false)) == .unlocked)
        let titles = Set(try reader.list(vault: again, view: .all).rows.map(\.title))
        #expect(titles.isSuperset(of: ["Mine unsaved", "Theirs"]), "both sides kept")
        model.lockAll()
    }
}
