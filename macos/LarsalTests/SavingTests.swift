import AppKit
import LarsalCore
import SwiftUI
import Testing

/// The frames of design/option-a/manifest.json that E5-S10 builds.
enum SavingFrame: String, CaseIterable, CustomTestStringConvertible {
    case disk = "dialogs-changed-on-disk"
    case close = "dialogs-close-with-unsaved-changes"
    case failed = "dialogs-save-failed"

    var testDescription: String { rawValue }

    /// The mockup's state (mockup.js `DIALOGS`); the reason of a failed
    /// save is the system's, here the mockup's demo text.
    var dialog: VaultModel.Dialog {
        switch self {
        case .disk: .changedOnDisk(ask: .unsaved, changes: 2)
        case .close: .closeUnsaved(changes: 2)
        case .failed: .saveFailed(reason: "The disk “Backup SSD” is not connected.")
        }
    }
}

@MainActor
@Suite(.serialized)
struct SavingSnapshotTests {
    init() { ParityDemo.setUp() }

    @Test("Option A saving dialog, offscreen, light and dark", arguments: SavingFrame.allCases)
    func frame(_ frame: SavingFrame) async throws {
        let window = try ParityDemo.window("saving-shots")
        let main = try #require(window.main)
        main.dialog = frame.dialog
        let root = AnyView(DialogView(model: main, dialog: frame.dialog).fixedSize())
        let host = NSHostingView(rootView: root.font(.sans(14)).foregroundStyle(Tok.text))
        host.frame = NSRect(origin: .zero, size: host.fittingSize)
        // Never ordered front (AGENTS.md rule 10); sRGB as the references.
        let offscreen = NSWindow(
            contentRect: host.frame.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless], backing: .buffered,
            defer: false)
        offscreen.colorSpace = .sRGB
        offscreen.backgroundColor = .clear
        offscreen.contentView = host
        let shots = SnapshotTests()
        for (folder, look) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            offscreen.appearance = NSAppearance(named: look)
            let png = try await shots.render(host)
            let out = ParityDemo.shotsDirectory.appending(path: "\(folder)/\(frame.rawValue).png")
            try FileManager.default.createDirectory(
                at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
            try png.write(to: out)
            #expect(png.count > 5_000, "\(out.path)")
            try shots.accessibilityTree(host).write(to: out.deletingPathExtension().appendingPathExtension("ax.json"))
        }
        offscreen.contentView = nil
        main.dialog = nil
        window.lockAll()
    }
}

/// Design parity (check 6) and AT-I05 through the screen: the saving
/// sheets do what the mockup and APP-05 make them do, pressed through the
/// accessibility tree offscreen. Demo vaults only, copied to target/.
@MainActor
@Suite(.serialized)
struct ParitySavingTests {
    init() { ParityDemo.setUp() }

    /// The Personal demo vault's file in the test's folder.
    func file(_ folder: String) -> String {
        ParityDemo.root.appending(path: "target/option-a/\(folder)/Personal.larsalvault").path(percentEncoded: false)
    }

    /// A second window on the same file (AT-I05's other writer).
    func otherWriter(_ path: String, adds title: String) throws {
        let other = Session()
        let id = try other.open(path: path)
        #expect(try other.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        try add(other, id, title)
        #expect(try other.save(vault: id).changes == 0)
        try other.close(vault: id)
    }

    func add(_ session: Session, _ vault: UInt64, _ title: String) throws {
        _ = try session.beginNew(vault: vault, group: nil)
        try session.setText(vault: vault, field: .title, value: title)
        _ = try session.commitEdit(vault: vault)
    }

    func titles(_ main: VaultModel) -> Set<String> {
        Set(((try? main.session.list(vault: main.vault.id, view: .all))?.rows ?? []).map(\.title))
    }

    /// Presses the last element named `name`: the sheet's button after the
    /// choice of the same name.
    func pressLast(_ screen: Screen, _ name: String) async throws {
        let element = try #require(
            screen.nodes().last { (($0.accessibilityLabel?() ?? nil) ?? "") == name }, "\(name) is on screen")
        #expect(element.accessibilityPerformPress?() == true, "\(name) takes a press")
        await screen.settle()
    }

    func setSaving(_ session: Session, autosave: Bool, onLock: Bool) throws {
        try session.saveSettings(changes: [
            LarsalSetting(key: "save.after_every_change", value: .flag(on: autosave)),
            LarsalSetting(key: "save.on_lock", value: .flag(on: onLock)),
        ])
    }

    @Test("Parity dialogs-changed-on-disk: the watch sees another writer while changes wait; Merge keeps both (AT-I05)")
    func mergeThroughTheWatch() async throws {
        let model = try ParityDemo.window("parity-saving-merge")
        let main = try #require(model.main)
        main.autosave = false
        let screen = Screen(model)
        await screen.settle()
        try add(main.session, main.vault.id, "Demo Shop")
        main.afterChange(select: nil)
        try otherWriter(file("parity-saving-merge"), adds: "Demo Bank 2")
        // No call from the test: the folder watch raises it (APP-05.24).
        for _ in 0..<200 where main.dialog == nil { try await Task.sleep(for: .milliseconds(50)) }
        #expect(main.dialog == .changedOnDisk(ask: .unsaved, changes: 1))
        await screen.settle()
        #expect(screen.strings().contains("Personal.larsalvault changed on disk"))
        try await pressLast(screen, "Merge")
        try await screen.wait { titles(main).isSuperset(of: ["Demo Shop", "Demo Bank 2"]) }
        #expect(titles(main).isSuperset(of: ["Demo Shop", "Demo Bank 2", "GitHub"]), "nothing lost")
        #expect(main.dialog == nil && (main.saveStatus?.changes ?? 0) > 0, "merged, not saved: auto-save is off")
        model.lockAll()
    }

    @Test("Parity dialogs-changed-on-disk: a save that finds the change asks; Cancel keeps; Overwrite saves over it")
    func overwriteOnSave() async throws {
        let model = try ParityDemo.window("parity-saving-overwrite")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        let path = file("parity-saving-overwrite")
        main.disk.watch = nil  // this test drives the save path only
        try otherWriter(path, adds: "Demo Bank 2")
        try add(main.session, main.vault.id, "Demo Shop")
        main.afterChange(select: nil)
        try await screen.wait { main.dialog != nil }
        #expect(main.dialog == .changedOnDisk(ask: .onSave, changes: 1))
        await screen.settle()
        try await screen.press("Cancel")
        #expect(main.dialog == nil && main.saveStatus?.changes == 1, "Cancel: nothing written, still changed")
        _ = await main.saveNow()
        #expect(main.dialog == .changedOnDisk(ask: .onSave, changes: 1), "the next save asks again")
        await screen.settle()
        try await screen.press("Overwrite")
        try await pressLast(screen, "Overwrite")
        try await screen.wait { main.saveStatus?.changes == 0 }
        let reader = Session()
        let id = try reader.open(path: path)
        _ = try reader.unlock(vault: id, password: "demo-pass-7", keyFile: nil)
        let onDisk = Set(try reader.list(vault: id, view: .all).rows.map(\.title))
        #expect(onDisk.contains("Demo Shop") && !onDisk.contains("Demo Bank 2"), "the disk version was replaced")
        model.lockAll()
    }

    @Test("Parity dialogs-close-with-unsaved-changes: Close Vault asks; Cancel keeps it open; Save saves and closes")
    func closeAsks() async throws {
        let model = try ParityDemo.window("parity-saving-close")
        let main = try #require(model.main)
        try setSaving(model.session, autosave: false, onLock: false)
        main.autosave = false
        let screen = Screen(model)
        await screen.settle()
        try add(main.session, main.vault.id, "Demo Shop")
        main.afterChange(select: nil)
        let id = main.vault.id
        model.close(id)
        try await screen.wait { main.dialog != nil }
        #expect(main.dialog == .closeUnsaved(changes: 1))
        await screen.settle()
        #expect(screen.strings().contains("Personal was changed. Save the changes?"))
        try await screen.press("Cancel")
        #expect(model.vaults.contains { $0.id == id } && main.dialog == nil, "Cancel: still open")
        model.close(id)
        try await screen.wait { main.dialog != nil }
        await screen.settle()
        try await screen.press("Save")
        try await screen.wait { !model.vaults.contains { $0.id == id } }
        #expect(!model.vaults.contains { $0.id == id }, "saved, then closed")
        let reader = Session()
        let again = try reader.open(path: file("parity-saving-close"))
        _ = try reader.unlock(vault: again, password: "demo-pass-7", keyFile: nil)
        #expect(try reader.list(vault: again, view: .all).rows.contains { $0.title == "Demo Shop" })
        try setSaving(model.session, autosave: true, onLock: true)
        model.lockAll()
    }

    @Test("Parity dialogs-close-with-unsaved-changes: Discard closes without saving")
    func closeDiscards() async throws {
        let model = try ParityDemo.window("parity-saving-discard")
        let main = try #require(model.main)
        try setSaving(model.session, autosave: false, onLock: false)
        main.autosave = false
        let screen = Screen(model)
        await screen.settle()
        let path = file("parity-saving-discard")
        let before = try Data(contentsOf: URL(fileURLWithPath: path))
        try add(main.session, main.vault.id, "Demo Shop")
        main.afterChange(select: nil)
        let id = main.vault.id
        model.close(id)
        try await screen.wait { main.dialog != nil }
        await screen.settle()
        try await screen.press("Discard")
        #expect(!model.vaults.contains { $0.id == id })
        #expect(try Data(contentsOf: URL(fileURLWithPath: path)) == before, "nothing written")
        try setSaving(model.session, autosave: true, onLock: true)
        model.lockAll()
    }

    @Test("APP-02.15 step 8 (quit): a changed vault saves first; one that cannot be saved asks and the quit waits")
    func quitSavesFirst() async throws {
        let model = try ParityDemo.window("saving-quit")
        let main = try #require(model.main)
        main.autosave = false  // the change waits for the quit
        try add(main.session, main.vault.id, "Demo Shop")
        main.afterChange(select: nil)
        #expect(await model.mayQuit(asks: true), "saved: the quit goes on")
        #expect(try model.session.saveStatus(vault: main.vault.id).changes == 0)
        let folder = URL(fileURLWithPath: file("saving-quit")).deletingLastPathComponent()
        let manager = FileManager.default
        try manager.setAttributes([.posixPermissions: 0o555], ofItemAtPath: folder.path)
        defer { try? manager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: folder.path) }
        try add(main.session, main.vault.id, "Demo Shop 2")
        main.afterChange(select: nil)
        #expect(await !model.mayQuit(asks: true), "the save failed: the quit waits")
        #expect(main.dialog == .closeUnsaved(changes: 1))
        main.dialog = nil
        model.lockAll()
    }

    /// What a fresh reader finds in the file.
    func onDisk(_ path: String) throws -> Set<String> {
        let reader = Session()
        let id = try reader.open(path: path)
        _ = try reader.unlock(vault: id, password: "demo-pass-7", keyFile: nil)
        return Set(try reader.list(vault: id, view: .all).rows.map(\.title))
    }

    @Test("APP-02.15 step 8, APP-02.16: Lock Everything and automatic locks save first; a failed save asks on the menu")
    func lockAllSavesFirst() async throws {
        let model = try ParityDemo.window("saving-lock-all")
        let main = try #require(model.main)
        let id = main.vault.id
        try setSaving(model.session, autosave: false, onLock: true)
        try add(main.session, id, "Demo Shop")
        main.afterChange(select: nil)
        model.lockAll()  // as LockSignals does on sleep, screen lock or idle
        #expect(model.vaults.allSatisfy { $0.locked })
        #expect(try onDisk(file("saving-lock-all")).contains("Demo Shop"), "saved before the lock")
        // The menu's Lock Everything with a save that fails asks; an
        // automatic lock still locks.
        #expect(try model.session.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        model.refresh()
        let again = try #require(model.main)
        let folder = URL(fileURLWithPath: file("saving-lock-all")).deletingLastPathComponent()
        let manager = FileManager.default
        try manager.setAttributes([.posixPermissions: 0o555], ofItemAtPath: folder.path)
        defer { try? manager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: folder.path) }
        try add(again.session, id, "Demo Shop 2")
        again.afterChange(select: nil)
        model.lockAll(asks: true)  // the save runs off the main thread (LD-228 (1))
        for _ in 0..<400 where again.dialog == nil { try await Task.sleep(for: .milliseconds(25)) }
        #expect(again.dialog == .closeUnsaved(changes: 1), "the save failed: it asks")
        #expect(model.vaults.contains { $0.id == id && !$0.locked }, "and the lock waits")
        again.dialog = nil
        model.lockAll()
        #expect(model.vaults.allSatisfy { $0.locked }, "an automatic lock never waits")
    }

    @Test("APP-05.3 T06: S-FILE-01 turned off while the vault is open stops the save after each change; on, it saves")
    func autosaveReadsTheSettingLive() async throws {
        let model = try ParityDemo.window("saving-live-setting")
        let main = try #require(model.main)
        let path = file("saving-live-setting")
        try setSaving(model.session, autosave: false, onLock: false)
        try add(main.session, main.vault.id, "Demo Shop")
        main.afterChange(select: nil)
        try await Task.sleep(for: .milliseconds(600))
        let off = try onDisk(path)
        #expect(main.saveStatus?.changes == 1 && !off.contains("Demo Shop"), "off: not saved")
        try setSaving(model.session, autosave: true, onLock: true)
        try add(main.session, main.vault.id, "Demo Shop 2")
        main.afterChange(select: nil)
        for _ in 0..<200 where main.saveStatus?.changes != 0 { try await Task.sleep(for: .milliseconds(25)) }
        #expect(try onDisk(path).isSuperset(of: ["Demo Shop", "Demo Shop 2"]), "on: saved")
        model.lockAll()
    }

    @Test("Parity dialogs-save-failed: a failed save asks; Close keeps the changes; Try Again and Save As… save")
    func saveFailed() async throws {
        let model = try ParityDemo.window("parity-saving-failed")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        let folder = URL(fileURLWithPath: file("parity-saving-failed")).deletingLastPathComponent()
        let manager = FileManager.default
        try manager.setAttributes([.posixPermissions: 0o555], ofItemAtPath: folder.path)
        defer { try? manager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: folder.path) }
        try add(main.session, main.vault.id, "Demo Shop")
        main.afterChange(select: nil)
        try await screen.wait { main.dialog != nil }
        #expect(main.dialog == .saveFailed(reason: "This vault's file or its folder cannot be written."))
        await screen.settle()
        #expect(screen.strings().contains("Larsal could not save “Personal”"))
        try await screen.press("Close")
        #expect(main.dialog == nil && main.saveStatus?.changes == 1, "changes kept")
        model.lock(main.vault.id)  // ⌘L: unsaved changes save or ask first
        try await screen.wait { main.dialog != nil }
        #expect(main.dialog == .closeUnsaved(changes: 1), "the save on lock failed: it asks")
        await screen.settle()
        try await screen.press("Cancel")
        try manager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: folder.path)
        main.dialog = .saveFailed(reason: "This vault's file or its folder cannot be written.")
        await screen.settle()
        try await screen.press("Try Again")
        try await screen.wait { main.saveStatus?.changes == 0 }
        #expect(main.dialog == nil && main.saveStatus?.failure == nil)
        // Save As…: the panel is a fake (never on screen, rule 10).
        let target = folder.appending(path: "Copy.larsalvault")
        try? manager.removeItem(at: target)
        let panel = VaultModel.saveAsPanel
        VaultModel.saveAsPanel = { _ in target }
        defer { VaultModel.saveAsPanel = panel }
        main.dialog = .saveFailed(reason: "The disk is read-only.")
        await screen.settle()
        try await screen.press("Save As…")
        _ = await main.saving?.value
        #expect(manager.fileExists(atPath: target.path(percentEncoded: false)))
        #expect(main.fileName == "Copy.larsalvault")
        model.lockAll()
    }
}

/// APP-02.16 (LD-217): what an automatic lock cannot save goes to a recovery copy.
extension ParitySavingTests {
    @Test("APP-02.16 T56, APP-05.28 T60: an automatic lock meeting a changed file keeps the change in a recovery copy")
    func automaticLockWritesARecoveryCopy() async throws {
        let model = try ParityDemo.window("saving-recovery")
        let main = try #require(model.main)
        let path = file("saving-recovery")
        let settings = (path as NSString).deletingLastPathComponent + "/settings"
        try? FileManager.default.removeItem(atPath: settings)
        defer { try? FileManager.default.removeItem(atPath: settings) }
        model.session.settings().useFolder(folder: settings)
        try setSaving(model.session, autosave: false, onLock: true)
        try add(main.session, main.vault.id, "Demo Shop")
        main.afterChange(select: nil)
        try otherWriter(path, adds: "Demo Bank 2")
        model.lockAll()  // as LockSignals does on sleep, screen lock or idle
        #expect(model.vaults.allSatisfy { $0.locked })
        #expect(try !onDisk(path).contains("Demo Shop"), "the changed file is not overwritten")
        let copies = try FileManager.default.contentsOfDirectory(atPath: settings + "/recovery")
        #expect(copies.count == 1)
        #expect(try onDisk(settings + "/recovery/" + (copies.first ?? "")).contains("Demo Shop"), "the change is kept")
    }
}
