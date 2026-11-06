import AppKit
import LarsalCore
import SwiftUI
import Testing

// E11-S5: the share flows through W-15's screens, their models and a real
// session (ShareSnapshotTests.swift has the demo). Demo vaults only; every
// copy goes to the session's private pasteboard (LD-206), and no window is
// ever shown (AGENTS.md rule 10).

@MainActor
@Suite(.serialized)
struct ShareFlowTests {
    init() { ParityDemo.setUp() }

    @Test("INT-08.21, INT-08.31, INT-08.17, INT-08.15: a share made here exports at the save; another vault imports it")
    func makeExportImport() async throws {
        let window = try ShareDemo.window("share-flow", household: false, allow: true)
        let main = try #require(window.main)
        let session = window.session
        let home = try ShareDemo.group(main, "Household")
        main.choose(.group(home))
        #expect(main.sharing.label == nil && main.sharing.marks[home] == nil, "no share yet")
        main.editGroup(home)
        let editor = try #require(main.sharing.editor)
        #expect(editor.view.mode == .inactive && !editor.view.item && editor.view.keepGroups)
        editor.change(.mode(mode: .export))
        editor.change(.path(path: "household.larsalvault"))
        editor.typed("M2ciPK%tX7UctF=AQMGf")
        #expect(editor.view.warning == nil && !editor.view.weak && editor.shown == nil)
        main.saveGroup()
        #expect(main.sharing.marks[home] == true, "INT-08.31: approved by the editor, so active")
        #expect(main.sharing.label?.state == .running && main.sharing.label?.mode == .export)
        let container = ParityDemo.root.appending(path: "target/option-a/share-flow/household.larsalvault")
            .path(percentEncoded: false)
        try? FileManager.default.removeItem(atPath: container)  // a run before this one
        await main.saveNow()
        try await ShareDemo.until { FileManager.default.fileExists(atPath: container) }
        #expect(FileManager.default.fileExists(atPath: container), "INT-08.17: the save exported")
        // The second demo vault: Work, a group of its own imports the file.
        let work = try #require(window.vaults.first { $0.name == "Work" }?.id)
        #expect(try session.unlock(vault: work, password: "demo-pass-8", keyFile: nil) == .unlocked)
        try session.switchTo(vault: work)
        window.refresh()
        let second = try #require(window.main)
        #expect(second.vault.id == work)
        second.addGroup(name: "From home", parent: nil, glyph: "house-line", colour: "purple")
        let target = try ShareDemo.group(second, "From home")
        second.editGroup(target)
        let importer = try #require(second.sharing.editor)
        importer.change(.mode(mode: .import))
        importer.change(.path(path: container))
        importer.typed("M2ciPK%tX7UctF=AQMGf")
        second.saveGroup()
        let titles = {
            try session.list(vault: work, view: .group(id: target)).rows.map(\.title).sorted()
        }
        let all = ["Alarm system", "Electricity", "Netflix", "Spotify Family"]  // Keep group structure: Streaming too
        try await ShareDemo.until { try titles() == all }
        let imported = try titles()
        #expect(imported == all, "INT-08.15: the import ran at once")
        #expect(
            try ShareDemo.real(session.sharePaths(vault: work)) == ShareDemo.real([container]), "INT-08.15: one watch")
        window.lockAll()
        PasteboardProof.expectOnlyPrivate(session, copied: false)
    }

    @Test("LD-304 (5): a share the disk merge brings is not watched or exported before Approve; the next save writes")
    func approveMerged() async throws {
        let window = try ShareDemo.window("share-merge", household: false, allow: true)
        let main = try #require(window.main)
        let session = window.session
        let home = try ShareDemo.group(main, "Household")
        await main.saveNow()
        // A change here, not saved, then the file changes on disk: another
        // session sets Household up as a share.
        _ = try session.addGroup(vault: main.vault.id, parent: nil, name: "Local", icon: 48, customIcon: nil)
        let file = ParityDemo.root.appending(path: "target/option-a/share-merge/Personal.larsalvault").path(
            percentEncoded: false)
        let container = ParityDemo.root.appending(path: "target/option-a/share-merge/merged.larsalvault")
            .path(percentEncoded: false)
        try? FileManager.default.removeItem(atPath: container)
        try ShareDemo.elsewhere(file, group: "Household", mode: .synchronize, path: "merged.larsalvault")
        main.checkDisk()
        try await ShareDemo.until {
            if case .changedOnDisk = main.dialog { return true }
            return false
        }
        guard case .changedOnDisk(let ask, _) = main.dialog else {
            let event = try? session.checkDisk(vault: main.vault.id)
            Issue.record(
                "APP-05.27: the merge question, got \(String(describing: main.dialog)), \(String(describing: event))")
            return
        }
        main.resolveDisk(.merge, ask: ask)
        await main.saving?.value
        main.choose(.group(home))
        let label = try #require(main.sharing.label)
        #expect(label.state == .waiting, "MI08-18")
        #expect(main.sharing.marks[home] == false, "LD-270 (3): the inactive badge")
        #expect(try main.session.sidebar(vault: main.vault.id).groups.contains { $0.name == "Local" }, "merged")
        #expect(try session.sharePaths(vault: main.vault.id).isEmpty, "not watched before Approve")
        await main.saveNow()
        try await Task.sleep(for: .milliseconds(300))
        #expect(!FileManager.default.fileExists(atPath: container), "not exported before Approve")
        try await Self.approve(window)
        #expect(main.sharing.label?.state == .running && main.sharing.marks[home] == true)
        #expect(
            try ShareDemo.real(session.sharePaths(vault: main.vault.id)) == ShareDemo.real([container]),
            "watched after Approve")
        _ = try session.addGroup(vault: main.vault.id, parent: home, name: "After", icon: 48, customIcon: nil)
        await main.saveNow()
        try await ShareDemo.until { FileManager.default.fileExists(atPath: container) }
        #expect(FileManager.default.fileExists(atPath: container), "the save after Approve wrote the container")
        window.lockAll()
    }

    @Test("APP-10, INT-08.39: the share password field is secure while focused; Show fills the no-copy field only")
    func secureInput() async throws {
        let window = try ShareDemo.window("share-secure")
        let main = try #require(window.main)
        main.editGroup(try ShareDemo.group(main, "Household"))
        let editor = try #require(main.sharing.editor)
        let screen = Screen(window)
        await screen.settle()
        let fields = Self.views(screen.host).compactMap { $0 as? NSTextField }
        let masked = try #require(fields.first { $0.accessibilityLabel() == "Share password" })
        #expect(masked is NSSecureTextField, "AppKit's secure input while it has the focus (APP-10)")
        #expect(editor.shown == nil && editor.view.passwordChars == 16, "Swift holds the length only")
        try await screen.press("Show password")
        #expect(editor.shown == ShareDemo.password, "the Show the user asked for (rule 4)")
        try await screen.press("Hide password")
        #expect(editor.shown == nil, "Hide drops it")
        editor.toggleShow()
        main.leave()
        #expect(editor.shown == nil, "leaving the screen drops it")
        main.enter()
        main.cancelGroup()
        window.lockAll()
    }

    @Test("F-196, APP-08.14, APP-10.9: ⌃H shows and hides the share password; ⌃G opens the generator (FEA-02)")
    func passwordKeys() async throws {
        let window = try ShareDemo.window("share-keys")
        let main = try #require(window.main)
        main.editGroup(try ShareDemo.group(main, "Household"))
        let editor = try #require(main.sharing.editor)
        let screen = Screen(window)
        await screen.settle()
        #expect(try MenuKeysTests.controlKey("h", 4, screen), "⌃H is handled")
        #expect(editor.shown == ShareDemo.password, "Show")
        await screen.settle()
        #expect(try MenuKeysTests.controlKey("h", 4, screen))
        #expect(editor.shown == nil, "Hide")
        await screen.settle()
        #expect(try MenuKeysTests.controlKey("g", 5, screen), "⌃G is handled")
        #expect(main.generator?.fromEditor == true, "the generator for the share password")
        window.lockAll()
    }

    @Test(
        "Parity w-15-sharing-sync: Type, Keep group structure, Clear and Cancel work; FEA-02 fills the share password")
    func controls() async throws {
        let window = try ShareDemo.window("share-controls")
        let main = try #require(window.main)
        let home = try ShareDemo.group(main, "Household")
        main.editGroup(home)
        let editor = try #require(main.sharing.editor)
        let screen = Screen(window)
        await screen.settle()
        #expect(editor.view.warning == .bothOff, "MI08-14 with the defaults")
        #expect(screen.strings().contains { $0.contains("Sharing is turned off.") })
        try await screen.press("Import")
        #expect(editor.view.mode == .import)
        try await screen.press("Keep group structure")
        #expect(!editor.view.keepGroups)
        try await screen.press("Open generator (⌥⌘G)")
        let generator = try #require(main.generator)
        await generator.settled()
        main.useGenerated()
        try await ShareDemo.until { main.overlay == nil }
        #expect(editor.view.passwordChars == generator.options.length, "FEA-02: the generator's value")
        try await screen.press("Clear")
        #expect(!editor.view.item && editor.view.mode == .inactive)
        try await screen.press("Cancel")
        #expect(main.sharing.editor == nil)
        #expect(try main.session.shareEdit(vault: main.vault.id, group: home).mode == .synchronize, "Cancel kept it")
        try main.session.shareEditCancel(vault: main.vault.id)
        window.lockAll()
    }

    @Test("F-176, INT-08.24, INT-08.15: Allow import reaches the badge, the label and the watch at once")
    func allowChanges() async throws {
        let window = try ShareDemo.window("share-allow", allow: true)
        let main = try #require(window.main)
        let home = try ShareDemo.group(main, "Household")
        main.choose(.group(home))
        try await ShareDemo.until { !main.disk.shareWatches.isEmpty }
        #expect(main.sharing.marks[home] == true && main.sharing.label?.importOff == false)
        #expect(!main.disk.shareWatches.isEmpty, "Synchronize imports, so it is watched")
        try ShareDemo.flags(window.session, false)
        window.refresh()  // what AppDelegate.settingsApplied does after OK
        try await ShareDemo.until { main.disk.shareWatches.isEmpty }
        #expect(main.sharing.marks[home] == false, "Share inactive")
        #expect(main.sharing.label?.importOff == true && main.sharing.label?.exportOff == true, "MI08-16, MI08-15")
        #expect(main.disk.shareWatches.isEmpty, "no watch with import off")
        try ShareDemo.flags(window.session, true)
        window.refresh()
        try await ShareDemo.until { !main.disk.shareWatches.isEmpty }
        #expect(main.sharing.marks[home] == true && !main.disk.shareWatches.isEmpty, "on again at once")
        let code = try #require(try ScreenProtectionTests.sources().first { $0.file == "AppDelegate.swift" }?.code)
        let applied = code.components(separatedBy: "func settingsApplied").dropFirst().first ?? ""
        #expect((applied.components(separatedBy: "\n    }").first ?? "").contains("window.refresh()"))
        window.lockAll()
    }

    @Test("F-174, APP-08.12: the Entry menu waits under the group editor; Use password fills the editor over it")
    func entryMenuWaits() async throws {
        let window = try ShareDemo.window("share-menus")
        let main = try #require(window.main)
        let session = window.session
        main.editGroup(try ShareDemo.group(main, "Household"))
        #expect(MenuState(window: window).list == nil, "the Sharing page covers the list")
        let entry = await MenuLine.read(EntryMenuItems(window: window))
        for title in ["New Entry", "Edit Entry", "Clone Entry…", "Delete Entry"] {
            #expect(entry.line(title)?.enabled == false, "\(title)")
        }
        #expect(await MenuLine.read(GroupMenuItems(window: window)).line("Edit Group…")?.enabled == false)
        // An entry editor over the Sharing page opened the generator: its
        // value goes to the entry, never to the hidden share password.
        main.newEntry()
        main.openGenerator(fromEditor: true)
        let generator = try #require(main.generator)
        await generator.settled()
        main.useGenerated()
        try await ShareDemo.until { main.overlay == nil }
        #expect(try session.shareEditShow(vault: main.vault.id) == ShareDemo.password, "the share password stays")
        #expect(try !session.draftPassword(vault: main.vault.id).isEmpty, "the entry's draft takes the value")
        window.lockAll()
    }

    @Test("F-178, APP-08.7: Edit Group… is on for All entries and opens the root group's Sharing page")
    func editRoot() async throws {
        guard #available(macOS 14.4, *) else { return }
        let window = try ShareDemo.window("share-root")
        let main = try #require(window.main)
        main.choose(.all)
        let title = "Edit Group…"
        #expect(await MenuLine.read(GroupMenuItems(window: window)).line(title)?.enabled == true)
        let native = NSHostingMenu(rootView: GroupMenuItems(window: window))
        native.update()
        try await Task.sleep(for: .milliseconds(30))
        native.update()
        native.performActionForItem(at: native.indexOfItem(withTitle: title))
        let editor = try #require(main.sharing.editor)
        let root = try #require(main.sidebar?.root)
        #expect(try window.session.shareEdit(vault: main.vault.id, group: root).name == editor.view.name)
        #expect(main.sharing.label == nil, "INT-08.24: a root share shows no label")
        main.cancelGroup()
        window.lockAll()
    }

    /// Approve, as the label's action and the sheet's default button do.
    static func approve(_ window: MainWindowModel) async throws {
        let main = try #require(window.main)
        let screen = Screen(window)
        await screen.settle()
        #expect(screen.strings().contains { $0.hasPrefix("Sharing is paused for this group") })
        try await screen.press("Approve")
        guard case .approveShare(let asked) = main.dialog else {
            Issue.record("the Approve sheet, got \(String(describing: main.dialog))")
            return
        }
        main.approveShare(asked)
    }

    static func views(_ root: NSView) -> [NSView] { [root] + root.subviews.flatMap(views) }
}

// LD-310 (7): the disk check and the group editor (SwiftLint type_body_length).
extension ShareFlowTests {
    @Test(
        "LD-310 (7), APP-05.25: a change on disk waits while the group editor is open; Cancel or Save lets it ask",
        arguments: [false, true])
    func diskWaitsForTheGroupEditor(save: Bool) async throws {
        let name = save ? "share-disk-wait-save" : "share-disk-wait"
        let window = try ShareDemo.window(name, household: false)
        let main = try #require(window.main)
        let session = window.session
        // F-249: the test's own checkDisk() is the only event, and no save asks.
        main.disk.watch = nil
        main.autosave = false
        let home = try ShareDemo.group(main, "Household")
        await main.saveNow()
        // A change here, not saved, so the change on disk asks (APP-05.27).
        _ = try session.addGroup(vault: main.vault.id, parent: nil, name: "Local", icon: 48, customIcon: nil)
        main.editGroup(home)
        #expect(main.sharing.editor != nil)
        let file = ParityDemo.root.appending(path: "target/option-a/\(name)/Personal.larsalvault").path(
            percentEncoded: false)
        try ShareDemo.elsewhere(file, group: "Household", mode: .export, path: "elsewhere.larsalvault")
        main.checkDisk()
        #expect(main.disk.pending && main.disk.pendingEvent, "the watch event waits for the group editor")
        try await Task.sleep(for: .milliseconds(300))
        #expect(main.dialog == nil, "no question over the group editor")
        if save { main.saveGroup() } else { main.cancelGroup() }
        try await ShareDemo.until {
            if case .changedOnDisk = main.dialog { return true }
            return false
        }
        guard case .changedOnDisk(let ask, _) = main.dialog else {
            Issue.record("APP-05.25: the question after Cancel or Save, got \(String(describing: main.dialog))")
            return
        }
        #expect(!main.disk.pending)
        main.resolveDisk(.merge, ask: ask)
        await main.saving?.value
        window.lockAll()
    }
}

// LD-310 (7): conflict copies and the group editor (SwiftLint type_body_length).
extension ShareFlowTests {
    @Test("LD-310 (7), APP-05.17, APP-05.25: conflict copies are not merged while the group editor is open")
    func copiesWaitForTheGroupEditor() async throws {
        let name = "share-copies-wait"
        let window = try ShareDemo.window(name, household: false)
        let main = try #require(window.main)
        main.disk.watch = nil
        main.autosave = false
        let home = try ShareDemo.group(main, "Household")
        await main.saveNow()
        try await ShareDemo.until { !main.disk.finding }
        let file = ParityDemo.root.appending(path: "target/option-a/\(name)/Personal.larsalvault").path(
            percentEncoded: false)
        let copy = (file as NSString).deletingLastPathComponent + "/Personal-DemoMac.larsalvault"
        try? FileManager.default.removeItem(atPath: copy)
        try FileManager.default.copyItem(atPath: file, toPath: copy)
        defer { try? FileManager.default.removeItem(atPath: copy) }
        // Another Mac's save of the copy (APP-05.17), its own backup off.
        let other = Session()
        try other.saveSettings(changes: [LarsalSetting(key: "backup.enabled", value: .flag(on: false))])
        let id = try other.open(path: copy)
        #expect(try other.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        _ = try other.addGroup(vault: id, parent: nil, name: "From the copy", icon: 48, customIcon: nil)
        _ = try other.save(vault: id)
        try other.close(vault: id)
        main.editGroup(home)
        #expect(main.sharing.editor != nil)
        main.findCopies()
        try await ShareDemo.until { !main.disk.finding }
        try await Task.sleep(for: .milliseconds(300))
        let groups = try window.session.sidebar(vault: main.vault.id).groups.map(\.name)
        #expect(!groups.contains("From the copy"), "APP-05.17: merged while the group editor was open")
        #expect(main.dialog == nil, "no copies sheet over the group editor")
        main.cancelGroup()
        window.lockAll()
    }
}

// LD-310 (7): a disk check already running when the group editor opens.
extension ShareFlowTests {
    @Test("LD-310 (7), APP-05.25: a check that started before the group editor opened waits for it too")
    func checkInFlightWaitsForTheGroupEditor() async throws {
        let name = "share-disk-in-flight-" + UUID().uuidString
        let window = try ShareDemo.window(name, household: false)
        let main = try #require(window.main)
        let session = window.session
        main.disk.watch = nil
        main.autosave = false
        let home = try ShareDemo.group(main, "Household")
        await main.saveNow()
        _ = try session.addGroup(vault: main.vault.id, parent: nil, name: "Local", icon: 48, customIcon: nil)
        let file = ParityDemo.root.appending(path: "target/option-a/\(name)/Personal.larsalvault").path(
            percentEncoded: false)
        try ShareDemo.elsewhere(file, group: "Household", mode: .export, path: "elsewhere.larsalvault")
        main.checkDisk()
        main.editGroup(home)  // before the check's read runs
        #expect(main.sharing.editor != nil)
        try await ShareDemo.until { !main.disk.checking }
        try await Task.sleep(for: .milliseconds(300))
        #expect(main.dialog == nil, "no question over the group editor")
        #expect(main.disk.pending, "the event waits for the group editor")
        main.cancelGroup()
        try await ShareDemo.until {
            if case .changedOnDisk = main.dialog { return true }
            return false
        }
        guard case .changedOnDisk(let ask, _) = main.dialog else {
            Issue.record("APP-05.25: the question after Cancel, got \(String(describing: main.dialog))")
            return
        }
        main.resolveDisk(.merge, ask: ask)
        await main.saving?.value
        window.lockAll()
    }
}
