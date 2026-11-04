import AppCore
import AppKit
import Darwin
import Foundation
import SwiftUI
import Testing
import os

/// E15-S3 (APP-05.24, APP-05.30; spec/research/sync-server.md P18 (1),
/// (2)): coordinated reads and writes of the vault file, off the main
/// thread, and "Still downloading". Demo vaults only, copied to target/;
/// every window offscreen (AGENTS.md rule 10). A dataless file comes from
/// a test seam (real clouds: E15-S5).
extension ParitySavingTests {
    /// Waits up to 10 s for `done`.
    private func until(_ done: () -> Bool) async throws {
        for _ in 0..<400 where !done() { try await Task.sleep(for: .milliseconds(25)) }
    }

    /// The vault file as FileAccess names it: links resolved.
    private func resolved(_ path: String) -> String {
        URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    }

    /// A copy of the vault at `path` with `title` added by another writer,
    /// made in a folder of its own.
    private func sideCopy(_ path: String, adds title: String) throws -> String {
        let side = FileManager.default.temporaryDirectory.appending(path: "app-file-access-side-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: side, withIntermediateDirectories: true)
        let copy = side.appending(path: "Personal.appvault").path(percentEncoded: false)
        try FileManager.default.copyItem(atPath: path, toPath: copy)
        try otherWriter(copy, adds: title)
        return copy
    }

    /// T72 (P18 (1)): the presenter is told of App's unlock read and its
    /// replacing save; App's reload waits for the other process's
    /// coordinated write and sees it whole.
    @Test("APP-05.24 T72: a presenter in another process sees App's access; App sees its write whole")
    func t72PresenterInAnotherProcess() async throws {
        let folder = "file-access-presenter"
        let model = try ParityDemo.window(folder, unlocked: [])
        let unlock = try #require(model.unlock)
        let path = file(folder)
        let other = try await OtherProcess(presenting: resolved(path))
        defer { other.stop() }
        unlock.password = "demo-pass-7"
        unlock.unlock()
        try await until { model.main != nil && other.said("read") }
        let main = try #require(model.main)
        main.autosave = false
        #expect(other.said("read"), "told of the unlock read")
        try add(main.session, main.vault.id, "Demo Note")
        main.afterChange(select: nil)
        #expect(await main.saveNow()?.changes == 0)
        try await until { other.said("write") && other.said("changed") }
        #expect(other.said("write"), "asked to give way to App's replacing write")
        #expect(other.said("changed"), "told the file changed")
        // The other process writes half of a new version, waits 2 s inside
        // its coordinated write, then writes the rest.
        let side = try sideCopy(path, adds: "Demo Shop")
        defer { try? FileManager.default.removeItem(atPath: (side as NSString).deletingLastPathComponent) }
        other.send("write " + side)
        try await until { other.said("writing") }
        main.checkDisk()
        var unreadable = false
        for _ in 0..<400 where !titles(main).contains("Demo Shop") {
            unreadable = unreadable || main.toast?.text.hasPrefix("App could not read") == true
            try await Task.sleep(for: .milliseconds(25))
        }
        #expect(titles(main).isSuperset(of: ["Demo Shop", "Demo Note"]), "the reload saw the other process's write")
        #expect(!unreadable, "the reload waited for the write: it never read half a file")
        #expect(other.said("wrote"))
        model.lockAll()
    }

    @Test("APP-05.24 T72: unlock, reload and save do their file I/O coordinated, never on the main thread")
    func t72NoFileCallOnTheMainThread() async throws {
        let folder = "file-access-threads"
        FileAccess.accesses.withLock { $0 = [] }
        defer { FileAccess.accesses.withLock { $0 = nil } }
        let model = try ParityDemo.window(folder, unlocked: [])
        let unlock = try #require(model.unlock)
        let path = file(folder)
        try await oneAccess(.read, folder, "the unlock screen's header check") {}
        // APP-06.14: Unlock on the KDF cost question runs the attempt again.
        try await oneAccess(.read, folder, "the KDF cost question's Unlock") { unlock.answer(unlock: true) }
        try await until { !unlock.working }
        try await oneAccess(.read, folder, "the unlock") {
            unlock.password = "demo-pass-7"
            unlock.unlock()
            try await until { model.main != nil }
        }
        let main = try #require(model.main)
        main.autosave = false
        main.disk.watch = nil
        let reads = accessCount(.read, folder)
        try otherWriter(path, adds: "Demo Shop")
        main.checkDisk()
        try await until { titles(main).contains("Demo Shop") }
        #expect(titles(main).contains("Demo Shop"), "reloaded")
        #expect(accessCount(.read, folder) > reads, "the reload")
        try await oneAccess(.replace, folder, "the save") {
            try add(main.session, main.vault.id, "Demo Note")
            main.afterChange(select: nil)
            #expect(await main.saveNow()?.changes == 0)
        }
        let seen = FileAccess.accesses.withLock { $0 ?? [] }
        #expect(seen.allSatisfy { !$0.main }, "no file call on the main thread: \(seen)")
        model.lockAll()
    }

    /// T73: once the file is whole, the waiting change is handled.
    @Test("APP-05.30 T73: a watch event on a dataless file shows Still downloading, never blocks the window")
    func t73DatalessEventShowsStillDownloading() async throws {
        let folder = "file-access-dataless"
        let model = try ParityDemo.window(folder)
        let main = try #require(model.main)
        main.autosave = false
        main.disk.watch = nil
        let screen = Screen(model)
        await screen.settle()
        try otherWriter(file(folder), adds: "Demo Shop")
        let files = FakeFiles(folder)
        defer { files.remove() }
        main.checkDisk()
        try await until { main.downloading && files.state.withLock { $0.downloads } > 0 }
        await screen.settle()
        let words = "Still downloading. “Personal.appvault” is not on this Mac yet."
        #expect(screen.strings().contains { $0.hasPrefix(words) })
        #expect(files.state.withLock { $0.downloads } == 1, "the download was started")
        // The window works meanwhile; nothing is read and nothing changes.
        main.choose(.favorites)
        #expect(main.title == "Favorites")
        main.checkDisk()
        #expect(main.disk.pending, "a second event waits for the download (APP-05.25)")
        try await Task.sleep(for: .seconds(1))
        #expect(main.downloading && !titles(main).contains("Demo Shop") && main.saveStatus?.changes ?? 0 == 0)
        files.state.withLock { $0.dataless = false }
        try await until { titles(main).contains("Demo Shop") }
        #expect(titles(main).contains("Demo Shop"), "handled once the file is on this Mac")
        #expect(!main.downloading)
        #expect(files.state.withLock { !$0.onMain }, "no file call on the main thread")
        model.lockAll()
    }

    @Test("APP-05.30 T73: unlock of a dataless file shows Still downloading, goes on once it is whole")
    func t73DatalessUnlockWaits() async throws {
        let folder = "file-access-dataless-unlock"
        let files = FakeFiles(folder)
        defer { files.remove() }
        let model = try ParityDemo.window(folder, unlocked: [])
        let unlock = try #require(model.unlock)
        let screen = Screen(model)
        try await until { unlock.downloading && files.state.withLock { $0.downloads } > 0 }
        await screen.settle()
        #expect(screen.strings().contains("Still downloading. “Personal.appvault” opens when the download ends."))
        #expect(files.state.withLock { $0.downloads } == 1, "the unlock screen started the download")
        unlock.password = "demo-pass-7"
        unlock.unlock()
        try await Task.sleep(for: .seconds(1))
        #expect(model.main == nil && unlock.working, "the unlock waits for the file")
        files.state.withLock { $0.dataless = false }
        try await until { model.main != nil }
        #expect(model.main?.vault.name == "Personal", "unlocked once the file is on this Mac")
        #expect(files.state.withLock { !$0.onMain }, "no file call on the main thread")
        model.lockAll()
    }

    /// T73: a dataless file, or one that turns dataless between the test
    /// and the read (`EDEADLK`), is no change: no message, no download.
    @Test("APP-05.24 T73: a 30-second tick never fetches; dataless and EDEADLK count as no change")
    func t73TicksNeverFetch() async throws {
        let folder = "file-access-ticks"
        let model = try ParityDemo.window(folder)
        let main = try #require(model.main)
        main.autosave = false
        main.disk.watch = nil
        try otherWriter(file(folder), adds: "Demo Shop")
        let files = FakeFiles(folder)
        defer { files.remove() }
        let quiet = {
            !main.downloading && main.toast == nil && main.dialog == nil && !titles(main).contains("Demo Shop")
                && files.state.withLock { $0.downloads } == 0
        }
        main.checkDisk(tick: true)
        try await until { !main.disk.checking }
        #expect(quiet(), "dataless: no change, no message, no download")
        // A tick that waits behind a sheet runs as a tick once it closes.
        main.dialog = .saveFailed(reason: "Demo reason.")
        main.checkDisk(tick: true)
        #expect(main.disk.pending)
        main.dialog = nil
        try await until { !main.disk.checking }
        #expect(quiet(), "the waiting tick ran as a tick: no download")
        files.state.withLock {
            $0.dataless = false
            $0.probe = EDEADLK
        }
        main.checkDisk(tick: true)
        try await until { !main.disk.checking }
        #expect(quiet(), "EDEADLK: no change")
        let policy = files.state.withLock { $0.policy }
        #expect(policy == IOPOL_MATERIALIZE_DATALESS_FILES_OFF, "fetching off on the tick's thread")
        // Nothing was noted: the next watch event still finds the change.
        files.state.withLock { $0.probe = 0 }
        main.checkDisk()
        try await until { titles(main).contains("Demo Shop") }
        #expect(titles(main).contains("Demo Shop"))
        #expect(files.state.withLock { $0.downloads } == 0)
        model.lockAll()
    }

    @Test("APP-05.24: the disk watch tells its tick from a file event")
    func watchTellsTickFromEvent() async throws {
        let folder = FileManager.default.temporaryDirectory.appending(path: "app-watch-tick-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appending(path: "Personal.appvault")
        try Data("demo".utf8).write(to: file)
        let looks = OSAllocatedUnfairLock(initialState: [Bool]())
        let watch = DiskWatch(path: file.path(percentEncoded: false), tick: .milliseconds(400)) { tick in
            looks.withLock { $0.append(tick) }
        }
        try await Task.sleep(for: .milliseconds(200))  // armed, before the first tick
        try Data("demo 2".utf8).write(to: file)
        try await until { Set(looks.withLock { $0 }) == [true, false] }
        #expect(looks.withLock { $0.contains(false) }, "the file event")
        #expect(looks.withLock { $0.contains(true) }, "the tick")
        withExtendedLifetime(watch) {}
    }

    @Test("F-101, APP-05.24: a FIFO at the vault's path never holds App's coordinated file access")
    func fifoNeverHoldsTheCoordinator() async throws {
        let folder = FileManager.default.temporaryDirectory.appending(path: "app-coordinate-fifo-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let fifo = folder.appending(path: "Personal.appvault").path(percentEncoded: false)
        let other = folder.appending(path: "Work.appvault")
        #expect(mkfifo(fifo, 0o600) == 0)
        try Data("demo".utf8).write(to: other)
        let ran = OSAllocatedUnfairLock(initialState: 0)
        FileAccess.coordinate(.read, fifo) { ran.withLock { $0 += 1 } }
        FileAccess.coordinate(.replace, other.path(percentEncoded: false)) { ran.withLock { $0 += 1 } }
        try await until { ran.withLock { $0 } == 2 }
        let seen = ran.withLock { $0 }
        // A blocking open waits for a writer: this one frees it.
        let writer = open(fifo, O_RDWR | O_NONBLOCK)
        if writer >= 0 { close(writer) }
        #expect(seen == 2, "both ran: the FIFO held nothing")
    }

    /// Another process holds the file in a coordinated write.
    @Test("APP-02.16, APP-05.24: a lock whose save still waits for the file keeps a recovery copy")
    func lockKeepsACopyWhileTheFileIsHeld() async throws {
        let folder = "file-access-held"
        let model = try ParityDemo.window(folder)
        let main = try #require(model.main)
        main.autosave = false
        main.disk.watch = nil
        let settings = FileManager.default.temporaryDirectory.appending(path: "app-file-access-held-\(getpid())")
        try? FileManager.default.removeItem(at: settings)
        defer { try? FileManager.default.removeItem(at: settings) }
        model.session.settings().useFolder(folder: settings.path(percentEncoded: false))
        try setSaving(model.session, autosave: false, onLock: true)
        try add(main.session, main.vault.id, "Demo Held")
        let path = file(folder)
        let before = try Data(contentsOf: URL(fileURLWithPath: path))
        // Another program's coordinated write holds the file; it goes before
        // the folder does, also when the test fails.
        let release = try await hold(path)
        defer { release() }
        model.saveBeforeLock(within: .milliseconds(500))
        let copies = try FileManager.default.contentsOfDirectory(atPath: settings.path + "/recovery")
        #expect(copies.count == 1)
        #expect(try onDisk(settings.path + "/recovery/" + (copies.first ?? "")).contains("Demo Held"), "kept")
        release()
        try await Task.sleep(for: .seconds(1))
        #expect(try Data(contentsOf: URL(fileURLWithPath: path)) == before, "the late save never writes")
        model.lockAll()
    }

    @Test("APP-05.30 Mac QA: Still downloading on the vault and the unlock screen, offscreen, light and dark")
    func stillDownloadingShots() async throws {
        let shots = SnapshotTests()
        for (folder, name, locked) in [
            ("file-access-shot-vault", "states-still-downloading", false),
            ("file-access-shot-unlock", "lock-still-downloading", true),
        ] {
            let files = FakeFiles(folder)
            defer { files.remove() }
            let model = try ParityDemo.window(folder, unlocked: locked ? [] : [0])
            if let main = model.main {
                main.autosave = false
                main.disk.watch = nil
                main.checkDisk()
                try await until { main.downloading }
            } else {
                try await until { model.unlock?.downloading == true }
            }
            let size = NSRect(x: 0, y: 0, width: 1320, height: 820)
            let host = NSHostingView(rootView: MainWindow(model: model).frame(width: size.width, height: size.height))
            host.frame = size
            // Never ordered front (AGENTS.md rule 10); sRGB as the references.
            let offscreen = NSWindow(
                contentRect: size.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless], backing: .buffered,
                defer: false)
            offscreen.colorSpace = .sRGB
            offscreen.contentView = host
            for (look, appearance) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
                offscreen.appearance = NSAppearance(named: appearance)
                let png = try await shots.render(host)
                let out = ParityDemo.root.appending(path: "app-shots/\(look)/\(name).png")
                try FileManager.default.createDirectory(
                    at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
                try png.write(to: out)
                #expect(png.count > 10_000, "\(out.path)")
            }
            offscreen.contentView = nil
            model.lockAll()
        }
    }
}
