import AppCore
import Darwin
import Foundation
import Testing
import os

/// E15-S3 (APP-05.24, APP-05.30): the other roads to the vault file, each
/// coordinated and off the main thread: the key change's save, the save
/// before a quit, Save As, the header read of an open and of the launch;
/// and what a lock or a second open does while one waits. Demo vaults
/// only, copied to target/; every window offscreen (AGENTS.md rule 10).
extension ParitySavingTests {
    /// Waits up to 10 s for `done`.
    private func until(_ done: () -> Bool) async throws {
        for _ in 0..<400 where !done() { try await Task.sleep(for: .milliseconds(25)) }
    }

    /// Another program holds `path` in a coordinated write, as a file
    /// provider's fetch or a slow folder does, until the returned call. It
    /// gives up after 20 s, so a test that fails or hangs never leaves it
    /// held (and its folders behind).
    func hold(_ path: String) async throws -> @Sendable () -> Void {
        let (held, release) = (OSAllocatedUnfairLock(initialState: false), DispatchSemaphore(value: 0))
        let url = URL(fileURLWithPath: path).resolvingSymlinksInPath()
        DispatchQueue.global().async {
            NSFileCoordinator().coordinate(writingItemAt: url, options: .forReplacing, error: nil) { _ in
                held.withLock { $0 = true }
                _ = release.wait(timeout: .now() + 20)
            }
        }
        try await until { held.withLock { $0 } }
        return { release.signal() }
    }

    /// A locked vault's unlock, typed and started, waits for its dataless
    /// file; the attempt's lock state.
    private func waitingUnlock(_ model: MainWindowModel) async throws -> AttemptState {
        let unlock = try #require(model.unlock)
        try await until { unlock.downloading }
        unlock.password = "demo-pass-7"
        unlock.unlock()
        return try #require(unlock.attempt?.state)
    }

    typealias AttemptState = OSAllocatedUnfairLock<(stopped: Bool, typed: String?)>

    private func unlocked(_ model: MainWindowModel) -> [String] {
        model.session.vaults().filter { !$0.locked }.map(\.name)
    }

    /// A fresh settings folder in the temp folder, never App's own.
    private func settingsFolder(_ name: String) -> URL {
        let folder = FileManager.default.temporaryDirectory.appending(path: "app-file-access-\(name)-\(getpid())")
        try? FileManager.default.removeItem(at: folder)
        return folder
    }

    @Test("APP-05.24 T72: the key change's save, the quit's save and Save As are coordinated, off the main thread")
    func t72EverySaveIsCoordinated() async throws {
        let folder = "file-access-every-save"
        FileAccess.accesses.withLock { $0 = [] }
        defer { FileAccess.accesses.withLock { $0 = nil } }
        let model = try ParityDemo.window(folder)
        let main = try #require(model.main)
        main.autosave = false
        main.disk.watch = nil
        let copy = (file(folder) as NSString).deletingLastPathComponent + "/Copy.appvault"
        try? FileManager.default.removeItem(atPath: copy)
        defer { try? FileManager.default.removeItem(atPath: copy) }
        let settings = settingsFolder("every-save")
        defer { try? FileManager.default.removeItem(at: settings) }
        // MOD-13.9: the save after a new master key.
        try await oneAccess(.replace, folder, "the key change's save") {
            let prompt = KeyChangeModel(window: model, vault: main.vault, words: "Demo words.")
            prompt.changeNow()
            try #require(prompt.settings).changed()
        }
        // APP-02.15 step 8: the save before Lock Everything or a quit.
        model.session.settings().useFolder(folder: settings.path(percentEncoded: false))
        try setSaving(model.session, autosave: false, onLock: true)
        try await oneAccess(.replace, folder, "the save before a quit") {
            try add(main.session, main.vault.id, "Demo Lock")
            #expect(await model.saveAll(asks: true) {})
        }
        // APP-05.6 Save As: the panel is a fake (never on screen, rule 10).
        let panel = VaultModel.saveAsPanel
        VaultModel.saveAsPanel = { _ in URL(fileURLWithPath: copy) }
        defer { VaultModel.saveAsPanel = panel }
        try await oneAccess(.replace, folder, "Save As") {
            main.saveAs()
            _ = await main.saving?.value
        }
        #expect(FileManager.default.fileExists(atPath: copy))
        let seen = FileAccess.accesses.withLock { $0 ?? [] }
        #expect(seen.allSatisfy { !$0.main }, "no file call on the main thread: \(seen)")
        model.lockAll()
    }

    @Test("APP-05.24, APP-05.30 T73: an open reads the file coordinated, off the main thread, never fetching it")
    func t73DatalessOpen() async throws {
        let folder = "file-access-dataless-open"
        let path = try ParityDemo.path(0, folder: folder)
        let files = FakeFiles(folder)
        defer { files.remove() }
        FileAccess.accesses.withLock { $0 = [] }
        defer { FileAccess.accesses.withLock { $0 = nil } }
        let model = MainWindowModel(session: try ParityDemo.session())
        Task { await model.open(path) }
        try await until { model.unlock != nil }
        let unlock = try #require(model.unlock, "it opened at once, the file still dataless")
        let seen = FileAccess.accesses.withLock { $0 ?? [] }.filter {
            $0.path.hasSuffix("/\(folder)/Personal.appvault")
        }
        #expect(seen.map(\.kind) == [.tick], "one coordinated access, fetching off: \(seen)")
        #expect(seen.allSatisfy { !$0.main }, "off the main thread")
        let screen = Screen(model)
        try await until { unlock.downloading && files.state.withLock { $0.downloads } > 0 }
        await screen.settle()
        #expect(screen.strings().contains("Still downloading. “Personal.appvault” opens when the download ends."))
        #expect(files.state.withLock { $0.downloads } == 1, "the unlock screen started the download")
        files.state.withLock { $0.dataless = false }
        try await until { !unlock.downloading }
        #expect(!unlock.downloading && files.state.withLock { !$0.onMain })
        model.lockAll()
    }

    /// A changed vault whose file turned dataless (offline, say).
    @Test("APP-02.16, APP-05.30: a logout never waits for a dataless file; the user's quit shows Still downloading")
    func quitMeetsADatalessFile() async throws {
        let folder = "file-access-dataless-quit"
        let model = try ParityDemo.window(folder)
        let main = try #require(model.main)
        main.autosave = false
        main.disk.watch = nil
        let settings = settingsFolder("quit")
        defer { try? FileManager.default.removeItem(at: settings) }
        model.session.settings().useFolder(folder: settings.path(percentEncoded: false))
        try setSaving(model.session, autosave: false, onLock: true)
        try add(main.session, main.vault.id, "Demo Quit")
        let path = file(folder)
        let before = try Data(contentsOf: URL(fileURLWithPath: path))
        let files = FakeFiles(folder)
        defer { files.remove() }
        // A logout, restart, shut down or quit signal: a recovery copy at once.
        let done = OSAllocatedUnfairLock<Bool?>(initialState: nil)
        Task {
            let may = await model.saveAll(asks: false) {}
            done.withLock { $0 = may }
        }
        try await until { done.withLock { $0 } != nil }
        #expect(done.withLock { $0 } == true, "it never waited for the download")
        let copies = (try? FileManager.default.contentsOfDirectory(atPath: settings.path + "/recovery")) ?? []
        #expect(copies.count == 1)
        #expect(try onDisk(settings.path + "/recovery/" + (copies.first ?? "")).contains("Demo Quit"), "kept")
        #expect(try Data(contentsOf: URL(fileURLWithPath: path)) == before, "the file was not touched")
        #expect(files.state.withLock { $0.downloads } == 0)
        // The user's quit or Lock Everything waits, and says why.
        let quit = Task { await model.saveAll(asks: true) {} }
        try await until { main.downloading }
        #expect(main.downloading, "Still downloading on the vault")
        files.state.withLock { $0.dataless = false }
        #expect(await quit.value, "saved once the file is on this Mac")
        #expect(!main.downloading)
        #expect(try onDisk(path).contains("Demo Quit"))
        model.lockAll()
    }

    /// Checker 1's probe A, kept: the unlock waits for a dataless file, and
    /// another program holds the file, as a file provider's fetch does.
    @Test("APP-06.16, APP-06.5: a lock ends an unlock that waits for its file at once and wipes its password")
    func lockStopsAnUnlockThatWaits() async throws {
        let folder = "file-access-dataless-lock"
        let files = FakeFiles(folder)
        defer { files.remove() }
        let model = try ParityDemo.window(folder, unlocked: [])
        let state = try await waitingUnlock(model)
        let unlock = try #require(model.unlock)
        #expect(state.withLock { $0.typed } == "demo-pass-7", "the password waits in the attempt's lock")
        try await Task.sleep(for: .milliseconds(500))
        #expect(model.main == nil && unlock.working, "the unlock waits for the file")
        let release = try await hold(file(folder))
        defer { release() }
        model.lockAll()
        #expect(!unlock.working, "the attempt ended at the lock, the file still held")
        #expect(state.withLock { $0.stopped && $0.typed == nil }, "its password is wiped")
        #expect(unlock.downloading, "the header check still waits: Still downloading stays")
        try await Task.sleep(for: .seconds(1))
        #expect(!unlock.working, "still ended a second later")
        release()
        files.state.withLock { $0.dataless = false }
        try await until { !unlock.downloading }
        try await Task.sleep(for: .seconds(2))
        #expect(unlocked(model).isEmpty, "unlocked: \(unlocked(model))")
        #expect(unlock.message == nil, "no message")
        model.lockAll()
    }

    @Test("APP-06.16 (LD-285 (3)): closing a vault whose unlock waits for its file stops it and wipes its password")
    func closeStopsAnUnlockThatWaits() async throws {
        let folder = "file-access-dataless-close"
        let files = FakeFiles(folder)
        defer { files.remove() }
        let model = try ParityDemo.window(folder, unlocked: [])
        let state = try await waitingUnlock(model)
        let unlock = try #require(model.unlock)
        let id = unlock.vault.id
        model.close(id)
        #expect(state.withLock { $0.stopped && $0.typed == nil }, "its password is wiped at the close")
        #expect(!unlock.working, "the attempt ended")
        files.state.withLock { $0.dataless = false }
        try await Task.sleep(for: .seconds(1))
        #expect(!model.session.vaults().contains { $0.id == id }, "closed, never unlocked")
        model.lockAll()
    }

    /// F-145 (LD-280 (2)): the lock lands while Rust's unlock runs (AES-KDF
    /// 1,000,000 rounds); once that unlock ends the form is ready again.
    /// When Rust's unlock ended before the test saw it run (a loaded
    /// Mac), there is nothing to judge: no verdict.
    @Test("APP-06.16 F-145: a lock while Rust's unlock runs leaves the form ready once that unlock ends")
    func f145ALockWhileRustUnlocks() async throws {
        let place = ParityDemo.root.appending(path: "target/option-a/file-access-lock-during-unlock")
        try? FileManager.default.removeItem(at: place)
        try FileManager.default.createDirectory(at: place, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: place) }
        let path = place.appending(path: "Default.appvault")
        let demo = ParityDemo.root.appending(path: "testdata/default-time.appvault")
        try FileManager.default.copyItem(at: demo, to: path)
        let model = MainWindowModel(session: try ParityDemo.session())
        await model.open(path.path(percentEncoded: false))
        try await until { model.unlock != nil }
        let unlock = try #require(model.unlock)
        let id = unlock.vault.id
        let rust = { model.session.vaults().first { $0.id == id }?.unlocking == true }
        unlock.password = "demo-pass-3"
        unlock.unlock()
        for _ in 0..<2000 where !rust() && unlock.working { try await Task.sleep(for: .milliseconds(5)) }
        guard rust() else {
            model.lockAll()
            return
        }
        model.lockAll()
        try await until { !rust() }
        try await Task.sleep(for: .milliseconds(300))
        #expect(!unlock.working, "the form is ready again")
        #expect(model.session.vaults().first { $0.id == id }?.locked == true, "the lock won")
        model.lockAll()
    }

    /// Checker 1's probes B and D, kept.
    @Test("APP-05.30: an unlock that waits for its file goes on after a vault switch or a lock of another vault")
    func unlockGoesOnAfterASwitchOrAnotherLock() async throws {
        for (folder, lockWork) in [("file-access-wait-switch", false), ("file-access-wait-lock-work", true)] {
            let files = FakeFiles(folder)
            defer { files.remove() }
            let model = try ParityDemo.window(folder, unlocked: lockWork ? [1] : [])
            _ = try await waitingUnlock(model)
            let work = try #require(model.vaults.first { $0.name == "Work" }).id
            if lockWork { model.lock(work) } else { model.switchTo(work) }
            files.state.withLock { $0.dataless = false }
            try await until { unlocked(model) == ["Personal"] }
            #expect(unlocked(model) == ["Personal"], "\(folder): unlocked once the file is on this Mac")
            model.lockAll()
        }
    }

    @Test("APP-06.16: Lock Everything also stops an unlock whose screen went with a vault switch")
    func lockEverythingStopsAnUnlockAfterASwitch() async throws {
        let folder = "file-access-wait-switch-lock"
        let files = FakeFiles(folder)
        defer { files.remove() }
        let model = try ParityDemo.window(folder, unlocked: [])
        let state = try await waitingUnlock(model)
        let unlock = try #require(model.unlock)
        model.switchTo(try #require(model.vaults.first { $0.name == "Work" }).id)
        #expect(model.unlock !== unlock && unlock.working, "it goes on after the switch")
        model.lockAll()
        #expect(!unlock.working && state.withLock { $0.stopped && $0.typed == nil }, "ended, its password wiped")
        files.state.withLock { $0.dataless = false }
        try await Task.sleep(for: .seconds(2))
        #expect(unlocked(model).isEmpty, "unlocked: \(unlocked(model))")
    }

    @Test("APP-06.10, APP-06.17: back on a vault whose unlock waits, its form shows that unlock and its failure")
    func theWaitingUnlockKeepsItsForm() async throws {
        let folder = "file-access-wait-back"
        let files = FakeFiles(folder)
        defer { files.remove() }
        let model = try ParityDemo.window(folder, unlocked: [])
        let unlock = try #require(model.unlock)
        try await until { unlock.downloading }
        unlock.password = "wrong"
        unlock.unlock()
        model.switchTo(try #require(model.vaults.first { $0.name == "Work" }).id)
        model.switchTo(unlock.vault.id)
        #expect(model.unlock === unlock && unlock.working, "the form is disabled while its unlock runs")
        files.state.withLock { $0.dataless = false }
        try await until { !unlock.working }
        #expect(model.unlock?.message?.id == "M06-06", "the failure shows on the form on screen")
        model.lockAll()
    }

    /// The key file is no secret and stays with the attempt: for a vault
    /// with no password only the stop flag keeps Rust from starting.
    @Test("APP-06.16: a lock stops a waiting unlock of a key-file-only vault before Rust starts")
    func lockStopsAKeyFileOnlyUnlock() async throws {
        let folder = "file-access-wait-key-file"
        let place = ParityDemo.root.appending(path: "target/option-a/" + folder)
        try FileManager.default.createDirectory(at: place, withIntermediateDirectories: true)
        let path = place.appending(path: "Personal.appvault")
        try? FileManager.default.removeItem(at: path)
        let demo = ParityDemo.root.appending(path: "testdata/keyfile-hex64.appvault")
        try FileManager.default.copyItem(at: demo, to: path)
        let files = FakeFiles(folder)
        defer { files.remove() }
        let session = try ParityDemo.session()
        try session.switchTo(vault: try session.open(path: path.path(percentEncoded: false)))
        let model = MainWindowModel(session: session)
        let unlock = try #require(model.unlock)
        try await until { unlock.downloading }
        unlock.keyFile = ParityDemo.root.appending(path: "testdata/key-hex64.appkey").path(percentEncoded: false)
        unlock.unlock()
        model.lockAll()
        files.state.withLock { $0.dataless = false }
        try await Task.sleep(for: .seconds(2))
        #expect(unlocked(model).isEmpty, "unlocked: \(unlocked(model))")
        // Control: the same key file unlocks it, so the stop kept it locked.
        unlock.unlock()
        try await until { model.main != nil }
        #expect(model.main != nil)
        model.lockAll()
    }

    @Test("APP-06.16: an attempt stopped by a lock never ends the unlock started after it")
    func aStoppedAttemptLeavesTheNextOne() async throws {
        let folder = "file-access-wait-again"
        let files = FakeFiles(folder)
        defer { files.remove() }
        let model = try ParityDemo.window(folder, unlocked: [])
        _ = try await waitingUnlock(model)
        let unlock = try #require(model.unlock)
        let release = try await hold(file(folder))
        defer { release() }
        // The stopped attempt now waits in its coordinated read.
        model.lockAll()
        unlock.password = "demo-pass-7"
        unlock.unlock()
        #expect(unlock.working)
        release()
        try await Task.sleep(for: .seconds(1))
        #expect(unlock.working, "the stopped attempt's read ran; the second one still waits for the file")
        files.state.withLock { $0.dataless = false }
        try await until { model.main != nil }
        #expect(model.main?.vault.name == "Personal", "the second attempt unlocked")
        model.lockAll()
    }

    /// A slow folder: another program holds the first file in a
    /// coordinated write.
    @Test("APP-09.23: opens from two events run in the order asked; the last one asked for is shown")
    func opensKeepTheirOrder() async throws {
        let folder = "file-access-open-order"
        let first = try ParityDemo.path(0, folder: folder)
        let second = try ParityDemo.path(1, folder: folder)
        let model = MainWindowModel(session: try ParityDemo.session())
        let release = try await hold(first)
        defer { release() }
        model.open([first])
        let last = model.open([second])
        try await Task.sleep(for: .seconds(1))
        #expect(model.session.vaults().isEmpty, "the second open waits for the first")
        release()
        await last.value
        #expect(model.vaults.map(\.name) == ["Personal", "Work"])
        #expect(model.shown?.name == "Work", "the last one asked for is shown")
        model.lockAll()
    }

    /// A Finder multi-select or the Open panel.
    @Test("APP-09.23: the files of one open event open in the order given; the last is shown")
    func opensOfOneEventKeepTheirOrder() async throws {
        let folder = "file-access-open-one-event"
        let paths = [try ParityDemo.path(0, folder: folder), try ParityDemo.path(1, folder: folder)]
        let model = MainWindowModel(session: try ParityDemo.session())
        await model.open(paths).value
        #expect(model.vaults.map(\.name) == ["Personal", "Work"])
        #expect(model.shown?.name == "Work", "the last one given is shown")
        model.lockAll()
    }

    @Test("APP-05.24: the launch's Rust reads run with fetching off; the thread's policy comes back after")
    func launchNeverFetches() {
        let policy = { getiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD) }
        let before = policy()
        var during: Int32 = -1
        FileAccess.launch { during = policy() }
        #expect(during == IOPOL_MATERIALIZE_DATALESS_FILES_OFF, "fetching off while Rust reads")
        #expect(policy() == before)
    }
}
