import AppCore
import Foundation
import Testing

/// The flow around the picker (INT-05.25 steps 1 to 5, INT-05.29, SR-16):
/// App in front, no vault, the unlock panel (APP-06.27) and what closes a
/// picker untyped and which app it brings back. Fakes only.
extension AutoTypeTests {
    @Test("INT-05.25 T60, T61, T62: App in front does nothing; no vault beeps; a locked shown vault asks to unlock")
    func flowSteps() throws {
        let log = Log()
        let own = FakeWindows([Self.window("App", app: "App", pid: ownPid)])
        autoType(own, log: log).fired()
        #expect(log.shown.isEmpty && log.alerts == 0 && log.unlocks.isEmpty)
        autoType(FakeWindows([Self.window(Self.safari)]), log: log).fired()
        #expect(log.alerts == 1 && log.shown.isEmpty)
        let id = try session.open(path: try ParityDemo.path(0, folder: "at-locked"))
        autoType(FakeWindows([Self.window(Self.safari)]), log: log).fired()
        #expect(log.unlocks == [id] && log.shown.isEmpty)
    }

    @Test("INT-05.25 step 5, T62: the unlock panel shows M06-40; after the unlock the picker lists both vaults")
    func unlockPanel() async throws {
        // Personal shown and locked, Work unlocked.
        let personal = try session.open(path: try ParityDemo.path(0, folder: "at-unlock"))
        let work = try session.open(path: try ParityDemo.path(1, folder: "at-unlock"))
        #expect(try session.unlock(vault: work, password: ParityDemo.vaults[1].2, keyFile: nil) == .unlocked)
        try session.switchTo(vault: personal)
        let log = Log()
        let windows = FakeWindows([Self.window("", app: "Notes")])
        let auto = autoType(windows, log: log)
        auto.fired()
        let panel = try #require(auto.waiting)
        #expect(log.unlocks == [personal] && auto.picker == nil)
        // APP-06.27: M06-40 over the form, Cancel and Unlock; no switcher.
        let text = try await tree(AutoTypeUnlockPanel.view(panel))
        for word in ["Auto-Type needs this vault unlocked.", "Cancel", "Unlock", "Password", "Unlock Personal"] {
            #expect(text.contains(word), "\(word)")
        }
        #expect(!text.contains("Switch vault") && !text.contains("Other vaults"))
        // Step 2: another press while the panel shows does nothing.
        auto.fired()
        #expect(log.unlocks.count == 1 && windows.reads == 1)
        // The panel's form unlocks: the flow goes on for the captured target,
        // with no new capture, over every unlocked vault.
        panel.form.password = ParityDemo.vaults[0].2
        panel.form.unlock()
        for _ in 0..<1200 where auto.picker == nil { try await Task.sleep(for: .milliseconds(25)) }
        let picker = try #require(auto.picker)
        #expect(auto.waiting == nil && log.unlocks.last! == nil && windows.reads == 1)
        #expect(Set(picker.rows.map(\.vault)) == [personal, work])
        // INT-05.29: closed without typing after the panel, the target app
        // is brought back.
        #expect(picker.press(.escape, []) && auto.picker == nil && log.activated == [4242])
    }

    @Test("INT-05.25 step 5, APP-06.27: Cancel, lock everything or the vault closing stops, nothing typed")
    func unlockCancel() throws {
        let id = try session.open(path: try ParityDemo.path(0, folder: "at-unlock-cancel"))
        let log = Log()
        let windows = FakeWindows([Self.window(Self.safari)])
        let auto = autoType(windows, log: log)
        auto.fired()
        let panel = try #require(auto.waiting)
        panel.form.password = "typed"
        panel.cancel()
        #expect(auto.waiting == nil && log.unlocks == [id, nil] && panel.form.password.isEmpty)
        #expect(log.activated == [4242], "Cancel brings the target back")
        // Every lock-everything event (the main window's lockAll) cancels it.
        auto.fired()
        MainWindowModel(session: session).lockAll()
        #expect(auto.waiting == nil && log.unlocks == [id, nil, id, nil] && log.activated == [4242])
        // The vault closed while the panel shows.
        auto.fired()
        try session.close(vault: id)
        auto.vaultsChanged()
        #expect(auto.waiting == nil && log.unlocks.last! == nil && log.activated == [4242, 4242])
        #expect(auto.picker == nil && log.shown.isEmpty && windows.reads == 3)
    }

    @Test("SR-16, INT-05.29: a lock, another app or the target quitting closes the picker untyped")
    func closes() throws {
        let id = try personal("at-close")
        let log = Log()
        let auto = autoType(FakeWindows([Self.window(Self.safari)]), log: log)
        auto.fired()
        auto.appChanged(pid: ownPid, quit: false)
        #expect(auto.picker != nil, "App's own activation keeps it")
        auto.appChanged(pid: 4545, quit: false)
        #expect(auto.picker == nil)
        auto.fired()
        auto.appChanged(pid: 4242, quit: true)
        #expect(auto.picker == nil)
        auto.fired()
        try session.lock(vault: id)
        auto.vaultsChanged()
        #expect(auto.picker == nil && log.shown.last! == nil)
    }

    @Test("INT-05.29: after a panel flow that typed at once, a later picker closed untyped brings no app back")
    func noStaleTarget() async throws {
        // Verify's V7: Personal shown and locked, S-AT-03 off, Mail in front
        // with a mail sign-in title (one match).
        let id = try session.open(path: try ParityDemo.path(0, folder: "at-stale"))
        try set("autotype.always_ask", .flag(on: false))
        let windows = FakeWindows([Self.window("Inbox – Proton Mail", app: "Mail", pid: 4343)])
        let log = Log()
        let auto = autoType(windows, log: log)
        auto.fired()
        let panel = try #require(auto.waiting)
        panel.form.password = ParityDemo.vaults[0].2
        panel.form.unlock()
        for _ in 0..<1200 where auto.waiting != nil { try await Task.sleep(for: .milliseconds(25)) }
        // The flow went on: the single match typed at once, no picker.
        #expect(auto.waiting == nil && auto.picker == nil && log.unlocks == [id, nil])
        // INT-05.38 step 1: App was active for the panel, so Mail comes back
        // to the front before the first key.
        #expect(windows.reads == 1 + 1 + 71 && log.alerts == 0 && log.activated == [4343])
        // Later, in Safari: a picker closed with Escape brings Mail back
        // only if the old flow's target was kept.
        windows.windows = [Self.window(Self.safari)]
        auto.fired()
        #expect(try #require(auto.picker).press(.escape, []) && auto.picker == nil)
        #expect(log.activated == [4343], "no app brought to the front again")
    }

    @Test("F-074, MOD-13.8: a vault behind the forced key change prompt gets no second unlock panel and nothing typed")
    func forcedKeyChange() async throws {
        // The Work demo vault that asks for a key change (testdata/README.md).
        let place = ParityDemo.root.appending(path: "target/option-a/at-forced")
        try FileManager.default.createDirectory(at: place, withIntermediateDirectories: true)
        let copy = place.appending(path: "Work.appvault")
        try? FileManager.default.removeItem(at: copy)
        try FileManager.default.copyItem(
            at: ParityDemo.root.appending(path: "testdata/option-a-work-key-change.appvault"), to: copy)
        let id = try session.open(path: copy.path(percentEncoded: false))
        let log = Log()
        let windows = FakeWindows([Self.window(Self.safari)])
        let auto = autoType(windows, log: log)
        auto.fired()
        let panel = try #require(auto.waiting)
        panel.form.password = ParityDemo.vaults[1].2
        panel.form.unlock()
        for _ in 0..<1200 where auto.waiting != nil { try await Task.sleep(for: .milliseconds(25)) }
        // Open behind the prompt: the panel goes with the alert sound, the
        // target comes back, nothing is typed.
        #expect(session.vaults().first { $0.id == id }?.keyChange != nil)
        #expect(auto.waiting == nil && auto.picker == nil && log.unlocks == [id, nil])
        #expect(log.alerts == 1 && log.activated == [4242] && log.shown.isEmpty && log.stopped.isEmpty)
        #expect(windows.reads == 1)
        // Pressed again while the prompt waits: the sound, no panel.
        auto.fired()
        #expect(auto.waiting == nil && log.unlocks == [id, nil] && log.alerts == 2 && windows.reads == 2)
    }
}
