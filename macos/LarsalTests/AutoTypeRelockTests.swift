import Foundation
import LarsalCore
import Testing

/// INT-05.32 (S-AT-06, APP-02.14): a vault the unlock panel opened for a
/// global Auto-Type locks again, through the main window's lock, when the
/// run ends. Fakes only (AGENTS.md rule 10).
extension AutoTypeTests {
    /// The panel flow on the locked Personal vault: the shortcut, then the
    /// panel's unlock; the picker shows after it.
    private func unlockThroughPanel(_ auto: AutoType) async throws -> UInt64 {
        auto.fired()
        let panel = try #require(auto.waiting)
        panel.form.password = ParityDemo.vaults[0].2
        panel.form.unlock()
        for _ in 0..<1200 where auto.waiting != nil { try await Task.sleep(for: .milliseconds(25)) }
        return panel.form.vault.id
    }

    private func isLocked(_ id: UInt64) -> Bool { session.vaults().first { $0.id == id }?.locked == true }

    /// "GitHub (bad)", whose window rule types `{USERNAME` (MI05-11); saved,
    /// then the vault is locked.
    private func addBadEntry(_ id: UInt64) throws {
        _ = try session.beginNew(vault: id, group: nil)
        try session.setText(vault: id, field: .title, value: "GitHub (bad)")
        try session.addWindow(vault: id, window: "*GitHub*", sequence: "{USERNAME")
        _ = try session.commitEdit(vault: id)
        #expect(try session.save(vault: id).failure == nil)
        try session.lock(vault: id)
    }

    @Test("INT-05.32 T74: S-AT-06 on: locked after the last key; with the picker closed by Escape, locked at once")
    func t74LockAgainAfterAutoType() async throws {
        let id = try session.open(path: try ParityDemo.path(0, folder: "at-relock"))
        try set("lock.relock_after_autotype", .flag(on: true))
        defer { try? set("lock.relock_after_autotype", .flag(on: false)) }
        let window = MainWindowModel(session: session)
        let log = Log()
        let windows = FakeWindows([Self.window(Self.safari)])
        let auto = autoType(windows, log: log)
        var relocked: [UInt64] = []
        auto.relock = {
            relocked.append($0)
            window.lock($0)
        }
        // Typed from the picker: locked after the last key.
        #expect(try await unlockThroughPanel(auto) == id)
        #expect(!isLocked(id) && relocked.isEmpty, "unlocked while the picker shows")
        #expect(try #require(auto.picker).press(.return, []))
        #expect(windows.reads > 2 && log.alerts == 0, "typed")
        #expect(relocked == [id] && isLocked(id), "locked again after the last key")
        // Closed with Escape: locked at once, nothing typed.
        let reads = windows.reads
        _ = try await unlockThroughPanel(auto)
        #expect(!isLocked(id))
        #expect(try #require(auto.picker).press(.escape, []) && auto.picker == nil)
        #expect(relocked == [id, id] && isLocked(id) && windows.reads == reads + 1, "locked, nothing typed")
        // A vault that was already unlocked stays so after a run.
        #expect(try session.unlock(vault: id, password: ParityDemo.vaults[0].2, keyFile: nil) == .unlocked)
        auto.fired()
        #expect(try #require(auto.picker).press(.escape, []))
        #expect(relocked == [id, id] && !isLocked(id), "not unlocked for Auto-Type: not locked again")
        // A failed run (MI05-11: a sequence with an open brace) locks again.
        try addBadEntry(id)
        _ = try await unlockThroughPanel(auto)
        let picker = try #require(auto.picker)
        let bad = try #require(picker.rows.firstIndex { $0.title == "GitHub (bad)" })
        picker.choose(.login, row: bad)
        #expect(log.lines.last == "Auto-Type failed: MI05-11")
        #expect(relocked == [id, id, id] && isLocked(id), "failed: locked again")
        // A stopped run (another window comes to the front once the run starts) too.
        let mail = Self.window("Mail", app: "Mail", pid: 4444)
        let stops = autoType(FakeWindows([Self.window(Self.safari), mail]), log: log)
        stops.relock = {
            relocked.append($0)
            window.lock($0)
        }
        _ = try await unlockThroughPanel(stops)
        let good = try #require(stops.picker?.rows.firstIndex { $0.title != "GitHub (bad)" })
        try #require(stops.picker).choose(.login, row: good)
        #expect(log.lines.last?.hasPrefix("Auto-Type stopped: ") == true, "\(log.lines)")
        #expect(relocked == [id, id, id, id] && isLocked(id), "stopped: locked again")
        // S-AT-06 off: the panel's vault stays unlocked.
        try set("lock.relock_after_autotype", .flag(on: false))
        _ = try await unlockThroughPanel(auto)
        #expect(try #require(auto.picker).press(.return, []))
        #expect(relocked.count == 4 && !isLocked(id), "off: stays unlocked")
        try session.lock(vault: id)
    }
}
