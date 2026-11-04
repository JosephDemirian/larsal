import AppCore
import AppKit
import Testing

/// Fake windows in front, read in order, the last one staying; `nil` is no
/// app in front. Never the owner's (AGENTS.md rule 10).
nonisolated final class ScriptedWindows: WindowSource, @unchecked Sendable {
    let script: [FrontWindow?]
    private(set) var reads = 0

    init(_ script: [FrontWindow?]) { self.script = script }

    func front() -> FrontWindow? {
        defer { reads += 1 }
        return script[min(reads, script.count - 1)]
    }
}

/// E8-S3's Verify gaps (LD-234 (1)) in the controller: the not-in-front
/// line, the target asked forward before Rust waits for it, App's own
/// secure input off before typing, and no app in front stopping the run.
/// Fakes only; the session posts nothing.
extension AutoTypeTests {
    @Test("LD-234 (1), INT-05.38 step 1, INT-05.47: the target never comes back: nothing typed, the not-in-front line")
    func notInFrontLine() throws {
        _ = try personal("at-not-front")
        let log = Log()
        let windows = FakeWindows([Self.window(Self.safari), Self.window("Mail", app: "Mail", pid: 4444)])
        let auto = autoType(windows, log: log)
        auto.layout = { [] }
        auto.fired()
        try #require(auto.picker).choose(.login)
        #expect(log.activated == [4242])
        #expect(windows.reads == 1 + 41, "the capture, then step 1 every 50 ms for 2 s")
        #expect(log.alerts == 1 && log.lines == ["Auto-Type stopped: not-in-front after 0 keys"])
    }

    @Test("LD-234 (1), INT-05.38 step 1: the target is asked forward before Rust waits for it")
    func activateBeforeWait() throws {
        _ = try personal("at-activate")
        let log = Log()
        let target = Self.window(Self.safari)
        // The target comes forward only once macOS was asked for it.
        let windows = FakeWindows([target, Self.window("App", app: "App", pid: ownPid)])
        let auto = autoType(windows, log: log)
        auto.layout = { [] }
        auto.activate = { pid in
            log.activated.append(pid)
            if pid == target.pid { windows.windows = [target] }
        }
        auto.fired()
        try #require(auto.picker).choose(.login)
        #expect(log.activated == [4242])
        #expect(windows.reads > 3 && log.alerts == 0 && log.lines.isEmpty, "it came forward: typed to the end")
    }

    @Test("LD-234 (1), INT-05.38 step 4: App's own secure input is off before typing starts")
    func secureInputOffBeforeTyping() throws {
        _ = try personal("at-secure")
        let rig = SecureInputTests.Rig()
        rig.focus(rig.field())
        #expect(rig.calls == ["enable"], "App's call is on")
        let log = Log()
        let auto = autoType(FakeWindows([Self.window(Self.safari)]), log: log)
        auto.layout = { [] }
        auto.secureInput = rig.input
        var atStart: [String] = []
        auto.runner = { work, done in
            atStart = rig.calls
            done(work())
        }
        auto.fired()
        try #require(auto.picker).choose(.login)
        #expect(atStart == ["enable", "disable"])
        #expect(log.alerts == 0 && log.lines.isEmpty, "typed to the end")
    }

    @Test("LD-234 (1), AT-G02 T103: no app in front during typing stops the run")
    func noAppInFrontStops() throws {
        _ = try personal("at-no-app")
        let log = Log()
        let target = Self.window(Self.safari)
        // The capture, step 1 and two keys, then no app in front.
        let windows = ScriptedWindows([target, target, target, target, nil])
        let auto = AutoType(session: session, hotKeys: keys, windows: windows) { log.shown.append($0) }
        auto.alert = { log.alerts += 1 }
        auto.activate = { log.activated.append($0) }
        auto.log = { log.lines.append($0) }
        auto.runner = { work, done in done(work()) }
        auto.layout = { [] }
        auto.fired()
        try #require(auto.picker).choose(.login)
        #expect(windows.reads == 5, "two keys, then the failed check")
        #expect(log.alerts == 1 && log.lines == ["Auto-Type stopped: window-changed after 2 keys"])
    }
}
