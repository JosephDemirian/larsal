import AppKit
import Carbon.HIToolbox
import LarsalCore
import SwiftUI
import Testing

/// The permission of the tests: never the system's (AGENTS.md rule 10).
final class FakeTrust: AccessibilityTrust {
    var granted: Bool
    private(set) var requests = 0

    init(granted: Bool) { self.granted = granted }

    func trusted() -> Bool { granted }
    func request() { requests += 1 }
}

/// Fake windows in front that hold the typing thread at read `holdAt` until
/// the test lets it go. Never the owner's.
nonisolated final class GatedWindows: WindowSource, @unchecked Sendable {
    let window: FrontWindow
    let holdAt: Int
    let gate = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var count = 0

    init(_ window: FrontWindow, holdAt: Int) {
        self.window = window
        self.holdAt = holdAt
    }

    var reads: Int { lock.withLock { count } }

    func front() -> FrontWindow? {
        let read = lock.withLock {
            count += 1
            return count
        }
        if read == holdAt { gate.wait() }
        return window
    }
}

/// E8-S3 in the controller (INT-05.38, INT-05.39, INT-05.41, INT-05.44,
/// INT-05.46): the permission seam, the layout table, the typing thread.
/// Fakes only; the session posts nothing (`autotypePostEvents` is Larsal's
/// launch only).
extension AutoTypeTests {
    @Test("INT-05.44 T94: without access MI05-30 each time, macOS's request once per Larsal run, nothing typed")
    func accessMissing() throws {
        _ = try personal("at-access")
        let log = Log()
        let windows = FakeWindows([Self.window(Self.safari)])
        let auto = autoType(windows, log: log)
        let trust = FakeTrust(granted: false)
        auto.trust = trust
        var alerts = 0
        auto.needsAccess = { alerts += 1 }
        var layouts = 0
        auto.layout = {
            layouts += 1
            return []
        }
        auto.fired()
        auto.fired()
        #expect(alerts == 2 && trust.requests == 1)
        #expect(auto.picker == nil && log.shown.isEmpty && windows.reads == 2, "captured only: no picker, no key")
        #expect(layouts == 0)
        // V-INT05-5: granted meanwhile, the next press goes on, no restart.
        trust.granted = true
        auto.fired()
        #expect(auto.picker != nil && alerts == 2 && trust.requests == 1)
        #expect(layouts == 1, "INT-05.41: the layout is read once per run")
        auto.picker?.cancel()
        // MI05-30's words and the pane its button opens.
        #expect(AccessAlert.title == "Larsal needs Accessibility access.")
        #expect(
            AccessAlert.text
                == "To type into other apps, turn on Larsal in Privacy & Security › Accessibility, then try again.")
        #expect(AccessAlert.open == "Open Privacy & Security" && AccessAlert.cancel == "Cancel")
        #expect(
            AccessAlert.pane?.absoluteString
                == "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
    }

    @Test("INT-05.41, INT-05.45, LD-186 (3): the layout table from macOS's US and French layouts")
    func layoutTable() throws {
        let usLayout = try #require(Self.layoutSource("com.apple.keylayout.US"))
        let usKeys = try #require(KeyboardLayoutTable.keys(of: usLayout))
        // The first key for a character has the fewest modifiers.
        func key(_ table: [AutoTypeKey], _ char: String) -> AutoTypeKey? { table.first { $0.character == char } }
        #expect(key(usKeys, "a") == AutoTypeKey(character: "a", code: 0x00, shift: false, option: false))
        #expect(key(usKeys, "A") == AutoTypeKey(character: "A", code: 0x00, shift: true, option: false))
        #expect(key(usKeys, "1") == AutoTypeKey(character: "1", code: 0x12, shift: false, option: false))
        #expect(key(usKeys, "!") == AutoTypeKey(character: "!", code: 0x12, shift: true, option: false))
        #expect(key(usKeys, "ç") == AutoTypeKey(character: "ç", code: 0x08, shift: false, option: true))
        #expect(key(usKeys, "é") == nil, "⌥E is a dead key on US: é goes as its Unicode string (T97)")
        #expect(!usKeys.contains { $0.code == 0x0E && $0.option && !$0.shift }, "⌥E is a dead key on US")
        #expect(!usKeys.contains { $0.code >= 0x41 && $0.code <= 0x5C }, "no keypad keys")
        #expect(!usKeys.contains { $0.character.unicodeScalars.contains { $0.value < 0x20 } }, "no control characters")
        // T98: on AZERTY `a` is key 0x0C and `q` key 0x00; digits need ⇧.
        let french = try #require(Self.layoutSource("com.apple.keylayout.French"))
        let frKeys = try #require(KeyboardLayoutTable.keys(of: french))
        #expect(key(frKeys, "a")?.code == 0x0C && key(frKeys, "q")?.code == 0x00)
        #expect(key(frKeys, "1") == AutoTypeKey(character: "1", code: 0x12, shift: true, option: false))
        // Rust keeps it for the plans of the run.
        session.autotypeLayout(keys: frKeys)
    }

    @Test("INT-05.39, INT-05.46 T92: typing runs off the main thread; the shortcut pressed again stops it")
    func shortcutStopsTyping() async throws {
        _ = try personal("at-stop")
        let log = Log()
        // Reads: the capture, step 1, the first key, then the second key's
        // check holds the typing thread.
        let windows = GatedWindows(Self.window(Self.safari), holdAt: 4)
        let auto = AutoType(session: session, hotKeys: keys, windows: windows) { log.shown.append($0) }
        auto.alert = { log.alerts += 1 }
        auto.activate = { log.activated.append($0) }
        auto.log = { log.lines.append($0) }
        auto.layout = { [] }
        auto.fired()
        #expect(try #require(auto.picker).press(.return, []))
        #expect(auto.typing, "the main thread goes on while it types")
        for _ in 0..<800 where windows.reads < 4 { try await Task.sleep(for: .milliseconds(10)) }
        #expect(windows.reads == 4)
        auto.fired()
        #expect(auto.picker == nil && log.shown.count == 2, "the press stops the run, it opens no picker")
        windows.gate.signal()
        for _ in 0..<800 where auto.typing { try await Task.sleep(for: .milliseconds(25)) }
        #expect(!auto.typing && log.alerts == 1, "stopped: the alert sound")
        #expect(windows.reads == 4, "no window check after the stop: the rest never went out")
        // The second key's check was under way at the press: it does not
        // go out either (INT-05.39 "at once"); T106's line.
        #expect(log.lines == ["Auto-Type stopped: stopped after 1 keys"])
        // The next press starts a new run.
        auto.fired()
        #expect(auto.picker != nil)
        auto.picker?.cancel()
    }

    @Test("INT-05.38 step 1: Larsal came in front while the picker showed; the target is asked back, then typed into")
    func targetAskedBack() throws {
        _ = try personal("at-front")
        let log = Log()
        let target = Self.window(Self.safari)
        // The capture, Larsal in front at step 1's first look, then the target.
        let windows = FakeWindows([target, Self.window("Larsal", app: "Larsal", pid: ownPid), target])
        let auto = autoType(windows, log: log)
        auto.fired()
        auto.appChanged(pid: ownPid, quit: false)
        try #require(auto.picker).choose(.login)
        #expect(log.activated == [4242], "macOS is asked to make the target active")
        #expect(windows.reads > 3 && log.alerts == 0 && log.lines.isEmpty, "it came back: typed to the end")
    }

    @Test("INT-05.15, INT-05.47 T106: a failing sequence shows its reason and logs only the message id")
    func failureLine() throws {
        let id = try personal("at-fail", bot: false)
        _ = try session.beginNew(vault: id, group: nil)
        try session.setText(vault: id, field: .title, value: "Bank login")
        try session.addWindow(vault: id, window: "*Bank*", sequence: "{TAB 101}")
        _ = try session.commitEdit(vault: id)
        let log = Log()
        let windows = FakeWindows([Self.window("My Bank")])
        let auto = autoType(windows, log: log)
        auto.fired()
        #expect(try #require(auto.picker).press(.return, []))
        #expect(log.stopped == ["{TAB 101} repeats more than 100 times."])
        #expect(log.lines == ["Auto-Type failed: MI05-12"], "no token, no title")
        #expect(windows.reads == 1 && log.alerts == 0, "nothing typed")
    }

    @Test("INT-05.35, INT-05.44 T88: the settings notice follows the permission, checked again on activation")
    func settingsNotice() async throws {
        let trust = FakeTrust(granted: false)
        let model = LarsalSettingsModel(
            session: session, loginItem: FakeLoginItem(), accessibility: { trust.granted },
            sshProbe: { _ in frameSshStatus })
        let host = NSHostingView(rootView: LarsalSettingsAutoTypePage(model: model).frame(width: 640))
        host.frame = NSRect(origin: .zero, size: host.fittingSize)
        let offscreen = NSWindow(
            contentRect: host.frame.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless],
            backing: .buffered, defer: false)
        offscreen.contentView = host
        defer { offscreen.contentView = nil }
        let shots = SnapshotTests()
        func text() async throws -> String {
            _ = try await shots.render(host)
            return String(bytes: try shots.accessibilityTree(host), encoding: .utf8) ?? ""
        }
        let off = try await text()
        #expect(off.contains("Accessibility access is off. Larsal can't type into other apps until you turn it on."))
        #expect(off.contains("Open Privacy & Security") && !off.contains("access is on"))
        // Granted in System Settings; Larsal becomes active again (simulated).
        trust.granted = true
        NotificationCenter.default.post(name: NSApplication.didBecomeActiveNotification, object: nil)
        let granted = try await text()
        #expect(granted.contains("Accessibility access is on. macOS lets Larsal type into other apps."))
        #expect(trust.requests == 0, "the page only checks; it never asks macOS")
    }

    /// An installed keyboard layout by its id (reads macOS's list; selects
    /// nothing).
    static func layoutSource(_ id: String) -> TISInputSource? {
        let filter = [kTISPropertyInputSourceID as String: id] as CFDictionary
        guard let list = TISCreateInputSourceList(filter, true)?.takeRetainedValue(), CFArrayGetCount(list) > 0,
            let first = CFArrayGetValueAtIndex(list, 0)
        else { return nil }
        return Unmanaged<TISInputSource>.fromOpaque(first).takeUnretainedValue()
    }
}
