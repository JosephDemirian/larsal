import AppKit
import LarsalCore
import Testing

/// SR-06, AT-D05, card APP-10.8 to APP-10.13 (E6-S5), through the seam: a
/// test never calls the real secure input, which changes keyboard input for
/// every app on the Mac, and never posts a real system notification
/// (AGENTS.md rule 10). Fields are focused in offscreen windows that are
/// never ordered in; only shown fields (`NoCopyTextField`): a focused secure
/// field would turn on the real thing by itself.
@MainActor
@Suite(.serialized)
struct SecureInputTests {
    /// The calls Larsal makes, in order.
    final class Recorder: SecureEventInput {
        private(set) var calls: [String] = []
        func enable() { calls.append("enable") }
        func disable() { calls.append("disable") }
    }

    /// One controller over a private notification center, Larsal active and
    /// the window key unless a test says otherwise.
    final class Rig {
        let recorder = Recorder()
        let center = NotificationCenter()
        let input: SecureInput
        var active = true
        var key = true
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 300, height: 120), styleMask: [.titled], backing: .buffered,
            defer: false)

        init() {
            input = SecureInput(center: center)
            input.system = recorder
            input.isActive = { [unowned self] in active }
            input.isKey = { [unowned self] _ in key }
        }

        func field() -> NoCopyTextField {
            let field = NoCopyTextField(frame: NSRect(x: 0, y: 0, width: 200, height: 24))
            field.secureInput = input
            window.contentView?.addSubview(field)
            return field
        }

        func focus(_ view: NSView?) { _ = window.makeFirstResponder(view) }
        func post(_ name: Notification.Name, _ object: Any? = nil) { center.post(name: name, object: object) }
        var calls: [String] { recorder.calls }
    }

    @Test("Rule 10: a test run never makes the real secure input calls")
    func inertInTests() {
        #expect(SecureInput.shared.system is InertSecureEventInput)
        #expect(SecureInput().system is InertSecureEventInput)
    }

    @Test(
        "APP-10.8-e, APP-10.11: a shown password field turns Larsal's secure input on with the focus, off as it leaves")
    func focusAndBlur() {
        let rig = Rig()
        let field = rig.field()
        let other = NSTextField(frame: NSRect(x: 0, y: 40, width: 200, height: 24))
        rig.window.contentView?.addSubview(other)
        rig.focus(other)
        #expect(rig.calls.isEmpty, "a plain field turns nothing on")
        rig.focus(field)
        #expect(rig.calls == ["enable"] && rig.input.enabled)
        rig.focus(other)
        #expect(rig.calls == ["enable", "disable"] && !rig.input.enabled)
    }

    @Test(
        "APP-10.8-b, APP-10.13-a, -b: off when Larsal resigns active; on again when active with the field still focused"
    )
    func deactivateAndBack() {
        let rig = Rig()
        rig.focus(rig.field())
        rig.active = false
        rig.post(NSApplication.didResignActiveNotification)
        #expect(rig.calls == ["enable", "disable"])
        rig.post(NSApplication.didHideNotification)
        #expect(rig.calls.count == 2, "hidden too: nothing more")
        rig.active = true
        rig.post(NSApplication.didBecomeActiveNotification)
        #expect(rig.calls == ["enable", "disable", "enable"] && rig.input.enabled)
    }

    @Test("APP-10.13: after a window close's release, on again when Larsal or the window is active, the field focused")
    func backAfterRelease() {
        let rig = Rig()
        let field = rig.field()
        rig.focus(field)
        // A window Larsal keeps and shows again; its field keeps the focus.
        rig.input.release()
        #expect(rig.calls == ["enable", "disable"] && field.currentEditor() != nil)
        rig.post(NSWindow.didResignKeyNotification, rig.window)
        #expect(!rig.input.enabled, "off until Larsal or the window is back")
        rig.active = false
        rig.post(NSApplication.didResignActiveNotification)
        rig.active = true
        rig.post(NSApplication.didBecomeActiveNotification)
        #expect(rig.calls == ["enable", "disable", "enable"])
        rig.input.release()
        rig.post(NSWindow.didBecomeKeyNotification, rig.window)
        #expect(rig.calls == ["enable", "disable", "enable", "disable", "enable"])
        // Not for a field that lost the focus meanwhile.
        rig.input.release()
        rig.focus(nil)
        rig.post(NSApplication.didBecomeActiveNotification)
        #expect(!rig.input.enabled && rig.calls.last == "disable")
    }

    @Test("APP-10.11, APP-10.11-a: a stale focus report for a field with no editor turns nothing on")
    func staleReport() {
        let rig = Rig()
        let field = rig.field()
        rig.input.focused(field)
        rig.post(NSApplication.didBecomeActiveNotification)
        rig.post(NSWindow.didBecomeKeyNotification, rig.window)
        rig.input.update()
        #expect(field.currentEditor() == nil && !rig.input.enabled && rig.calls.isEmpty, "\(rig.calls)")
    }

    @Test("APP-10.8: off while another window is key; on again when the field's window is key")
    func keyWindow() {
        let rig = Rig()
        rig.focus(rig.field())
        rig.key = false
        rig.post(NSWindow.didResignKeyNotification, rig.window)
        #expect(rig.calls == ["enable", "disable"])
        rig.key = true
        rig.post(NSWindow.didBecomeKeyNotification, rig.window)
        #expect(rig.calls == ["enable", "disable", "enable"])
    }

    @Test("APP-10.8: off when the field is hidden, removed or its text replaced while typing; off as its window closes")
    func hiddenRemovedClosed() {
        let rig = Rig()
        let field = rig.field()
        rig.focus(field)
        field.isHidden = true
        #expect(rig.calls == ["enable", "disable"])
        field.isHidden = false
        rig.focus(field)
        field.removeFromSuperview()
        #expect(rig.calls == ["enable", "disable", "enable", "disable"])
        let again = rig.field()
        rig.focus(again)
        _ = again.abortEditing()
        #expect(rig.calls.suffix(2) == ["enable", "disable"])
        rig.focus(again)
        // A close ends no editing (AppKit): the window's notice does.
        rig.post(NSWindow.willCloseNotification, Rig().window)
        #expect(rig.input.enabled, "another window closing changes nothing")
        rig.post(NSWindow.willCloseNotification, rig.window)
        #expect(!rig.input.enabled && rig.calls.last == "disable")
    }

    @Test(
        "APP-10.8, APP-10.11, APP-10.12-b: locking the main window keeps secure input only while the field edits"
    )
    func lockRechecks() throws {
        ParityDemo.setUp()
        let shared = SecureInput.shared
        let recorder = Recorder()
        let (system, isActive, isKey) = (shared.system, shared.isActive, shared.isKey)
        defer {
            shared.release()
            (shared.system, shared.isActive, shared.isKey) = (system, isActive, isKey)
        }
        shared.system = recorder
        shared.isActive = { true }
        shared.isKey = { _ in true }
        let model = try ParityDemo.window("app10-lock", unlocked: [0, 1])
        let window = Rig().window
        let field = NoCopyTextField(frame: NSRect(x: 0, y: 0, width: 200, height: 24))
        window.contentView?.addSubview(field)
        _ = window.makeFirstResponder(field)
        #expect(shared.enabled && recorder.calls == ["enable"])
        // The New Vault wizard's field outlives the lock, Larsal active, its window key.
        model.lockNow(model.vaults[0].id)
        #expect(field.currentEditor() != nil && shared.enabled && recorder.calls == ["enable"], "still typing")
        // A missed focus-out: the editor goes with no report to Larsal.
        field.secureInput = SecureInput(center: NotificationCenter())
        _ = window.makeFirstResponder(nil)
        #expect(shared.enabled, "nothing reported yet")
        model.lockAll()
        #expect(!shared.enabled && recorder.calls == ["enable", "disable"])
    }

    @Test("APP-10.10-a, APP-10.12: calls alternate, starting with enable; never two enables; none left on after quit")
    func neverLeftOn() {
        let rig = Rig()
        let first = rig.field()
        let second = rig.field()
        let plain = NSTextField(frame: NSRect(x: 0, y: 80, width: 200, height: 24))
        rig.window.contentView?.addSubview(plain)
        // The card's run: focus, out, in twice, quit. The second focus-in
        // ends AppKit's editing and starts it again: off, then on.
        rig.focus(first)
        rig.focus(plain)
        rig.focus(first)
        rig.focus(first)
        rig.post(NSApplication.willTerminateNotification)
        #expect(rig.calls == ["enable", "disable", "enable", "disable", "enable", "disable"], "\(rig.calls)")
        #expect(!rig.input.enabled)
        // Then 400 steps of every event in a fixed pseudo-random order: at
        // every step Larsal's state is exactly the card's three conditions and
        // the calls alternate.
        var seed: UInt64 = 0x5EC0_1A9E
        let steps: [() -> Void] = [
            { rig.focus(first) }, { rig.focus(second) }, { rig.focus(plain) }, { rig.focus(nil) },
            {
                rig.active.toggle()
                rig.post(
                    rig.active ? NSApplication.didBecomeActiveNotification : NSApplication.didResignActiveNotification)
            },
            {
                rig.key.toggle()
                rig.post(rig.key ? NSWindow.didBecomeKeyNotification : NSWindow.didResignKeyNotification)
            },
            { rig.input.release() }, { rig.input.update() },
        ]
        for _ in 0..<400 {
            seed = seed &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            steps[Int(seed >> 33) % steps.count]()
            let editing = [first, second].contains { $0.currentEditor() != nil }
            #expect(!rig.input.enabled || (editing && rig.active && rig.key))
            #expect(rig.calls.enumerated().allSatisfy { $1 == ($0.isMultiple(of: 2) ? "enable" : "disable") })
        }
        rig.post(NSApplication.willTerminateNotification)
        #expect(!rig.input.enabled && rig.calls.last == "disable")
        #expect(rig.calls.filter { $0 == "enable" }.count == rig.calls.filter { $0 == "disable" }.count)
    }
}
