import AppCore
import AppKit
import Carbon.HIToolbox

/// The Accessibility permission (INT-05.44), behind a seam: App's launch
/// gives the system's (`SystemAccessibility`, which the test target does
/// not build), tests a fake. Nothing here shows a system dialog.
protocol AccessibilityTrust {
    /// True when App may post keyboard events to other apps.
    func trusted() -> Bool
    /// Asks macOS to show its own permission request.
    func request()
}

/// Until App's launch sets the system's: says yes and asks nothing. Without
/// `Session.autotypePostEvents` nothing is posted anyway.
struct AssumedAccessibility: AccessibilityTrust {
    func trusted() -> Bool { true }
    func request() {}
}

/// MI05-30 (INT-05.44): the alert when the permission is missing.
enum AccessAlert {
    static let title = "App needs Accessibility access."
    static let text = "To type into other apps, turn on App in Privacy & Security › Accessibility, then try again."
    static let open = "Open Privacy & Security"
    static let cancel = "Cancel"
    /// Privacy & Security › Accessibility in System Settings.
    static let pane = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")

    /// Shows MI05-30; the pane opens only when the user clicks Open Privacy
    /// & Security. Never in a test or hidden launch (AGENTS.md rule 10).
    static func show() {
        guard !launchHidden(), ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil else { return }
        let box = ScreenProtection.shared.alert()
        box.messageText = title
        box.informativeText = text
        box.addButton(withTitle: open)
        box.addButton(withTitle: cancel)
        if box.runModal() == .alertFirstButtonReturn, let pane { NSWorkspace.shared.open(pane) }
    }
}

/// The current keyboard layout as one table for Rust (INT-05.41,
/// INT-05.45, LD-186 (3)): each key of the main block that types one
/// character with one press, with no modifier, ⇧, ⌥ or ⌥⇧; dead keys and
/// the keypad are left out. Swift never looks up a character of a sequence.
enum KeyboardLayoutTable {
    /// The current keyboard input source's layout, else the current
    /// ASCII-capable one (D-INT05-5); empty when neither has layout data.
    static func current() -> [AutoTypeKey] {
        // Each copy is made only when reached and always released: a copy
        // made up front and never taken would leak (LD-234 (1)).
        let copies = [TISCopyCurrentKeyboardLayoutInputSource, TISCopyCurrentASCIICapableKeyboardLayoutInputSource]
        for copy in copies {
            if let source = copy()?.takeRetainedValue(), let keys = keys(of: source) { return keys }
        }
        return []
    }

    /// The table of `source`; `nil` when it has no key layout data.
    static func keys(of source: TISInputSource) -> [AutoTypeKey]? {
        guard let raw = TISGetInputSourceProperty(source, kTISPropertyUnicodeKeyLayoutData) else { return nil }
        let data = Unmanaged<CFData>.fromOpaque(raw).takeUnretainedValue() as Data
        return data.withUnsafeBytes { bytes in
            guard let layout = bytes.baseAddress?.assumingMemoryBound(to: UCKeyboardLayout.self) else { return nil }
            var keys: [AutoTypeKey] = []
            for (shift, option) in [(false, false), (true, false), (false, true), (true, true)] {
                let state = UInt32((shift ? shiftKey : 0) | (option ? optionKey : 0)) >> 8
                // The keypad (0x41 to 0x5C) types digits and signs the main
                // block has too.
                for code in UInt16(0)..<0x80 where !(0x41...0x5C).contains(code) {
                    guard let character = character(layout, code, state) else { continue }
                    keys.append(AutoTypeKey(character: character, code: code, shift: shift, option: option))
                }
            }
            return keys
        }
    }

    /// What one press of `code` types with `mods` (UCKeyTranslate's
    /// form); `nil` for a dead key, nothing, more than one character, a
    /// control or a private-use one.
    private static func character(_ map: UnsafePointer<UCKeyboardLayout>, _ code: UInt16, _ mods: UInt32) -> String? {
        var dead: UInt32 = 0
        var length = 0
        var units = [UniChar](repeating: 0, count: 4)
        let status = UCKeyTranslate(
            map, code, UInt16(kUCKeyActionDown), mods, UInt32(LMGetKbdType()), 0, &dead, units.count, &length,
            &units)
        guard status == noErr, dead == 0, length > 0 else { return nil }
        let text = String(utf16CodeUnits: units, count: length)
        guard let scalar = text.unicodeScalars.first, text.unicodeScalars.count == 1,
            scalar.value >= 0x20, scalar.value != 0x7F, !(0xE000...0xF8FF).contains(scalar.value)
        else { return nil }
        return text
    }
}

/// Runs the typing (`work`) and then its end (`done`) on the main thread.
typealias AutoTypeRunner =
    @MainActor (
        _ work: @escaping @Sendable () -> AutoTypeEnd, _ done: @escaping @MainActor (AutoTypeEnd) -> Void
    ) -> Void

extension AutoType {
    /// The typing waits between keys, so it runs on its own thread, never
    /// the main thread or the shared pool; the end comes back to the main
    /// thread (INT-05.39: the shortcut and a lock can stop it meanwhile).
    static func offMain(
        _ work: @escaping @Sendable () -> AutoTypeEnd, _ done: @escaping @MainActor (AutoTypeEnd) -> Void
    ) {
        Thread.detachNewThread {
            let end = work()
            Task { @MainActor in done(end) }
        }
    }
}
