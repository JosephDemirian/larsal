import ApplicationServices

/// macOS's Accessibility permission (INT-05.44). Only App's own launch
/// makes one (AppDelegate.swift); the test target does not build this file,
/// so no test can show the system's request (AGENTS.md rule 10).
struct SystemAccessibility: AccessibilityTrust {
    func trusted() -> Bool { AXIsProcessTrusted() }

    /// macOS's own request, which shows its dialog.
    func request() {
        // `kAXTrustedCheckOptionPrompt` as its text: the imported global is
        // not concurrency-safe in Swift 6.
        _ = AXIsProcessTrustedWithOptions(["AXTrustedCheckOptionPrompt": true] as CFDictionary)
    }
}
