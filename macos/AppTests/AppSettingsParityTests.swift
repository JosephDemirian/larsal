import AppCore
import AppKit
import SwiftUI
import Testing

/// The settings window offscreen, pressed through its accessibility tree as
/// VoiceOver would (as `Screen` does for the main window).
@MainActor
final class SettingsScreen {
    let host: NSHostingView<AnyView>
    let window: NSWindow

    init(_ model: AppSettingsModel) {
        let size = CGSize(width: 900, height: 680)
        host = NSHostingView(
            rootView: AnyView(AppSettingsView(model: model).frame(width: size.width, height: size.height)))
        host.frame = NSRect(origin: .zero, size: size)
        // Never ordered front (AGENTS.md rule 10).
        window = NSWindow(
            contentRect: NSRect(origin: CGPoint(x: -20_000, y: -20_000), size: size), styleMask: [.borderless],
            backing: .buffered, defer: false)
        window.contentView = host
        NSApplication.shared.setValue(true, forKey: "accessibilityEnhancedUserInterface")
    }

    isolated deinit {
        window.contentView = nil
    }

    func settle() async {
        host.layoutSubtreeIfNeeded()
        try? await Task.sleep(for: .milliseconds(150))
        host.layoutSubtreeIfNeeded()
    }

    /// The first element labelled `name`, else the first text that reads it.
    func node(_ name: String) -> AnyObject? {
        var labelled: AnyObject?
        var texts: AnyObject?
        func walk(_ any: Any, _ depth: Int) {
            let element = any as AnyObject
            guard labelled == nil, depth < 80 else { return }
            let label = (element.accessibilityLabel?() ?? nil) ?? ""
            let value: Any? = element.accessibilityValue?() ?? nil
            if label == name || label.hasPrefix(name + ", ") {
                labelled = element
                return
            }
            if texts == nil, (value as? String) == name { texts = element }
            for child in element.accessibilityChildren?() ?? [] { walk(child, depth + 1) }
        }
        walk(host, 0)
        return labelled ?? texts
    }

    func enabled(_ name: String) -> Bool? { node(name)?.isAccessibilityEnabled?() }

    func press(_ name: String) async throws {
        let element = try #require(node(name), "\(name) is on screen")
        #expect(element.isAccessibilityEnabled?() != false, "\(name) is enabled")
        #expect(element.accessibilityPerformPress?() == true, "\(name) takes a press")
        await settle()
    }
}

@MainActor
@Suite(.serialized)
struct AppSettingsParityTests {
    init() { Fonts.register() }

    @Test("Parity settings-settings-general: the nav opens every page; switches, steppers and the login item edit")
    func general() async throws {
        let model = settingsModel()
        let screen = SettingsScreen(model)
        await screen.settle()
        for page in AppSettingsPage.allCases.reversed() {
            try await screen.press(page.title)
            #expect(model.page == page)
        }
        let count = model.number("recent.count")
        try await screen.press("More")
        #expect(model.number("recent.count") == count + 1)
        let reopen = model.flag("recent.reopen_at_start")
        try await screen.press("Reopen")
        #expect(model.flag("recent.reopen_at_start") != reopen)
        try await screen.press("Login")
        #expect(model.loginOn)
        // E14: the update check is drawn and waits; nothing is sent.
        #expect(screen.enabled("Updates") == false)
    }

    @Test("Parity settings-settings-security: the clipboard switch and stepper edit; Touch ID waits; capture is live")
    func security() async throws {
        let model = settingsModel()
        model.go(.security)
        let screen = SettingsScreen(model)
        await screen.settle()
        try await screen.press("More")
        #expect(model.number("clipboard.clear.seconds") == 15)
        try await screen.press("Clipboard")
        #expect(!model.flag("clipboard.clear.enabled"))
        #expect(screen.enabled("Touch ID") == false)
        // APP-10.4: the run-only capture switch is live (not pressed here: it
        // changes every window of the test process).
        #expect(screen.enabled("Capture") == true)
    }

    @Test("Parity settings-settings-auto-type: matching switches edit; Change waits for Auto-Type")
    func autoType() async throws {
        let model = settingsModel()
        model.go(.autoType)
        let screen = SettingsScreen(model)
        await screen.settle()
        try await screen.press("Title")
        #expect(!model.flag("autotype.match_title"))
        #expect(screen.enabled("Change") == false)
    }

    @Test("Parity settings-settings-browser-integration: the main switch enables the page and the browsers")
    func browser() async throws {
        let model = settingsModel()
        model.go(.browser)
        let screen = SettingsScreen(model)
        await screen.settle()
        #expect(screen.enabled("Notify") == false, "APP-01.5: off with the main switch")
        try await screen.press("Browser")
        #expect(model.flag("browser.enabled"))
        #expect(screen.enabled("Notify") == true)
        #expect(screen.enabled("Chrome") == true)
        // "Safari" also names its logo, so the switch's state is read from the model.
        #expect(model.isDisabled("browser.safari"), "INT-01.15: this test build has no team id")
    }

    @Test("Parity settings-settings-ssh-agent: the switch shows the status row; the socket waits for W-05")
    func ssh() async throws {
        let model = settingsModel()
        model.go(.ssh)
        let screen = SettingsScreen(model)
        await screen.settle()
        try await screen.press("SSH")
        #expect(model.flag("ssh.enabled"))
        for _ in 0..<40 where model.sshStatus == nil { try await Task.sleep(for: .milliseconds(25)) }
        #expect(model.sshStatus == frameSshStatus)
        #expect(screen.enabled("Socket") == false)
    }

    @Test("Parity w-15-app-settings: INT-08.26's three switches edit; no signer or Generate (option b only)")
    func share() async throws {
        let model = settingsModel()
        model.go(.share)
        let screen = SettingsScreen(model)
        await screen.settle()
        #expect(!model.flag("share.import") && !model.flag("share.export"), "INT-08.7: off by default")
        #expect(model.flag("share.quiet"), "INT-08.7 (D-INT08-10): on by default")
        try await screen.press("Allow import")
        try await screen.press("Allow export")
        #expect(model.flag("share.import") && model.flag("share.export"))
        try await screen.press("Hide sync success messages")
        #expect(!model.flag("share.quiet"))
        #expect(screen.node("Your identity") == nil && screen.node("Export certificate…") == nil)
        let help =
            "A shared group is a group of your vault, shared as a file. Set one up on the Sharing page of the "
            + "group's editor. These switches apply to every vault on this Mac."
        #expect(screen.node(help) != nil, "F-175: the straight apostrophe")
    }

    @Test("Parity settings-settings-shortcuts: the page lists the mockup's actions and keys; the search finds it")
    func shortcuts() async throws {
        let model = settingsModel()
        model.go(.keys)
        let screen = SettingsScreen(model)
        await screen.settle()
        #expect(screen.node("Copy Username") != nil)
        model.query = "generator"
        await screen.settle()
        #expect(model.visiblePages == [.keys])
    }
}
