import AppCore
import AppKit
import SwiftUI
import Testing

/// Stored settings that reach the parts using them (E5-S9, Checker 1 F2,
/// F3).
@MainActor
@Suite(.serialized)
struct AppSettingsEffectsTests {
    @Test("APP-01.27 a, b: the search clears a while after the field lost focus; focus back stops it")
    func searchClears() async throws {
        let session = Session()
        let vault = VaultInfo(
            id: 1, name: "demo", path: "", hue: 0, locked: false, unlocking: false, shown: true, colour: nil, icon: -1,
            lockedAt: nil, keyChange: nil
        )
        let model = VaultModel(session: session, vault: vault)
        let clearer = SearchClearTimer()
        clearer.minute = .milliseconds(150)
        let settings = settingsModel(session)
        settings.setNumber("search.clear_after_minutes", 1)
        #expect(settings.ok())
        // S-TIME-05 off (the default): never cleared.
        model.setSearch("git")
        clearer.focus(false, model)
        try await Task.sleep(for: .milliseconds(450))
        #expect(model.search == "git", "S-TIME-05 off")
        settings.setFlag("search.clear_when_idle", true)
        #expect(settings.ok())
        // b: focus back before the end stops the countdown.
        clearer.focus(false, model)
        clearer.focus(true, model)
        try await Task.sleep(for: .milliseconds(450))
        #expect(model.search == "git", "b: focus back stops it")
        // a: focus lost, one minute: the text is cleared.
        clearer.focus(false, model)
        for _ in 0..<80 where !model.search.isEmpty { try await Task.sleep(for: .milliseconds(25)) }
        #expect(model.search.isEmpty, "a: cleared")
        // a: S-TIME-06 sets the wait: 20 minutes of 25 ms is 500 ms. Load
        // only delays the clear, so the early check cannot fail falsely.
        clearer.minute = .milliseconds(25)
        settings.setNumber("search.clear_after_minutes", 20)
        #expect(settings.ok())
        model.setSearch("git")
        clearer.focus(false, model)
        try await Task.sleep(for: .milliseconds(250))
        #expect(model.search == "git", "S-TIME-06: not before 20 minutes")
        for _ in 0..<120 where !model.search.isEmpty { try await Task.sleep(for: .milliseconds(25)) }
        #expect(model.search.isEmpty, "S-TIME-06: cleared after 20 minutes")
    }

    @Test("APP-01.27 c: a change of selected entry restarts a running search clear countdown from full")
    func searchClearRestartsOnSelection() async throws {
        ParityDemo.setUp()
        let window = try ParityDemo.window("search-clear-selection")
        defer { window.lockAll() }
        try window.session.saveSettings(changes: [
            AppSetting(key: "search.clear_when_idle", value: .flag(on: true)),
            AppSetting(key: "search.clear_after_minutes", value: .number(value: 1)),
        ])
        let main = try #require(window.main)
        main.searchClearer.minute = .seconds(2)
        let other = try #require(main.rows.first { $0.id != main.selection }?.id)
        let screen = Screen(window)  // the vault view: its selection change restarts the countdown
        await screen.settle()
        main.setSearch("o")
        main.searchClearer.focus(false, main)  // the field lost the focus
        try await Task.sleep(for: .milliseconds(1_200))
        main.select(other)
        await screen.settle()
        try await Task.sleep(for: .milliseconds(1_200))
        #expect(main.search == "o", "restarted: not cleared 2 s after the focus loss")
        for _ in 0..<200 where !main.search.isEmpty { try await Task.sleep(for: .milliseconds(25)) }
        #expect(main.search.isEmpty, "cleared a full wait after the new selection")
    }

    @Test("S-UI-07 (APP-01.24, LD-212 (5)): on by default; the detail's shown password follows the switch")
    func colourPasswords() async throws {
        let session = Session()
        let view = ViewOptions()
        view.load(session.settings())
        #expect(view.colourPasswords, "on by default")
        #expect(PasswordRow.secret("aB3$", coloured: true) != Text(verbatim: "aB3$"), "digits and symbols coloured")
        view.set("display.color_passwords", false, session)
        #expect(!view.colourPasswords)
        #expect(PasswordRow.secret("aB3$", coloured: false) == Text(verbatim: "aB3$"), "plain when off")
        // The drawn detail, offscreen: the shown password's coloured ink
        // follows the switch through the vault view.
        ParityDemo.setUp()
        let window = try ParityDemo.window("s-ui-07")
        defer { window.lockAll() }
        let main = try #require(window.main)
        let screen = Screen(window)
        await screen.settle()
        await main.toggleShow("Password")
        let shown = try #require(main.shown["Password"])
        #expect(shown.contains { $0.isNumber || !($0.isLetter || $0.isWhitespace) }, "a digit or symbol to colour")
        var ink: [Bool: Int] = [:]
        for coloured in [true, false] {
            window.view.set("display.color_passwords", coloured, window.session)
            await screen.settle()
            let text = try #require(screen.nodes().first { Self.value($0) == shown }, "the shown password")
            ink[coloured] = try Self.colouredPixels(screen, in: screen.box(text))
        }
        #expect((ink[true] ?? 0) > 20, "on: digits and symbols in colour \(ink)")
        #expect(ink[false] == 0, "off: plain \(ink)")
    }

    private static func value(_ element: AnyObject) -> String {
        let value: Any? = element.accessibilityValue?() ?? nil
        return (value as? String) ?? ""
    }

    /// The pixels in `box` (points) far from grey: the plain ink and the
    /// ground are grey, Tok.digit and Tok.symbol are not.
    private static func colouredPixels(_ screen: Screen, in box: CGRect) throws -> Int {
        let image = try #require(screen.host.bitmapImageRepForCachingDisplay(in: screen.host.bounds))
        screen.host.cacheDisplay(in: screen.host.bounds, to: image)
        let scale = CGFloat(image.pixelsWide) / screen.host.bounds.width
        var count = 0
        for row in Int(box.minY * scale)..<Int(box.maxY * scale) {
            for col in Int(box.minX * scale)..<Int(box.maxX * scale) {
                guard let pixel = image.colorAt(x: col, y: row)?.usingColorSpace(.sRGB) else { continue }
                let parts = [pixel.redComponent, pixel.greenComponent, pixel.blueComponent]
                if (parts.max() ?? 0) - (parts.min() ?? 0) > 0.25 { count += 1 }
            }
        }
        return count
    }

    @Test("Mac QA snapshots keep the look they asked for over S-VIEW-01 (debug builds)")
    func debugAppearanceWins() {
        let app = NSApplication.shared  // the test process's own, never shown
        let before = app.appearance
        defer { app.appearance = before }
        let session = Session()
        let model = settingsModel(session)
        model.setText("ui.theme", "dark")
        #expect(model.ok())
        Appearance.apply(session.settings(), environment: ["APP_DEBUG_APPEARANCE": "light"])
        #expect(app.appearance?.name == .aqua)
        Appearance.apply(session.settings(), environment: [:])
        #expect(app.appearance?.name == .darkAqua)
    }
}
