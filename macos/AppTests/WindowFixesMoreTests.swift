import AppCore
import AppKit
import SwiftUI
import Testing

/// E13-S6 part d, continued: F-078, F-082 to F-084 and SD-13.
@MainActor
@Suite(.serialized)
struct WindowFixesMoreTests {
    init() { ParityDemo.setUp() }

    // MARK: F-078 lock on minimize

    @Test("F-078, APP-02.8: the app's lock on minimize waits for Rust's clipboard countdown")
    func f078MinimizeWaitsForTheClipboard() throws {
        let window = try ParityDemo.window("f078")
        let session = window.session
        try session.saveSettings(changes: [AppSetting(key: "lock.on_minimize", value: .flag(on: true))])
        var time = ContinuousClock.now
        var locks = 0
        let signals = LockSignals.app(
            session: session, workspace: NotificationCenter(), distributed: NotificationCenter(),
            local: NotificationCenter(), now: { time }, lock: { locks += 1 })
        let main = try #require(window.main)
        main.select(try githubID(main))
        main.copy("Password")  // a 10 s countdown in Rust, on a private pasteboard
        #expect(session.clipboardSecondsLeft() >= 9)
        signals.minimized()
        time += .seconds(2)
        signals.tick()
        #expect(locks == 0, "not after 1 s while the countdown runs")
        time += .seconds(9)
        signals.tick()
        #expect(locks == 1)
    }

    // MARK: F-082, F-084 hide notes, codes; dots for empty

    @Test("F-082, F-084: the stored switches reach the detail options")
    func f082Stored() throws {
        let session = Session()
        try session.saveSettings(
            changes: ["display.hide_notes", "display.hide_totp_in_preview", "display.dots_for_empty"].map {
                AppSetting(key: $0, value: .flag(on: true))
            })
        let view = ViewOptions()
        view.load(session.settings())
        #expect(view.detail == DetailOptions(hideNotes: true, hideCodes: true, dotsForEmpty: true))
    }

    /// The whole window, tall enough for the detail pane's notes.
    static let big = CGSize(width: 1320, height: 1400)

    /// Stored switch `key` on, loaded into the window's options as App's
    /// settings change does: the path from the store to the detail pane.
    static func store(_ key: String, _ window: MainWindowModel) throws {
        try window.session.saveSettings(changes: [AppSetting(key: key, value: .flag(on: true))])
        window.view.load(window.session.settings())
    }

    @Test("F-082, APP-01.23 b: S-CONV-05 hides the notes behind Show in the detail pane")
    func f082HideNotesInTheDetail() async throws {
        let window = try ParityDemo.window("f082-notes")
        let main = try #require(window.main)
        main.select(try githubID(main))
        let notes = "Recovery codes are in the attachment."
        let plain = Offscreen(VaultView(model: main, window: window), size: Self.big)
        #expect(await plain.strings().contains { $0.hasPrefix(notes) }, "off: shown")
        try Self.store("display.hide_notes", window)
        let hidden = Offscreen(VaultView(model: main, window: window), size: Self.big)
        #expect(await !hidden.strings().contains { $0.hasPrefix(notes) })
        try await hidden.press("Show notes")
        #expect(await hidden.strings().contains { $0.hasPrefix(notes) })
    }

    @Test("F-082, APP-01.23 b: S-CONV-05 hides the notes in the editor with a reveal button")
    func f082HideNotesInTheEditor() async throws {
        let window = try ParityDemo.window("f082-editor")
        let main = try #require(window.main)
        main.edit(try githubID(main))
        let editor = try #require(main.editor)
        let notes = "Recovery codes are in the attachment."
        let screen = Offscreen(
            EditorScreen(model: main, editor: editor).environment(\.detailOptions, DetailOptions(hideNotes: true)),
            size: CGSize(width: 1000, height: 1400))
        #expect(await !screen.strings().contains { $0.hasPrefix(notes) })
        try await screen.press("Show Notes")
        #expect(await screen.strings().contains { $0.hasPrefix(notes) })
        main.closeEditor()
    }

    @Test("F-082, APP-01.23 c: S-CONV-04 hides the live code until its button")
    func f082HideCodes() async throws {
        let window = try ParityDemo.window("f082-codes")
        let main = try #require(window.main)
        main.select(try githubID(main))
        let plain = Offscreen(VaultView(model: main, window: window), size: Self.big)
        #expect(await plain.strings().contains { $0.hasPrefix("New code in") }, "off: shown")
        try Self.store("display.hide_totp_in_preview", window)
        let hidden = Offscreen(VaultView(model: main, window: window), size: Self.big)
        #expect(await !hidden.strings().contains { $0.hasPrefix("New code in") })
        try await hidden.press("Show one-time code")
        #expect(await hidden.strings().contains { $0.hasPrefix("New code in") })
    }

    @Test("F-084, APP-01.23 a: S-CONV-01 draws an empty password as a filled one")
    func f084DotsForEmpty() async throws {
        let window = try ParityDemo.window("f084")
        let main = try #require(window.main)
        let id = try githubID(main)
        main.edit(id)
        try #require(main.editor).passwordTyped("")
        main.saveEditor()
        main.select(id)
        let plain = Offscreen(RailView(model: main), size: CGSize(width: 368, height: 1200))
        #expect(await !plain.strings().contains("Password"), "off: an empty password shows nothing")
        let dots = Offscreen(
            RailView(model: main).environment(\.detailOptions, DetailOptions(dotsForEmpty: true)),
            size: CGSize(width: 368, height: 1200))
        let strings = await dots.strings()
        #expect(strings.contains("Password") && strings.contains(Masked.spoken))
    }

    // MARK: F-083 search clear timer

    /// A direct restart check, robust under load (LD-230 (5)): the countdown
    /// started at the focus loss waits an hour; a restart reads the test
    /// minute again, now 200 ms, so only a restarted countdown clears.
    @Test(
        "F-083, APP-01.27: opening or closing the editor or the reports restarts the search clear countdown",
        arguments: ["editor opens", "editor closes", "reports open", "reports close"])
    func f083ScreenChangeRestarts(_ change: String) async throws {
        let window = try ParityDemo.window("f083")
        defer { window.lockAll() }
        try window.session.saveSettings(changes: [
            AppSetting(key: "search.clear_when_idle", value: .flag(on: true)),
            AppSetting(key: "search.clear_after_minutes", value: .number(value: 1)),
        ])
        let main = try #require(window.main)
        main.setSearch("git")
        if change == "editor closes" { main.edit() }
        if change == "reports close" { main.openReports() }
        main.searchClearer.minute = .seconds(3600)
        main.searchClearer.focus(false, main)  // the field lost the focus
        main.searchClearer.minute = .milliseconds(200)
        switch change {
        case "editor opens": main.edit()
        case "editor closes": main.closeEditor()
        case "reports open": main.openReports()
        default: main.closeReports()
        }
        for _ in 0..<1200 where !main.search.isEmpty { try await Task.sleep(for: .milliseconds(25)) }
        #expect(main.search.isEmpty, "restarted from full: cleared after the new wait")
        main.closeEditor()
        main.closeReports()
    }

    // MARK: SD-13 attachment preview

    @Test("SD-13, MOD-05.9, L05-3: Preview shows a text attachment as plain text inside App")
    func sd13PreviewText() async throws {
        let window = try ParityDemo.window("sd13")
        let main = try #require(window.main)
        main.select(try githubID(main))
        let name = try #require(main.detail?.attachments.first?.name)
        main.previewAttachment(name)
        guard case .preview(let shown, let preview) = main.dialog else {
            Issue.record("no preview: \(String(describing: main.dialog))")
            return
        }
        #expect(shown == name)
        guard case .text(let text) = preview else {
            Issue.record("not text")
            return
        }
        let screen = Offscreen(
            PreviewSheet(model: main, name: name, preview: preview), size: CGSize(width: 600, height: 520))
        #expect(await screen.strings().contains(text))
        try await screen.press("Done")
        #expect(main.dialog == nil)
    }
}
