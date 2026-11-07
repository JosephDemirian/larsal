import AppKit
import LarsalCore
import SwiftUI
import Testing

/// QR-T01 in the editor: each visible button gives the draft's value, not the
/// saved one, and saves nothing (FEA-10.1, .3). Offscreen only (AGENTS.md rule 10).
@MainActor
@Suite(.serialized)
struct QrDraftEntryTests {
    init() { ParityDemo.setUp() }

    @Test("QR-T01 FEA-10.3: in the editor each visible button gives the draft's value, masked and shown; nothing saved")
    func draftButtons() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let (demo, values) = try QrDemo.protected("qr-draft-buttons")
        defer { demo.window.lockAll() }
        let (window, main, id) = (demo.window, demo.main, demo.entry)
        let (session, vault) = (demo.session, demo.vault)
        let before = try QrDemo.savedAt(demo)
        main.edit(id)
        let editor = try #require(main.editor)
        _ = try session.setPassword(vault: vault, value: "typed-not-saved")
        editor.refresh()
        let screen = Screen(window)
        await screen.settle()
        let onEntry = try await QrDemo.pressEach(screen.host, main)
        #expect(onEntry == [.draft(name: "Password"): Data("typed-not-saved".utf8)], "the literal draft")
        editor.page = .advanced
        await screen.settle()
        let custom = ["PIN", "Private key note"]
        let wanted = Dictionary(
            uniqueKeysWithValues: custom.map { (QrRequest.draft(name: $0), Data((values[$0] ?? "").utf8)) })
        #expect(try await QrDemo.pressEach(screen.host, main) == wanted, "masked")
        for name in custom { editor.toggleShowField(name) }
        #expect(editor.shownFields.count == 2)
        await screen.settle()
        #expect(try await QrDemo.pressEach(screen.host, main) == wanted, "shown")
        try QrDemo.expectUnchanged(demo, since: before)
        main.closeEditor()
        let saved = try session.qrShowField(vault: vault, entry: id, field: "Password")
        #expect(try QrRead.payload(saved.symbol).bytes == Data("demo-pass".utf8), "the saved value is as it was")
    }

    @Test("QR-T01 FEA-10.1: the editor's button on each protected standard field gives its draft, masked and shown")
    func draftProtectedStandard() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-draft-standard")
        defer { demo.window.lockAll() }
        let (window, main, id) = (demo.window, demo.main, demo.entry)
        let (session, vault) = (demo.session, demo.vault)
        let before = try QrDemo.savedAt(demo)
        main.edit(id)
        let real = try #require(main.editor)
        let typed: [(EditText, String)] = [
            (.title, "typed title"), (.userName, "typed user"), (.url, "https://typed.example"),
            (.notes, "typed notes"),
        ]
        for (field, text) in typed { try session.setText(vault: vault, field: field, value: text) }
        real.refresh()
        // What Rust sends for a protected standard field (F-060): the flag and no value.
        var view = real.view
        view.protected = typed.map(\.0)
        (view.title, view.user, view.url, view.notes) = ("", "", "", "")
        let editor = EditorModel(session: session, vault: main.vault, view: view)
        editor.showQr = real.showQr
        main.editor = editor
        var wanted = Dictionary(uniqueKeysWithValues: typed.map { (QrRequest.draft(name: $0.0.name), Data($0.1.utf8)) })
        wanted[.draft(name: "Password")] = Data("demo-pass".utf8)
        let screen = Screen(window)
        await screen.settle()
        #expect(try await QrDemo.pressEach(screen.host, main) == wanted, "masked")
        for (field, _) in typed { editor.toggleShowField(field.name) }
        #expect(editor.shownFields.count == typed.count)
        await screen.settle()
        #expect(try await QrDemo.pressEach(screen.host, main) == wanted, "shown")
        try QrDemo.expectUnchanged(demo, since: before)
    }
}
