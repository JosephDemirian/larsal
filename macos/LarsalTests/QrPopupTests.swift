import AppKit
import LarsalCore
import SwiftUI
import Testing

/// The pop-up's life (FEA-10.1 to .3, .11 to .15). Offscreen only: a fake
/// clock, private notification centers, never a real panel, picker or
/// notification (AGENTS.md rule 10).
@MainActor
@Suite(.serialized)
struct QrPopupTests {
    init() { ParityDemo.setUp() }

    @Test("QR-T01 FEA-10.3: in the editor the draft is asked for, and nothing changes")
    func draftActions() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-draft")
        defer { demo.window.lockAll() }
        let (window, main, id) = (demo.window, demo.main, demo.entry)
        main.edit(id)
        let editor = try #require(main.editor)
        let before = try window.session.saveStatus(vault: main.vault.id).changes
        editor.showQr("Password")
        let popup = try await QrDemo.answered(main)
        #expect(popup.request == .draft(name: "Password") && popup.stage == .code)
        main.showQrFromKeys(focused: "Notes")
        #expect(main.qrPopup?.request == .draft(name: "Notes"))
        main.qrPopup?.revoke()
        #expect(try window.session.saveStatus(vault: main.vault.id).changes == before)
        main.closeEditor()
    }

    @Test("QR-T02 FEA-10.2: no selection, a lock or a sheet disable it; a bad call shows no old matrix")
    func refusals() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-refusals")
        let (window, main, id) = (demo.window, demo.main, demo.entry)
        main.select(id)
        main.dialog = .clone(id: id, title: "QR demo")
        var items = await MenuLine.read(EntryMenuItems(window: window))
        #expect(items.line(QrText.title)?.enabled == false, "a sheet is open")
        main.dialog = nil
        items = await MenuLine.read(EntryMenuItems(window: window))
        #expect(items.line(QrText.title)?.enabled == true)
        main.select(nil)
        items = await MenuLine.read(EntryMenuItems(window: window))
        #expect(items.line(QrText.title)?.enabled == false, "no selection")
        main.showQr()
        #expect(main.qrPopup == nil)
        main.select(id)
        // Live, then a failing request: the old matrix is gone with no new one.
        main.showQr()
        let live = try await QrDemo.answered(main)
        #expect(live.symbol != nil)
        main.showQr(field: "No such field")
        #expect(live.stage == .closed && live.symbol == nil)
        let failed = try await QrDemo.answered(main)
        guard case .refused = failed.stage else {
            Issue.record("no refusal")
            return
        }
        #expect(failed.symbol == nil && !failed.canExport)
        failed.ask(.save)
        #expect(failed.stage != .warning(.save))
        failed.revoke()
        main.showQr(field: "Notes")
        let empty = try await QrDemo.answered(main)
        #expect(empty.stage == .refused("This field is empty."))
        empty.revoke()
        window.lockAll()
        items = await MenuLine.read(EntryMenuItems(window: window))
        #expect(items.line(QrText.title)?.enabled == false, "locked")
    }

    @Test("QR-T03 FEA-10.3: a saved value reads back byte for byte: whitespace, control bytes, its end")
    func savedBytes() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-saved-bytes")
        defer { demo.window.lockAll() }
        let (session, vault) = (demo.session, demo.vault)
        for value in [" ", "\t", "\r\n", "\n", "a\u{0}b", "a\n", "a ", "  demo  "] {
            let entry = try QrDemo.entry(
                session, vault, [("Title", "Bytes"), ("Password", value), ("Demo note", value)])
            for field in ["Password", "Demo note"] {
                let shown = try session.qrShowField(vault: vault, entry: entry, field: field)
                let got = try QrRead.payload(shown.symbol)
                #expect(got.bytes == Data(value.utf8) && got.eci == 26, "\(field): \(Array(value.utf8))")
            }
        }
    }

    @Test("QR-T06 FEA-10.9: an unknown placeholder stays literal; a missing reference is empty")
    func resolution() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-resolve", password: "{FOO}")
        defer { demo.window.lockAll() }
        let main = demo.main
        main.showQr()
        var popup = try await QrDemo.answered(main)
        #expect(try QrRead.payload(try #require(popup.symbol)).bytes == Data("{FOO}".utf8))
        popup.revoke()
        let (session, vault) = (demo.session, demo.vault)
        let missing = try QrDemo.entry(session, vault, [("Title", "Missing"), ("Password", "{REF:P@T:Nonexistent}")])
        main.afterChange(select: missing)
        main.select(missing)
        main.showQr()
        popup = try await QrDemo.answered(main)
        #expect(popup.stage == .refused("This field is empty."))
        popup.revoke()
        main.showQr(field: "TimeOtp-Secret-Base32")
        popup = try await QrDemo.answered(main)
        if case .refused = popup.stage {} else { Issue.record("the excluded field must error") }
        popup.revoke()
    }

    @Test("QR-T12 FEA-10.6: the demo's WPA3 entry refuses the join; its Password stays offered")
    func wifiRefusal() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let window = try ParityDemo.window("qr-wpa3")
        defer { window.lockAll() }
        let main = try #require(window.main)
        main.select(try #require(main.rows.first { $0.title == "Home Wi-Fi" }?.id))
        #expect(main.canJoinWifi)
        main.showWifiJoin()
        var popup = try await QrDemo.answered(main)
        let refusal =
            "This network type cannot be shared as a Wi-Fi join code. Show an individual field as text instead."
        #expect(popup.stage == .refused(refusal))
        #expect(!popup.canExport)
        popup.revoke()
        main.showQr()
        popup = try await QrDemo.answered(main)
        #expect(popup.stage == .code)
        popup.revoke()
    }
}
