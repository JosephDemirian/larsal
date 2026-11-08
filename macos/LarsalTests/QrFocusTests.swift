import AppKit
import LarsalCore
import SwiftUI
import Testing

/// What the dialog says and where the keys go (FEA-10.13). Offscreen only: a
/// never-ordered window that may say it is key, never a focused window on the
/// screen (AGENTS.md rule 10). A person's check in a real key window stays
/// W-08.
@MainActor
@Suite(.serialized)
struct QrFocusTests {
    init() { ParityDemo.setUp() }

    @Test("QR-T16 FEA-10.13: the words and the image's name, no payload; a long name wraps and the buttons stay")
    func accessibility() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let secret = "demo-pass-unique-77"
        let demo = try QrDemo.window("qr-ax", password: secret)
        defer { demo.window.lockAll() }
        let (window, main, id) = (demo.window, demo.main, demo.entry)
        let screen = Screen(window)
        await screen.settle()
        main.showQr()
        let popup = try await QrDemo.answered(main)
        popup.settle()
        await screen.settle()
        try await QrDemo.render(screen.host)
        await screen.settle()
        let strings = screen.strings()
        for line in [QrText.title, "Password", QrText.exposure, QrText.capture, "Save Image…", "Done"] {
            #expect(strings.contains(line), "\(line)")
        }
        #expect(screen.node("QR code for Password") != nil, "the image is named")
        #expect(!strings.joined().contains(secret))
        #expect(AccessWalk.check(screen.host, screen: "QR pop-up", secrets: [secret]).isEmpty)
        // Keyboard: Save Image… opens the warning; its Cancel returns.
        try await screen.press("Save Image…")
        await screen.settle()
        #expect(popup.stage == .warning(.save))
        #expect(screen.strings().contains(QrText.warning))
        popup.scrimClicked()
        #expect(popup.stage == .warning(.save), "a click outside leaves the warning up")
        popup.escape()
        #expect(popup.stage == .code, "Escape answers the warning as Cancel")
        popup.scrimClicked()
        #expect(popup.stage == .closed, "a click outside dismisses the pop-up")
        // Long names: whole, in plain text, with the buttons inside the dialog.
        let ticket = { try window.session.qrShowField(vault: main.vault.id, entry: id, field: "Password") }
        for count in [80, 81, 400, 5_000] {
            let name = String(repeating: "long name ", count: count / 10)
            let long = QrPopup(model: main, request: .field(entry: id, name: name), purpose: name, now: { .now })
            long.received(.success(try ticket()))
            long.settle()
            let host = QrDemo.host(long, size: CGSize(width: 640, height: 860))
            try await QrDemo.render(host)
            #expect(!long.sizeRefused, "\(count)")
            #expect(long.purpose == name, "\(count): not cut")
            #expect(QrDemo.texts(host).contains { $0.contains(name) }, "\(count): the whole name")
            #expect(!QrDemo.texts(host).contains { $0.contains("…\u{0}") || $0.hasSuffix(name.prefix(80) + "…") })
            let done = try #require(QrDemo.named(host, "Done").first)
            let box = done.accessibilityFrame?() ?? .zero
            let bounds = try #require(host.window).frame
            #expect(bounds.contains(box) && box.height > 0, "\(count): Done is inside the dialog: \(box)")
            long.revoke()
        }
    }

    @Test("QR-T16 FEA-10.13: Tab and Shift-Tab cycle the enabled stops; the warning focuses Cancel and returns")
    func focusCycle() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-focus")
        defer { demo.window.lockAll() }
        let main = demo.main
        main.showQr()
        var popup = try await QrDemo.painted(main)
        #expect(popup.focus == .done, "Done first")
        #expect(popup.focusStops == [.save, .done], "Share is unavailable: no stop")
        popup.moveFocus()
        #expect(popup.focus == .save, "from the last round to the first")
        popup.moveFocus()
        #expect(popup.focus == .done)
        popup.moveFocus(back: true)
        #expect(popup.focus == .save)
        popup.activateFocus()
        #expect(popup.stage == .warning(.save) && popup.focus == .cancel, "the warning focuses Cancel")
        #expect(popup.focusStops == [.cancel, .confirm], "and traps it")
        popup.moveFocus()
        #expect(popup.focus == .confirm)
        popup.moveFocus()
        #expect(popup.focus == .cancel)
        popup.activateFocus()
        #expect(popup.stage == .code && popup.focus == .save, "back to the button that asked")
        popup.revoke()
        // With a route Share is a stop, and its warning returns to it.
        VaultModel.qrShareRoutes = [.sendViaAirDrop]
        main.showQr()
        popup = try await QrDemo.painted(main)
        #expect(popup.focusStops == [.save, .share, .done])
        popup.ask(.share)
        popup.cancelWarning()
        #expect(popup.focus == .share)
        popup.focus = .done
        popup.activateFocus()
        #expect(popup.stage == .closed, "Space on Done")
        // A refusal has only Done.
        main.showQr(field: "Notes")
        popup = try await QrDemo.answered(main)
        #expect(popup.focusStops == [.done])
        popup.revoke()
    }

    @Test("QR-T16 FEA-10.13: real Tab, Shift-Tab and Space move the focus and the warning traps it, in a key window")
    func realKeys() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-keys")
        defer { demo.window.lockAll() }
        let main = demo.main
        main.showQr()
        let popup = try await QrDemo.answered(main)
        let window = QrKeyWindow(
            contentRect: NSRect(x: -20_000, y: -20_000, width: 480, height: 800), styleMask: [.borderless],
            backing: .buffered, defer: false)
        let host = QrDemo.placed(NSHostingView(rootView: QrDemo.root(popup)), window: window)
        try await QrDemo.render(host)
        let tab = try QrDemo.key(48, "\t")
        let (back, space) = (try QrDemo.key(48, "\u{19}", .shift), try QrDemo.key(49, " "))
        #expect(window.makeFirstResponder(host))
        try await QrDemo.press(tab, in: window, host)
        #expect(popup.focus == .save, "Tab wraps from Done to Save Image…: Share is unavailable")
        try await QrDemo.press(back, in: window, host)
        #expect(popup.focus == .done, "Shift-Tab goes back")
        try await QrDemo.press(tab, in: window, host)
        try await QrDemo.press(space, in: window, host)
        #expect(popup.stage == .warning(.save) && popup.focus == .cancel, "Space on Save Image…: Cancel has the focus")
        try await QrDemo.press(tab, in: window, host)
        #expect(popup.focus == .confirm)
        try await QrDemo.press(tab, in: window, host)
        #expect(popup.focus == .cancel, "the warning traps Tab")
        try await QrDemo.press(space, in: window, host)
        #expect(popup.stage == .code && popup.focus == .save, "Space on Cancel: back to the button that asked")
        try await QrDemo.press(back, in: window, host)
        try await QrDemo.press(space, in: window, host)
        #expect(popup.stage == .closed, "Space on Done")
    }

    @Test("QR-T16 FEA-10.13: the ring is drawn where the focus is, and nowhere else")
    func focusRing() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-ring")
        defer { demo.window.lockAll() }
        let main = demo.main
        _ = Screen(demo.window)  // Its process flag builds the accessibility nodes.
        main.showQr()
        let popup = try await QrDemo.answered(main)
        let host = QrDemo.host(popup)
        try await QrDemo.render(host)
        let window = try #require(host.window)
        let box = { (name: String) throws -> CGRect in
            let frame = try #require(QrDemo.named(host, name).first?.accessibilityFrame?(), "\(name)")
            return CGRect(
                x: frame.minX - window.frame.minX, y: window.frame.maxY - frame.maxY, width: frame.width,
                height: frame.height)
        }
        let (done, save) = (try box("Done"), try box("Save Image…"))
        // The four points above a button, where its ring would be.
        let band = { (rep: NSBitmapImageRep, box: CGRect) -> [NSColor?] in
            let scale = CGFloat(rep.pixelsWide) / host.bounds.width
            return (1...4).map { rep.colorAt(x: Int(box.midX * scale), y: Int((box.minY - CGFloat($0)) * scale)) }
        }
        let onDone = try QrDemo.picture(host)
        popup.focus = .save
        try await QrDemo.render(host)
        let onSave = try QrDemo.picture(host)
        #expect(band(onDone, done) != band(onSave, done), "the ring left Done")
        #expect(band(onDone, save) != band(onSave, save), "the ring came to Save Image…")
        popup.focus = .done
        try await QrDemo.render(host)
        #expect(band(try QrDemo.picture(host), done) == band(onDone, done), "and back")
        popup.revoke()
    }

    @Test("QR-T16 FEA-10.13: the fallback target is the list: real arrow keys reach it only after its turn")
    func listTakesFocus() async throws {
        // Its turns go to `QrFocus.shared`, whose turns the other QR tests count.
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-list-focus")
        defer { demo.window.lockAll() }
        let main = demo.main
        let first = try #require(main.rows.first?.id)
        main.select(first)
        let size = CGSize(width: 1_320, height: 820)
        let window = QrKeyWindow(
            contentRect: NSRect(origin: CGPoint(x: -20_000, y: -20_000), size: size), styleMask: [.borderless],
            backing: .buffered, defer: false)
        let host = QrDemo.placed(
            NSHostingView(rootView: MainWindow(model: demo.window).frame(width: size.width, height: size.height)),
            size: size, window: window)
        try await QrDemo.render(host)
        let down = try QrDemo.key(125, "\u{F701}", [.function, .numericPad])
        try await QrDemo.press(down, in: window, host)
        #expect(main.selection == first, "the keys do not reach the list yet")
        QrFocus.shared.give(to: nil)
        try await QrDemo.render(host)
        try await QrDemo.press(down, in: window, host)
        #expect(main.selection == first, "another window's turn is not this list's")
        QrFocus.shared.give(to: main)
        try await QrDemo.render(host)
        try await QrDemo.press(down, in: window, host)
        #expect(main.selection != first, "they do now")
    }

    @Test("QR-T16 FEA-10.13: a click on a disabled button leaves the ring in the cycle; on an enabled one it moves")
    func clickOnDisabledStop() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-click")
        defer { demo.window.lockAll() }
        let main = demo.main
        _ = Screen(demo.window)  // Its process flag builds the accessibility nodes.
        main.showQr()
        let popup = try await QrDemo.answered(main)
        #expect(!popup.shareAvailable, "Share… is disabled")
        let window = QrKeyWindow(
            contentRect: NSRect(x: -20_000, y: -20_000, width: 480, height: 800), styleMask: [.borderless],
            backing: .buffered, defer: false)
        let host = QrDemo.placed(NSHostingView(rootView: QrDemo.root(popup)), window: window)
        try await QrDemo.render(host)
        #expect(window.makeFirstResponder(host))
        // Delivered to the hosting view: a never-ordered window routes no mouse event itself.
        func click(_ name: String) throws {
            let box = try #require(QrDemo.named(host, name).first?.accessibilityFrame?(), "\(name)")
            let place = CGPoint(x: box.midX - window.frame.minX, y: box.midY - window.frame.minY)
            host.mouseDown(
                with: try #require(
                    NSEvent.mouseEvent(
                        with: .leftMouseDown, location: place, modifierFlags: [], timestamp: 0,
                        windowNumber: window.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)))
        }
        try click("Share…")
        try await QrDemo.render(host)
        #expect(popup.focus == .done, "the ring stays in the cycle")
        try click("Save Image…")
        try await QrDemo.render(host)
        #expect(popup.focus == .save, "the clicks do arrive")
        popup.revoke()
    }
}
