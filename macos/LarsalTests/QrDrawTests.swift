import AppKit
import LarsalCore
import SwiftUI
import Testing

/// How the pop-up draws and reads (FEA-10.11 to .13, .21). Offscreen only.
@MainActor
@Suite(.serialized)
struct QrDrawTests {
    init() { ParityDemo.setUp() }

    @Test("QR-T14 FEA-10.11: no code until the motion has truly ended; Reduce Motion paints at once; no restart")
    func motion() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-motion")
        defer { demo.window.lockAll() }
        let main = demo.main
        main.showQr()
        let popup = try await QrDemo.answered(main)
        #expect(!popup.settled && popup.paintable() == nil && popup.seconds == nil, "during entry: no code")
        // A motion far longer than the frames': no timer can mistake its end.
        let start = ContinuousClock.now
        let moving = QrDemo.host(popup, reduce: false, motion: .easeOut(duration: 1.5))
        try await QrDemo.render(moving)
        if start.duration(to: .now) < .seconds(1.4) {
            #expect(!popup.settled && popup.seconds == nil, "the deadline waits for the first complete code")
        }
        for _ in 0..<3_000 where !popup.settled {
            moving.layoutSubtreeIfNeeded()
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(start.duration(to: .now) >= .seconds(1.5), "the motion ended, not a timer beside it")
        #expect(popup.settled, "the motion's own end")
        try await QrDemo.render(moving)
        #expect(popup.seconds == 44, "the first complete frame starts it")
        // A later settle, Reduce Motion or repaint never moves the deadline.
        seams.elapsed = .seconds(5)
        popup.settle()
        try await QrDemo.render(QrDemo.host(popup, reduce: true))
        popup.tick()
        #expect(popup.seconds == 39)
        popup.revoke()
        #expect(popup.symbol == nil && popup.paintable() == nil, "dismissal clears at once")
        // Reduce Motion on: painted at once, before any 160 ms.
        main.showQr()
        let still = try await QrDemo.answered(main)
        try await QrDemo.render(QrDemo.host(still, reduce: true))
        #expect(still.settled && still.seconds == 44)
        still.revoke()
    }

    @Test("QR-T14 FEA-10.11: Reduce Motion changed live: at rest at once before the code, no restart after it")
    func motionChangedLive() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-motion-live", password: "demo-motion-value")
        defer { demo.window.lockAll() }
        let main = demo.main
        main.showQr()
        let popup = try await QrDemo.answered(main)
        let slow = Animation.easeOut(duration: 60)
        let host = QrDemo.host(popup, reduce: false, motion: slow)
        try await QrDemo.render(host)
        #expect(!popup.settled && popup.seconds == nil, "still moving")
        // On, before the first complete code.
        host.rootView = QrDemo.root(popup, reduce: true, motion: slow)
        try await QrDemo.render(host)
        try await QrDemo.render(host)
        #expect(popup.settled && popup.seconds == 44, "settled at once, and the code starts the deadline")
        // Off and on again, after it: the same deadline, the dialog still at rest.
        seams.elapsed = .seconds(5)
        host.rootView = QrDemo.root(popup, reduce: false, motion: slow)
        try await QrDemo.render(host)
        popup.tick()
        #expect(popup.seconds == 39)
        let drawn = try #require(try QrDemo.picture(host).cgImage)
        #expect(try QrRead.payload(image: drawn).bytes == Data("demo-motion-value".utf8), "whole and opaque")
        host.rootView = QrDemo.root(popup, reduce: true, motion: slow)
        try await QrDemo.render(host)
        popup.tick()
        #expect(popup.seconds == 39)
        popup.revoke()
    }

    @Test("QR-T15 FEA-10.12: every version and scale in whole pixels; N185 is 599 pt at 1×, 277.5 at 2×")
    func geometry() throws {
        for version in 1...40 {
            let side = 17 + 4 * version + 8
            for scale in [1.0, 2.0, 3.0] as [CGFloat] {
                let layout = QrLayout(modules: side, scale: scale)
                #expect(layout.pitch >= 3)
                #expect(CGFloat(layout.pitch) == (CGFloat(layout.pitch) * 1).rounded())
                #expect((layout.points * scale).rounded() == layout.points * scale, "whole pixels")
                #expect((layout.leading * scale).rounded() == layout.leading * scale, "a whole-pixel origin")
                #expect(layout.points <= 296 || layout.pitch == 3, "296 pt is preferred")
            }
        }
        let dense1x = QrLayout(modules: 185, scale: 1)
        #expect(dense1x.pitch == 3 && dense1x.points == 555 && dense1x.outer == 599)
        let dense2x = QrLayout(modules: 185, scale: 2)
        #expect(dense2x.pitch == 3 && dense2x.points == 277.5)
        #expect(dense2x.outer == 460 && dense2x.leading == 69.5)
        #expect(QrLayout(modules: 29, scale: 1).pitch == 10)
    }

    @Test("QR-T15 FEA-10.12: pure #000 and #FFF, whole cells, four white quiet modules")
    func pixels() throws {
        for size in [1, 300, 1_272] {
            let window = try ParityDemo.window("qr-pixels")
            defer { window.lockAll() }
            let (session, vault) = (window.session, try #require(window.main?.vault.id))
            _ = try session.beginNew(vault: vault, group: nil)
            _ = try session.setPassword(vault: vault, value: String(repeating: "x", count: size))
            let symbol = try session.qrShowDraft(vault: vault, field: "Password").symbol
            try session.cancelEdit(vault: vault)
            let side = Int(symbol.size)
            let pitch = QrLayout(modules: side, scale: 1).pitch
            let rep = try QrRead.draw(symbol, pitch: pitch)
            #expect(rep.pixelsWide == side * pitch)
            for row in stride(from: 0, to: side, by: max(1, side / 40)) {
                for column in stride(from: 0, to: side, by: max(1, side / 40)) {
                    let cell = symbol.modules[symbol.modules.startIndex + row * side + column]
                    // The first and last pixel of each cell: no blur at its edges.
                    for edge in [0, pitch - 1] {
                        let pixel = rep.colorAt(x: column * pitch + edge, y: row * pitch + edge)
                        let color = try #require(pixel?.usingColorSpace(.deviceRGB))
                        let wanted: CGFloat = cell == 1 ? 0 : 1
                        #expect(color.redComponent == wanted && color.greenComponent == wanted)
                        #expect(color.blueComponent == wanted && color.alphaComponent == 1)
                    }
                    if min(row, column) < 4 || max(row, column) >= side - 4 { #expect(cell == 0) }
                }
            }
        }
    }

    @Test("QR-T15 FEA-10.12: too small a space gives MSG-QR-SIZE: no paint, no deadline, no export")
    func tooSmall() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-size")
        defer { demo.window.lockAll() }
        let main = demo.main
        main.showQr()
        let popup = try await QrDemo.answered(main)
        let host = QrDemo.host(popup, size: CGSize(width: 480, height: 300))
        try await QrDemo.render(host)
        #expect(popup.sizeRefused)
        #expect(popup.seconds == nil && popup.paintable() == nil && !popup.canExport)
        popup.ask(.save)
        #expect(popup.stage == .code, "no export")
        // Larger: the code comes; never scaled or cropped on the way.
        host.setFrameSize(CGSize(width: 900, height: 900))
        host.rootView = AnyView(QrPopupView(popup: popup, reduceMotion: true).frame(width: 900, height: 900))
        try await QrDemo.render(host)
        try await QrDemo.render(host)
        #expect(!popup.sizeRefused)
        #expect(popup.seconds == 44)
        popup.revoke()
    }

    @Test("QR-T15 FEA-10.12 FEA-10.14: MSG-QR-SIZE holds no matrix or ticket with no end; the bound closes it")
    func tooSmallIsBounded() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-size-bound")
        defer { demo.window.lockAll() }
        let (main, session, vault) = (demo.main, demo.session, demo.vault)
        main.showQr()
        var popup = try await QrDemo.answered(main)
        let ticket = try #require(popup.liveTicket)
        try await QrDemo.render(QrDemo.host(popup, size: CGSize(width: 480, height: 300)))
        #expect(popup.sizeRefused && popup.symbol != nil)
        seams.elapsed = .seconds(43)
        popup.tick()
        #expect(popup.stage == .code, "inside the bound")
        seams.elapsed = .seconds(44)
        popup.tick()
        #expect(popup.stage == .closed && popup.symbol == nil && main.dialog == nil)
        #expect(!session.qrIsCurrent(vault: vault, ticket: ticket), "the ticket went with it")
        // Larger inside the bound: the code comes with its own whole 44 seconds.
        main.showQr()
        popup = try await QrDemo.answered(main)
        let host = QrDemo.host(popup, size: CGSize(width: 480, height: 300))
        try await QrDemo.render(host)
        seams.elapsed += .seconds(43)
        host.setFrameSize(CGSize(width: 900, height: 900))
        host.rootView = QrDemo.root(popup, size: CGSize(width: 900, height: 900))
        try await QrDemo.render(host)
        try await QrDemo.render(host)
        #expect(popup.seconds == 44)
        seams.elapsed += .seconds(43)
        #expect(popup.live(), "the bound is over once the code is up")
        popup.revoke()
    }

    @Test("QR-T25 FEA-10.21: the pop-up's window reads back as the guard says: the real main window, then off and on")
    func captureGuard() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-guard")
        defer { demo.window.lockAll() }
        let main = demo.main
        // The real path: the pop-up inside MainWindow, whose chrome adopted it
        // before anything drew.
        let screen = Screen(demo.window)
        await screen.settle()
        main.showQr()
        let popup = try await QrDemo.answered(main)
        popup.settle()
        await screen.settle()
        #expect(screen.node("QR code for Password") != nil, "the code is in this window")
        let wanted: NSWindow.SharingType = ScreenProtection.shared.allowed ? .readOnly : .none
        #expect(screen.window.sharingType == wanted)
        for allowed in [false, true] {
            let protection = ScreenProtection()
            protection.allow(allowed)
            let box = protection.window(NSRect(x: -20_000, y: -20_000, width: 600, height: 900), style: [.borderless])
            box.contentView = NSHostingView(rootView: QrPopupView(popup: popup, reduceMotion: true))
            #expect(box.sharingType == (allowed ? .readOnly : .none))
            box.contentView = nil
        }
        popup.revoke()
    }

    @Test("QR-T29 FEA-10.14: a late answer is dropped; a new pop-up ends the old; a bad matrix never draws")
    func lateAndMalformed() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-late")
        defer { demo.window.lockAll() }
        let (main, id) = (demo.main, demo.entry)
        let (session, vault) = (demo.session, demo.vault)
        main.showQr()
        let first = try await QrDemo.answered(main)
        let ticket = try session.qrShowField(vault: vault, entry: id, field: "Password")
        #expect(!first.live(), "the newer request ended it")
        first.revoke()
        // An answer to a closed pop-up: its ticket is released, never shown.
        first.received(.success(ticket))
        #expect(first.symbol == nil && first.stage == .closed)
        #expect(!session.qrIsCurrent(vault: vault, ticket: ticket.ticket))
        // Malformed matrices, each refused before drawing.
        func bad(_ size: UInt32, _ edit: (inout Data) -> Void = { _ in }) -> Qr {
            var modules = Data(repeating: 0, count: Int(size) * Int(size))
            edit(&modules)
            return Qr(size: size, modules: modules)
        }
        #expect(QrPopup.valid(bad(29)))
        #expect(!QrPopup.valid(bad(21)) && !QrPopup.valid(bad(30)) && !QrPopup.valid(bad(189)))
        #expect(!QrPopup.valid(Qr(size: 29, modules: Data(count: 10))))
        #expect(!QrPopup.valid(bad(29) { $0[500] = 2 }), "a non-binary cell")
        #expect(!QrPopup.valid(bad(29) { $0[0] = 1 }), "a dark quiet zone")
        let popup = QrPopup(model: main, request: .wifi(entry: id), purpose: "x", now: { .now })
        popup.received(.success(QrShown(ticket: 1, symbol: bad(30))))
        #expect(popup.stage == .refused(QrText.failed) && popup.symbol == nil)
        popup.revoke()
    }
}
