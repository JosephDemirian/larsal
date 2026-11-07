import AppKit
import LarsalCore
import SwiftUI
import Testing

/// E21-S1's frames for the Mac app (design/option-a/proposals.html), offscreen
/// in both themes (design/option-a/BUILD-AND-VERIFY.md). The frames' pictures
/// are illustrations: here the code is a real one of a demo value, with no
/// illustration caption. `-browser-unavailable` belongs to the browser stories.
@MainActor
@Suite(.serialized)
struct QrSnapshotTests {
    init() { ParityDemo.setUp() }

    enum Frame: String, CaseIterable, CustomTestStringConvertible {
        case popup = "e21-s1-qr-popup"
        case wifi = "e21-s1-qr-wifi"
        case saveWarning = "e21-s1-qr-save-warning"
        case shareWarning = "e21-s1-qr-share-warning"
        case dense1x = "e21-s1-qr-dense-1x"
        case dense2x = "e21-s1-qr-dense-2x"
        case size = "e21-s1-qr-size"
        case entry = "e21-s1-qr-entry"

        var testDescription: String { rawValue }
    }

    @Test("QR frames E21-S1, offscreen, light and dark, at their own scale", arguments: Frame.allCases)
    func frame(_ frame: Frame) async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        if frame == .shareWarning { VaultModel.qrShareRoutes = [.sendViaAirDrop] }
        let demo = try QrDemo.window("qr-shot-" + frame.rawValue, password: "demo-pass-frame")
        defer { demo.window.lockAll() }
        try open(frame, demo)
        let popup = try await QrDemo.answered(demo.main)
        let scale: CGFloat = frame == .dense2x ? 2 : 1
        let bounds = frame == .size ? CGSize(width: 460, height: 300) : nil
        let host = NSHostingView(rootView: view(popup, scale: scale, bounds: bounds))
        host.frame = NSRect(origin: .zero, size: bounds ?? host.fittingSize)
        let offscreen = NSWindow(
            contentRect: host.frame.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless], backing: .buffered,
            defer: false)
        offscreen.colorSpace = .sRGB
        offscreen.backgroundColor = .clear
        offscreen.contentView = host
        try await Task.sleep(for: .milliseconds(100))
        try await state(frame, popup, host, demo)
        host.layoutSubtreeIfNeeded()
        if frame != .size { host.frame = NSRect(origin: .zero, size: host.fittingSize) }
        let shots = SnapshotTests()
        for (folder, look) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            offscreen.appearance = NSAppearance(named: look)
            let png = try await render(host, scale: scale)
            let out = ParityDemo.shotsDirectory.appending(path: "\(folder)/\(frame.rawValue).png")
            try FileManager.default.createDirectory(
                at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
            try png.write(to: out)
            #expect(png.count > 2_000, "\(out.path)")
            try shots.accessibilityTree(host).write(to: out.deletingPathExtension().appendingPathExtension("ax.json"))
        }
        offscreen.contentView = nil
        demo.main.qrPopup?.revoke()
    }

    private func open(_ frame: Frame, _ demo: QrDemo.Demo) throws {
        let (main, session, vault) = (demo.main, demo.session, demo.vault)
        switch frame {
        case .dense1x, .dense2x:
            _ = try session.beginEdit(vault: vault, entry: demo.entry)
            _ = try session.setPassword(vault: vault, value: String(repeating: "d", count: 1_272))
            _ = try session.commitEdit(vault: vault)
            main.afterChange(select: demo.entry)
            main.showQr()
        case .wifi:
            let fields = [
                ("Title", "Demo Wi-Fi"), ("UserName", "Demo Net"), ("Password", "demo-pass"),
                ("Security", "WPA2 Personal"),
            ]
            let wifi = try QrDemo.entry(session, vault, fields)
            main.afterChange(select: wifi)
            main.select(wifi)
            main.showWifiJoin()
        default:
            main.showQr()
        }
    }

    private func view(_ popup: QrPopup, scale: CGFloat, bounds: CGSize?) -> AnyView {
        let root = QrPopupView(popup: popup, reduceMotion: true)
            .font(.sans(14))
            .foregroundStyle(Tok.text)
            .environment(\.displayScale, scale)
        guard let bounds else { return AnyView(root.fixedSize()) }
        return AnyView(root.frame(width: bounds.width, height: bounds.height, alignment: .top))
    }

    private func state(
        _ frame: Frame, _ popup: QrPopup, _ host: NSHostingView<AnyView>, _ demo: QrDemo.Demo
    ) async throws {
        switch frame {
        case .entry:
            // The entry interval: the chrome with no code. A fresh pop-up never settled.
            demo.main.showQr()
            let fresh = try await QrDemo.answered(demo.main)
            let chrome = QrPopupContent(popup: fresh).font(.sans(14)).foregroundStyle(Tok.text).fixedSize()
            host.rootView = AnyView(chrome)
        case .saveWarning:
            try await QrDemo.render(host)
            popup.ask(.save)
        case .shareWarning:
            try await QrDemo.render(host)
            popup.ask(.share)
        default:
            break
        }
    }

    /// At the frame's own scale, whatever the Mac's screen uses, so its pitch is
    /// real; sRGB as the references.
    private func render(_ host: NSView, scale: CGFloat) async throws -> Data {
        host.layoutSubtreeIfNeeded()
        try await Task.sleep(for: .milliseconds(300))
        host.layoutSubtreeIfNeeded()
        let rep = try #require(
            NSBitmapImageRep(
                bitmapDataPlanes: nil, pixelsWide: Int(host.bounds.width * scale),
                pixelsHigh: Int(host.bounds.height * scale), bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0))
        rep.size = host.bounds.size
        host.cacheDisplay(in: host.bounds, to: rep)
        let tagged = try #require(rep.retagging(with: .sRGB))
        return try #require(tagged.representation(using: .png, properties: [:]))
    }

    @Test("QR-T15 frame e21-s1-qr-dense-1x: the dense dialog is 599 wide with a 555-pixel panel; at 2× it stays 460")
    func denseWidths() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-dense-widths")
        defer { demo.window.lockAll() }
        let (main, id, session, vault) = (demo.main, demo.entry, demo.session, demo.vault)
        _ = try session.beginEdit(vault: vault, entry: id)
        _ = try session.setPassword(vault: vault, value: String(repeating: "d", count: 1_272))
        _ = try session.commitEdit(vault: vault)
        main.afterChange(select: id)
        main.showQr()
        let popup = try await QrDemo.answered(main)
        for (scale, width) in [(1.0, 599.0), (2.0, 460.0)] as [(CGFloat, CGFloat)] {
            let host = NSHostingView(
                rootView: QrPopupView(popup: popup, reduceMotion: true)
                    .font(.sans(14))
                    .environment(\.displayScale, scale)
                    .fixedSize())
            #expect(host.fittingSize.width == width, "at \(scale)x")
        }
        popup.revoke()
    }
}
