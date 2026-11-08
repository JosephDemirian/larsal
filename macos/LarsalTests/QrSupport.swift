import AppKit
import CoreImage
import LarsalCore
import SwiftUI
import Testing

/// A drawn code as Core Image reads it. Everything goes through the app's own
/// `QrCodeNSView`; the bytes come from the recovered descriptor, never from
/// `messageString` (FEA-10.24).
@MainActor
enum QrRead {
    struct Payload: Equatable {
        /// The ECI designator; nil for a byte-only symbol.
        let eci: Int?
        let bytes: Data
        let version: Int
    }

    private static let detector = CIDetector(
        ofType: CIDetectorTypeQRCode, context: CIContext(options: [.useSoftwareRenderer: true]),
        options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])

    static func draw(_ symbol: Qr, pitch: Int) throws -> NSBitmapImageRep {
        let side = Int(symbol.size) * pitch
        let view = QrCodeNSView(frame: NSRect(x: 0, y: 0, width: side, height: side))
        view.cell = CGFloat(pitch)
        view.source = { symbol }
        let rep = try #require(
            NSBitmapImageRep(
                bitmapDataPlanes: nil, pixelsWide: side, pixelsHigh: side, bitsPerSample: 8, samplesPerPixel: 4,
                hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0))
        view.cacheDisplay(in: view.bounds, to: rep)
        return rep
    }

    /// The whole readback at FEA-10.12's 2× pitch: adequate space, no scaling.
    static func payload(_ symbol: Qr) throws -> Payload {
        let pitch = QrLayout(modules: Int(symbol.size), scale: 2).pitch
        let image = try #require(try draw(symbol, pitch: pitch).cgImage)
        return try payload(image: image)
    }

    static func payload(image: CGImage) throws -> Payload {
        let features = detector?.features(in: CIImage(cgImage: image)) ?? []
        let feature = try #require(features.first as? CIQRCodeFeature, "Core Image found no code")
        #expect(features.count == 1)
        let descriptor = try #require(feature.symbolDescriptor)
        #expect(descriptor.errorCorrectionLevel == .levelH)
        return try #require(parse(descriptor.errorCorrectedPayload, version: descriptor.symbolVersion))
    }

    /// ISO/IEC 18004's bit stream: at most one ECI header, one byte segment,
    /// then only terminator bits and the 0xEC, 0x11 padding. Anything else,
    /// a second segment too, is nil.
    static func parse(_ data: Data, version: Int) -> Payload? {
        var bit = 0
        let total = data.count * 8
        func take(_ count: Int) -> Int? {
            guard bit + count <= total else { return nil }
            var out = 0
            for _ in 0..<count {
                let byte = data[data.startIndex + bit / 8]
                out = out << 1 | Int(byte >> UInt8(7 - bit % 8) & 1)
                bit += 1
            }
            return out
        }
        var mode = take(4)
        var eci: Int?
        if mode == 0b0111 {
            guard let first = take(8), first & 0x80 == 0 else { return nil }
            eci = first
            mode = take(4)
        }
        guard mode == 0b0100, let count = take(version <= 9 ? 8 : 16) else { return nil }
        var bytes = Data(capacity: count)
        for _ in 0..<count {
            guard let byte = take(8) else { return nil }
            bytes.append(UInt8(byte))
        }
        guard take(min(4, total - bit)) == 0, take((total - bit) % 8) == 0 else { return nil }
        var pad = 0xEC
        while bit < total {
            guard take(8) == pad else { return nil }
            pad = pad == 0xEC ? 0x11 : 0xEC
        }
        return Payload(eci: eci, bytes: bytes, version: version)
    }
}

/// A seeded generator, so a failing value can be made again.
nonisolated struct QrRandom: RandomNumberGenerator {
    var state: UInt64

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var value = state
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return value ^ (value >> 31)
    }
}

/// A fake elapsed clock, and the seams of a QR test put back afterwards. The
/// seams are one set for the process and suites run side by side, so one QR
/// test holds them at a time.
@MainActor
final class QrSeams {
    private static var held = false
    private static var waiting: [CheckedContinuation<Void, Never>] = []

    static func begin() async -> QrSeams {
        if held {
            await withCheckedContinuation { waiting.append($0) }
        } else {
            held = true
        }
        return QrSeams()
    }

    var elapsed: Duration = .zero
    let start = ContinuousClock.now
    let centers = QrCenters(
        workspace: NotificationCenter(), distributed: NotificationCenter(), local: NotificationCenter())
    var mainWindow: NSWindow?
    private let saved = VaultModel.qrCenters
    private let savedWindow = VaultModel.qrWindow
    private let savedClock = VaultModel.qrClock
    private let savedPanel = VaultModel.qrSavePanel
    private let savedRoutes = VaultModel.qrShareRoutes
    private let savedPresenter = VaultModel.qrSharePresenter

    private init() {
        VaultModel.qrCenters = centers
        VaultModel.qrWindow = { [weak self] in self?.mainWindow }
        VaultModel.qrClock = { [weak self] in (self?.start ?? .now) + (self?.elapsed ?? .zero) }
        // Never the real panel or picker (AGENTS.md rule 10).
        VaultModel.qrSavePanel = { _ in {} }
        VaultModel.qrSharePresenter = { _, _ in {} }
    }

    func restore() {
        VaultModel.qrCenters = saved
        VaultModel.qrWindow = savedWindow
        VaultModel.qrClock = savedClock
        VaultModel.qrSavePanel = savedPanel
        VaultModel.qrShareRoutes = savedRoutes
        VaultModel.qrSharePresenter = savedPresenter
        if Self.waiting.isEmpty {
            Self.held = false
        } else {
            Self.waiting.removeFirst().resume()
        }
    }
}

/// The demo: an unlocked window, entries made in Rust, the pop-up on screen.
@MainActor
enum QrDemo {
    /// A saved entry with these fields.
    static func entry(_ session: Session, _ vault: UInt64, _ fields: [(String, String)]) throws -> String {
        _ = try session.beginNew(vault: vault, group: nil)
        for (name, value) in fields {
            switch name {
            case "Password": _ = try session.setPassword(vault: vault, value: value)
            case "Title": try session.setText(vault: vault, field: .title, value: value)
            case "UserName": try session.setText(vault: vault, field: .userName, value: value)
            default:
                let made = try session.addField(vault: vault)
                try session.renameField(vault: vault, old: made, name: name)
                try session.setField(vault: vault, name: name, value: value)
            }
        }
        return try session.commitEdit(vault: vault)
    }

    /// The Personal vault with one demo login selected.
    struct Demo {
        let window: MainWindowModel
        let main: VaultModel
        let entry: String
        var session: Session { window.session }
        var vault: UInt64 { main.vault.id }
    }

    static func window(_ folder: String, password: String = "demo-pass") throws -> Demo {
        let window = try ParityDemo.window(folder)
        let main = try #require(window.main)
        let id = try entry(window.session, main.vault.id, [("Title", "QR demo"), ("Password", password)])
        main.afterChange(select: id)
        main.select(id)
        return Demo(window: window, main: main, entry: id)
    }

    /// The current pop-up, once Rust answered.
    static func answered(_ main: VaultModel, at place: SourceLocation = #_sourceLocation) async throws -> QrPopup {
        let popup = try #require(main.qrPopup, sourceLocation: place)
        for _ in 0..<400 where popup.stage == .waiting { try await Task.sleep(for: .milliseconds(5)) }
        return popup
    }

    /// The pop-up's view; the same shape for any Reduce Motion, so changing it
    /// live keeps the view's state.
    static func root(
        _ popup: QrPopup, size: CGSize? = nil, reduce: Bool = true, motion: Animation = .easeOut(duration: 0.16)
    ) -> AnyView {
        let view = QrPopupView(popup: popup, reduceMotion: reduce, motion: motion)
            .font(.sans(14)).foregroundStyle(Tok.text)
        return size.map { AnyView(view.frame(width: $0.width, height: $0.height)) } ?? AnyView(view.fixedSize())
    }

    /// A never-ordered host for the pop-up; a render paints the first frame.
    static func host(
        _ popup: QrPopup, size: CGSize? = nil, reduce: Bool = true, motion: Animation = .easeOut(duration: 0.16)
    ) -> NSHostingView<AnyView> {
        let host = NSHostingView(rootView: root(popup, size: size, reduce: reduce, motion: motion))
        return placed(host, size: size)
    }

    /// `host` in a never-ordered offscreen window of its own.
    static func placed<V: NSView>(_ host: V, size: CGSize? = nil, window made: NSWindow? = nil) -> V {
        let box = size ?? host.fittingSize
        host.frame = NSRect(origin: .zero, size: box)
        let window =
            made
            ?? NSWindow(
                contentRect: host.frame.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless],
                backing: .buffered, defer: false)
        window.colorSpace = .sRGB
        window.contentView = host
        hosts.append(window)
        return host
    }

    /// Every element named `name` under `root`, in walk order.
    static func named(_ root: NSView, _ name: String) -> [AnyObject] {
        var out: [AnyObject] = []
        func walk(_ any: Any, _ depth: Int) {
            let element = any as AnyObject
            guard depth < 80 else { return }
            if (element.accessibilityLabel?() ?? nil) == name { out.append(element) }
            for child in element.accessibilityChildren?() ?? [] { walk(child, depth + 1) }
        }
        walk(root, 0)
        return out
    }

    /// Every label and text value under `root`.
    static func texts(_ root: NSView) -> [String] {
        var out: [String] = []
        func walk(_ any: Any, _ depth: Int) {
            let element = any as AnyObject
            guard depth < 80 else { return }
            let value: Any? = element.accessibilityValue?() ?? nil
            out += [(element.accessibilityLabel?() ?? nil) ?? "", (value as? String) ?? ""].filter { !$0.isEmpty }
            for child in element.accessibilityChildren?() ?? [] { walk(child, depth + 1) }
        }
        walk(root, 0)
        return out
    }

    /// The pixels `host` draws now.
    static func picture(_ host: NSView) throws -> NSBitmapImageRep {
        host.layoutSubtreeIfNeeded()
        let rep = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: rep)
        return rep
    }

    private static var hosts: [NSWindow] = []

    /// Hosts the pop-up, lets it settle and paints it: the 44 seconds start.
    static func painted(_ main: VaultModel) async throws -> QrPopup {
        let popup = try await answered(main)
        let host = host(popup)
        try await render(host)
        return popup
    }

    static func render(_ host: NSView) async throws {
        host.layoutSubtreeIfNeeded()
        try await Task.sleep(for: .milliseconds(50))
        host.layoutSubtreeIfNeeded()
        let rep = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: rep)
    }
}

extension QrDemo {
    /// QR-T01's fixture: a login with a protected PIN and a protected note that
    /// fills most of one code.
    static func protected(_ folder: String) throws -> (demo: Demo, values: [String: String]) {
        let demo = try window(folder)
        let values = [
            "Password": "demo-pass", "PIN": "4921", "Private key note": String(repeating: "demo note ", count: 120),
        ]
        let (session, vault) = (demo.session, demo.vault)
        _ = try session.beginEdit(vault: vault, entry: demo.entry)
        for name in ["PIN", "Private key note"] {
            let made = try session.addField(vault: vault)
            try session.renameField(vault: vault, old: made, name: name)
            try session.setField(vault: vault, name: name, value: values[name] ?? "")
            try session.protectField(vault: vault, name: name, on: true)
        }
        _ = try session.commitEdit(vault: vault)
        demo.main.afterChange(select: demo.entry)
        return (demo, values)
    }

    /// Presses each visible Show as QR Code once: what it asked for, and what
    /// its code reads as.
    static func pressEach(_ root: NSView, _ main: VaultModel) async throws -> [QrRequest: Data] {
        var out: [QrRequest: Data] = [:]
        let count = named(root, QrText.title).count
        for index in 0..<count {
            let button = named(root, QrText.title)[index]
            #expect(button.accessibilityPerformPress?() == true, "button \(index)")
            let popup = try await answered(main)
            #expect(popup.stage == .code, "\(popup.request)")
            out[popup.request] = try QrRead.payload(try #require(popup.symbol)).bytes
            popup.revoke()
            root.layoutSubtreeIfNeeded()
            try await Task.sleep(for: .milliseconds(150))
            root.layoutSubtreeIfNeeded()
        }
        #expect(out.count == count, "no two buttons ask for one field")
        return out
    }

    /// Writes out what is pending: from here on a change would show as a change
    /// count or a later save, an autosave cannot hide it. The save's time.
    static func savedAt(_ demo: Demo) throws -> Int64? {
        #expect(try demo.session.save(vault: demo.vault).changes == 0)
        return try demo.session.saveStatus(vault: demo.vault).savedAt
    }

    static func expectUnchanged(_ demo: Demo, since: Int64?, at place: SourceLocation = #_sourceLocation) throws {
        let now = try demo.session.saveStatus(vault: demo.vault)
        #expect(now.changes == 0 && now.savedAt == since, "nothing to save, nothing saved", sourceLocation: place)
    }
}

/// A never-ordered window that says it is key, so SwiftUI's focus runs with
/// no window on screen and no focus taken (AGENTS.md rule 10).
final class QrKeyWindow: NSWindow {
    /// The QR buttons that appeared at its last `layOut`. `QrFocus.shared.there`
    /// holds every window's, and other suites add theirs while a test waits.
    private(set) var buttons: Set<Namespace.ID> = []
    override var isKeyWindow: Bool { true }
    override var canBecomeKey: Bool { true }

    /// Makes `change` and lays the window out with no await between, so no
    /// other suite's window adds a button meanwhile: what appears is this one's.
    func layOut(after change: () -> Void) {
        let others = QrFocus.shared.there
        change()
        contentView?.layoutSubtreeIfNeeded()
        buttons = QrFocus.shared.there.subtracting(others)
    }
}

extension QrDemo {
    static func key(_ code: UInt16, _ text: String, _ flags: NSEvent.ModifierFlags = []) throws -> NSEvent {
        try #require(
            NSEvent.keyEvent(
                with: .keyDown, location: .zero, modifierFlags: flags, timestamp: 0, windowNumber: 0, context: nil,
                characters: text, charactersIgnoringModifiers: text, isARepeat: false, keyCode: code))
    }

    /// A real press, delivered as AppKit delivers it.
    static func press(_ event: NSEvent, in window: NSWindow, _ host: NSView) async throws {
        window.sendEvent(event)
        host.layoutSubtreeIfNeeded()
        try await Task.sleep(for: .milliseconds(100))
        host.layoutSubtreeIfNeeded()
    }
}
