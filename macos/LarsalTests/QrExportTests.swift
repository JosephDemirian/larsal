import AppKit
import LarsalCore
import Testing

/// Save Image… and Share… (FEA-10.16 to .19): fake panels and pickers, demo
/// files under the test's own folder. No real panel or picker (AGENTS.md
/// rule 10).
@MainActor
@Suite(.serialized)
struct QrExportTests {
    init() { ParityDemo.setUp() }

    @Test("QR-T19 FEA-10.16: each attempt gets the warning; Cancel is no consent; a double click is one")
    func consent() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        var panels = 0
        VaultModel.qrSavePanel = { _ in
            panels += 1
            return {}
        }
        let demo = try QrDemo.window("qr-consent")
        defer { demo.window.lockAll() }
        let main = demo.main
        main.showQr()
        let popup = try await QrDemo.painted(main)
        popup.confirm()
        #expect(popup.stage == .code && panels == 0, "no warning, no consent")
        for _ in 0..<2 {
            popup.ask(.save)
            #expect(popup.stage == .warning(.save))
            popup.escape()
            #expect(popup.stage == .code && panels == 0, "Escape cancels")
        }
        popup.ask(.save)
        popup.cancelWarning()
        #expect(panels == 0, "Cancel cancels")
        popup.ask(.save)
        popup.confirm()
        popup.confirm()
        #expect(panels == 1, "a double click is one panel")
        #expect(popup.stage == .exporting)
        popup.revoke()
    }

    @Test("QR-T20 FEA-10.17: a confirmed Save writes the PNG, 8 px a module, 0600; Cancel writes nothing")
    func save() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let place = try folder("qr-save")
        let file = place.appending(path: "Larsal QR.png")
        var answer: ((URL?) -> Void)?
        VaultModel.qrSavePanel = { done in
            answer = done
            return {}
        }
        let demo = try QrDemo.window("qr-save", password: "demo-save-value")
        defer { demo.window.lockAll() }
        let main = demo.main
        main.showQr()
        var popup = try await QrDemo.painted(main)
        let symbol = try #require(popup.symbol)
        let side = Int(symbol.size)
        popup.ask(.save)
        popup.confirm()
        answer?(file)
        for _ in 0..<400 where popup.stage != .closed { try await Task.sleep(for: .milliseconds(5)) }
        #expect(popup.stage == .closed, "own copies are gone after the write")
        let bytes = try Data(contentsOf: file)
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path(percentEncoded: false))
        #expect((attributes[.posixPermissions] as? Int) == 0o600)
        let rep = try #require(NSBitmapImageRep(data: bytes))
        #expect(rep.pixelsWide == side * 8 && rep.pixelsHigh == side * 8)
        let got = try QrRead.payload(image: try #require(rep.cgImage))
        #expect(got.bytes == Data("demo-save-value".utf8) && got.eci == 26)
        #expect(wrongPixels(rep, symbol) == 0, "every pixel of the saved file")
        try FileManager.default.removeItem(at: file)
        // The panel's Cancel: nothing written, and the pop-up does not return.
        main.showQr()
        popup = try await QrDemo.painted(main)
        popup.ask(.save)
        popup.confirm()
        answer?(nil)
        #expect(popup.stage == .closed && main.qrPopup == nil && main.dialog == nil)
        #expect(try FileManager.default.contentsOfDirectory(atPath: place.path(percentEncoded: false)).isEmpty)
    }

    @Test("QR-T20 FEA-10.17: expired under the panel writes nothing; a failed write says so and keeps nothing")
    func saveRefused() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let place = try folder("qr-save-refused")
        let file = place.appending(path: "Larsal QR.png")
        var answer: ((URL?) -> Void)?
        VaultModel.qrSavePanel = { done in
            answer = done
            return {}
        }
        let demo = try QrDemo.window("qr-save-refused", password: "demo-save-value")
        defer { demo.window.lockAll() }
        let main = demo.main
        // Expired while the panel was open: nothing written.
        main.showQr()
        var popup = try await QrDemo.painted(main)
        popup.ask(.save)
        popup.confirm()
        seams.elapsed = .seconds(44)
        answer?(file)
        #expect(popup.stage == .closed)
        // A write that fails says so and keeps nothing.
        seams.elapsed = .zero
        main.showQr()
        popup = try await QrDemo.painted(main)
        popup.ask(.save)
        popup.confirm()
        answer?(place.appending(path: "nowhere/x.png"))
        for _ in 0..<400 where popup.stage != .closed { try await Task.sleep(for: .milliseconds(5)) }
        #expect(main.toast?.text == QrText.saveFailed)
        #expect(try FileManager.default.contentsOfDirectory(atPath: place.path(percentEncoded: false)).isEmpty)
    }

    @Test("QR-T21 FEA-10.18: no proved route: Share is unavailable; its path has an in-memory item only")
    func share() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-share", password: "demo-share-value")
        defer { demo.window.lockAll() }
        let (window, main) = (demo.window, demo.main)
        main.showQr()
        var popup = try await QrDemo.painted(main)
        #expect(!popup.shareAvailable, "no route is proved: functional Share stays open (W-08)")
        popup.ask(.share)
        #expect(popup.stage == .code, "unavailable: no warning")
        let screen = Screen(window)
        await screen.settle()
        #expect(screen.node("Share…")?.isAccessibilityEnabled?() == false)
        popup.revoke()
        // A future proved route, behind a fake picker: warning first, then
        // an item with no file, whose bytes are made only while live.
        VaultModel.qrShareRoutes = [.sendViaAirDrop]
        var item: NSItemProvider?
        var finished: ((Bool) -> Void)?
        VaultModel.qrSharePresenter = { provider, done in
            item = provider
            finished = done
            return {}
        }
        main.showQr()
        popup = try await QrDemo.painted(main)
        popup.ask(.share)
        #expect(popup.stage == .warning(.share) && item == nil, "nothing before the warning's answer")
        popup.confirm()
        let provider = try #require(item)
        #expect(provider.registeredTypeIdentifiers == ["public.png"])
        #expect(popup.symbol == nil && main.dialog == nil, "own pixels gone at handoff")
        let bytes = try #require(await load(provider))
        let rep = try #require(NSBitmapImageRep(data: bytes))
        #expect(try QrRead.payload(image: try #require(rep.cgImage)).bytes == Data("demo-share-value".utf8))
        // Past the deadline the same item gives nothing.
        seams.elapsed = .seconds(44)
        #expect(await load(provider) == nil)
        #expect(popup.stage == .closed)
        finished?(false)
        // A lock before the destination asks: nothing either.
        seams.elapsed = .zero
        main.showQr()
        popup = try await QrDemo.painted(main)
        popup.ask(.share)
        popup.confirm()
        let late = try #require(item)
        popup.revoke()
        #expect(await load(late) == nil)
    }

    @Test("QR-T21 FEA-10.18: with no proved route the picker policy offers no service at all")
    func sharePolicy() {
        let picker = NSSharingServicePicker(items: [])
        var chosen: [Bool] = []
        let none = QrSharePolicy(routes: [], done: { chosen.append($0) })
        let names: [NSSharingService.Name] = [.sendViaAirDrop, .composeEmail]
        let proposed = names.compactMap { NSSharingService(named: $0) }
        let offered = none.sharingServicePicker(picker, sharingServicesForItems: [], proposedSharingServices: proposed)
        #expect(offered.isEmpty)
        none.sharingServicePicker(picker, didChoose: nil)
        #expect(chosen == [false], "dismissed")
        if let service = proposed.first {
            none.sharingServicePicker(picker, didChoose: service)
            #expect(chosen == [false, true], "a service was chosen")
        }
    }

    private func load(_ item: NSItemProvider) async -> Data? {
        await withCheckedContinuation { done in
            _ = item.loadDataRepresentation(forTypeIdentifier: "public.png") { data, _ in done.resume(returning: data) }
        }
    }

    @Test("QR-T22 E21-S2: show, resize, cancel and expire write no image or value, and touch no board")
    func noWrites() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let marker = "qr-t22-demo-marker-41"
        let places = [
            URL(fileURLWithPath: NSTemporaryDirectory()), FileManager.default.temporaryDirectory,
            URL(fileURLWithPath: NSHomeDirectory()).appending(path: "Library/Caches"),
            // Where macOS would keep a window's state (FEA-10.19); `noRestoration` turns it off.
            URL(fileURLWithPath: NSHomeDirectory())
                .appending(path: "Library/Saved Application State/app.larsal.desktop.savedState"),
            // The run's own place for files, this test's demo vault included.
            ParityDemo.root.appending(path: "target/option-a"),
        ]
        let before = listing(places)
        let demo = try QrDemo.window("qr-writes", password: marker)
        defer { demo.window.lockAll() }
        let (window, main) = (demo.window, demo.main)
        // Show, resize, cancel a warning, cancel a panel, expire.
        main.showQr()
        var popup = try await QrDemo.painted(main)
        try await QrDemo.render(QrDemo.host(popup, size: CGSize(width: 480, height: 300)))
        popup.ask(.save)
        popup.cancelWarning()
        seams.elapsed = .seconds(44)
        popup.tick()
        seams.elapsed = .zero
        var answer: ((URL?) -> Void)?
        VaultModel.qrSavePanel = { done in
            answer = done
            return {}
        }
        main.showQr()
        popup = try await QrDemo.painted(main)
        popup.ask(.save)
        popup.confirm()
        answer?(nil)
        // No new or changed file holds the value or a code that reads as it.
        let after = listing(places)
        for (path, date) in after where before[path] != date {
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)), data.count < 8_000_000 else { continue }
            #expect(data.range(of: Data(marker.utf8)) == nil, "\(path)")
            guard let image = NSBitmapImageRep(data: data)?.cgImage else { continue }
            let read = try? QrRead.payload(image: image)
            #expect(read?.bytes != Data(marker.utf8), "\(path)")
        }
        // Rust's own record: this session's board was never written.
        let board = window.session.pasteboardName()
        #expect(board == nil || !pasteboardsWritten().contains(board ?? ""))
        PasteboardProof.expectOnlyPrivate(window.session, copied: false)
    }

    @Test("QR-T22 FEA-10.19: the QR sources call no pasteboard, file-write, drag, log or network API")
    func sourceScan() throws {
        let files = [
            "macos/Larsal/QrPopup.swift", "macos/Larsal/QrViews.swift", "macos/Larsal/QrWiring.swift",
            "macos/Larsal/DetailRows.swift", "macos/Larsal/DetailFields.swift", "macos/Larsal/ContextMenus.swift",
            "macos/Larsal/Platform/WindowRules.swift", "crates/larsal-ffi/src/qr.rs",
        ]
        // Spelled apart, so this test's own words are not what it finds.
        let banned = [
            "NSPaste" + "board", "copy_" + "value", "clip" + "board_", "paste" + "board", ".write" + "(to:",
            "createFile" + "(", "File::" + "create", "fs::" + "write(", "tiff" + "Representation", "png" + "Data(",
            ".dragg" + "able", "on" + "Drag", "beginDragging" + "Session", "registerFile" + "Representation",
            "Log" + "ger.", "NS" + "Log", "pr" + "int(", "os_" + "log", "User" + "Defaults", "temporary" + "Directory",
            "URL" + "Session", "Http" + "Client", "eprint" + "ln!", "pr" + "intln!",
        ]
        for file in files {
            var code = try String(contentsOf: ParityDemo.root.appending(path: file), encoding: .utf8)
            if let tests = code.range(of: "#[cfg(test)]") { code = String(code[..<tests.lowerBound]) }
            code = code.replacingOccurrences(of: "ingerpr" + "int(", with: "")
            for word in banned { #expect(!code.contains(word), "\(file): \(word)") }
        }
    }
}

/// Pixels of `rep` that are not 8 a module of `symbol` in pure #000 and #FFF
/// with a white quiet zone.
@MainActor
private func wrongPixels(_ rep: NSBitmapImageRep, _ symbol: Qr) -> Int {
    let side = Int(symbol.size)
    var wrong = rep.bitsPerSample == 8 && rep.samplesPerPixel == 4 ? 0 : rep.pixelsHigh * rep.pixelsWide
    var pixel = [0, 0, 0, 0]
    for row in 0..<rep.pixelsHigh {
        for column in 0..<rep.pixelsWide {
            let cell = symbol.modules[symbol.modules.startIndex + row / 8 * side + column / 8]
            // The file's own samples, no color conversion on the way.
            rep.getPixel(&pixel, atX: column, y: row)
            let want = cell == 1 ? 0 : 255
            if pixel != [want, want, want, 255] { wrong += 1 }
            if min(row, column) < 32 || max(row, column) >= side * 8 - 32, cell != 0 { wrong += 1 }
        }
    }
    return wrong
}

/// A folder of the test's own under the run's target.
@MainActor
private func folder(_ name: String) throws -> URL {
    let place = ParityDemo.root.appending(path: "target/option-a/\(name)-out")
    try? FileManager.default.removeItem(at: place)
    try FileManager.default.createDirectory(at: place, withIntermediateDirectories: true)
    return place
}

/// New or changed files under `places`: path to size and date.
@MainActor
private func listing(_ places: [URL]) -> [String: Date] {
    var out: [String: Date] = [:]
    for place in places {
        let key = URLResourceKey.contentModificationDateKey
        let walk = FileManager.default.enumerator(at: place, includingPropertiesForKeys: [key])
        while let url = walk?.nextObject() as? URL {
            let date = try? url.resourceValues(forKeys: [key]).contentModificationDate
            out[url.path(percentEncoded: false)] = date ?? .distantPast
        }
    }
    return out
}
