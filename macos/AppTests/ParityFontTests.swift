import AppCore
import AppKit
import SwiftUI
import Testing

// Design parity (Verify, 2026-10-28; LD-169): two looks measured instead of
// noted. (1) One-time codes: the accessibility tree's font runs of the large
// code, and the drawn glyphs of the large code and a row code compared with
// the same string set by Core Text in IBM Plex Mono 500 and in the system
// face. (2) The focused row: rendered offscreen in its focused state and read
// back for the mockup's `.win :focus-visible` (2 pt --accent outline, 1 pt
// out). A real key window stays with Mac QA (LD-169). Names start "Font
// check" and "Focus check" so the parity report can cite them.

@MainActor
@Suite(.serialized)
struct ParityFontTests {
    init() { ParityDemo.setUp() }

    @Test("Font check: one-time codes are one run of IBM Plex Mono 500 and draw its glyphs")
    func codeFont() async throws {
        let model = try ParityDemo.window("parity-font")
        let main = try #require(model.main)
        let screen = Screen(model)
        main.tick()
        await screen.settle()
        let image = try #require(screen.host.bitmapImageRepForCachingDisplay(in: screen.host.bounds))
        screen.host.cacheDisplay(in: screen.host.bounds, to: image)
        let nodes = screen.nodes()
        let isCode = { (text: String) in text.range(of: #"^\d{3}[ \u{2009}]\d{3}$"#, options: .regularExpression) != nil
        }
        // The large code of the detail: its own text element.
        let big = try #require(
            nodes.first { ($0.accessibilityRole?()?.rawValue == "AXStaticText") && isCode(Self.value($0)) })
        let text = Self.value(big)
        let length = text.utf16.count
        let runs = try #require(big.accessibilityAttributedString?(for: NSRange(location: 0, length: length)) ?? nil)
        var fonts: [String] = []
        runs.enumerateAttribute(
            NSAttributedString.Key(rawValue: "AXFont"), in: NSRange(location: 0, length: runs.length)
        ) { value, range, _ in
            let font = value as? [String: Any]
            fonts.append("\(range.length) \(font?["AXFontName"] ?? "?") \(font?["AXFontSize"] ?? "?")")
        }
        #expect(fonts == ["\(length) IBMPlexMono-Medium 28"], "one run: \(fonts)")
        let bigBox = screen.box(big)
        Self.expectMono(image, bigBox, text, size: 28, tracking: 1.12)
        // A row code: the selected row, in the column under "Code".
        let header = try #require(nodes.first { Self.value($0) == "Code" })
        let row = try #require(nodes.first { (($0.accessibilityLabel?() ?? nil) ?? "").hasPrefix("GitHub, ") })
        let selection = try #require(main.selection)
        let rowCode = try #require(main.codes[selection]?.code)
        let rowBox = CGRect(x: screen.box(header).minX - 2, y: screen.box(row).minY + 12, width: 90, height: 32)
        Self.expectMono(image, rowBox, rowCode, size: 14, tracking: 0.28)
    }

    @Test("Focus check: the focused row draws a 2 pt --accent outline 1 pt outside, light and dark")
    func focusedRow() async throws {
        let model = try ParityDemo.window("parity-font")
        let main = try #require(model.main)
        let row = try #require(main.rows.first)
        for look in [NSAppearance.Name.aqua, .darkAqua] {
            for focused in [true, false] {
                let view = EntryRowView(row: row, code: nil, selected: true, rule: false, focused: focused) {}
                    .frame(width: 622).padding(9)
                let host = NSHostingView(rootView: AnyView(view.background(Tok.surface)))
                host.frame = NSRect(x: 0, y: 0, width: 640, height: 74)
                let window = NSWindow(
                    contentRect: host.frame.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless],
                    backing: .buffered, defer: false)
                window.appearance = NSAppearance(named: look)
                window.colorSpace = .sRGB
                window.contentView = host
                host.layoutSubtreeIfNeeded()
                try await Task.sleep(for: .milliseconds(100))
                let image = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
                host.cacheDisplay(in: host.bounds, to: image)
                var accent = NSColor.clear
                window.appearance?.performAsCurrentDrawingAppearance {
                    accent = (NSColor(named: "accent", bundle: appBundle) ?? .clear).usingColorSpace(.sRGB) ?? .clear
                }
                // Mid-height on the left edge and mid-width on the top edge:
                // points 1 to 3 outside the row are accent, 0 and 4 are not.
                let left = (0..<6).map { Self.isColor(image, x: 9 - 0.25 - Double($0) * 0.5 - 0.5, y: 37, accent) }
                let top = (0..<6).map { Self.isColor(image, x: 320, y: 9 - 0.25 - Double($0) * 0.5 - 0.5, accent) }
                let want = focused ? [false, true, true, true, true, false] : Array(repeating: false, count: 6)
                #expect(left == want, "\(look.rawValue) focused \(focused): left \(left)")
                #expect(top == want, "\(look.rawValue) focused \(focused): top \(top)")
                window.contentView = nil
            }
        }
    }

    private static func value(_ element: AnyObject) -> String {
        let value: Any? = element.accessibilityValue?() ?? nil
        return (value as? String) ?? ""
    }

    /// Whether the pixel at a point has `color`: raw samples against its
    /// sRGB components, within 6 of 255 (the render is sRGB).
    private static func isColor(_ image: NSBitmapImageRep, x left: Double, y top: Double, _ color: NSColor) -> Bool {
        var pixel = [Int](repeating: 0, count: 4)
        image.getPixel(&pixel, atX: Int(left * 2), y: Int(top * 2))
        let want = [color.redComponent, color.greenComponent, color.blueComponent].map { Int(($0 * 255).rounded()) }
        return zip(pixel.prefix(3), want).allSatisfy { abs($0 - $1) <= 6 }
    }

    /// The drawn glyphs in `box` are nearer to `text` set in IBM Plex Mono
    /// 500 than in the system face (ink resampled to one grid).
    private static func expectMono(
        _ image: NSBitmapImageRep, _ box: CGRect, _ text: String, size: CGFloat, tracking: CGFloat
    ) {
        let drawn = ink(crop(image, box))
        let mono = ink(set(text, NSFont(name: "IBMPlexMono-Medium", size: size), tracking))
        let system = ink(set(text, .monospacedDigitSystemFont(ofSize: size, weight: .medium), tracking))
        let toMono = distance(drawn, mono)
        let toSystem = distance(drawn, system)
        let line =
            "Font check \(text) at \(size) pt: ink distance \(toMono) to IBM Plex Mono 500, "
            + "\(toSystem) to the system face\n"
        FileHandle.standardError.write(Data(line.utf8))
        #expect(
            toMono < toSystem * 0.6, "\(text) at \(size) pt: \(toMono) to IBM Plex Mono, \(toSystem) to the system face"
        )
    }

    private static func crop(_ image: NSBitmapImageRep, _ box: CGRect) -> [[Double]] {
        (Int(box.minY * 2)..<Int(box.maxY * 2)).map { row in
            (Int(box.minX * 2)..<Int(box.maxX * 2)).map { col in
                Double(image.colorAt(x: col, y: row)?.usingColorSpace(.sRGB)?.brightnessComponent ?? 1)
            }
        }
    }

    private static func set(_ text: String, _ font: NSFont?, _ tracking: CGFloat) -> [[Double]] {
        let string = NSAttributedString(
            string: text,
            attributes: [
                .font: font ?? NSFont.systemFont(ofSize: 12), .kern: tracking, .foregroundColor: NSColor.black,
            ])
        let size = string.size()
        let image = NSImage(size: NSSize(width: size.width + 8, height: size.height + 8))
        image.lockFocus()
        NSColor.white.setFill()
        NSRect(origin: .zero, size: image.size).fill()
        string.draw(at: NSPoint(x: 4, y: 4))
        image.unlockFocus()
        guard let tiff = image.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff) else { return [] }
        return (0..<rep.pixelsHigh).map { row in
            (0..<rep.pixelsWide).map { col in
                Double(rep.colorAt(x: col, y: row)?.usingColorSpace(.sRGB)?.brightnessComponent ?? 1)
            }
        }
    }

    /// Ink (distance from the most common tone), cut to its bounding box
    /// and resampled to 96 × 24.
    private static func ink(_ gray: [[Double]]) -> [[Double]] {
        let flat = gray.flatMap { $0 }
        guard !flat.isEmpty else { return [] }
        let counts = Dictionary(grouping: flat.map { ($0 * 50).rounded() }) { $0 }.mapValues(\.count)
        let ground = (counts.max { $0.value < $1.value }?.key ?? 50) / 50
        let amount = gray.map { $0.map { min(1, abs($0 - ground) * 2) } }
        let rows = amount.indices.filter { amount[$0].contains { $0 > 0.3 } }
        let cols = amount[0].indices.filter { col in amount.contains { $0[col] > 0.3 } }
        guard let top = rows.first, let bottom = rows.last, let left = cols.first, let right = cols.last else {
            return []
        }
        return (0..<24).map { gridRow in
            (0..<96).map { gridCol in
                amount[top + (bottom - top) * gridRow / 23][left + (right - left) * gridCol / 95]
            }
        }
    }

    private static func distance(_ one: [[Double]], _ two: [[Double]]) -> Double {
        guard one.count == two.count, !one.isEmpty else { return .infinity }
        return zip(one.flatMap { $0 }, two.flatMap { $0 }).map { abs($0 - $1) }.reduce(0, +) / Double(96 * 24)
    }
}
