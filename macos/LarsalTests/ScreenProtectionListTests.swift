import Foundation
import Testing

/// The window list's source checks (APP-10.3, AT-D04): `listIsComplete`
/// and the `adoptedBeforeShown` way read Larsal's sources through these.
extension ScreenProtectionTests {
    @Test("APP-10.3: the list catches each way to write a window made outside the factory")
    func listCatchesSpellings() {
        let made = [
            "NSWindow(contentRect: r, styleMask: [], backing: .buffered, defer: true)", "NSPanel()",
            "NSAlert(error: e)",
            "NSWindow.init(contentViewController: c)", "NSAlert.init()", "NSPanel.init(contentRect: r)",
            "Picker(contentRect: r)", "Picker(contentViewController: c)", "NSPopover()", "NSPopover.init()",
            ".sheet(isPresented: $shown) {}", "final class Picker: NSPanel {}\nlet picker = Picker()",
            "class Big: NSWindow, NSWindowDelegate {}", "ColorPicker(\"Tint\", selection: $tint)",
            "ShareLink(item: url)", "NSPrintOperation(view: v).run()", ".fileMover(isPresented: $moving, file: f) {}",
            "NSWindowController(windowNibName: \"Main\")",
        ]
        for code in made {
            #expect(!Self.problems("New.swift", code).isEmpty, "\(code)")
        }
    }

    @Test("APP-10.3: each spelling of a menu, picker or calendar AppKit opens for Larsal is named by a kind")
    func listNamesSpellings() {
        let swept = [
            "Menu(\"Export\") {}", "Menu {} label: {}", "Picker(\"Appearance\", selection: $theme) {}",
            "DatePicker(\"Expires\", selection: $date).datePickerStyle(.graphical)", "CommandMenu(\"Vault\") {}",
            "CommandGroup(replacing: .help) {}", "NSMenu(title: \"\")", ".contextMenu { }",
        ]
        for code in swept {
            #expect(Self.kinds.contains { $0.marker.map { Self.found($0, in: code) } ?? false }, "\(code)")
        }
    }

    @Test("APP-10.1: every show in a function needs that window adopted before it in the same function")
    func showsNeedAdopt() {
        let code = """
            func a() { ScreenProtection.shared.adopt(p)
            p.makeKeyAndOrderFront(nil) }
            func b() { q.makeKeyAndOrderFront(nil) }
            func c() { ScreenProtection.shared.adopt(p)
            q.orderFrontRegardless() }
            init() { orderFront(nil) }
            """
        #expect(Self.shows(code).map(\.window) == ["p", "q", "q", "self"])
        #expect(Self.shows(code).map(\.adopted) == [true, false, false, false])
    }

    /// Larsal's Swift files, comments left out.
    static func sources() throws -> [(file: String, code: String)] {
        let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appending(path: "../Larsal")
            .standardizedFileURL
        let urls = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: nil)?.allObjects ?? []
        return try urls.compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" }.map { url in
            let text = try String(contentsOf: url, encoding: .utf8)
            let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
            let code = lines.map { line in line.range(of: "//").map { String(line[..<$0.lowerBound]) } ?? String(line) }
            return (url.lastPathComponent, code.joined(separator: "\n"))
        }
    }

    /// Why `code` in `file` breaks the list, if it does.
    static func problems(_ file: String, _ code: String) -> [String] {
        var problems: [String] = []
        for kind in kinds {
            guard let marker = kind.marker, found(marker, in: code), kind.files?.contains(file) == false else {
                continue
            }
            problems.append(
                "\(file) makes a window as \(kind.name) where the list does not expect it: add it to the kind")
        }
        for pattern in unlisted where found(pattern, in: code) {
            problems.append("\(file) makes a window (\(pattern)) no kind covers: add a kind to the list")
        }
        return problems
    }

    static func found(_ pattern: String, in code: String) -> Bool {
        code.range(of: pattern, options: .regularExpression) != nil
    }

    /// Each window `code` orders in (`x.makeKeyAndOrderFront(` and the other
    /// order-front calls; no `x.`: `self`), and whether
    /// `ScreenProtection.shared.adopt(x)` comes before it in its function.
    static func shows(_ code: String) -> [(window: String, adopted: Bool)] {
        code.split(separator: /\bfunc\s|\binit[?!]?\(/).flatMap { body in
            body.matches(of: /(?:(\w+)\??\.)?(?:makeKeyAndOrderFront|orderFront(?:Regardless)?|orderWindow)\(/)
                .map { show in
                    let window = show.1.map(String.init) ?? "self"
                    return (window, body[..<show.range.lowerBound].contains("ScreenProtection.shared.adopt(\(window))"))
                }
        }
    }
}
