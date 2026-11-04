import AppCore
import AppKit
import SwiftUI
import Testing

// SD-07 in the window (LD-227 (3), E13-S6 part m): File > Export CSV, HTML
// and XML, and the Passkeys report's Export, show Rust's warning before any
// file is written. The panels never show (AGENTS.md rule 10): each test
// says what they answer and counts the asks.

@MainActor
@Suite(.serialized)
struct ExportScreensTests {
    init() {
        ParityDemo.setUp()
    }

    /// A private folder for the files under target/, never the temp folder
    /// (LD-285 (3)): removed first, so a run that failed leaves nothing for
    /// the next, and removed again after the test.
    static func folder(_ name: String) throws -> URL {
        let url = ParityDemo.root.appending(path: "target/option-a/export-\(name)")
        try? FileManager.default.removeItem(at: url)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    static func mode(_ url: URL) throws -> Int {
        try #require(FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int) & 0o777
    }

    /// Presses `title` in File > Export, as a click on the native menu would.
    static func pressExport(_ window: MainWindowModel, _ title: String) async throws {
        guard #available(macOS 14.4, *) else { return }
        let menu = NSHostingMenu(rootView: FileMenuItems(window: window))
        menu.update()
        try await Task.sleep(for: .milliseconds(30))
        menu.update()
        let export = try #require(menu.items.first { $0.title == "Export" }?.submenu, "File > Export")
        export.update()
        let index = export.indexOfItem(withTitle: title)
        try #require(index >= 0, "\(title) in File > Export")
        #expect(export.items[index].isEnabled, "\(title) is enabled with an unlocked vault on screen")
        export.performActionForItem(at: index)
    }

    /// Return and Escape each answer the question `ask` puts up with No:
    /// No is the default (FEA-09.2, INT-04.50, LD-244 (2)).
    static func keysAnswerNo(_ screen: Screen, ask: () async throws -> Void, answeredNo: () -> Bool) async throws {
        for (code, key) in [(UInt16(36), "\r"), (53, "\u{1b}")] {
            try await ask()
            await screen.settle()
            let press = try MenuKeysTests.key(code, key, key, [])
            #expect(screen.window.performKeyEquivalent(with: press), "a button's key: \(code)")
            await screen.settle()
            #expect(answeredNo(), "No, by key \(code)")
        }
    }

    @Test(
        "SD-07, FEA-09.2: File > Export CSV and XML ask MSG-EXP-CONFIRM before the save panel; No writes nothing",
        arguments: [ExportFormat.csv, .xml])
    func sd07CsvAndXmlAskFirst(_ format: ExportFormat) async throws {
        let window = try ParityDemo.window("sd07-ask")
        defer { window.lockAll() }
        let main = try #require(window.main)
        let warning = exportWarning(format: format)
        let folder = try Self.folder("sd07-ask")
        defer { try? FileManager.default.removeItem(at: folder) }
        let out = folder.appending(path: "Personal." + warning.extension)
        var asked: [String] = []
        let saved = VaultModel.exportPanel
        defer { VaultModel.exportPanel = saved }
        VaultModel.exportPanel = { type, name in
            asked.append(type + " " + name)
            return out
        }
        let screen = Screen(window)
        await screen.settle()
        let item = warning.extension.uppercased() + "…"
        try await Self.pressExport(window, item)
        #expect(main.dialog == .export(.ask(format, warning)), "the question comes first")
        await screen.settle()
        #expect(screen.strings().contains(warning.text), "Rust's warning text is on the sheet")
        #expect(asked.isEmpty && !FileManager.default.fileExists(atPath: out.path))
        try await screen.press("No")
        #expect(main.dialog == nil && asked.isEmpty, "No ends the export")
        #expect(!FileManager.default.fileExists(atPath: out.path), "nothing written")
        try await Self.keysAnswerNo(screen) {
            try await Self.pressExport(window, item)
        } answeredNo: {
            main.dialog == nil && asked.isEmpty && !FileManager.default.fileExists(atPath: out.path)
        }
        try await Self.pressExport(window, item)
        await screen.settle()
        try await screen.press("Yes")
        #expect(asked == [warning.extension + " Personal"], "the save panel after Yes, named after the vault")
        try await screen.wait { FileManager.default.fileExists(atPath: out.path) }
        let start = format == .csv ? "\"Group\"" : "<?xml"
        #expect(try String(contentsOf: out, encoding: .utf8).hasPrefix(start))
        #expect(try Self.mode(out) == 0o600)
    }

    @Test("SD-07, FEA-09.7: File > Export HTML shows the warning as the dialog's banner; OK opens the save panel")
    func sd07HtmlBanner() async throws {
        let window = try ParityDemo.window("sd07-html")
        defer { window.lockAll() }
        let main = try #require(window.main)
        let warning = exportWarning(format: .html)
        let folder = try Self.folder("sd07-html")
        defer { try? FileManager.default.removeItem(at: folder) }
        let out = folder.appending(path: "Personal.html")
        var asked = 0
        let saved = VaultModel.exportPanel
        defer { VaultModel.exportPanel = saved }
        VaultModel.exportPanel = { _, _ in
            asked += 1
            return out
        }
        let screen = Screen(window)
        await screen.settle()
        try await Self.pressExport(window, "HTML…")
        #expect(main.dialog == .export(.html(warning)), "the dialog, no separate question")
        await screen.settle()
        let strings = screen.strings()
        #expect(strings.contains(warning.text), "the warning stays on the dialog")
        for choice in ["Name, A to Z", "Name, Z to A", "Order in the vault"] {
            #expect(screen.node(choice) != nil, "\(choice)")
        }
        try await screen.press("Cancel")
        #expect(main.dialog == nil && asked == 0 && !FileManager.default.fileExists(atPath: out.path))
        try await Self.pressExport(window, "HTML…")
        await screen.settle()
        try await screen.press("Name, Z to A")
        try await screen.press("OK")
        #expect(asked == 1)
        try await screen.wait { FileManager.default.fileExists(atPath: out.path) }
        let page = try String(contentsOf: out, encoding: .utf8)
        #expect(page.hasPrefix("<!DOCTYPE html>"))
        // Name, Z to A: the Work group's section before the Banking one's.
        let work = try #require(page.range(of: " › Work</h2>")).lowerBound
        #expect(work < (try #require(page.range(of: " › Banking</h2>")).lowerBound))
        #expect(try Self.mode(out) == 0o600)
    }

    @Test("SD-07, INT-04.50: the Passkeys report's Export asks MI04-30 first, then the list, the folder and MI04-32")
    func sd07PasskeyExportWarns() async throws {
        let window = try ParityDemo.window("sd07-passkeys")
        defer { window.lockAll() }
        let main = try #require(window.main)
        main.openReports(.passkeys)
        let reports = try #require(main.reports)
        for _ in 0..<400 where reports.passkeys == nil { try await Task.sleep(for: .milliseconds(25)) }
        let rows = try #require(reports.passkeys)
        let folder = try Self.folder("sd07-passkeys")
        defer { try? FileManager.default.removeItem(at: folder) }
        var asked = 0
        let saved = VaultModel.passkeyFolderPanel
        defer { VaultModel.passkeyFolderPanel = saved }
        VaultModel.passkeyFolderPanel = {
            asked += 1
            return folder
        }
        let files = { (try? FileManager.default.contentsOfDirectory(atPath: folder.path).sorted()) ?? [] }
        let screen = Screen(window)
        await screen.settle()
        // The row menu's "Export Passkeys…".
        main.askPasskeyExport()
        #expect(main.dialog == .export(.passkeyWarning(text: passkeyExportWarning(), rows: rows)))
        await screen.settle()
        #expect(screen.strings().contains(passkeyExportWarning()), "MI04-30, Rust's text")
        try await screen.press("No")
        #expect(main.dialog == nil && asked == 0 && files().isEmpty, "No: nothing written")
        try await Self.keysAnswerNo(screen) {
            main.askPasskeyExport()
        } answeredNo: {
            main.dialog == nil && asked == 0 && files().isEmpty
        }
        main.askPasskeyExport()
        await screen.settle()
        try await screen.press("Yes")
        #expect(main.dialog == .export(.passkeys(rows)) && asked == 0, "the list before the folder")
        await screen.settle()
        #expect(screen.strings().contains("Each file is named after its entry's title."))
        let github = try #require(rows.first { $0.entry.title == "GitHub" })
        try await screen.press("GitHub - " + github.user)
        try await screen.press("Export Selected")
        #expect(asked == 1 && main.dialog == nil)
        #expect(files() == ["Apple Account.passkey", "Linear.passkey", "Mastodon.passkey"])
        for file in files() { #expect(try Self.mode(folder.appending(path: file)) == 0o600, "\(file)") }
        let linear = try #require(rows.first { $0.entry.title == "Linear" }?.entry.id)
        try await Self.replaceAsks(main, screen, entry: linear, file: folder.appending(path: "Linear.passkey"))
    }

    /// MI04-32 (INT-04.50 step 4, T75): No leaves the file there untouched;
    /// Yes replaces it, 0600.
    private static func replaceAsks(_ main: VaultModel, _ screen: Screen, entry: String, file: URL) async throws {
        try Data("x".utf8).write(to: file)
        let folder = file.deletingLastPathComponent().path(percentEncoded: false)
        main.exportPasskeys([entry], to: folder)
        let ask = ExportStep.passkeyExists(file: file.lastPathComponent, entry: entry, folder: folder, rest: [])
        #expect(main.dialog == .export(ask))
        await screen.settle()
        try await screen.press("No")
        #expect(main.dialog == nil && (try? String(contentsOf: file, encoding: .utf8)) == "x")
        try await keysAnswerNo(screen) {
            main.exportPasskeys([entry], to: folder)
        } answeredNo: {
            main.dialog == nil && (try? String(contentsOf: file, encoding: .utf8)) == "x"
        }
        main.exportPasskeys([entry], to: folder)
        await screen.settle()
        try await screen.press("Yes")
        #expect(main.dialog == nil)
        #expect((try String(contentsOf: file, encoding: .utf8)).contains("linear.app"))
        #expect(try mode(file) == 0o600)
    }
}
