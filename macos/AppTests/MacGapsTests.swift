import AppCore
import AppKit
import SwiftUI
import Testing

// E13-S6 part m: the small Mac gaps of LD-230 (4), (5) and LD-243 (1), (3),
// each through the real views, offscreen and never ordered front
// (AGENTS.md rule 10).

/// Every node of `view`'s accessibility tree, depth first.
@MainActor
func axNodes(_ view: NSView) -> [AnyObject] {
    var out: [AnyObject] = []
    func walk(_ any: Any, _ depth: Int) {
        let element = any as AnyObject
        guard depth < 80 else { return }
        out.append(element)
        for child in element.accessibilityChildren?() ?? [] { walk(child, depth + 1) }
    }
    walk(view, 0)
    return out
}

@MainActor
@Suite(.serialized)
struct MacGapsTests {
    init() {
        ParityDemo.setUp()
    }

    /// A 64 × 48 demo PNG.
    static func png() throws -> Data {
        let rep = try #require(
            NSBitmapImageRep(
                bitmapDataPlanes: nil, pixelsWide: 64, pixelsHigh: 48, bitsPerSample: 8, samplesPerPixel: 4,
                hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0))
        return try #require(rep.representation(using: .png, properties: [:]))
    }

    // MARK: MOD-05.9 preview

    @Test("MOD-05.9 (LD-230 (4)): the preview decodes its image off the main thread, then shows it")
    func mod059ImageDecodedOffMain() async throws {
        let png = try Self.png()
        // The sheet's decoder answers only off the main thread.
        let real = PreviewSheet.decoder
        defer { PreviewSheet.decoder = real }
        PreviewSheet.decoder = { Thread.isMainThread ? nil : real($0) }
        let window = try ParityDemo.window("mod059-image")
        defer { window.lockAll() }
        let main = try #require(window.main)
        let screen = Offscreen(
            PreviewSheet(model: main, name: "demo.png", preview: .image(png: png)),
            size: CGSize(width: 600, height: 520))
        await screen.settle()
        let shown = axNodes(screen.host).contains {
            $0.accessibilityRole?()?.rawValue == "AXImage" && ($0.accessibilityLabel?() ?? nil) == "demo.png"
        }
        #expect(shown, "the image, decoded off the main thread, is on the sheet")
    }

    @Test("MOD-05.9 (LD-230 (4)): Open and Save in the preview run the editor's own actions on its attachments")
    func mod059PreviewOpenAndSave() async throws {
        let window = try ParityDemo.window("mod059-open")
        defer { window.lockAll() }
        let main = try #require(window.main)
        main.select(try githubID(main))
        let name = try #require(main.detail?.attachments.first?.name)
        let screen = Screen(window)
        main.previewAttachment(name)
        await screen.settle()
        let before = FakeOpener.opened.count  // shared with suites running side by side
        try await screen.press("Open")
        #expect(main.editor?.page == .advanced, "the entry's editor, on its attachments")
        // A copy under a random name with the attachment's extension; other
        // suites may open files meanwhile, so no exact count.
        let opened = FakeOpener.opened.dropFirst(before).map(\.pathExtension)
        #expect(main.dialog == nil && opened.contains(URL(filePath: name).pathExtension), "Open ran: \(opened)")
        main.closeEditor()
        let folder = try ExportScreensTests.folder("mod059-save")
        defer { try? FileManager.default.removeItem(at: folder) }
        let saved = VaultModel.attachmentFolderPanel
        defer { VaultModel.attachmentFolderPanel = saved }
        VaultModel.attachmentFolderPanel = { nil }
        main.previewAttachment(name)
        await screen.settle()
        try await screen.press("Save…")
        #expect(main.editor == nil && main.dialog != nil, "a cancelled folder panel keeps the preview")
        VaultModel.attachmentFolderPanel = { folder }
        try await screen.press("Save…")
        #expect(main.editor?.page == .advanced && main.dialog == nil, "the editor's Save ran")
        #expect(FileManager.default.fileExists(atPath: folder.appending(path: name).path))
        main.closeEditor()
    }

    @Test("SD-13 (LD-230 (5)): a link in an HTML or Markdown text preview is no link, shown exactly as typed")
    func sd13LinkIsText() async throws {
        let window = try ParityDemo.window("sd13-link")
        defer { window.lockAll() }
        let main = try #require(window.main)
        let texts = [
            ("page.html", "<p>Hi <a href=\"https://example.com/x\">demo link</a></p>"),
            ("notes.md", "Read [demo link](https://example.com/x) and <https://example.com/y>"),
        ]
        for (name, text) in texts {
            let screen = Offscreen(
                PreviewSheet(model: main, name: name, preview: .text(text: text)), size: CGSize(width: 600, height: 520)
            )
            #expect(await screen.strings().contains(text), "\(name): the text as typed")
            let links = axNodes(screen.host).filter { $0.accessibilityRole?()?.rawValue == "AXLink" }
            #expect(links.isEmpty, "\(name): no AXLink node")
        }
    }

    // MARK: APP-08 Fetch Site Icons for Group…

    @Test("LD-243 (1): Fetch Site Icons for Group… is on for a group with entries, off for an empty one and the bin")
    func ld243FetchGroupIcons() async throws {
        guard #available(macOS 14.4, *) else { return }
        let window = try ParityDemo.window("ld243-icons")
        defer { window.lockAll() }
        let main = try #require(window.main)
        let title = "Fetch Site Icons for Group…"
        let email = try #require(main.sidebar?.groups.first { $0.name == "Email" })
        let empty = try window.session.addGroup(
            vault: main.vault.id, parent: nil, name: "Empty", icon: 48, customIcon: nil)
        main.rated()
        let emptyRow = try #require(main.sidebar?.groups.first { $0.id == empty })
        for (place, enabled) in [
            (VaultModel.Place.group(email.id), true), (.all, true), (.group(empty), false), (.bin, false),
        ] {
            main.choose(place)
            let line = await MenuLine.read(GroupMenuItems(window: window)).line(title)
            #expect(line?.enabled == enabled, "\(place): \(String(describing: line))")
        }
        let menu = await MenuLine.read(GroupContextMenu(model: main, group: email))
        #expect(menu.line(title)?.enabled == true)
        #expect(await MenuLine.read(GroupContextMenu(model: main, group: emptyRow)).line(title)?.enabled == false)
        // The press reaches Rust with the group's entries; downloads are off
        // by default (S-ENTRY-11), so nothing leaves this Mac.
        main.choose(.group(email.id))
        let native = NSHostingMenu(rootView: GroupMenuItems(window: window))
        native.update()
        try await Task.sleep(for: .milliseconds(30))
        native.update()
        native.performActionForItem(at: native.indexOfItem(withTitle: title))
        for _ in 0..<400 where main.toast == nil { try await Task.sleep(for: .milliseconds(25)) }
        #expect(main.toast?.text == "Website icon downloads are off. Turn them on in Settings › Entries.")
    }

    // MARK: APP-07 wizard

    @Test("LD-243 (3): the wizard's step 3 body is disabled while 'Creating the vault…' shows")
    func ld243Step3DisabledWhileCreating() async throws {
        let folder = try ExportScreensTests.folder("ld243-wizard")
        defer { try? FileManager.default.removeItem(at: folder) }
        let model = try await WizardDemo.model(.password)
        let screen = Offscreen(NewVaultView(model: model), size: CGSize(width: 720, height: 720))
        await screen.settle()
        func enabled(_ name: String) -> Bool? {
            axNodes(screen.host).first { ($0.accessibilityLabel?() ?? nil) == name }?.isAccessibilityEnabled?()
        }
        #expect(enabled("New Key File…") == true && enabled("Generate password") == true)
        model.write(to: folder.appending(path: "Family.appvault"))
        // The main actor stays here until the write's answer: still creating.
        #expect(model.creating)
        screen.host.layoutSubtreeIfNeeded()
        for name in ["New Key File…", "Choose Key File…", "Hide password", "Generate password"] {
            #expect(enabled(name) == false, "\(name) while creating")
        }
        for _ in 0..<400 where model.creating { try await Task.sleep(for: .milliseconds(25)) }
    }
}
