import AppKit
import LarsalCore
import SwiftUI
import Testing

/// Every frame of design/option-a/manifest.json that E5-S5 builds: the
/// editor's pages, the two window states and the sheets.
enum EditorFrame: String, CaseIterable, CustomTestStringConvertible {
    case entry = "editor-editor-entry"
    case advanced = "editor-editor-advanced"
    case icon = "editor-editor-icon"
    case autoType = "editor-editor-auto-type"
    case browser = "editor-editor-browser"
    case ssh = "editor-editor-ssh-agent"
    case properties = "editor-editor-properties"
    case history = "editor-editor-history"
    case new = "editor-new-entry"
    case unsaved = "states-unsaved-changes"
    case deleteSheet = "states-delete-as-a-sheet"
    case moveToBin = "dialogs-move-to-recycle-bin"
    case deleteForever = "dialogs-delete-forever"
    case emptyBin = "dialogs-empty-recycle-bin"
    case discard = "dialogs-discard-changes"
    case clone = "dialogs-clone-entry"
    case totpSetup = "dialogs-add-one-time-code"
    case totpQr = "dialogs-one-time-code-as-qr"
    case wifiQr = "dialogs-wi-fi-as-qr"
    case newGroup = "dialogs-new-group"
    case removePasskey = "dialogs-remove-passkey"
    case version = "dialogs-earlier-version"

    var testDescription: String { rawValue }
    /// The dialog frames are the sheet alone (mockup `card: true`).
    var card: Bool { rawValue.hasPrefix("dialogs-") }
    var page: EditorModel.Page? {
        switch self {
        case .entry, .new: .entry
        case .advanced: .advanced
        case .icon: .icon
        case .autoType: .autoType
        case .browser: .browser
        case .ssh: .ssh
        case .properties: .properties
        case .history: .history
        default: nil
        }
    }
}

@MainActor
@Suite(.serialized)
struct EditorSnapshotTests {
    init() { ParityDemo.setUp() }

    @Test("Option A editor frame, offscreen, light and dark", arguments: EditorFrame.allCases)
    func frame(_ frame: EditorFrame) async throws {
        let seams = frame == .wifiQr ? await QrSeams.begin() : nil
        defer { seams?.restore() }
        let window = try ParityDemo.window("editor-shots")
        let main = try #require(window.main)
        try ParityDemo.rate(window)
        try await state(frame, main)
        let root: AnyView =
            frame.card
            ? AnyView(DialogView(model: main, dialog: try #require(main.dialog)).fixedSize())
            : AnyView(MainWindow(model: window).frame(width: 1320, height: 820))
        let host = NSHostingView(rootView: root.font(.sans(14)).foregroundStyle(Tok.text))
        let size = frame.card ? host.fittingSize : CGSize(width: 1320, height: 820)
        host.frame = NSRect(origin: .zero, size: size)
        // Never ordered front (AGENTS.md rule 10); sRGB as the references.
        let offscreen = NSWindow(
            contentRect: host.frame.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless], backing: .buffered,
            defer: false)
        offscreen.colorSpace = .sRGB
        offscreen.backgroundColor = .clear
        offscreen.contentView = host
        let shots = SnapshotTests()
        for (folder, look) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            offscreen.appearance = NSAppearance(named: look)
            main.editor?.tick()
            let png = try await shots.render(host)
            let out = ParityDemo.shotsDirectory.appending(path: "\(folder)/\(frame.rawValue).png")
            try FileManager.default.createDirectory(
                at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
            try png.write(to: out)
            #expect(png.count > 5_000, "\(out.path)")
            try shots.accessibilityTree(host).write(to: out.deletingPathExtension().appendingPathExtension("ax.json"))
        }
        offscreen.contentView = nil
        main.closeEditor()
        window.lockAll()
    }

    // The screen state of `frame` (mockup.js `SECTIONS`, `DIALOGS`).
    // One case per frame: a table, not logic.
    // swiftlint:disable:next cyclomatic_complexity function_body_length
    private func state(_ frame: EditorFrame, _ main: VaultModel) async throws {
        let session = main.session
        let vault = main.vault.id
        let id = { (title: String) throws -> String in
            let all = try session.list(vault: vault, view: .all).rows + session.list(vault: vault, view: .bin).rows
            return try #require(all.first { $0.title == title }?.id, "\(title)")
        }
        let github = { () throws in
            main.edit(try id("GitHub"))
            try Self.githubDraft(session, vault)
            main.editor?.refresh()
            // LD-199 (1): masked at first; the frame shows it after Show.
            main.editor?.toggleShowPassword()
        }
        switch frame {
        case .entry, .advanced, .icon, .autoType, .browser, .properties, .history:
            try github()
        case .ssh:
            main.edit(try id("Server root · web-01"))
        case .new:
            let work = try #require(main.sidebar?.groups.first { $0.name == "Work" }?.id)
            main.newEntry(in: work)
            // A generated password of the generator's look (E5-S6 makes it;
            // S-ENTRY-03 comes with the settings, E5-S9).
            main.editor?.passwordTyped("k7#Rv2!pXq9@Lw4$Tz8m")
        case .unsaved:
            // Two changes that leave the list as drawn: Twitter (old account)
            // restored, then moved back to the bin; no save.
            main.autosave = false
            let twitter = try id("Twitter (old account)")
            _ = try session.restoreEntry(vault: vault, entry: twitter)
            _ = try session.deleteEntry(vault: vault, entry: twitter)
            main.afterChange(select: try id("Google"))
        case .deleteSheet:
            main.chooseTab(.attention)
            main.select(try id("Amazon"))
            main.askBeforeBin = true
            main.askDelete()
        case .moveToBin:
            main.dialog = .moveToBin(id: try id("Amazon"), title: "Amazon")
        case .deleteForever:
            main.dialog = .deleteForever(id: try id("MySpace"), title: "MySpace")
        case .emptyBin:
            main.askEmptyBin()
        case .discard:
            main.edit(try id("GitHub"))
            main.editor?.passwordTyped("m8@Ty3!Kq6#Pv1$Zr4&")
            try session.setTags(vault: vault, chips: ["2fa", "dev", "work"])
            main.editor?.refresh()
            main.cancelEditor()
        case .clone:
            main.dialog = .clone(id: try id("GitHub"), title: "GitHub")
        case .totpSetup:
            main.newEntry()
            main.dialog = .totpSetup(
                TotpSetup(
                    secret: "JBSW Y3DP EHPK 3PXP", choice: "standard", digits: 6, period: 30, algorithm: "SHA-1",
                    invalid: false))
        case .totpQr:
            main.edit(try id("GitHub"))
            main.dialog = .totpQr(title: "GitHub", symbol: try session.totpQr(vault: vault), custom: false)
        case .wifiQr:
            main.select(try id("Home Wi-Fi"))
            main.showWifiJoin()
        case .newGroup:
            main.dialog = .newGroup(name: "Travel")
        case .removePasskey:
            main.edit(try id("GitHub"))
            main.dialog = .removePasskey(site: "github.com")
        case .version:
            main.edit(try id("GitHub"))
            main.dialog = .version(index: 2, try session.showVersion(vault: vault, index: 2))
        }
        if let page = frame.page { main.editor?.page = page }
        // The strength is rated off the screen thread (LD-137): wait for it.
        for _ in 0..<100 where main.editor != nil && main.editor?.rating == nil {
            try await Task.sleep(for: .milliseconds(20))
        }
        main.editor?.tick()
    }

    /// The mockup's GitHub draft (mockup.js `EDP.advanced`, `allow`): three
    /// custom fields, the API token protected, and gist.github.com as an
    /// additional URL. Demo values only; never saved.
    static func githubDraft(_ session: Session, _ vault: UInt64) throws {
        for (name, value, protected) in [
            ("Recovery email", "alex.backup@posteo.de", false), ("Organization", "morgan-labs", false),
            ("API token", "ghp_demo0000000000000000", true),
        ] {
            let added = try session.addField(vault: vault)
            try session.renameField(vault: vault, old: added, name: name)
            try session.setField(vault: vault, name: name, value: value)
            if protected { try session.protectField(vault: vault, name: name, on: true) }
        }
        try session.addUrl(vault: vault, url: "https://gist.github.com")
    }
}

/// Design parity (check 6) for the editor: its controls do what the mockup
/// makes them do, pressed through the accessibility tree offscreen.
@MainActor
@Suite(.serialized)
struct ParityEditorTests {
    init() { ParityDemo.setUp() }

    @Test("Parity editor-editor-entry: Edit entry opens the editor; each page shows; Cancel without changes closes")
    func pages() async throws {
        let model = try ParityDemo.window("parity-editor")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        let editor = try #require(main.editor)
        #expect(screen.strings().contains("Sign-in"))
        for page in EditorModel.Page.allCases {
            try await screen.press(page.rawValue)
            #expect(editor.page == page)
        }
        try await screen.press("Cancel")
        #expect(main.editor == nil && main.dialog == nil)
    }

    @Test("Parity editor-editor-entry: Hide password drops the shown value; Show password brings it back")
    func showHide() async throws {
        let model = try ParityDemo.window("parity-editor")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        let editor = try #require(main.editor)
        // LD-199 (1): masked at first, in a secure field; the value is not
        // in Swift until Show.
        #expect(editor.shownPassword == nil)
        func secure(_ view: NSView) -> NSSecureTextField? {
            (view as? NSSecureTextField) ?? view.subviews.lazy.compactMap(secure).first
        }
        #expect(secure(screen.host) is FocusSecureField)
        try await screen.press("Show password")
        #expect(editor.shownPassword?.isEmpty == false)
        try await screen.press("Hide password")
        #expect(editor.shownPassword == nil)
        try await screen.press("Show password")
        #expect(editor.shownPassword?.isEmpty == false)
    }

    @Test("Parity editor-editor-entry: leaving the vault with changes asks; Cancel stays; Discard wipes and switches")
    func leaveVault() async throws {
        let model = try ParityDemo.window("parity-editor", unlocked: [0, 1])
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        main.editor?.set(.notes, "demo change")
        let work = try #require(model.vaults.first { $0.name == "Work" }?.id)
        model.switchTo(work)
        #expect(main.dialog == .leaveEditor && model.main === main, "asked, not switched")
        await screen.settle()
        try await screen.press("Cancel")
        #expect(main.editor != nil && model.main === main)
        model.switchTo(work)
        await screen.settle()
        try await screen.press("Discard")
        #expect(main.editor == nil && model.main?.vault.id == work)
        #expect(
            (try? model.session.editor(vault: main.vault.id)) == nil, "cancelEdit: the draft and its copies are gone")
    }

    @Test("Parity dialogs-discard-changes: Cancel with changes asks; Keep Editing stays; Discard Changes closes")
    func discard() async throws {
        let model = try ParityDemo.window("parity-editor")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        main.editor?.set(.notes, "demo change")
        await screen.settle()
        try await screen.press("Cancel")
        #expect(main.dialog == .discard)
        try await screen.press("Keep Editing")
        #expect(main.dialog == nil && main.editor != nil)
        try await screen.press("Cancel")
        try await screen.press("Discard Changes")
        #expect(main.editor == nil)
        #expect(main.detail?.fields.first { $0.kind == .notes }?.value != "demo change", "nothing changed")
    }

    @Test("Parity states-unsaved-changes: Save commits the draft and the vault saves; the footer reads Saved at")
    func saveAfterChange() async throws {
        let model = try ParityDemo.window("parity-editor")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        main.editor?.set(.notes, "demo saved note")
        await screen.settle()
        try await screen.press("Save")
        #expect(main.editor == nil)
        #expect(main.detail?.fields.first { $0.kind == .notes }?.value == "demo saved note")
        try await screen.wait { main.saveStatus?.savedAt != nil && main.saveStatus?.changes == 0 }
        #expect(main.savedWords.text.hasPrefix("Saved at "))
    }

    @Test("Parity editor-new-entry: New Entry opens a new entry; Save adds it to the list")
    func newEntry() async throws {
        let model = try ParityDemo.window("parity-editor")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        let before = main.placeRows.count
        try await screen.press("New Entry")
        #expect(main.editor?.view.new == true)
        main.editor?.set(.title, "Demo entry")
        await screen.settle()
        try await screen.press("Save")
        #expect(main.placeRows.count == before + 1)
        #expect(main.detail?.title == "Demo entry")
    }

    @Test("Parity states-delete-as-a-sheet: Move to Recycle Bin moves the entry; Cancel keeps it")
    func deleteSheet() async throws {
        let model = try ParityDemo.window("parity-editor")
        let main = try #require(model.main)
        main.askBeforeBin = true
        let screen = Screen(model)
        await screen.settle()
        let bin = main.sidebar?.bin ?? 0
        main.askDelete()
        await screen.settle()
        try await screen.press("Cancel")
        #expect(main.dialog == nil && main.sidebar?.bin == bin)
        main.askDelete()
        await screen.settle()
        try await screen.press("Move to Recycle Bin")
        #expect(main.sidebar?.bin == bin + 1)
    }

    @Test("Parity dialogs-clone-entry: Clone makes a copy named with ' - Clone' and selects it")
    func clone() async throws {
        let model = try ParityDemo.window("parity-editor")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        let title = try #require(main.detail?.title)
        main.askClone()
        await screen.settle()
        try await screen.press("Clone")
        #expect(main.detail?.title == title + " - Clone")
    }
}
