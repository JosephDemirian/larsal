import AppCore
import AppKit
import SwiftUI
import Testing

/// Design parity (check 6) for the editor's pages and the E5-S5 sheets:
/// each control the mockup makes clickable, pressed through the
/// accessibility tree offscreen (never ordered front, AGENTS.md rule 10).
@MainActor
@Suite(.serialized)
struct ParityEditorPagesTests {
    init() { ParityDemo.setUp() }

    /// The Personal vault with GitHub's editor open on `page`.
    private func github(_ page: EditorModel.Page = .entry) async throws -> (VaultModel, Screen) {
        let model = try ParityDemo.window("parity-editor-pages")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        try await screen.press(page.rawValue)
        return (main, screen)
    }

    @Test("Parity editor-editor-advanced: Add field adds New field; its Protect switch protects it")
    func advanced() async throws {
        let (main, screen) = try await github(.advanced)
        try await screen.press("Add field")
        #expect(main.editor?.view.custom.contains { $0.name == "New field" } == true)
        try await screen.press("Protect New field")
        #expect(main.editor?.view.custom.first { $0.name == "New field" }?.protected == true)
    }

    @Test("Parity editor-editor-icon: a symbol and a colour become the entry's custom icon")
    func icon() async throws {
        let (main, screen) = try await github(.icon)
        try await screen.press("airplane")
        #expect(main.editor?.view.icon == -1)
        try await screen.press("teal")
        #expect(main.editor?.view.customIcon == "airplane teal")
        try await screen.press("Save")
        #expect(main.detail?.customIcon == "airplane teal")
    }

    @Test("Parity editor-editor-auto-type: the switch turns Auto-Type off; the group's sequence clears the entry's")
    func autoType() async throws {
        let (main, screen) = try await github(.autoType)
        try await screen.pressLast("Auto-Type")
        #expect(main.editor?.view.autoType.enabled == false)
        try await screen.press("Use the group's sequence")
        #expect(main.editor?.view.autoType.sequence.isEmpty == true)
    }

    @Test("Parity editor-editor-browser: the switches and the site lists are stored with the editor (INT-02.29)")
    func browser() async throws {
        let (main, screen) = try await github(.browser)
        #expect(main.editor?.view.allow == ["gist.github.com", "github.com"])
        try await screen.press("Do not submit")
        #expect(main.editor?.view.browserOptions.first { $0.key == "BrowserSkipAutoSubmit" }?.on == false)
        try await screen.press("Remove gist.github.com")
        #expect(main.editor?.view.allow == ["github.com"])
        #expect(screen.strings().contains("Firefox on MacBook"))
    }

    @Test("Parity editor-editor-ssh-agent: the key's type shows; the agent settings wait for E9")
    func ssh() async throws {
        let model = try ParityDemo.window("parity-editor-pages")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Servers")
        try await screen.press("Server root · web-01")
        try await screen.press("Edit entry (⌘E)")
        try await screen.press("SSH Agent")
        #expect(main.editor?.view.ssh?.kind == "ED25519")
        #expect(screen.node("Add on unlock")?.isAccessibilityEnabled?() == false)
    }

    @Test("Parity editor-editor-properties: Remove asks; Delete drops the custom data item from the draft")
    func properties() async throws {
        let (main, screen) = try await github(.properties)
        try await screen.press("Remove")
        #expect(main.dialog == .removeCustomData(key: "browser.last_fill"))
        let before = main.editor?.view.customData.count ?? 0
        try await screen.press("Delete")
        #expect(main.editor?.view.customData.count == before - 1 && main.dialog == nil)
    }

    @Test("Parity editor-editor-history: Delete version hides the version until Save")
    func history() async throws {
        let (main, screen) = try await github(.history)
        let before = main.editor?.view.historyItems ?? 0
        try await screen.pressLast("Delete version")
        #expect(main.editor?.view.historyItems == before - 1)
    }

    @Test("Parity dialogs-earlier-version: Show opens an earlier version; Restore This Version puts it in the draft")
    func version() async throws {
        let (main, screen) = try await github(.history)
        try await screen.pressLast("Show")
        guard case .version = main.dialog else {
            Issue.record("no version sheet")
            return
        }
        try await screen.press("Restore This Version")
        #expect(main.dialog == nil && main.editor?.view.changed.contains("Password") == true)
    }

    @Test("Parity dialogs-one-time-code-as-qr: Show QR opens the code as QR; Done closes it")
    func totpQr() async throws {
        let (main, screen) = try await github()
        try await screen.press("Show QR")
        guard case .totpQr = main.dialog else {
            Issue.record("no QR sheet")
            return
        }
        #expect(screen.node("QR code") != nil)
        try await screen.press("Done")
        #expect(main.dialog == nil)
    }

    @Test("Parity dialogs-add-one-time-code: Change… opens the setup filled in; Add Code keeps the code")
    func totpSetup() async throws {
        let (main, screen) = try await github()
        try await screen.press("Change…")
        guard case .totpSetup(let setup) = main.dialog else {
            Issue.record("no setup sheet")
            return
        }
        #expect(!setup.secret.isEmpty)
        await screen.settle()
        // LD-199 (5): the secret is in the no-copy field (APP-03.19).
        func noCopy(_ view: NSView) -> NoCopyTextField? {
            (view as? NoCopyTextField) ?? view.subviews.lazy.compactMap(noCopy).first
        }
        let field = try #require(noCopy(screen.host))
        #expect(field.accessibilityLabel() == "Secret key" && field.stringValue == setup.secret)
        try await screen.press("Add Code")
        #expect(main.dialog == nil && main.editor?.view.totp != nil)
    }

    @Test("Parity dialogs-remove-passkey: Remove asks; Remove Passkey drops the passkey from the draft")
    func removePasskey() async throws {
        let (main, screen) = try await github()
        try await screen.pressLast("Remove")
        #expect(main.dialog == .removePasskey(site: "github.com"))
        try await screen.press("Remove Passkey")
        #expect(main.editor?.view.passkey == nil)
    }

    @Test("Parity dialogs-wi-fi-as-qr: Show as QR code opens the network as QR")
    func wifiQr() async throws {
        let model = try ParityDemo.window("parity-editor-pages")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Devices")
        try await screen.press("Home Wi-Fi")
        try await screen.press("Show as QR code")
        guard case .wifiQr(let network, _) = main.dialog else {
            Issue.record("no Wi-Fi sheet")
            return
        }
        #expect(network == "Morgan-Home 5G")
    }

    @Test("Parity dialogs-new-group: Create Group adds the group with its symbol and colour as a custom icon")
    func newGroup() async throws {
        let model = try ParityDemo.window("parity-editor-pages")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("New group")
        #expect(main.dialog == .newGroup(name: ""))
        main.dialog = .newGroup(name: "Travel")
        await screen.settle()
        try await screen.press("boat")
        try await screen.press("Create Group")
        #expect(main.sidebar?.groups.contains { $0.name == "Travel" && $0.customIcon == "boat cyan" } == true)
    }

    @Test("Parity dialogs-move-to-recycle-bin: Do not ask again turns the question off; the entry moves")
    func moveToBin() async throws {
        let model = try ParityDemo.window("parity-editor-pages")
        let main = try #require(model.main)
        main.askBeforeBin = true
        let screen = Screen(model)
        await screen.settle()
        let bin = main.sidebar?.bin ?? 0
        try await screen.press("More actions")
        try await screen.press("Move to Recycle Bin")
        try await screen.press("Do not ask again")
        try await screen.pressLast("Move to Recycle Bin")
        #expect(!main.askBeforeBin && main.sidebar?.bin == bin + 1)
    }

    @Test("Parity dialogs-delete-forever: Delete forever asks; Delete Forever removes the entry from the bin")
    func deleteForever() async throws {
        let model = try ParityDemo.window("parity-editor-pages")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Recycle Bin")
        let bin = main.sidebar?.bin ?? 0
        try await screen.press("Delete forever")
        guard case .deleteForever = main.dialog else {
            Issue.record("no sheet")
            return
        }
        try await screen.press("Delete Forever")
        #expect(main.sidebar?.bin == bin - 1)
    }

    @Test("Parity dialogs-empty-recycle-bin: Empty Recycle Bin asks, then empties the bin")
    func emptyBin() async throws {
        let model = try ParityDemo.window("parity-editor-pages")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Recycle Bin")
        try await screen.press("Empty Recycle Bin")
        guard case .emptyBin(let titles) = main.dialog else {
            Issue.record("no sheet")
            return
        }
        #expect(titles.count == 2)
        try await screen.pressLast("Empty Recycle Bin")
        #expect(main.sidebar?.bin == 0)
    }
}

/// Attachments (MOD-05) and the typed expiry (MOD-09.10).
@MainActor
@Suite(.serialized)
struct ParityEditorFilesTests {
    init() { ParityDemo.setUp() }

    @Test("Parity editor-editor-advanced: Open hands a private copy to the default app; Remove asks first")
    func openAndRemove() async throws {
        let model = try ParityDemo.window("parity-editor-files")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        try await screen.press("Advanced")
        let before = FakeOpener.opened.count
        try await screen.press("Open")
        #expect(main.toast == nil, "\(main.toast?.text ?? "")")
        // Other suites open files side by side: pick this attachment's copy by its extension.
        let mine = FakeOpener.opened.dropFirst(before).last(where: {
            $0.pathExtension == "txt" && FileManager.default.fileExists(atPath: $0.path)
        })
        let copy = try #require(mine)
        #expect(copy.path.contains("/App/open-attachments/") && FileManager.default.fileExists(atPath: copy.path))
        try await screen.pressLast("Remove")
        #expect(main.dialog == .removeAttachment(name: "github-recovery-codes.txt"))
        try await screen.pressLast("Remove")
        #expect(main.editor?.view.attachments.isEmpty == true)
        try await screen.press("Cancel")
        try await screen.press("Discard Changes")
        #expect(!FileManager.default.fileExists(atPath: copy.path), "wiped when the editor closes")
    }

    @Test("Parity editor-editor-advanced: Save… writes into a folder and asks before overwriting")
    func saveToFolder() async throws {
        let model = try ParityDemo.window("parity-editor-files")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        let folder = ParityDemo.root.appending(path: "target/option-a/parity-editor-files/saved")
        try? FileManager.default.removeItem(at: folder)
        let path = folder.path(percentEncoded: false)
        main.saveAttachment("github-recovery-codes.txt", to: path)
        #expect(main.dialog == nil)
        main.saveAttachment("github-recovery-codes.txt", to: path)
        #expect(main.dialog == .replaceFile(name: "github-recovery-codes.txt", folder: path))
        await screen.settle()
        try await screen.pressLast("Overwrite")
        #expect(main.dialog == nil)
        let mode = try FileManager.default.attributesOfItem(atPath: path + "/github-recovery-codes.txt")[
            .posixPermissions]
        #expect((mode as? Int) == 0o600)
    }

    @Test("Parity editor-editor-entry: the Expires switch sets the date to now; the field takes a typed date")
    func expiry() async throws {
        let model = try ParityDemo.window("parity-editor-files")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        try await screen.press("Expires")
        let view = try #require(main.editor?.view)
        #expect(view.expires && abs(view.expiry - Int64(Date().timeIntervalSince1970)) < 5)
        main.editor?.run { try main.session.setExpiry(vault: main.vault.id, on: true, at: 1_800_000_000) }
        #expect(main.editor?.view.expiry == 1_800_000_000)
    }

    @Test("F-060: a protected standard field opens masked with Show; Show gives it, Hide drops it; untyped, it stays")
    func protectedStandardField() async throws {
        let model = try ParityDemo.window("parity-editor-files")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        let real = try #require(main.editor?.view)
        #expect(!real.user.isEmpty)
        // What Rust sends for a protected UserName (the Rust test
        // f_060_the_editor_view_holds_no_protected_standard_value): the
        // flag and no value. The page draws what it is given.
        var view = real
        view.protected = [.userName]
        view.user = ""
        let editor = EditorModel(session: main.session, vault: main.vault, view: view)
        main.editor = editor
        await screen.settle()
        func username() -> [String] { screen.values("Username") }
        #expect(username().contains(MaskedRow.dots) && !username().contains(real.user), "masked")
        try await screen.press("Show Username")
        #expect(editor.shownFields["UserName"] == real.user && username().contains(real.user))
        try await screen.press("Hide Username")
        #expect(editor.shownFields.isEmpty && !username().contains(real.user))
        #expect(try main.session.editor(vault: main.vault.id).user == real.user, "nothing typed, nothing stored")
    }

    @Test("F-060: an earlier version's protected user name shows masked with Show; Show gives it, Hide drops it")
    func protectedVersionField() async throws {
        let model = try ParityDemo.window("parity-editor-files")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Edit entry (⌘E)")
        try await screen.press("History")
        let real = try main.session.showVersion(vault: main.vault.id, index: 0)
        #expect(!real.user.isEmpty)
        // What Rust sends for a protected UserName (the Rust test
        // f_060_an_earlier_version_holds_no_protected_standard_value).
        var version = real
        version.protected = [.userName]
        version.user = ""
        main.dialog = .version(index: 0, version)
        await screen.settle()
        #expect(screen.values("Username").contains(MaskedRow.dots), "masked")
        #expect(!screen.values("Username").contains(real.user))
        try await screen.press("Show Username")
        #expect(screen.values("Username").contains(real.user))
        try await screen.press("Hide Username")
        #expect(!screen.values("Username").contains(real.user) && screen.values("Username").contains(MaskedRow.dots))
    }
}

/// What attachment Open handed over in tests, instead of the default app.
@MainActor
enum FakeOpener {
    static var opened: [URL] = []
}

extension Screen {
    /// The text values of every element labelled `name`.
    func values(_ name: String) -> [String] {
        nodes().filter { ($0.accessibilityLabel?() ?? nil) == name }.compactMap { element in
            let value: Any? = element.accessibilityValue?() ?? nil
            return value as? String
        }
    }

    /// Presses the last element named `name` (a sheet's button drawn over
    /// one of the same name, or the oldest row's).
    func pressLast(_ name: String) async throws {
        let element = try #require(
            nodes().last { element in
                let label = (element.accessibilityLabel?() ?? nil) ?? ""
                return (label == name || label.hasPrefix(name + ", ")) && element.isAccessibilityEnabled?() != false
            }, "\(name) is on screen")
        #expect(element.accessibilityPerformPress?() == true, "\(name) takes a press")
        await settle()
    }
}
