import AppKit
import LarsalCore
import SwiftUI
import Testing

/// E24-S2 New SSH Key on the Mac (spec INT-06.E24.01 to .05): the frames
/// `e24-s1-new-ssh` to `e24-s1-ssh-save-error` drawn offscreen, light and
/// dark, and the flow through the window. Offscreen only; the folder panel
/// never shows; copies go to the session's private pasteboard (AGENTS.md
/// rule 10).
@MainActor
@Suite(.serialized)
struct NewSshKeyTests {
    init() { ParityDemo.setUp() }

    /// The frames' demo key (K1 of spec INT-06): public parts only.
    static let demoKey = NewSshKeyView(
        entry: "", attachment: "id_ed25519", kind: "ED25519",
        fingerprint: "SHA256:R3aMsbAq88Fv8wlNcuy3oN+ZIl7yqPd3lRkAP/AP+uc",
        publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcFDq2T71wERCeKk/6BZCGHILdNQmAt+6GVCObXA9mG demo@app")

    /// The Personal demo window with GitHub's editor open on the SSH page.
    private static func editing(_ folder: String) throws -> (MainWindowModel, VaultModel) {
        let window = try ParityDemo.window(folder)
        let main = try #require(window.main)
        main.edit(try githubID(main))
        try #require(main.editor).page = .ssh
        return (window, main)
    }

    private static func saved(_ main: VaultModel) -> (NewSshKeyView, String)? {
        if case .sshKeySaved(let key, let line) = main.dialog { (key, line) } else { nil }
    }

    /// Waits for Rust's work off the screen thread, up to two minutes: a Mac
    /// under load never fails these tests by the clock.
    private static func until(_ done: () -> Bool) async throws {
        for _ in 0..<4_800 where !done() { try await Task.sleep(for: .milliseconds(25)) }
    }

    /// No file under `folder` holds a private key in the clear.
    private static func noPrivateFile(_ folder: URL) throws -> Bool {
        try FileManager.default.subpathsOfDirectory(atPath: folder.path).allSatisfy { name in
            let data = (try? Data(contentsOf: folder.appending(path: name))) ?? Data()
            return data.range(of: Data("PRIVATE KEY".utf8)) == nil
        }
    }

    @Test("E24-S01 INT-06.E24.01: Ed25519 by default with no size; ECDSA offers P-256, P-384, P-521; RSA 3072, 4096")
    func e24S01Choices() async throws {
        let (window, main) = try Self.editing("e24-choices")
        defer { window.lockAll() }
        #expect(SshKeyChoice().kind == .ed25519, "the default")
        let curves = (0..<3).map { SshKeyChoice(family: 1, curve: $0).kind }
        let sizes = (0..<2).map { SshKeyChoice(family: 2, bits: $0).kind }
        #expect(curves + sizes == [.ecdsaP256, .ecdsaP384, .ecdsaP521, .rsa3072, .rsa4096])
        #expect(SshKeyChoice(family: 1).kind == .ecdsaP256 && SshKeyChoice(family: 2).kind == .rsa3072)
        let screen = Screen(window)
        await screen.settle()
        try await screen.press("New SSH Key…")
        #expect(main.dialog == .newSshKey)
        #expect(screen.strings().contains("Fixed key size · Ed25519 is the default."))
        let labels = ["P-256", "P-384", "P-521", "3072", "4096"]
        #expect(labels.allSatisfy { screen.node($0) == nil }, "no size for Ed25519")
        try await screen.press("RSA")
        #expect(screen.node("3072") != nil && screen.node("4096") != nil && screen.node("2048") == nil)
        #expect(screen.node("P-256") == nil)
        try await screen.press("ECDSA")
        #expect(["P-256", "P-384", "P-521"].allSatisfy { screen.node($0) != nil } && screen.node("3072") == nil)
        try await screen.press("Cancel")
        #expect(main.dialog == nil && main.editor != nil, "Cancel leaves the editor as it was")
    }

    @Test("E24-S04 E24-S05 INT-06.E24.04, .05: the key is committed and saved; Copy and Save give the public line")
    func e24S04S05GenerateSaveCopy() async throws {
        let (window, main) = try Self.editing("e24-generate")
        defer { window.lockAll() }
        let (session, vault, path) = (window.session, main.vault.id, main.path)
        let screen = Screen(window)
        await screen.settle()
        try await screen.press("New SSH Key…")
        try await screen.type("e24@demo", into: "Public comment")
        try await screen.press("Generate and Add Key")
        try await Self.until { Self.saved(main) != nil }
        let (key, line) = try #require(Self.saved(main), "SSH key saved after the save")
        #expect(main.editor == nil, "the editor was committed")
        #expect(try session.saveStatus(vault: vault).changes == 0, "the vault file has it")
        #expect(key.kind == "ED25519" && key.attachment == "id_ed25519" && line.hasPrefix("GitHub · "))
        #expect(key.publicKey.hasPrefix("ssh-ed25519 ") && key.publicKey.hasSuffix(" e24@demo"))
        #expect(key.fingerprint.hasPrefix("SHA256:") && key.fingerprint.count == 50)
        await screen.settle()
        #expect(screen.strings().contains(key.fingerprint) && screen.strings().contains(key.publicKey))
        // The file as saved, read in a second session: the entry's key.
        let other = try ParityDemo.session()
        let copy = try other.open(path: path)
        #expect(try other.unlock(vault: copy, password: "demo-pass-7", keyFile: nil) == .unlocked)
        let stored = try other.beginEdit(vault: copy, entry: key.entry)
        #expect(stored.sshPublicKey == key.publicKey && stored.ssh?.fingerprint == key.fingerprint)
        #expect(Set(["id_ed25519", "id_ed25519.pub"]).isSubset(of: Set(stored.attachments.map(\.name))))
        try other.cancelEdit(vault: copy)
        try other.lock(vault: copy)
        // Copy Public Key: Rust's copy, to the session's private pasteboard.
        try await screen.press("Copy Public Key")
        #expect(main.toast?.text == "Public key copied.")
        PasteboardProof.expectOnlyPrivate(session)
        // Save Public Key…: nothing before a folder; then the line; then ask.
        let folder = try ExportScreensTests.folder("e24-public")
        defer { try? FileManager.default.removeItem(at: folder) }
        let panel = VaultModel.attachmentFolderPanel
        defer { VaultModel.attachmentFolderPanel = panel }
        VaultModel.attachmentFolderPanel = { nil }
        try await screen.press("Save Public Key…")
        #expect(try FileManager.default.contentsOfDirectory(atPath: folder.path).isEmpty)
        VaultModel.attachmentFolderPanel = { folder }
        try await screen.press("Save Public Key…")
        let file = folder.appending(path: "id_ed25519.pub")
        #expect(try String(contentsOf: file, encoding: .utf8) == key.publicKey + "\n")
        try Data("old".utf8).write(to: file)
        // Set again: a suite running side by side may have put the panel back.
        VaultModel.attachmentFolderPanel = { folder }
        try await screen.press("Save Public Key…")
        #expect(try String(contentsOf: file, encoding: .utf8) == "old", "a file there is never replaced unasked")
        try await screen.press("Overwrite")
        #expect(try String(contentsOf: file, encoding: .utf8) == key.publicKey + "\n")
        #expect(try Self.noPrivateFile(folder))
        #expect(try Self.noPrivateFile(URL(filePath: path).deletingLastPathComponent()))
        try await screen.press("Done")
        #expect(main.dialog == nil)
    }

    @Test("E24-S04 INT-06.E24.04: a failed save says Key not saved, keeps the key unsaved; Try Again saves it")
    func e24S04FailedSave() async throws {
        let (window, main) = try Self.editing("e24-unsaved")
        defer { window.lockAll() }
        let folder = URL(filePath: main.path).deletingLastPathComponent()
        let before = try Data(contentsOf: URL(filePath: main.path))
        try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: folder.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: folder.path) }
        let screen = Screen(window)
        await screen.settle()
        try await screen.press("New SSH Key…")
        try await screen.press("ECDSA")
        try await screen.press("P-384")
        try await screen.press("Generate and Add Key")
        try await Self.until { if case .sshKeyNotSaved = main.dialog { true } else { false } }
        guard case .sshKeyNotSaved(let key, _) = main.dialog else {
            Issue.record("Key not saved shows: \(String(describing: main.dialog))")
            return
        }
        #expect(key.kind == "ECDSA P-384" && key.attachment == "id_ecdsa")
        #expect(try Data(contentsOf: URL(filePath: main.path)) == before, "the vault file is unchanged")
        await screen.settle()
        #expect(screen.strings().contains("The vault file is unchanged."))
        #expect(screen.strings().contains { $0.contains("The new key stays in this entry as an unsaved change.") })
        #expect(main.saveStatus?.changes == 1, "the key stays in the open vault as an unsaved change")
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: folder.path)
        try await screen.press("Try Again")
        try await Self.until { Self.saved(main) != nil }
        #expect(Self.saved(main)?.0 == key, "the same key, saved")
        #expect(try Data(contentsOf: URL(filePath: main.path)) != before)
    }

    @Test("E24-S06 INT-06.E24.04, .06: Cancel while the key is made closes the sheet and keeps the editor as it was")
    func e24S06CancelWhileMaking() async throws {
        let (window, main) = try Self.editing("e24-cancel")
        defer { window.lockAll() }
        let editor = try #require(main.editor)
        let before = editor.view.attachments
        let job = SshKeyJob()
        job.making = true
        main.dialog = .newSshKey
        let sheet = Offscreen(NewSshKeySheet(model: main, job: job), size: CGSize(width: 600, height: 400))
        #expect(await sheet.strings().contains("Making your SSH key"))
        let cancel = try #require(axNodes(sheet.host).first { ($0.accessibilityLabel?() ?? nil) == "Cancel" })
        #expect(cancel.accessibilityPerformPress?() == true)
        #expect(job.cancelled && main.dialog == nil && main.editor != nil)
        editor.refresh()
        #expect(editor.view.attachments == before && editor.view.ssh == nil)
    }

    private func shot(_ root: some View, _ name: String) async throws -> CGSize {
        try await Shots.write(root.fixedSize().font(.sans(14)).foregroundStyle(Tok.text), size: nil, frame: name)
    }

    @Test("E24-S01 to E24-S05: frames e24-s1-new-ssh, -rsa, -ecdsa, ssh-generating, -created, -save-error, light, dark")
    func e24Frames() async throws {
        let (window, main) = try Self.editing("e24-frames")
        defer { window.lockAll() }
        try #require(main.editor).set(.title, "Development key")
        let making = SshKeyJob()
        making.making = true
        let saved = SshKeySavedSheet(model: main, key: Self.demoKey, line: "Development key · Personal › Servers")
        let frames: KeyValuePairs<String, (AnyView, [String])> = [
            "new-ssh": (AnyView(NewSshKeySheet(model: main)), ["New SSH Key", "Generate and Add Key"]),
            "new-ssh-rsa": (AnyView(NewSshKeySheet(model: main, choice: .init(family: 2))), ["RSA bits"]),
            "new-ssh-ecdsa": (AnyView(NewSshKeySheet(model: main, choice: .init(family: 1))), ["ECDSA curve"]),
            "ssh-generating": (AnyView(NewSshKeySheet(model: main, job: making)), ["Making your SSH key"]),
            "ssh-created": (AnyView(saved), ["SSH key saved", "Public key · ED25519", "Copy Public Key"]),
            "ssh-save-error": (
                AnyView(SshKeyNotSavedSheet(model: main, key: Self.demoKey, line: "")),
                ["The vault file is unchanged.", "Check that the vault is writable, then try again.", "Try Again"]
            ),
        ]
        for (state, (view, words)) in frames {
            let size = try await shot(view, "e24-s1-" + state)
            #expect(size.width == 600, "\(state)")
            let strings = await Offscreen(view, size: size).strings()
            #expect(words.allSatisfy { word in strings.contains { $0.contains(word) } }, "\(state): \(strings)")
        }
    }
}
