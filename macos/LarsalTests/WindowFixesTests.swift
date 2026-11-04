import AppKit
import LarsalCore
import SwiftUI
import Testing

/// A view laid out offscreen, read through its accessibility tree.
@MainActor
final class Offscreen {
    let host: NSHostingView<AnyView>
    let window: NSWindow

    init(_ view: some View, size: CGSize) {
        host = NSHostingView(rootView: AnyView(view.frame(width: size.width, height: size.height)))
        host.frame = NSRect(origin: .zero, size: size)
        window = NSWindow(
            contentRect: NSRect(origin: CGPoint(x: -20_000, y: -20_000), size: size), styleMask: [.borderless],
            backing: .buffered, defer: false)
        window.contentView = host
        NSApplication.shared.setValue(true, forKey: "accessibilityEnhancedUserInterface")
    }

    isolated deinit { window.contentView = nil }

    func settle() async {
        host.layoutSubtreeIfNeeded()
        try? await Task.sleep(for: .milliseconds(300))
        host.layoutSubtreeIfNeeded()
    }

    private func nodes() -> [AnyObject] {
        var out: [AnyObject] = []
        func walk(_ any: Any, _ depth: Int) {
            let element = any as AnyObject
            guard depth < 80 else { return }
            out.append(element)
            for child in element.accessibilityChildren?() ?? [] { walk(child, depth + 1) }
        }
        walk(host, 0)
        return out
    }

    /// Every label and text value on screen, after it settled.
    func strings() async -> [String] {
        await settle()
        return nodes().flatMap { element -> [String] in
            let value: Any? = element.accessibilityValue?() ?? nil
            return [(element.accessibilityLabel?() ?? nil) ?? "", (value as? String) ?? ""].filter { !$0.isEmpty }
        }
    }

    func press(_ name: String) async throws {
        let element = try #require(nodes().first { ($0.accessibilityLabel?() ?? nil) == name }, "\(name)")
        #expect(element.accessibilityPerformPress?() == true, "\(name) takes a press")
        await settle()
    }

    /// The shown password field labelled `label` takes the focus, as a
    /// click would.
    func focus(_ label: String) async {
        func find(_ view: NSView) -> NoCopyTextField? {
            if let field = view as? NoCopyTextField, field.accessibilityLabel() == label { return field }
            return view.subviews.lazy.compactMap(find).first
        }
        await settle()
        // F-102: the editor's shown password is text until a press makes
        // the field.
        if find(host) == nil, let shown = nodes().first(where: { ($0.accessibilityLabel?() ?? nil) == label }) {
            _ = shown.accessibilityPerformPress?()
            await settle()
        }
        if let field = find(host) { _ = window.makeFirstResponder(field) }
    }
}

@MainActor
func githubID(_ main: VaultModel) throws -> String {
    try #require(main.rows.first { $0.title == "GitHub" }?.id)
}

/// E13-S6 part d: the Mac screen fixes of F-074, F-076 and F-077 (the rest:
/// WindowFixesMoreTests), each through the real views, offscreen and never ordered
/// front (AGENTS.md rule 10). No test focuses a secure field: the shown
/// (no-copy) fields stand in, so the real secure input never turns on.
@MainActor
@Suite(.serialized)
struct WindowFixesTests {
    init() {
        ParityDemo.setUp()
        WizardDemo.panels()
    }

    // MARK: F-076 Caps Lock

    @Test("F-076, APP-07.11: the wizard's Password shows the Caps Lock note; Verify password never")
    func f076WizardPassword() async throws {
        let model = try await WizardDemo.model(.password)
        let screen = Offscreen(
            NewVaultView(model: model).environment(\.capsLockFake, true), size: CGSize(width: 720, height: 720))
        #expect(await screen.strings().contains(CapsLock.note))
        await screen.focus("Password")
        #expect(await screen.strings().contains(CapsLock.note))
        await screen.focus("Verify password")
        #expect(await !screen.strings().contains(CapsLock.note), "not on the repeat field")
        model.cancel()
    }

    @Test("F-076, MOD-12.10: the vault settings' new password shows the Caps Lock note; Verify password never")
    func f076VaultSettingsPassword() async throws {
        let window = try ParityDemo.window("f076-settings")
        let model = VaultSettingsModel(session: window.session, vault: try #require(window.shown))
        model.askPassword()
        model.toggleShow()
        let screen = Offscreen(
            SettingsSheet(model: model).environment(\.capsLockFake, true), size: CGSize(width: 900, height: 640))
        #expect(await screen.strings().contains(CapsLock.note))
        await screen.focus("Password")
        #expect(await screen.strings().contains(CapsLock.note))
        await screen.focus("Verify password")
        #expect(await !screen.strings().contains(CapsLock.note), "not on the repeat field")
        model.clearPassword()
    }

    @Test("F-076, APP-06.6: the entry editor's password shows the Caps Lock note while focused, Caps Lock on")
    func f076EditorPassword() async throws {
        let window = try ParityDemo.window("f076-editor")
        let main = try #require(window.main)
        main.edit(try githubID(main))
        let editor = try #require(main.editor)
        editor.toggleShowPassword()
        for capsOn in [false, true] {
            let screen = Offscreen(
                EditorScreen(model: main, editor: editor).environment(\.capsLockFake, capsOn),
                size: CGSize(width: 1000, height: 1400))
            #expect(await !screen.strings().contains(CapsLock.note), "not before the focus")
            await screen.focus("Password")
            #expect(await screen.strings().contains(CapsLock.note) == capsOn)
        }
        main.closeEditor()
    }

    @Test("F-076, APP-06.6: the unlock form keeps its note, now from the shared part")
    func f076UnlockPassword() async throws {
        let window = try ParityDemo.window("f076-unlock", unlocked: [])
        let unlock = try #require(window.unlock)
        unlock.touchForm = false
        unlock.reveal = true
        let screen = Offscreen(
            UnlockView(model: unlock, window: window).environment(\.capsLockFake, true),
            size: CGSize(width: 1320, height: 820))
        #expect(await screen.strings().contains(CapsLock.note))
    }

    @Test("F-207, APP-06.6, M06-37: the share password shows the Caps Lock note while it has focus")
    func f207SharePassword() async throws {
        let window = try ShareDemo.window("share-caps")
        let main = try #require(window.main)
        main.editGroup(try ShareDemo.group(main, "Household"))
        let editor = try #require(main.sharing.editor)
        // The shown (no-copy) field stands in: no test focuses a secure field.
        editor.toggleShow()
        for capsOn in [false, true] {
            let screen = Offscreen(
                GroupEditorScreen(model: main, editor: editor).environment(\.capsLockFake, capsOn),
                size: CGSize(width: 1000, height: 1400))
            #expect(await !screen.strings().contains(CapsLock.note), "not before the focus")
            await screen.focus("Password")
            await screen.focus("Share password")
            #expect(await screen.strings().contains(CapsLock.note) == capsOn)
        }
        window.lockAll()
    }

    // MARK: F-077 expiry notice, F-074 key change

    @Test("F-077, APP-01.18 a, b: the first unlock fills the search with the expiry notice, titled; not after a lock")
    func f077ExpiryNotice() async throws {
        let path = try ParityDemo.path(0, folder: "f077")
        do {
            // GitHub expired yesterday, saved through the editor and Rust.
            let session = Session()
            let id = try session.open(path: path)
            #expect(try session.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
            let row = try #require(try session.list(vault: id, view: .all).rows.first { $0.title == "GitHub" })
            _ = try session.beginEdit(vault: id, entry: row.id)
            try session.setExpiry(vault: id, on: true, at: Int64(Date().timeIntervalSince1970) - 86_400)
            _ = try session.commitEdit(vault: id)
            #expect(try session.save(vault: id).failure == nil)
        }
        let session = Session()
        let id = try session.open(path: path)
        #expect(try session.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        let window = MainWindowModel(session: session)
        let main = try #require(window.main)
        #expect(main.search == "is:expired-3")
        #expect(main.title == "Expired or due to expire in 3 days")
        #expect(main.rows.contains { $0.title == "GitHub" })
        // b: lock, unlock: no notice.
        window.lockNow(id)
        #expect(try session.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        window.refresh()
        #expect(window.main?.search == "")
    }

    /// The Work demo vault that asks for a key change at this unlock
    /// (testdata/README.md), copied under target/.
    private func forced(_ folder: String) throws -> (window: MainWindowModel, path: String) {
        let place = ParityDemo.root.appending(path: "target/option-a/" + folder)
        try FileManager.default.createDirectory(at: place, withIntermediateDirectories: true)
        let target = place.appending(path: "Work.larsalvault")
        try? FileManager.default.removeItem(at: target)
        try FileManager.default.copyItem(
            at: ParityDemo.root.appending(path: "testdata/option-a-work-key-change.larsalvault"), to: target)
        let path = target.path(percentEncoded: false)
        let session = Session()
        let id = try session.open(path: path)
        #expect(try session.unlock(vault: id, password: "demo-pass-8", keyFile: nil) == .unlocked)
        return (MainWindowModel(session: session), path)
    }

    @Test("F-074, MOD-13.8 T13: the forced prompt takes the vault's place; Change Now's new password opens the vault")
    func f074ForcedChange() async throws {
        let (window, path) = try forced("f074-change")
        #expect(window.main == nil, "no vault screen behind the prompt")
        let prompt = try #require(window.keyChange)
        let screen = Offscreen(MainWindow(model: window), size: CGSize(width: 1320, height: 820))
        #expect(await screen.strings().contains { $0.hasPrefix("This vault requires a new master key") })
        // Vault Settings… (the Vault menu) stays closed behind the prompt.
        var presented = 0
        AuxWindows.present = { _ in presented += 1 }
        let before = AuxWindows.settings?.window
        AuxWindows.vaultSettings(window)
        #expect(presented == 0 && AuxWindows.settings?.window === before, "no Vault Settings")
        try await screen.press("Change Now")
        let settings = try #require(prompt.settings)
        // The credentials page (SecurityKeyTests): its password row's Change….
        settings.askPassword()
        #expect(settings.sheet == .changePassword)
        settings.passwordTyped("orchid-meteor-pine-quartz-41")
        settings.repeatTyped("orchid-meteor-pine-quartz-41")
        settings.changePassword()
        for _ in 0..<400 where window.main == nil { try await Task.sleep(for: .milliseconds(25)) }
        #expect(window.keyChange == nil && window.main != nil, "the vault opens")
        // Saved with the new key and without the request.
        let again = Session()
        let id = try again.open(path: path)
        #expect(try again.unlock(vault: id, password: "orchid-meteor-pine-quartz-41", keyFile: nil) == .unlocked)
        #expect(again.vaults().first?.keyChange == nil)
    }

    @Test("F-074, MOD-13.8 T14: Lock on the forced prompt locks the vault again")
    func f074ForcedLock() async throws {
        let window = try forced("f074-lock").window
        let id = try #require(window.shown?.id)
        let screen = Offscreen(MainWindow(model: window), size: CGSize(width: 1320, height: 820))
        try await screen.press("Lock")
        #expect(window.keyChange == nil && window.unlock != nil)
        #expect(window.session.vaults().first { $0.id == id }?.locked == true)
    }

    @Test("F-074, MOD-13.10: the recommended notice shows in the vault view; Later hides it")
    func f074RecommendedNotice() async throws {
        let window = try ParityDemo.window("f074-notice")
        let main = try #require(window.main)
        let words = "The master key was last changed 10 days ago; a change every 1 day is recommended."
        main.afterUnlock(AfterUnlock(expirySearch: nil, expiryTitle: nil, keyChange: words, diskNotice: nil))
        let screen = Offscreen(VaultView(model: main, window: window), size: CGSize(width: 1320, height: 820))
        #expect(await screen.strings().contains(words))
        try await screen.press("Later")
        #expect(await !screen.strings().contains(words))
    }

}
