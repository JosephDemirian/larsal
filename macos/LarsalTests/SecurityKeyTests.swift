import AppKit
import LarsalCore
import SwiftUI
import Testing

/// The fake key watch (OD-01): no USB key is reached; the screens' sinks
/// are kept, so a test hands them looks as larsal-hwkey's watcher would.
@MainActor
enum FakeKeys {
    static var sinks: [KeyLooks] = []
    static let item = KeyItem(
        label: "YubiKey 5 · serial 24531878 · slot 2", pick: KeyPick(serial: 24_531_878, slot: 2, needsTouch: false))
    static let none = "Larsal sees no security key. Plug one in and look again."

    static func install() {
        KeyPicker.watching = { sink in
            sinks.append(sink)
            return nil
        }
    }

    /// One look, from the watcher's thread as Rust calls the sink.
    static func deliver(_ items: [KeyItem], note: String, to sink: KeyLooks) async {
        let look = KeyLook(items: items, note: note)
        await Task.detached { sink.found(look: look) }.value
        try? await Task.sleep(for: .milliseconds(100))
    }
}

/// E13-S6 part k: security keys in Larsal's own screens (F-126) and the
/// forced key change's credentials page (F-074 residual, LD-230 (1)).
@MainActor
@Suite(.serialized)
struct SecurityKeyTests {
    init() {
        ParityDemo.setUp()
        WizardDemo.panels()
        FakeKeys.install()
    }

    /// Whether the control labelled `name` is enabled (a `.later` one is not).
    private func enabled(_ screen: Offscreen, _ name: String) async -> Bool? {
        _ = await screen.strings()
        var found: AnyObject?
        func walk(_ any: Any, _ depth: Int) {
            let element = any as AnyObject
            guard found == nil, depth < 80 else { return }
            if (element.accessibilityLabel?() ?? nil) == name, element.accessibilityPerformPress != nil {
                found = element
                return
            }
            for child in element.accessibilityChildren?() ?? [] { walk(child, depth + 1) }
        }
        walk(screen.host, 0)
        return found?.isAccessibilityEnabled?()
    }

    @Test("F-126, APP-06.8 T17, T18: the unlock screen lists each look of the key watch; one item is chosen")
    func f126UnlockScreenFollowsTheKeyWatch() async throws {
        let window = try ParityDemo.window("f126-unlock", unlocked: [])
        let unlock = try #require(window.unlock)
        let sink = try #require(FakeKeys.sinks.last, "the unlock screen starts the key watch")
        // The look at start: one key, chosen; no M06-36 note.
        await FakeKeys.deliver([FakeKeys.item], note: "Found 1 security key.", to: sink)
        #expect(unlock.keyPicker.keys == [FakeKeys.item])
        #expect(unlock.pick == FakeKeys.item.pick)
        #expect(unlock.keyPicker.note == nil)
        unlock.useKey = true
        // The look 0.5 s after a plug-in, with no usable key now.
        await FakeKeys.deliver([], note: FakeKeys.none, to: sink)
        #expect(unlock.keyPicker.keys.isEmpty && unlock.pick == nil && !unlock.useKey)
        let screen = Offscreen(MainWindow(model: window), size: CGSize(width: 1320, height: 820))
        #expect(await screen.strings().contains(FakeKeys.none))
    }

    @Test("F-126, APP-07.15, M07-13: the wizard's Security key row adds a key from the key menu and removes it")
    func f126WizardSecurityKeyRow() async throws {
        let model = try await WizardDemo.model(.password)
        let screen = Offscreen(NewVaultView(model: model), size: CGSize(width: 720, height: 720))
        #expect(await screen.strings().contains("A YubiKey or OnlyKey with challenge-response."))
        #expect(await enabled(screen, "Add…") == true, "Option A's Add… works")
        // The key menu's watch (its onAppear), never a popover here.
        model.keyPicker.start()
        let sink = try #require(FakeKeys.sinks.last)
        await FakeKeys.deliver([FakeKeys.item], note: "Found 1 security key.", to: sink)
        #expect(model.keyPicker.keys == [FakeKeys.item])
        model.keyMenu = false
        model.chooseSecurityKey(FakeKeys.item)
        #expect(model.securityKey == FakeKeys.item)
        let chosen = await screen.strings()
        #expect(chosen.contains(FakeKeys.item.label) && chosen.contains("Change…"), "\(chosen)")
        try await screen.press("Remove")
        #expect(model.securityKey == nil)
        #expect(await enabled(screen, "Add…") == true)
        model.keyPicker.stop()
        model.cancel()
    }

    @Test("F-126, INT-07.13: with a security key chosen, Create Vault's checks run off the main thread")
    func f126CreateChecksRunOffTheMainThread() async throws {
        let model = try await WizardDemo.model(.password)
        model.chooseSecurityKey(FakeKeys.item)
        // Check 1 (M07-20) refuses before check 6, so no USB look runs (OD-01).
        model.repeatTyped("orchid-meteor-pine-quartz-4")
        model.create()
        #expect(model.creating, "the checks did not run on the main thread")
        #expect(!model.mismatchShown)
        for _ in 0..<300 where model.creating { try await Task.sleep(for: .milliseconds(10)) }
        #expect(!model.creating && model.mismatchShown)
        model.cancel()
    }

    @Test("F-126, MOD-13.9: a security key change Rust made is handled after its page or window closed")
    func f126KeyChangeIsHandledAfterThePageCloses() async throws {
        let (window, settings) = try SettingsDemo.model("f126-closed")
        var changes = 0
        weak var gone: VaultSettingsModel?
        do {
            let model = VaultSettingsModel(session: window.session, vault: settings.vault)
            model.changed = { changes += 1 }
            gone = model
            // Remove: no USB look (OD-01); Rust changes the key at once.
            model.setSecurityKey(nil)
        }
        // The page closed: only its key task holds the model now.
        for _ in 0..<300 where changes == 0 { try await Task.sleep(for: .milliseconds(10)) }
        #expect(changes == 1, "the change was saved and ended the forced prompt (changed())")
        for _ in 0..<100 where gone != nil { try await Task.sleep(for: .milliseconds(10)) }
        #expect(gone == nil, "the finished task lets the model go")
        window.lockAll()
    }

    @Test("F-126, MOD-12.10: the credentials page's Security key row works and its key menu follows the watch")
    func f126SettingsSecurityKeyRow() async throws {
        let (window, model) = try SettingsDemo.model("f126-settings")
        model.page = .security
        let screen = Offscreen(VaultSettingsWindow(model: model), size: CGSize(width: 900, height: 640))
        #expect(await screen.strings().contains("Not used"))
        #expect(await enabled(screen, "Add…") == true, "the row is no longer a later control")
        model.keyPicker.start()
        let sink = try #require(FakeKeys.sinks.last)
        await FakeKeys.deliver([], note: FakeKeys.none, to: sink)
        #expect(model.keyPicker.keys.isEmpty && model.keyPicker.note == FakeKeys.none)
        model.keyPicker.stop()
        window.lockAll()
    }

    @Test("F-126, INT-07.19: the save line shows M06-35 while a challenge waits; a session change reads Rust's flag")
    func f126SaveLineShowsTheTouchWait() async throws {
        let window = try ParityDemo.window("f126-touch")
        let main = try #require(window.main)
        // No await while the flag is on: other suites read the save line.
        KeyTouch.shared.waits = true
        let words = main.savedWords
        KeyTouch.shared.waits = false
        #expect(words.dirty && words.text == KeyTouch.words)
        #expect(main.savedWords.text != KeyTouch.words)
        // WindowEvents sets the flag from Rust at each session change (no
        // challenge runs here, so it reads false).
        KeyTouch.shared.waits = true
        WindowEvents(window: window).sessionChanged()
        await Task { @MainActor in }.value
        for _ in 0..<40 where KeyTouch.shared.waits { try await Task.sleep(for: .milliseconds(5)) }
        let left = KeyTouch.shared.waits
        KeyTouch.shared.waits = false
        #expect(!left)
        window.lockAll()
    }

    @Test("F-074 residual, MOD-13.8: Change Now opens the credentials page alone; its Cancel returns to the prompt")
    func f074ChangeNowOpensTheCredentialsPage() async throws {
        let place = ParityDemo.root.appending(path: "target/option-a/f074-credentials")
        try FileManager.default.createDirectory(at: place, withIntermediateDirectories: true)
        let target = place.appending(path: "Work.larsalvault")
        try? FileManager.default.removeItem(at: target)
        try FileManager.default.copyItem(
            at: ParityDemo.root.appending(path: "testdata/option-a-work-key-change.larsalvault"), to: target)
        let session = Session()
        let id = try session.open(path: target.path(percentEncoded: false))
        #expect(try session.unlock(vault: id, password: "demo-pass-8", keyFile: nil) == .unlocked)
        let window = MainWindowModel(session: session)
        let prompt = try #require(window.keyChange)
        let screen = Offscreen(MainWindow(model: window), size: CGSize(width: 1320, height: 820))
        try await screen.press("Change Now")
        let settings = try #require(prompt.settings)
        #expect(settings.sheet == nil, "not the password card alone")
        let page = await screen.strings()
        for row in ["Credentials", "Password", "Key file", "Security key"] {
            #expect(page.contains(row), "\(row)")
        }
        try await screen.press("Cancel")
        #expect(prompt.settings == nil)
        #expect(await screen.strings().contains { $0.hasPrefix("This vault requires a new master key") })
        // Again: the password row's Change… opens the password card.
        try await screen.press("Change Now")
        let again = try #require(prompt.settings)
        again.askPassword()
        #expect(again.sheet == .changePassword)
        again.clearPassword()
        window.lock(id)
    }
}
