import AppCore
import AppKit
import SwiftUI
import Testing

/// The E5 follow-up batch's wizard checks (LD-211 (4), LD-224 (3)): APP-07
/// T12, the S-CFG-02 edges through the screen and M07-07's list words.
/// Offscreen only (AGENTS.md rule 10).
@MainActor
@Suite(.serialized)
struct NewVaultChecksTests {
    init() {
        ParityDemo.setUp()
        WizardDemo.panels()
    }

    @Test("APP-07 T12: while step 2 measures, M07-08 shows, Continue waits and the screen thread still answers")
    func measuringWaits() async throws {
        let model = try await WizardDemo.model(.encryption)
        model.choose(recommended: false)
        model.setCustom { $0.memoryMib = 128 }
        #expect(model.measuring && !model.canContinue)
        // M07-08's line is on screen (read as VoiceOver reads it; offscreen).
        let screen = OtherWindow(AnyView(NewVaultView(model: model).frame(width: 720, height: 720)))
        await screen.settle()
        let view = try #require(screen.contentView)
        #expect(Self.strings(view).contains("Measuring this Mac…"), "M07-08 while measuring")
        // The screen thread answers meanwhile: Continue does nothing, a
        // new unlock time takes at once.
        model.primary()
        #expect(model.step == .encryption && model.sheet == nil)
        model.setCustom { $0.unlockMs = 2_000 }
        #expect(model.choice.unlockMs == 2_000 && model.measuring)
        await model.measured()
        #expect(!model.measuring && model.canContinue)
        await screen.settle()
        #expect(!Self.strings(view).contains("Measuring this Mac…"), "gone when measured")
        model.cancel()
    }

    @Test(
        "APP-07 T31, S-CFG-02: below the minimum M07-22 reaches the screen, step 3 stays; at it goes on; 4 refuses Good"
    )
    func minimumNotice() async throws {
        let model = try await WizardDemo.model(.encryption)
        let minimum = { (level: Int64) in
            try model.session.saveSettings(changes: [
                AppSetting(key: "security.min_master_quality", value: .number(value: level))
            ])
        }
        try minimum(3)
        var panelOpened = false
        model.savePanel = { _, _ in
            panelOpened = true
            return nil
        }
        model.primary()
        // The wizard as drawn (offscreen, never shown: AGENTS.md rule 10).
        let screen = OtherWindow(AnyView(NewVaultView(model: model).frame(width: 720, height: 720)))
        let m0722 = "This password is weaker than App allows. Choose a stronger one."
        let refused = { (password: String) async throws -> Bool in
            model.passwordTyped(password)
            model.repeatTyped(password)
            model.create()
            await screen.settle()
            let shown = Self.strings(try #require(screen.contentView)).contains(m0722)
            let refused = model.sheet == .notice(id: "M07-22", text: m0722) && shown
            #expect(model.step == .password && !panelOpened && !model.creating)
            model.sheet = nil
            await screen.settle()
            return refused
        }
        // Fair (2) below the minimum Good (3): M07-22 on screen, step 3 stays.
        #expect(try await refused("Tr0ub4dor&3"), "M07-22 for a password below the minimum")
        // Minimum 4: Good (3) is refused the same way.
        try minimum(4)
        #expect(try await refused("kT7#pQ2vZ9mW4x"), "M07-22 for Good under minimum 4")
        // Exactly at the minimum (Good at 3): no notice, the save panel is next.
        try minimum(3)
        model.passwordTyped("kT7#pQ2vZ9mW4x")
        model.repeatTyped("kT7#pQ2vZ9mW4x")
        model.create()
        await screen.settle()
        #expect(model.sheet == nil && panelOpened)
        #expect(!Self.strings(try #require(screen.contentView)).contains(m0722))
        model.cancel()
    }

    @Test("M07-07, APP-07 T09 (LD-224 (3)): the lists' items in order, with no \"(default)\" or \"(recommended)\"")
    func listWords() {
        #expect(EncryptionRows.ciphers.map(\.1) == ["AES-256", "Twofish-256", "ChaCha20"])
        #expect(EncryptionRows.kdfs.map(\.1) == ["Argon2id", "Argon2d", "AES-KDF"])
    }

    /// Every label and text value VoiceOver finds under `view`.
    private static func strings(_ view: NSView) -> [String] {
        var out: [String] = []
        func walk(_ any: Any, _ depth: Int) {
            let element = any as AnyObject
            guard depth < 80 else { return }
            let value: Any? = element.accessibilityValue?() ?? nil
            out += [(element.accessibilityLabel?() ?? nil) ?? "", (value as? String) ?? ""].filter { !$0.isEmpty }
            for child in element.accessibilityChildren?() ?? [] { walk(child, depth + 1) }
        }
        walk(view, 0)
        return out
    }
}
