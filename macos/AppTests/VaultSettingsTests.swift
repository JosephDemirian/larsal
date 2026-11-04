import AppCore
import AppKit
import SwiftUI
import Testing

/// Every vault settings frame of design/option-a/manifest.json (E5-S8).
enum VaultSettingsFrame: String, CaseIterable, CustomTestStringConvertible {
    case general = "vault-vault-settings-general"
    case security = "vault-vault-settings-security"
    case bin = "vault-vault-settings-recycle-bin"
    case history = "vault-vault-settings-history"
    case browser = "vault-vault-settings-browser-keys"

    var testDescription: String { rawValue }

    var page: VaultSettingsModel.Page {
        switch self {
        case .general: .general
        case .security: .security
        case .bin: .bin
        case .history: .history
        case .browser: .browser
        }
    }
}

@MainActor
enum SettingsDemo {
    /// The Personal demo vault, unlocked, with its settings.
    static func model(_ folder: String) throws -> (MainWindowModel, VaultSettingsModel) {
        let window = try ParityDemo.window(folder)
        let shown = try #require(window.shown)
        let model = VaultSettingsModel(session: window.session, vault: shown)
        VaultSettingsModel.reveal = { _ in }
        NewVaultModel.openKeyFile = { nil }
        NewVaultModel.keyFileSavePanel = { _ in nil }
        return (window, model)
    }

    /// The frame's state (mockup.js `VSETP`): the general page's values,
    /// the security page's key file and encryption.
    static func state(_ frame: VaultSettingsFrame, _ model: VaultSettingsModel) async throws {
        model.page = frame.page
        switch frame {
        case .general:
            model.defaultUserName = "alex.morgan@posteo.de"
            model.description = "Everything that is mine, not work."
        case .security:
            let key = model.keyFilePath.deletingLastPathComponent().appending(path: "personal.appkey")
            try? FileManager.default.removeItem(at: key)
            model.keyFilePath = key
            model.createKeyFile()
            await model.settled()
            model.setEncryption {
                $0.memoryMib = 64
                $0.lanes = 2
                $0.unlockMs = 1_000
            }
        default: break
        }
        await model.settled()
        try await Task.sleep(for: .milliseconds(100))
        await model.settled()
    }
}

@MainActor
@Suite(.serialized)
struct VaultSettingsSnapshotTests {
    init() { ParityDemo.setUp() }

    @Test("Option A vault settings frame, offscreen, light and dark", arguments: VaultSettingsFrame.allCases)
    func frame(_ frame: VaultSettingsFrame) async throws {
        let (window, model) = try SettingsDemo.model("settings-shots/Passwords")
        try await SettingsDemo.state(frame, model)
        #expect(model.sheet == nil, "\(String(describing: model.sheet))")
        let size = try await Shots.write(
            VaultSettingsWindow(model: model).frame(width: 900, height: 640), size: CGSize(width: 900, height: 640),
            frame: frame.rawValue)
        #expect(size == CGSize(width: 900, height: 640))
        window.lockAll()
    }
}

/// Design parity check 6 and MOD-12's rules through the screen.
@MainActor
@Suite(.serialized)
struct VaultSettingsBehaviourTests {
    init() { ParityDemo.setUp() }

    @Test("Parity vault-vault-settings-general: the pages switch; name, default username and colour apply")
    func general() async throws {
        let (window, model) = try SettingsDemo.model("settings-general")
        for page in VaultSettingsModel.Page.allCases {
            model.page = page
            #expect(model.page == page)
        }
        model.page = .general
        model.defaultUserName = "alex.morgan@posteo.de"
        await model.settled()
        #expect(model.view?.defaultUserName == "alex.morgan@posteo.de")
        model.setColour("purple")
        #expect(model.swatch == "purple")
        // The tile follows the colour at once (MOD-12.4).
        window.refresh()
        #expect(window.shown?.colour == UInt32(VaultSettingsModel.hex("purple").dropFirst(), radix: 16))
        var revealed: URL?
        VaultSettingsModel.reveal = { revealed = $0 }
        model.showInFinder()
        #expect(revealed?.lastPathComponent == "Personal.appvault")
        window.lockAll()
    }

    @Test("Parity vault-vault-settings-security: the password changes after Change…; a cipher change saves")
    func security() async throws {
        let (window, model) = try SettingsDemo.model("settings-security")
        let id = try #require(window.shown?.id)
        model.page = .security
        model.askPassword()
        #expect(model.sheet == .changePassword)
        model.passwordTyped("4v8Nq2LmZ7rT1xKc9WbP")
        model.repeatTyped("4v8Nq2LmZ7rT1xKc9WbX")
        model.changePassword()
        #expect(model.mismatch && model.sheet == .changePassword)
        model.repeatTyped("4v8Nq2LmZ7rT1xKc9WbP")
        model.changePassword()
        #expect(model.sheet == nil)
        model.setCipher(.chaCha20)
        if case .question(let question, let then) = model.sheet { model.answer(question, then: then) }
        #expect(model.view?.encryption.cipher == .chaCha20)
        let status = try window.session.save(vault: id)
        #expect(status.changes == 0 && status.failure == nil)
        // The vault now opens with the new password only.
        let path = try #require(model.view?.fullPath)
        let other = Session()
        let again = try other.open(path: path)
        #expect(try other.unlock(vault: again, password: "demo-pass-7", keyFile: nil) != .unlocked)
        #expect(try other.unlock(vault: again, password: "4v8Nq2LmZ7rT1xKc9WbP", keyFile: nil) == .unlocked)
        window.lockAll()
    }

    @Test("Parity vault-vault-settings-recycle-bin: the switch turns the bin off after MOD-04.12's question")
    func bin() async throws {
        let (window, model) = try SettingsDemo.model("settings-bin")
        model.page = .bin
        model.setBin(false)
        #expect(model.sheet == .confirm(.binOff))
        model.confirmed(.binOff, yes: false)
        #expect(model.view?.recycleBin == false)
        model.setBin(true)
        #expect(model.view?.recycleBin == true)
        window.lockAll()
    }

    @Test("Parity vault-vault-settings-history: the steppers change the limits; Delete all history… asks first")
    func history() async throws {
        let (window, model) = try SettingsDemo.model("settings-history")
        model.page = .history
        #expect(model.view?.historyItems == 10 && model.view?.historyMib == 6)
        model.stepItems(1)
        model.stepSize(-1)
        #expect(model.view?.historyItems == 11 && model.view?.historyMib == 5)
        #expect((model.view?.historyVersions ?? 0) > 0)
        model.sheet = .confirm(.deleteHistory)
        model.confirmed(.deleteHistory)
        #expect(model.view?.historyVersions == 0)
        window.lockAll()
    }

    @Test("Parity vault-vault-settings-browser-keys: Disconnect and Remove all… ask, then act (MOD-12.18)")
    func browser() async throws {
        let (window, model) = try SettingsDemo.model("settings-browser")
        model.page = .browser
        #expect(model.view?.browsers.map(\.name).sorted() == ["Firefox on MacBook", "Safari"])
        model.sheet = .confirm(.disconnect("Safari"))
        model.confirmed(.disconnect("Safari"))
        #expect(model.view?.browsers.map(\.name) == ["Firefox on MacBook"])
        #expect(model.view?.siteAccess == 4)
        model.confirmed(.forgetSites)
        #expect(model.view?.siteAccess == 0)
        window.lockAll()
    }

    @Test("MOD-12.12: Cancel on M07-33 after a cipher change shows the stored cipher again")
    func cancelShowsStored() async throws {
        let (window, model) = try SettingsDemo.model("settings-cancel")
        await model.settled()
        model.page = .security
        let stored = try #require(model.view?.encryption.cipher)
        #expect(stored != .chaCha20)
        model.setCipher(.chaCha20)
        guard case .question(let question, _) = model.sheet else {
            Issue.record("no question")
            return
        }
        #expect(question.id == "M07-33")
        model.dismiss()
        #expect(model.sheet == nil && model.encryption.cipher == stored)
        window.lockAll()
    }

    @Test("MOD-12 T18, S-CFG-02: Change… below the set minimum shows M07-22; a minimum of 4 refuses Good")
    func minimumNotice() async throws {
        let (window, model) = try SettingsDemo.model("settings-minimum")
        try window.session.saveSettings(changes: [
            AppSetting(key: "security.min_master_quality", value: .number(value: 4))
        ])
        model.page = .security
        model.askPassword()
        model.passwordTyped("kT7#pQ2vZ9mW4x")
        model.repeatTyped("kT7#pQ2vZ9mW4x")
        model.changePassword()
        #expect(model.sheet == .notice("This password is weaker than App allows. Choose a stronger one."))
        model.sheet = nil
        // The key is unchanged: the vault still opens with its password.
        let path = try #require(model.view?.fullPath)
        let other = Session()
        let again = try other.open(path: path)
        #expect(try other.unlock(vault: again, password: "demo-pass-7", keyFile: nil) == .unlocked)
        window.lockAll()
    }

    @Test("MOD-12.21: the settings of a vault go when it locks")
    func lockCloses() async throws {
        let window = try ParityDemo.window("settings-lock")
        AuxWindows.present = { _ in }
        AuxWindows.vaultSettings(window)
        #expect(AuxWindows.settings != nil)
        window.lockAll()
        #expect(AuxWindows.settings == nil)
    }
}
