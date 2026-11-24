import AppKit
import LarsalCore
import SwiftUI
import Testing

/// Every frame of design/option-a/manifest.json that E5-S8 builds for the
/// wizard, and the two dialogs APP-07 owns.
enum NewVaultFrame: String, CaseIterable, CustomTestStringConvertible {
    case step1 = "vault-new-vault-step-1"
    case step2 = "vault-new-vault-step-2"
    case step3 = "vault-new-vault-step-3"
    case weak = "dialogs-weak-vault-password"
    case keyFile = "dialogs-create-key-file"

    var testDescription: String { rawValue }
}

/// Offscreen shots, as the other parity suites take them: never ordered
/// front (AGENTS.md rule 10), sRGB as the references.
@MainActor
enum Shots {
    static func write(_ root: some View, size: CGSize?, frame: String) async throws -> CGSize {
        let host = NSHostingView(rootView: root)
        host.frame = NSRect(origin: .zero, size: size ?? host.fittingSize)
        let offscreen = NSWindow(
            contentRect: host.frame.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless], backing: .buffered,
            defer: false)
        offscreen.colorSpace = .sRGB
        offscreen.backgroundColor = .clear
        offscreen.contentView = host
        let shots = SnapshotTests()
        for (folder, look) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            offscreen.appearance = NSAppearance(named: look)
            let png = try await shots.render(host)
            let out = ParityDemo.shotsDirectory.appending(path: "\(folder)/\(frame).png")
            try FileManager.default.createDirectory(
                at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
            try png.write(to: out)
            #expect(png.count > 5_000, "\(out.path)")
            try shots.accessibilityTree(host).write(to: out.deletingPathExtension().appendingPathExtension("ax.json"))
        }
        let drawn = host.frame.size
        offscreen.contentView = nil
        return drawn
    }
}

/// A demo folder for the wizard's files, under target/ (never the owner's).
@MainActor
enum WizardDemo {
    static func folder(_ name: String) throws -> URL {
        let place = ParityDemo.root.appending(path: "target/option-a/new-vault/" + name)
        try? FileManager.default.removeItem(at: place)
        try FileManager.default.createDirectory(at: place, withIntermediateDirectories: true)
        return place
    }

    /// The panels never show: each test says what they answer.
    static func panels(open: URL? = nil) {
        NewVaultModel.chooseFolder = { _ in nil }
        NewVaultModel.keyFileSavePanel = { _ in nil }
        NewVaultModel.openKeyFile = { open }
        AuxWindows.present = { _ in }
    }

    /// The mockup's frame state of step `step` (mockup.js `wizard(i)`).
    static func model(_ step: NewVaultModel.Step, save: URL? = nil) async throws -> NewVaultModel {
        let model = NewVaultModel(session: Session())
        model.savePanel = { _, _ in save }
        model.name = "Family"
        model.description = "Streaming, the router and the kids’ school accounts."
        model.folder = URL(fileURLWithPath: NSHomeDirectory()).appending(
            path: "Library/Mobile Documents/com~apple~CloudDocs/Passwords")
        if step.rawValue >= 1 {
            model.primary()
            await model.measured()
        }
        if step == .password {
            model.primary()
            model.passwordTyped("orchid-meteor-pine-quartz-41")
            model.repeatTyped("orchid-meteor-pine-quartz-41")
            model.toggleShow()
        }
        #expect(model.step == step)
        return model
    }
}

@MainActor
@Suite(.serialized)
struct NewVaultSnapshotTests {
    init() {
        ParityDemo.setUp()
        WizardDemo.panels()
    }

    @Test("Option A new vault frame, offscreen, light and dark", arguments: NewVaultFrame.allCases)
    func frame(_ frame: NewVaultFrame) async throws {
        switch frame {
        case .step1, .step2, .step3:
            let step: NewVaultModel.Step = frame == .step1 ? .name : frame == .step2 ? .encryption : .password
            let model = try await WizardDemo.model(step)
            let size = try await Shots.write(
                NewVaultView(model: model).frame(width: 720, height: 720), size: CGSize(width: 720, height: 720),
                frame: frame.rawValue)
            #expect(size == CGSize(width: 720, height: 720))
            model.cancel()
        case .weak:
            // M07-23 as Rust words it (FEA-05.20), for a weak password.
            let model = try await WizardDemo.model(.encryption)
            model.primary()
            model.passwordTyped("family2026")
            model.repeatTyped("family2026")
            model.create()
            guard case .question(let question, _) = model.sheet else {
                Issue.record("no question: \(String(describing: model.sheet))")
                return
            }
            #expect(question.id == "M07-23")
            let card = QuestionCard(question: question, cancel: {}, yes: {}).fixedSize()
            let size = try await Shots.write(
                card.font(.sans(14)).foregroundStyle(Tok.text), size: nil, frame: frame.rawValue)
            #expect(size.width == 460)
            model.cancel()
        case .keyFile:
            let card = CreateKeyFileCard(fileName: "Family.larsalkey", change: {}, cancel: {}, create: {}).fixedSize()
            let size = try await Shots.write(
                card.font(.sans(14)).foregroundStyle(Tok.text), size: nil, frame: frame.rawValue)
            #expect(size.width == 460)
        }
    }
}

/// Design parity check 6 and APP-07's rules through the screen: the
/// controls the mockup makes clickable do what the card says.
@MainActor
@Suite(.serialized)
struct NewVaultBehaviourTests {
    init() {
        ParityDemo.setUp()
        WizardDemo.panels()
    }

    @Test("Parity vault-new-vault-step-1: Continue, Back and Cancel move as APP-07.4 says; values kept")
    func steps() async throws {
        let model = try await WizardDemo.model(.name)
        var closed = false
        model.closed = { closed = true }
        #expect(model.name == "Family" && model.fileName == "Family.larsalvault")
        #expect(model.folderText == "iCloud Drive › Passwords")
        model.primary()
        #expect(model.step == .encryption)
        await model.measured()
        model.primary()
        #expect(model.step == .password)
        model.passwordTyped("demo-new-1")
        model.back()
        model.back()
        #expect(model.step == .name && model.name == "Family")
        model.primary()
        await model.measured()
        model.primary()
        // T04: the password stays in Rust across Back; its dots come back.
        #expect(model.core.password() == "demo-new-1" && model.passwordLength == 10)
        model.cancel()
        #expect(closed)
        // APP-07.3: Rust wiped nothing yet only because the model lives;
        // the screen holds no Show value after Cancel.
        #expect(model.shownPassword == nil)
    }

    @Test("Parity vault-new-vault-step-2: Recommended and Custom choose; Custom's rows edit and measure again")
    func encryption() async throws {
        let model = try await WizardDemo.model(.encryption)
        let defaults = model.defaults
        #expect(defaults.cipher == .aes256 && defaults.kdf == .argon2id && defaults.memoryMib == 64)
        #expect(defaults.unlockMs == 1_000)
        model.choose(recommended: false)
        model.setCustom { $0.cipher = .chaCha20 }
        model.setCustom { $0.memoryMib = 32 }
        #expect(model.measuring)
        await model.measured()
        #expect(!model.measuring && model.choice.memoryMib == 32 && model.choice.cipher == .chaCha20)
        // T10: AES-KDF, then back to Argon2id: the family's defaults again.
        model.setCustom { $0.kdf = .aesKdf }
        await model.measured()
        model.setCustom { $0.kdf = .argon2id }
        await model.measured()
        #expect(model.choice.memoryMib == 64 && model.choice.lanes == defaults.lanes)
        // T16: more memory than this Mac has: M07-35, Continue off.
        model.setCustom { $0.memoryMib = 1_048_576 }
        #expect(model.memoryNote?.hasPrefix("This Mac has ") == true)
        #expect(!model.canContinue)
        model.setCustom { $0.memoryMib = 64 }
        await model.measured()
        #expect(model.canContinue)
        // Recommended keeps its own values (APP-07.7).
        model.choose(recommended: true)
        #expect(model.choice == defaults)
        model.cancel()
    }

    @Test("Parity vault-new-vault-step-3: Show, Generate, the match mark and M07-20 (APP-07.11, APP-07.16)")
    func password() async throws {
        let model = try await WizardDemo.model(.encryption)
        model.primary()
        model.passwordTyped("demo-new-1")
        #expect(model.rating != nil)
        model.repeatTyped("demo-new")
        #expect(model.match == false && model.mismatch)
        model.repeatTyped("demo-new-1")
        #expect(model.match == true && !model.mismatch)
        model.toggleShow()
        #expect(model.shownPassword == "demo-new-1" && model.shownRepeat == "demo-new-1")
        model.toggleShow()
        #expect(model.shownPassword == nil)
        model.generate()
        #expect(model.match == true && model.shownPassword == model.shownRepeat && !(model.shownPassword ?? "").isEmpty)
        // T28: only the repeat typed: M07-20 and the focus on it.
        model.passwordTyped("")
        model.repeatTyped("abc")
        model.create()
        #expect(model.mismatch && model.sheet == nil)
        model.cancel()
    }

    @Test("Parity dialogs-weak-vault-password: Cancel keeps step 3; Use this password goes to the save panel")
    func weak() async throws {
        let folder = try WizardDemo.folder("weak")
        let target = folder.appending(path: "Family.larsalvault")
        let model = try await WizardDemo.model(.encryption, save: target)
        model.primary()
        model.passwordTyped("password")
        model.repeatTyped("password")
        model.create()
        guard case .question(let question, let then) = model.sheet else {
            Issue.record("no question")
            return
        }
        #expect(question.confirm == "Use this password")
        model.sheet = nil
        #expect(model.step == .password && !FileManager.default.fileExists(atPath: target.path))
        var made: UInt64?
        model.created = { made = $0 }
        model.answer(question, then: then)
        try await waitFor { !model.creating && made != nil }
        #expect(FileManager.default.fileExists(atPath: target.path))
        let info = try #require(model.session.vaults().first { $0.id == made })
        #expect(info.shown && !info.locked)
    }

    @Test("Parity dialogs-create-key-file: Create Key File makes the file and fills the key file part (APP-07.13)")
    func createKeyFile() async throws {
        let folder = try WizardDemo.folder("key-file")
        let model = try await WizardDemo.model(.encryption)
        model.primary()
        model.keyFilePath = folder.appending(path: "x.larsalkey")
        model.askCreateKeyFile()
        #expect(model.sheet == .createKeyFile)
        #expect(model.keyFilePath.lastPathComponent == "Family.larsalkey")
        model.createKeyFile()
        #expect(model.sheet == nil && model.keyFile?.name == "Family.larsalkey")
        let attributes = try FileManager.default.attributesOfItem(
            atPath: folder.appending(path: "Family.larsalkey").path)
        #expect((attributes[.posixPermissions] as? Int) == 0o400)
        // LD-99: a second time at the same path is refused with M07-26.
        model.removeKeyFile()
        model.askCreateKeyFile()
        model.createKeyFile()
        guard case .notice(let id, _) = model.sheet else {
            Issue.record("no notice")
            return
        }
        #expect(id == "M07-26")
        model.sheet = nil
        model.cancel()
    }

    @Test("APP-07.17, APP-07.18: Create Vault writes through the save panel's path and the vault opens unlocked")
    func create() async throws {
        let folder = try WizardDemo.folder("create")
        let target = folder.appending(path: "Family.larsalvault")
        let window = MainWindowModel(session: Session())
        let model = NewVaultModel(session: window.session)
        model.savePanel = { _, _ in target }
        model.name = "Family"
        var closed = false
        model.closed = { closed = true }
        model.created = { _ in window.refresh() }
        model.primary()
        await model.measured()
        model.primary()
        model.passwordTyped("4v8Nq2LmZ7rT1xKc9WbP")
        model.repeatTyped("4v8Nq2LmZ7rT1xKc9WbP")
        model.create()
        try await waitFor { closed }
        #expect(window.main?.vault.name == "Family")
        let mode = try FileManager.default.attributesOfItem(atPath: target.path)[.posixPermissions] as? Int
        #expect(mode == 0o600)
        // T38: Cancel in the save panel stays on step 3 with the values.
        let again = try await WizardDemo.model(.encryption)
        again.primary()
        again.passwordTyped("4v8Nq2LmZ7rT1xKc9WbP")
        again.repeatTyped("4v8Nq2LmZ7rT1xKc9WbP")
        again.create()
        #expect(again.step == .password && !again.creating && again.core.password() == "4v8Nq2LmZ7rT1xKc9WbP")
        again.cancel()
        window.lockAll()
    }

    @Test("APP-07.9, APP-07.16: Create Vault after a step 2 yes asks no step 2 question again")
    func stepAnswersCarry() async throws {
        let model = try await WizardDemo.model(.encryption)
        model.choose(recommended: false)
        model.setCustom { $0.memoryMib = 8 }
        await model.measured()
        model.primary()
        guard case .question(let question, let then) = model.sheet else {
            Issue.record("no question")
            return
        }
        #expect(question.id == "M07-33")
        model.answer(question, then: then)
        #expect(model.step == .password && model.sheet == nil)
        model.passwordTyped("4v8Nq2LmZ7rT1xKc9WbP")
        model.repeatTyped("4v8Nq2LmZ7rT1xKc9WbP")
        var panelOpened = false
        model.savePanel = { _, _ in
            panelOpened = true
            return nil
        }
        model.create()
        #expect(model.sheet == nil && panelOpened)
        model.cancel()
    }

    @Test("APP-07.17: a name typed without the extension never replaces a vault the panel did not ask about")
    func neverOverAnUnaskedFile() async throws {
        let folder = try WizardDemo.folder("exists")
        let existing = folder.appending(path: "Work.larsalvault")
        let before = Data("not a vault".utf8)
        try before.write(to: existing)
        let model = try await WizardDemo.model(.encryption, save: folder.appending(path: "Work"))
        model.primary()
        model.passwordTyped("4v8Nq2LmZ7rT1xKc9WbP")
        model.repeatTyped("4v8Nq2LmZ7rT1xKc9WbP")
        model.create()
        guard case .notice(_, let text) = model.sheet else {
            Issue.record("no notice")
            return
        }
        #expect(text.contains("\"Work.larsalvault\" already exists"))
        #expect(!model.creating && model.step == .password)
        #expect(try Data(contentsOf: existing) == before)
        model.sheet = nil
        model.cancel()
    }

    private func waitFor(_ done: () -> Bool) async throws {
        for _ in 0..<300 where !done() { try await Task.sleep(for: .milliseconds(50)) }
        #expect(done())
    }
}
