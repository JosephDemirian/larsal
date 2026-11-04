import AppKit
import LarsalCore
import Observation

/// The vault settings window (E5-S8, MOD-12; mockup `settingsWin(VSET)`):
/// five pages of one unlocked vault. Every change goes to Rust at once,
/// through larsal-core's checks (`VaultSettings`, vault_settings.rs), and the
/// vault saves after it as after any change (APP-05). The Option A frames
/// draw no Apply or Cancel, so each control applies itself (LD for the
/// lead). The only secrets here are the Show values of the password sheet.
@Observable
final class VaultSettingsModel {
    enum Page: Int, CaseIterable, Identifiable {
        case general, security, bin, history, browser, shares

        var id: Int { rawValue }
        var title: String {
            ["General", "Security", "Recycle Bin", "History", "Browser Keys", "Shared Groups"][rawValue]
        }
        /// The page's tile (mockup `VSET`; W-15's `VSET15` adds Shared Groups).
        var tile: (color: String, glyph: String) {
            [
                ("teal", "keyhole"), ("blue", "lock-key"), ("gray", "trash"), ("orange", "clock-counter-clockwise"),
                ("teal", "globe-simple"), ("green", "share-network"),
            ][rawValue]
        }
    }

    /// A sheet over the window.
    enum Sheet: Equatable {
        case question(Question, then: Then)
        case notice(String)
        case confirm(Confirm)
        case changePassword
        case createKeyFile
    }

    /// What a question's yes goes on with.
    enum Then: Equatable {
        case cipher(CipherChoice)
        case kdf(EncryptionChoice)
        case password
        case keyFile(String, new: Bool)
        case removeKeyFile
        case securityKey(KeyPick?)
    }

    /// The screen's own confirmations before an action that acts at once.
    enum Confirm: Equatable {
        case binOff, historyOff, deleteHistory, forgetSites
        case disconnect(String)
    }

    let session: Session
    let core: VaultSettings
    let vault: VaultInfo
    var page = Page.general
    private(set) var view: VaultSettingsView?
    /// The General page's fields as typed; applied a moment after typing
    /// stops.
    var name = "" { didSet { if name != oldValue { soon { $0.applyText() } } } }
    var defaultUserName = "" { didSet { if defaultUserName != oldValue { soon { $0.applyText() } } } }
    var description = "" { didSet { if description != oldValue { soon { $0.applyText() } } } }
    /// The Security page's encryption values.
    private(set) var encryption = EncryptionChoice(
        cipher: .aes256, kdf: .argon2id, memoryMib: 64, lanes: 2, unlockMs: 1_000)
    private(set) var measuring = false
    private(set) var memoryNote: String?
    var keyMenu = false
    /// The security key row's menu and its list (F-126).
    var securityKeyMenu = false
    let keyPicker = KeyPicker()
    var sheet: Sheet?
    // The password sheet (APP-07.20).
    var rating: Rating?
    var match: Bool?
    var mismatchShown = false
    var shownPassword: String?
    var shownRepeat: String?
    var passwordLength = 0
    var repeatLength = 0
    var fieldTurn = 0
    /// "Create a key file": where the new file goes.
    var keyFilePath: URL
    /// Answers given for the action that asked.
    var answers: [Answer] = []
    /// After a change: the main window reads the vault again and saves.
    @ObservationIgnored var changed: () -> Void = {}
    @ObservationIgnored private var pending: Task<Void, Never>?
    @ObservationIgnored private var measurer: Task<Void, Never>?
    /// A security key change running off the main thread (F-126).
    @ObservationIgnored var keyTask: Task<Void, Never>?
    @ObservationIgnored private var loading = false
    /// Text typed but not applied yet: a reload keeps it on screen.
    @ObservationIgnored private var typing = false

    init(session: Session, vault: VaultInfo) {
        self.session = session
        self.vault = vault
        core = VaultSettings(session: session, vault: vault.id)
        let folder = URL(fileURLWithPath: (vault.path as NSString).expandingTildeInPath).deletingLastPathComponent()
        keyFilePath = folder.appending(path: vault.name + ".larsalkey")
        reload()
        measure(encryption, apply: false)
    }

    /// Reads the pages again from Rust.
    func reload() {
        guard let next = try? core.view() else { return }
        loading = true
        view = next
        if !typing {
            name = next.name
            defaultUserName = next.defaultUserName
            description = next.description
        }
        encryption = next.encryption
        loading = false
    }

    private func soon(_ work: @escaping (VaultSettingsModel) -> Void) {
        guard !loading else { return }
        typing = true
        pending?.cancel()
        pending = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(500))
            guard !Task.isCancelled, let self else { return }
            typing = false
            work(self)
        }
    }

    /// Waits for a change that is about to apply (tests).
    func settled() async {
        await pending?.value
        await keyTask?.value
        while measuring, let running = measurer { await running.value }
    }

    func done(_ outcome: Outcome?, then: Then? = nil) {
        switch outcome {
        case .done, .created:
            answers = []
            reload()
            changed()
        case .ask(let question):
            if let then { sheet = .question(question, then: then) }
        case .refused(let id, let text):
            answers = []
            if id == "M07-35" {
                memoryNote = text
            } else if id == "M07-20" {
                mismatchShown = true
            } else {
                sheet = .notice(text)
            }
            reload()
        case nil:
            reload()
        }
    }

    func apply(_ change: SettingsChange) {
        done(try? core.apply(change: change))
    }

    static func change(
        name: String? = nil, description: String? = nil, defaultUserName: String? = nil, colour: String? = nil,
        recycleBin: Bool? = nil, deleteOldBin: Bool = false, historyItems: Int32? = nil, historyMib: Int32? = nil
    ) -> SettingsChange {
        SettingsChange(
            name: name, description: description, defaultUserName: defaultUserName, colour: colour,
            recycleBin: recycleBin, deleteOldBin: deleteOldBin, historyItems: historyItems, historyMib: historyMib)
    }

    // MARK: General (MOD-12.3, MOD-12.4)

    func applyText() {
        guard let view else { return }
        apply(
            Self.change(
                name: name == view.name ? nil : name, description: description == view.description ? nil : description,
                defaultUserName: defaultUserName == view.defaultUserName ? nil : defaultUserName))
    }

    /// A swatch: the public colour (FMT-03.23), not encrypted.
    func setColour(_ swatch: String) {
        apply(Self.change(colour: Self.hex(swatch)))
    }

    /// The swatch's colour as `#rrggbb`.
    static func hex(_ swatch: String) -> String {
        guard let color = NSColor(named: swatch, bundle: appBundle)?.usingColorSpace(.sRGB) else { return "" }
        let parts = [color.redComponent, color.greenComponent, color.blueComponent].map { Int(($0 * 255).rounded()) }
        return String(format: "#%02x%02x%02x", parts[0], parts[1], parts[2])
    }

    /// The chosen swatch: the one whose colour is stored.
    var swatch: String? {
        guard let rgb = view?.colour else { return nil }
        return VaultLooks.swatches.first { Self.hex($0) == String(format: "#%06x", rgb) }
    }

    /// Show in Finder; tests put a fake here (AGENTS.md rule 10).
    static var reveal: (URL) -> Void = { NSWorkspace.shared.activateFileViewerSelecting([$0]) }

    func showInFinder() {
        guard let view else { return }
        Self.reveal(URL(fileURLWithPath: view.fullPath))
    }

    // MARK: Security: encryption (MOD-12.11 to MOD-12.14)

    func setCipher(_ cipher: CipherChoice) {
        encryption.cipher = cipher
        done(try? core.setCipher(cipher: cipher, answers: answers), then: .cipher(cipher))
    }

    /// Key derivation, memory, lanes or the unlock time: a new family loads
    /// its defaults (MOD-12.12); family, memory and lanes measure again; the
    /// change applies a moment after the last step.
    func setEncryption(_ edit: (inout EncryptionChoice) -> Void) {
        var next = encryption
        edit(&next)
        let aes = { (choice: EncryptionChoice) in choice.kdf == .aesKdf }
        if aes(next) != aes(encryption) && !aes(next) {
            next.memoryMib = 64
            next.lanes = min(max(UInt64(ProcessInfo.processInfo.activeProcessorCount), 1), 4)
        }
        guard next != encryption else { return }
        let remeasure =
            aes(next) != aes(encryption) || next.memoryMib != encryption.memoryMib
            || next.lanes != encryption.lanes
        encryption = next
        answers = []
        memoryNote = aes(next) ? nil : core.memoryNote(memoryMib: next.memoryMib)
        guard memoryNote == nil else { return }
        if remeasure {
            measure(next, apply: true)
        } else {
            soon { $0.applyEncryption(next) }
        }
    }

    private func applyEncryption(_ choice: EncryptionChoice) {
        done(try? core.setKdf(choice: choice, answers: answers), then: .kdf(choice))
    }

    /// APP-07.8 off the screen thread; on open, for the unlock time of a
    /// vault without the unlock time item.
    private func measure(_ choice: EncryptionChoice, apply: Bool) {
        let core = core
        measuring = true
        let previous = measurer
        measurer = Task { [weak self] in
            await previous?.value
            var measured = false
            while !measured, !Task.isCancelled {
                let result = await Task.detached { Result { try core.measure(choice: choice) } }.value
                switch result {
                case .success(let done): measured = done
                case .failure(let error):
                    self?.memoryNote = message(error)
                    self?.measuring = false
                    return
                }
                if !measured { try? await Task.sleep(for: .milliseconds(50)) }
            }
            guard let self else { return }
            measuring = false
            if apply, choice == encryption {
                applyEncryption(choice)
            } else if !apply {
                reload()
            }
        }
    }

    /// A question's yes: the action again with the answer.
    func answer(_ question: Question, then: Then) {
        sheet = nil
        answers.append(question.answer)
        switch then {
        case .cipher(let cipher): setCipher(cipher)
        case .kdf(let choice): applyEncryption(choice)
        case .password: changePassword()
        // A new key file exists by now: the retry reads it (LD-99 never
        // writes over it).
        case .keyFile(let path, _): keyFile(path, new: false)
        case .removeKeyFile: removeKeyFile()
        case .securityKey(let pick): setSecurityKey(pick)
        }
    }

    /// Cancel: nothing changed, so the page shows the stored values again,
    /// never the one the user turned down.
    func dismiss() {
        if case .question(_, .password) = sheet {
            sheet = .changePassword
        } else {
            sheet = nil
        }
        answers = []
        reload()
    }
}
