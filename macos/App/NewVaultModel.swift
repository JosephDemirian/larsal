import AppCore
import AppKit
import Observation
import UniformTypeIdentifiers

/// The new vault wizard (E5-S8, APP-07; mockup `wizard()`): three steps,
/// then the save panel, then the vault opens unlocked. Rust holds the typed
/// passwords, the key file and every check (`Wizard`, wizard.rs); this model
/// keeps the screen's values. The only secrets here are the Show values the
/// user asked for (`shownPassword`, `shownRepeat`), dropped on Hide and
/// when the wizard closes (AGENTS.md rule 4).
@Observable
final class NewVaultModel {
    enum Step: Int, CaseIterable {
        case name, encryption, password

        /// The step bar's words (mockup `steps`).
        var label: String { ["Name", "Encryption", "Password"][rawValue] }
    }

    /// A sheet over the wizard (mockup `.dlg`): a question with Cancel as
    /// the default, a notice with OK, or "Create a key file".
    enum Sheet: Equatable {
        case question(Question, then: Then)
        case notice(id: String, text: String)
        case createKeyFile
    }

    /// What a question's yes goes on with.
    enum Then: Equatable {
        case continueStep, create
        case chooseKeyFile(String)
    }

    let session: Session
    let core: Wizard
    private(set) var step = Step.name
    /// Step 1 (APP-07.5): "Passwords", selected, so typing replaces it.
    var name = "Passwords"
    var description = ""
    /// "Save in" (mockup): the folder the save panel opens in.
    var folder: URL
    /// Step 2 (APP-07.6, APP-07.7): Recommended is simple mode at 1.0 s.
    var recommended = true
    let defaults: EncryptionChoice
    /// Custom's own values; kept while the wizard is open.
    private(set) var custom: EncryptionChoice
    private(set) var measuring = false
    /// M07-35 under the Memory row.
    private(set) var memoryNote: String?
    /// The yeses of step 2 and of Create Vault, until a value changes.
    /// Create Vault gets both, so it never asks step 2's questions again
    /// (APP-07.9, APP-07.16).
    private var stepAnswers: [Answer] = []
    var createAnswers: [Answer] = []
    // Step 3.
    var rating: Rating?
    /// `true` check mark, `false` M07-20 under the field, `nil` empty.
    var match: Bool?
    /// M07-20 after Create Vault, with the focus on the repeat field.
    var mismatchShown = false
    var focusRepeat = false
    /// Show for both fields together (APP-07.11): the one value each.
    var shownPassword: String?
    var shownRepeat: String?
    /// The password fields are made again when Rust's values change.
    var fieldTurn = 0
    /// How many characters Rust holds in each field (the dots of a field
    /// made again); no text.
    var passwordLength = 0
    var repeatLength = 0
    var keyFile: KeyFileView?
    /// M07-27 (red) under the key file row.
    var keyFileProblem: String?
    /// The security key part (APP-07.15, F-126): the item chosen from the
    /// key menu, its list and whether the menu shows; not secret.
    var securityKey: KeyItem?
    let keyPicker = KeyPicker()
    var keyMenu = false
    /// "Create a key file": where the new file goes.
    var keyFilePath: URL
    var sheet: Sheet?
    private(set) var creating = false
    /// The vault was made: its session id.
    @ObservationIgnored var created: ((UInt64) -> Void)?
    /// The wizard closes (Cancel, or after the write).
    @ObservationIgnored var closed: (() -> Void)?
    @ObservationIgnored private var measurer: Task<Void, Never>?
    @ObservationIgnored private var measureTurn = 0

    init(session: Session) {
        self.session = session
        core = Wizard(session: session)
        defaults = core.defaults()
        custom = defaults
        let documents =
            FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory())
        folder = documents
        keyFilePath = documents.appending(path: "Passwords.appkey")
    }

    /// The values step 2 decides with (APP-07.7: the mode shown decides).
    var choice: EncryptionChoice { recommended ? defaults : custom }

    /// "<name>.appvault" (mockup's Save in note); `Passwords` when empty.
    var fileName: String { (name.isEmpty ? "Passwords" : name) + ".appvault" }

    /// The folder as the Save in row shows it: iCloud Drive and the folders
    /// below the home folder, joined with ›.
    var folderText: String {
        let home = URL(fileURLWithPath: NSHomeDirectory()).standardizedFileURL.path(percentEncoded: false)
        var path = folder.standardizedFileURL.path(percentEncoded: false)
        let cloud = home + "Library/Mobile Documents/com~apple~CloudDocs"
        var lead: [String] = []
        if path.hasPrefix(cloud) {
            lead = ["iCloud Drive"]
            path = String(path.dropFirst(cloud.count))
        } else if path.hasPrefix(home) {
            path = String(path.dropFirst(home.count))
        }
        let parts = lead + path.split(separator: "/").map(String.init)
        return parts.isEmpty ? "Home" : parts.joined(separator: " › ")
    }

    // MARK: Moving (APP-07.4)

    var canContinue: Bool {
        switch step {
        case .name: true
        case .encryption: !measuring && (recommended || memoryNote == nil)
        case .password: !creating
        }
    }

    func back() {
        guard !creating, let previous = Step(rawValue: step.rawValue - 1) else { return }
        step = previous
    }

    /// The primary button: Continue, or Create Vault on step 3.
    func primary() {
        guard canContinue else { return }
        switch step {
        case .name:
            step = .encryption
            if measurer == nil { measure() }
        case .encryption: continueEncryption()
        case .password: create()
        }
    }

    /// Cancel or Escape (APP-07.3): nothing is made; Rust wipes the typed
    /// passwords when the wizard goes. A write in progress finishes first.
    func cancel() {
        guard !creating else { return }
        core.cancelMeasure()
        measurer?.cancel()
        hidePasswords()
        closed?()
    }

    // MARK: Step 2 (APP-07.6 to APP-07.9)

    func choose(recommended value: Bool) {
        recommended = value
        stepAnswers = []
        measure()
    }

    /// Custom's controls; a new family loads its defaults (APP-07.7) and
    /// family, memory or lanes measure again (APP-07.8).
    func setCustom(_ edit: (inout EncryptionChoice) -> Void) {
        var next = custom
        edit(&next)
        let aes = { (choice: EncryptionChoice) in choice.kdf == .aesKdf }
        if aes(next) != aes(custom) && !aes(next) {
            next.memoryMib = defaults.memoryMib
            next.lanes = defaults.lanes
        }
        next.memoryMib = min(max(next.memoryMib, 1), 1_048_576)
        next.lanes = min(max(next.lanes, 1), 128)
        next.unlockMs = min(max(next.unlockMs, 100), 5_000)
        guard next != custom else { return }
        let remeasure = aes(next) != aes(custom) || next.memoryMib != custom.memoryMib || next.lanes != custom.lanes
        custom = next
        stepAnswers = []
        memoryNote = aes(next) ? nil : core.memoryNote(memoryMib: next.memoryMib)
        if remeasure { measure() }
    }

    /// APP-07.8: one measurement at a time, off the screen thread; the
    /// latest values win.
    func measure() {
        let wizard = core
        let wanted = choice
        if memoryNote != nil && wanted.kdf != .aesKdf { return }
        measureTurn += 1
        let turn = measureTurn
        measuring = true
        let previous = measurer
        measurer = Task { [weak self] in
            await previous?.value
            var done = false
            while !done, !Task.isCancelled {
                let result = await Task.detached { Result { try wizard.measure(choice: wanted) } }.value
                switch result {
                case .success(let measured): done = measured
                case .failure(let error):
                    self?.memoryNote = message(error)
                    done = true
                }
                if !done { try? await Task.sleep(for: .milliseconds(50)) }
            }
            guard let self, turn == self.measureTurn else { return }
            self.measuring = false
        }
    }

    /// Waits for the measurement in progress (tests).
    func measured() async {
        while measuring, let running = measurer { await running.value }
    }

    private func continueEncryption() {
        switch core.checkEncryption(choice: choice, recommended: recommended, answers: stepAnswers) {
        case .done, .created: step = .password
        case .ask(let question): sheet = .question(question, then: .continueStep)
        case .refused(let id, let text):
            if id == "M07-35" { memoryNote = text } else { sheet = .notice(id: id, text: text) }
        }
    }

    // MARK: Step 3 (APP-07.11 to APP-07.17)

    /// A question's yes.
    func answer(_ question: Question, then: Then) {
        sheet = nil
        switch then {
        case .continueStep:
            stepAnswers.append(question.answer)
            continueEncryption()
        case .create:
            createAnswers.append(question.answer)
            create()
        case .chooseKeyFile(let path):
            chooseKeyFile(path, answers: [question.answer])
        }
    }

    /// "Create Vault" (APP-07.16): Rust's checks, then the save panel, then
    /// the write off the screen thread (APP-07.17). With a security key
    /// chosen, check 6 looks for it on USB, so the checks run off the
    /// screen thread too (INT-07.13).
    func create() {
        guard !creating else { return }
        let wizard = core
        let (name, description, choice, recommended, answers) = (
            name, description, choice, recommended, stepAnswers + createAnswers
        )
        let checks: @Sendable () -> Outcome = {
            (try? wizard.create(
                name: name, description: description, path: "", choice: choice, recommended: recommended,
                answers: answers))
                ?? .refused(id: "M07-30", text: "The vault could not be created.")
        }
        guard securityKey != nil else {
            checked(checks())
            return
        }
        creating = true
        Task { [weak self] in
            let outcome = await Task.detached(operation: checks).value
            guard let self else { return }
            creating = false
            checked(outcome)
        }
    }

    /// The write, after the panel (APP-07.17 steps 3 to 5).
    func write(to url: URL) {
        let wizard = core
        let (name, description, choice, recommended, answers) = (
            name, description, choice, recommended, stepAnswers + createAnswers
        )
        creating = true
        Task { [weak self] in
            let outcome = await Task.detached {
                (try? wizard.create(
                    name: name, description: description, path: url.path(percentEncoded: false), choice: choice,
                    recommended: recommended, answers: answers)) ?? .refused(id: "M07-30", text: "")
            }.value
            guard let self else { return }
            creating = false
            if case .created(let id) = outcome {
                hidePasswords()
                created?(id)
                closed?()
            } else {
                _ = handle(outcome)
            }
        }
    }

    /// True when the checks passed; else the message shows.
    private func handle(_ outcome: Outcome) -> Bool {
        switch outcome {
        case .done, .created: return true
        case .ask(let question):
            sheet = .question(question, then: .create)
        case .refused(let id, let text):
            switch id {
            case "M07-20":
                mismatchShown = true
                focusRepeat = true
            case "M07-27":
                keyFileProblem = text
            default:
                sheet = .notice(id: id, text: text)
            }
        }
        return false
    }

    // MARK: Panels (never shown by tests, AGENTS.md rule 10)

    /// The save panel (M07-16) in `folder` with `name`; `nil` on Cancel.
    /// The vault type makes the panel add `.appvault` itself, so its replace
    /// question names the real file. Tests give each model its own answer.
    @ObservationIgnored var savePanel: (URL, String) -> URL? = { folder, name in
        let panel = NSSavePanel()
        panel.title = "Save the New Vault"
        panel.directoryURL = folder
        panel.nameFieldStringValue = name
        panel.allowedContentTypes = [UTType(filenameExtension: "appvault") ?? .data]
        panel.canCreateDirectories = true
        return panel.runModal() == .OK ? panel.url : nil
    }
}

extension NewVaultModel {
    /// The checks' outcome: the save panel, then the write.
    private func checked(_ outcome: Outcome) {
        guard handle(outcome) else { return }
        guard let picked = savePanel(folder, fileName) else { return }
        // APP-07.17 step 2: the panel asked about the name it returned. A
        // file at the name App adds the extension to was never asked about.
        let url = Self.withVaultExtension(picked)
        if url != picked, (try? FileManager.default.attributesOfItem(atPath: url.path(percentEncoded: false))) != nil {
            sheet = .notice(
                id: "APP-07.17",
                text: "A file named \"\(url.lastPathComponent)\" already exists there. Choose another name.")
            return
        }
        write(to: url)
    }
}
