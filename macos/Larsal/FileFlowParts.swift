import AppKit
import LarsalCore

/// What the file sheet shows of its flow (FIL-02.12, FIL-03's words): text
/// only, from counts and message ids.
extension FileFlow {
    /// MSG-FILE-INPUT.
    static let inputWords = "Choose one local file. Folders and links are not supported here."

    /// A file URL of a regular file, not a link, a folder, a package or a
    /// device. Rust opens it again with no link followed (FIL-03.5).
    nonisolated static func isOneRegularFile(_ url: URL) -> Bool {
        guard url.isFileURL,
            let values = try? url.resourceValues(forKeys: [
                .isRegularFileKey, .isSymbolicLinkKey, .isPackageKey, .isDirectoryKey,
            ])
        else { return false }
        return values.isRegularFile == true && values.isSymbolicLink != true && values.isPackage != true
            && values.isDirectory != true
    }

    /// The source's name, as cleaned plain text.
    var sourceLabel: String {
        String(fileNameSuggestion(sourceName: source?.lastPathComponent ?? "", encrypt: true).dropLast(4))
    }

    /// "12.4 MB" (decimal, as the frame).
    var sizeLabel: String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: sourceSize), countStyle: .decimal)
    }

}

extension FileFlow {
    /// The step line under the bar, FIL-02.12's words.
    var stepTitle: String { Self.title(of: progress?.step ?? .preparing) }

    /// "2.48 GB of 4 GB checked"; no total, no measure.
    var countLine: String {
        guard let progress else { return "" }
        let done = ByteCountFormatter.string(fromByteCount: Int64(clamping: progress.done), countStyle: .decimal)
        let verb =
            switch progress.step {
            case .checking: "checked"
            case .preparing: "copied"
            case .savingPassphrase: "saved"
            case .encrypting, .saving: "written"
            }
        guard progress.total > 0 else { return "\(done) \(verb)" }
        let total = ByteCountFormatter.string(fromByteCount: Int64(clamping: progress.total), countStyle: .decimal)
        return "\(done) of \(total) \(verb)"
    }

    /// The bar's fraction; `nil` for an unknown total.
    var fraction: Double? {
        guard let progress, progress.total > 0 else { return nil }
        return min(Double(progress.done) / Double(progress.total), 1)
    }

    /// The saved file, as the complete frame shows it.
    var savedTo: String {
        if case .done(let savedTo, _) = end { return savedTo }
        return ""
    }

    /// The chosen destination, as text.
    var destinationLabel: String {
        [folder?.lastPathComponent, name].compactMap { $0 }.joined(separator: " / ")
    }

    /// The failure's first sentence, for a title.
    var failureTitle: String {
        guard case .failed(_, let text, _) = end else { return "" }
        return text.split(separator: ".", maxSplits: 1).first.map(String.init) ?? text
    }

    /// The rest of the failure's words.
    var failureBody: String {
        guard case .failed(_, let text, _) = end else { return "" }
        let parts = text.split(separator: ".", maxSplits: 1)
        return parts.count > 1 ? parts[1].trimmingCharacters(in: .whitespaces) : ""
    }

    /// FIL-02.6: the generated passphrase is saved though no file was completed.
    var savedKey: Bool {
        if case .failed(_, _, let saved) = end { return saved }
        return false
    }
    /// FIL-02.12's words for a step.
    static func title(of step: FileStep) -> String {
        switch step {
        case .savingPassphrase: "Saving passphrase"
        case .encrypting: "Encrypting file"
        case .preparing: "Preparing encrypted copy"
        case .checking: "Checking the whole file"
        case .saving: "Saving readable file"
        }
    }

    /// The last job wrote readable bytes (a decrypt).
    var readable: Bool { progress.map { [.preparing, .checking, .saving].contains($0.step) } ?? true }
    /// A question of the job: MSG-FILE-WEAK, or MSG-FILE-UNPROTECTED's warned consent.
    func asked(_ end: FileEnd?) {
        switch end {
        case .askWeak(let number):
            question = number
            screen = .weakFile
        case .askUnprotected(let number):
            question = number
            screen = .unprotectedFile
        default: break
        }
    }

    /// FIL-03.12, advisory: the estimate for the chosen source and folder.
    func estimate() {
        guard let source, let folder else { return }
        spaceShort = session.fileSpaceShort(source: source.path, folder: folder.path, encrypt: sealing)
    }

    /// FIL-02.14 (C1-01): how long a quit waits for a file job's safe cleanup.
    nonisolated static let quitWait: UInt64 = 30_000

    /// Marks `job` and waits, off the screen thread, at most `quitWait` for its
    /// safe cleanup; true once its worker is over.
    nonisolated static func ended(_ job: FileJob) async -> Bool {
        await withCheckedContinuation { done in
            Thread.detachNewThread { done.resume(returning: job.endWithin(ms: FileFlow.quitWait)) }
        }
    }

    /// The whole failure text, as FIL-03 words it.
    var failureText: String {
        if case .failed(_, let text, _) = end { return text }
        return ""
    }
}

/// Recipients and file keys (FIL-02.8, FIL-02.9).
extension FileFlow {
    /// Encrypt is possible: every key valid and both boxes checked when
    /// none is the user's own (FIL-02.8).
    var recipientsReady: Bool {
        !recipients.isEmpty && recipients.allSatisfy { fileRecipientValid(text: $0) } && checkedWithOwner
            && mayNotDecrypt
    }

    func addRecipient() {
        let key = recipientDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard fileRecipientValid(text: key) else {
            notice = "Add a valid native X25519 recipient key."
            return
        }
        notice = nil
        if !recipients.contains(key) { recipients.append(key) }
        recipientDraft = ""
        checkedWithOwner = false
    }

    /// Add My File Key…: the vault's own file keys, public part only.
    func myFileKeys() -> [FileKeyChoice] {
        guard let vault else { return [] }
        return ((try? session.fileKeyChoices(vault: vault.id)) ?? []).filter { $0.recipient != nil }
    }

    func addMine(_ choice: FileKeyChoice) {
        guard let key = choice.recipient, !recipients.contains(key) else { return }
        recipients.append(key)
    }

    /// Create File Key (FIL-02.9): off the screen thread; the public key
    /// comes back only after the vault saved.
    func createKey() async {
        guard let vault else {
            screen = .locked
            return
        }
        let save = FileSave(vault: vault.id, group: nil, title: keyTitle)
        let session = session
        let made = await Task.detached { Result { try session.createFileKey(save: save) } }.value
        switch made {
        case .success(let key):
            if !recipients.contains(key) { recipients.append(key) }
            mode = .recipients
            screen = .recipients
        case .failure(let error):
            notice = message(error)
        }
    }
}

/// The real panels, never shown by tests (AGENTS.md rule 10).
enum FilePanels {
    @MainActor
    static func run(_ panel: FileFlow.Panel) -> URL? {
        switch panel {
        case .source, .keyFile:
            let open = NSOpenPanel()
            open.canChooseFiles = true
            open.canChooseDirectories = false
            open.allowsMultipleSelection = false
            open.treatsFilePackagesAsDirectories = false
            open.resolvesAliases = false
            return open.runModal() == .OK ? open.url : nil
        case .destination(let folder, let name):
            let save = NSSavePanel()
            save.directoryURL = folder
            save.nameFieldStringValue = name
            save.canCreateDirectories = true
            // FIL-02.4: a new name only; Rust refuses one that exists.
            save.showsTagField = false
            return save.runModal() == .OK ? save.url : nil
        }
    }
}

extension MainWindowModel {
    /// FIL-02.14 (C1-01, S2-02): a quit, by any path that reaches
    /// `applicationShouldTerminate` (the menu, the Dock, a logout, a quit signal),
    /// with a file job running revokes it and replies only after its safe cleanup,
    /// waited for at most `FileFlow.quitWait`; then the quit goes on as before.
    /// True when it took the reply over (`.terminateLater`). A force quit or a
    /// crash is not a quit: what it leaves is FIL-03.11's sweep (E22-S6).
    func quitAfterFiles(asks: Bool, reply: @escaping (Bool) -> Void) -> Bool {
        guard let job = files?.job, !job.progress().finished else { return false }
        files?.revoke()
        Task { [weak self] in
            let done = await FileFlow.ended(job)
            guard let self else { return reply(true) }
            // Past the bound the quit goes on; the sheet goes with it.
            if !done { self.files = nil }
            switch self.quitReply(asks: asks, reply: reply) {
            case .terminateNow: reply(true)
            case .terminateCancel: reply(false)
            default: break  // that run replies
            }
        }
        return true
    }

    /// File ▸ Encrypt File… and Decrypt File… (FIL-02.1): with or without a
    /// vault; one sheet at a time (FIL-02.17).
    func openFiles(encrypt: Bool) {
        if let files {
            files.notice = "A file operation is already running."
            return
        }
        let vault = main.map { (id: $0.vault.id, name: $0.vault.name) }
        let flow = FileFlow(session: session, vault: vault)
        flow.close = { [weak self, weak flow] in
            if let flow, self?.files === flow { self?.files = nil }
        }
        files = flow
        flow.screen = encrypt ? .entry : .decrypt
        flow.chooseSource(encrypt: encrypt)
        if flow.source == nil, !encrypt { flow.screen = .entry }
    }
}
