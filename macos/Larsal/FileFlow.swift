import AppKit
import LarsalCore
import Observation

/// Encrypt File and Decrypt File (FIL-02, E22-S4): the sheet's state over
/// larsal-ffi `files.rs`. It holds paths, ids, titles and public keys. What
/// the user types goes to Rust (`FileTyped`) on each change, and Swift keeps no
/// copy (S2-04). The generated passphrase stays in Rust (`FileDraft`); Show asks
/// for it and Hide drops it. No file key, private key or plaintext is here.
@MainActor
@Observable
final class FileFlow {
    /// The e22-s1 frames, and the low work factor question.
    enum Screen: Equatable {
        case entry, encrypt, manual, recipients, key, decrypt, progress, complete, error, collision, cleanup, locked
        case weakFile, unprotectedFile
    }

    enum Mode { case passphrase, recipients }
    enum Credential { case passphrase, fileKey }

    /// The panels the flow asks for; tests answer them (AGENTS.md rule 10,
    /// W-08 carries the real panels to the owner's Mac QA).
    enum Panel: Equatable {
        case source(encrypt: Bool)
        case destination(folder: URL?, name: String)
        case keyFile
    }

    let session: Session
    /// The writable vault the passphrase or file key goes into, if one is
    /// open and unlocked: its id and name.
    let vault: (id: UInt64, name: String)?
    var screen = Screen.entry
    var mode = Mode.passphrase
    private(set) var source: URL?
    private(set) var sourceSize: UInt64 = 0
    var folder: URL?
    var name = ""
    /// The generated passphrase in Rust; `shown` while Show is on.
    private(set) var draft: FileDraft?
    private(set) var shown: String?
    var title = ""
    /// The secure fields' text, in Rust; here only whether each holds any.
    let typed = FileTyped()
    private(set) var hasPassphrase = false
    private(set) var hasRepeat = false
    private(set) var hasDecrypt = false
    /// FIL-02.6: after a failure, the entry that holds the saved passphrase; a
    /// retry encrypts with it, shown as chosen, until a new generation.
    private(set) var reuse: (entry: String, title: String)?
    /// FIL-02.11: the save panel confirmed this destination for one output.
    private(set) var confirmed = false
    /// FIL-03.12's advisory estimate: the chosen disk may be too small.
    var spaceShort = false
    /// The source came for Encrypt (else for Decrypt).
    private(set) var sealing = true
    var saveManual = true
    /// FIL-01.7: the typed passphrase is below Excellent; Use Anyway goes on.
    private(set) var manualWeak = false
    var recipients: [String] = []
    var recipientDraft = ""
    var checkedWithOwner = false
    var mayNotDecrypt = false
    var keyTitle = "My file key"
    var credential = Credential.passphrase
    private(set) var keyFile: URL?
    private(set) var entry: FileKeyChoice?
    private(set) var job: FileJob?
    /// The job's last reading; the frame tests set it too.
    var progress: FileProgress?
    /// The last end, for the closing frames.
    var end: FileEnd?
    /// Inline words: MSG-FILE-BUSY, MSG-FILE-INPUT, a refusal.
    var notice: String?
    /// A revoke came (cancel, lock).
    private(set) var revoked = false
    /// A lock, a close or a quit came: nothing late is shown as a success. A user's
    /// Cancel that lost the race with the commit still says where the file is
    /// (FIL-02.13, C1R3-05).
    private(set) var locked = false
    /// The number of the question the sheet shows; its answer goes with it (C2R3-05).
    var question: UInt64?
    /// The last job came from Choose My Own Passphrase…: a collision goes back
    /// there with the typed passphrase kept (FIL-02.6, C1R3-04).
    private(set) var manualJob = false
    /// Back to the window: closes the sheet.
    @ObservationIgnored var close: () -> Void = {}

    static var choose: (Panel) -> URL? = { FilePanels.run($0) }
    /// How often the sheet reads the job (VoiceOver gets at most one a second).
    static var tick: Duration = .milliseconds(100)
    /// The wait between two readings; a test holds it to keep the next reading back.
    static var pause: @MainActor () async -> Void = { try? await Task.sleep(for: FileFlow.tick) }

    init(session: Session, vault: (id: UInt64, name: String)?) {
        self.session = session
        self.vault = vault
    }

    // MARK: Sources (FIL-02.2)

    /// A drop on the dedicated target: exactly one local regular file.
    func dropped(_ urls: [URL], encrypt: Bool = true) {
        guard urls.count == 1, let url = urls.first, Self.isOneRegularFile(url) else {
            notice = Self.inputWords
            return
        }
        use(url, encrypt: encrypt)
    }

    func chooseSource(encrypt: Bool) {
        guard let url = Self.choose(.source(encrypt: encrypt)) else { return }
        dropped([url], encrypt: encrypt)
    }

    private func use(_ url: URL, encrypt: Bool) {
        notice = nil
        source = url
        sourceSize = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).map { UInt64(max($0, 0)) } ?? 0
        folder = url.deletingLastPathComponent()
        name = fileNameSuggestion(sourceName: url.lastPathComponent, encrypt: encrypt)
        reuse = nil
        confirmed = false
        sealing = encrypt
        estimate()
        if !encrypt {
            screen = .decrypt
            return
        }
        title = "File passphrase · " + sourceLabel
        guard vault != nil, let made = try? FileDraft() else {
            screen = .locked
            return
        }
        draft = made
        screen = .encrypt
    }

}

extension FileFlow {
    // MARK: Encrypt (FIL-02.3 to FIL-02.9)

    /// Show and Hide of the generated passphrase (FIL-02.3).
    func toggleShow() {
        shown = shown == nil ? draft?.show() : nil
    }

    func chooseDestination() {
        guard let url = Self.choose(.destination(folder: folder, name: name)) else { return }
        folder = url.deletingLastPathComponent()
        name = url.lastPathComponent
        confirmed = true
        estimate()
    }

    /// Choose Another Name… after a collision: the panel, then the frame the
    /// work came from (FIL-02.6: a saved passphrase stays chosen; a typed one stays
    /// typed).
    func chooseAnotherName() {
        chooseDestination()
        screen = readable ? .decrypt : manualJob ? .manual : .encrypt
    }

    /// FIL-02.6: a new generation instead of the saved entry; it makes a new entry.
    func newPassphrase() {
        reuse = nil
        shown = nil
        draft = try? FileDraft()
    }

    /// Choose My Own Passphrase… and Recipients leave the generated value (S2-05).
    func leaveEncrypt(to next: Screen) {
        shown = nil
        if next == .recipients { mode = .recipients }
        screen = next
    }

    /// A keystroke in a secure field: its whole text goes to Rust (S2-04).
    func type(_ slot: FileSlot, _ text: String) {
        let filled = typed.set(slot: slot, text: text)
        switch slot {
        case .passphrase: hasPassphrase = filled
        case .repeated: hasRepeat = filled
        case .decrypt: hasDecrypt = filled
        }
    }

    /// The place line: vault and title.
    var placeLine: String {
        [vault?.name, title].compactMap { $0 }.joined(separator: " · ")
    }

    /// Encrypt File: by the mode and the screen.
    func encrypt() {
        guard let source, let folder else { return }
        manualJob = false
        let start: FileStart?
        switch (mode, screen) {
        case (.recipients, _):
            guard recipientsReady else { return }
            start = try? session.encryptFileRecipients(
                recipients: recipients, source: source.path, folder: folder.path, name: name)
        case (_, .manual):
            start = startManual(acceptWeak: false)
        default:
            if let reuse, let vault {
                start = try? session.encryptFileEntry(
                    vault: vault.id, entry: reuse.entry, source: source.path, folder: folder.path, name: name)
                break
            }
            guard let draft, let vault else {
                screen = .locked
                return
            }
            shown = nil
            start = try? session.encryptFileGenerated(
                draft: draft, save: FileSave(vault: vault.id, group: nil, title: title), source: source.path,
                folder: folder.path, name: name)
        }
        started(start)
    }

    /// Use Anyway of the weak passphrase warning.
    func useAnyway() {
        started(startManual(acceptWeak: true))
    }

    private func startManual(acceptWeak: Bool) -> FileStart? {
        guard let source, let folder else { return nil }
        let save = saveManual ? vault.map { FileSave(vault: $0.id, group: nil, title: title) } : nil
        manualJob = true
        let start = try? session.encryptFileTyped(
            typed: typed, acceptWeak: acceptWeak, save: save, source: source.path, folder: folder.path, name: name)
        if case .weak = start {
            manualWeak = true
        }
        return start
    }

    // MARK: Decrypt (FIL-02.10, FIL-02.11)

    func chooseKeyFile() {
        keyFile = Self.choose(.keyFile)
        if keyFile != nil { credential = .fileKey }
    }

    func choices() -> [FileKeyChoice] {
        guard let vault else { return [] }
        return (try? session.fileKeyChoices(vault: vault.id)) ?? []
    }

    func choose(_ choice: FileKeyChoice) {
        entry = choice
        credential = choice.recipient == nil ? .passphrase : .fileKey
    }

    /// Save Readable File: the save panel's confirmation authorizes this one
    /// output (FIL-02.11); a destination the panel confirmed before is not asked again.
    func decrypt() {
        if !confirmed {
            guard let url = Self.choose(.destination(folder: folder, name: name)) else { return }
            folder = url.deletingLastPathComponent()
            name = url.lastPathComponent
        }
        guard let source, let folder else { return }
        (confirmed, manualJob) = (false, false)
        let (from, into) = (source.path, folder.path)
        if let entry, let vault {
            started(
                try? session.decryptFileEntry(
                    vault: vault.id, entry: entry.entry, source: from, folder: into, name: name))
        } else {
            let file = credential == .fileKey ? keyFile?.path : nil
            started(try? session.decryptFileTyped(typed: typed, keyFile: file, source: from, folder: into, name: name))
        }
    }

}

extension FileFlow {
    // MARK: The job (FIL-02.12 to FIL-02.14, FIL-02.17)

    private func started(_ start: FileStart?) {
        switch start {
        case .started(let job):
            // A typed passphrase stays in Rust until the job ends: a collision keeps it.
            if !manualJob { clearTyped() }
            self.job = job
            screen = .progress
            Task { await follow(job) }
        case .busy:
            notice = "A file operation is already running."
        case .weak:
            screen = .manual
        case .refused(let text):
            notice = text
        case nil:
            notice = "The text is too long."
        }
    }

    /// Reads the job until it ends; a question shows as asked.
    func follow(_ job: FileJob) async {
        while true {
            let now = job.progress()
            progress = now
            if !revoked { asked(now.end) }
            if now.finished {
                if case .failed(_, _, true) = now.end, let entry = job.savedEntry() {
                    reuse = (entry, title)
                }
                return finished(now.end)
            }
            await Self.pause()
        }
    }

    private func finished(_ last: FileEnd?) {
        end = last
        job = nil
        question = nil
        if !keepsTyped(last) { clearTyped() }
        switch last {
        case .done:
            if locked { return close() }
            screen = .complete
        case .failed(let id, _, _):
            switch id {
            case "MSG-FILE-CANCELLED": close()
            case "MSG-FILE-EXISTS": screen = revoked ? .cleanup : .collision
            case "MSG-FILE-CLEANUP", "MSG-FILE-CLEANUP-EMPTY", "MSG-FILE-UNCERTAIN": screen = .cleanup
            default: if revoked { close() } else { screen = .error }
            }
        case .askWeak, .askUnprotected, nil:
            close()
        }
    }

    /// FIL-02.6 (C1R3-04): after a collision, Choose Another Name… goes on with the typed text.
    private func keepsTyped(_ last: FileEnd?) -> Bool {
        guard case .failed("MSG-FILE-EXISTS", _, _) = last else { return false }
        return manualJob && !revoked
    }

    /// The answer to the question the sheet shows, by its number: a late or second
    /// press answers nothing else (C2R3-05).
    func answerWeak(save: Bool) {
        guard let job, let question else { return }
        self.question = nil
        screen = .progress
        job.answerWeak(question: question, save: save)
    }

    /// Cancel, Escape: before an output exists, no new write starts; the
    /// sheet waits for the cleanup's result (FIL-02.13, FIL-02.17).
    func cancel() {
        guard let job else {
            forget()
            return close()
        }
        revoked = true
        Self.stop(job)
    }

    /// A lock, a close, a quit (FIL-02.14): typed and shown secrets go at
    /// once, the job is revoked, no late success shows.
    func revoke() {
        forget()
        revoked = true
        locked = true
        if let job {
            screen = .progress
            Self.stop(job)
        } else {
            close()
        }
    }

    /// `revoke()` waits for the chunk in hand, so it runs on a thread of its
    /// own, never the shared task pool, where other blocked work could delay
    /// the stop.
    private nonisolated static func stop(_ job: FileJob) {
        Thread.detachNewThread { job.revoke() }
    }

    private func clearTyped() {
        typed.clear()
        (hasPassphrase, hasRepeat, hasDecrypt) = (false, false, false)
        shown = nil
    }

    private func forget() {
        clearTyped()
        draft?.forget()
        draft = nil
    }
}
