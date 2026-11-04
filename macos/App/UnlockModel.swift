import AppCore
import AppKit
import Observation
import os

/// View data of the unlock screen (APP-06, E5-S3). The password text leaves
/// this model once, when an unlock starts, and the field is cleared at that
/// moment (APP-06.11, LD-95, Swift rule 4); nothing typed survives a lock.
@Observable
final class UnlockModel {
    /// The M06-34 question.
    struct Question: Equatable {
        let message: String
        let details: String
    }

    let session: Session
    var vault: VaultInfo
    /// UL-PW. Typing clears the message (APP-06.20).
    var password = "" {
        didSet { if !password.isEmpty { message = nil } }
    }
    var reveal = false
    /// UL-TOUCH (APP-04.9): shown only for a vault with a quick unlock slot,
    /// which comes with E6-S3; until then a vault always starts with the
    /// password form.
    var touchForm = false
    /// UL-KEY: a path, shown in clear (APP-06.7).
    var keyFile = "" {
        didSet { if keyFile != oldValue { message = nil } }
    }
    /// UL-HW (APP-06.8, F-107, F-126): the key watch's list, the switch
    /// and the chosen slot (UnlockKeys.swift); not secret. A change clears
    /// the message.
    let keyPicker = KeyPicker()
    var useKey = false {
        didSet { if useKey != oldValue { message = nil } }
    }
    var pick: KeyPick? {
        didSet { if pick != oldValue { message = nil } }
    }
    /// M06-35 (APP-06.15): a challenge waits for a touch.
    var touchWaits = false
    /// APP-06.9: the remembered slot, chosen when a look finds it.
    var rememberedPick: KeyPick?
    private(set) var message: UnlockMessage?
    private(set) var busy = false
    /// APP-05.30: the vault file is still downloading; the unlock goes on
    /// when it is on this Mac. `waits` counts the reads that wait for it.
    var downloading: Bool { waits > 0 }
    private var waits = 0
    /// Counts failures that shake the form (APP-06.17).
    private(set) var shakes = 0
    var question: Question?
    private let onChange: () -> Void
    /// The unlock that waits for its file. Its typed password waits in the
    /// lock with the stop flag, never in a closure, so one stop both ends
    /// it and wipes the password (APP-06.5, APP-06.16, LD-277).
    private(set) var attempt: (state: OSAllocatedUnfairLock<(stopped: Bool, typed: String?)>, task: Task<Void, Never>)?

    init(session: Session, vault: VaultInfo, onChange: @escaping () -> Void) {
        self.session = session
        self.vault = vault
        self.onChange = onChange
        message = try? session.takeMessage(vault: vault.id)
        if message == nil {
            Task { await checkHeader() }
        }
        prefillKeys()
    }

    /// The session changed: new state for this vault, and the message of a
    /// passed-in unlock that failed meanwhile (APP-06.24).
    func update(_ newVault: VaultInfo) {
        vault = newVault
        if let found = try? session.takeMessage(vault: vault.id) {
            message = found
        }
        touchWaits = securityKeyWaits()
    }

    /// An unlock runs: from this form or with passed-in credentials.
    var working: Bool { busy || vault.unlocking }

    /// The vault's file name, as `MSG-DISK-DOWNLOADING` names it.
    var fileName: String { (vault.path as NSString).lastPathComponent }

    /// `body` (Rust's file I/O) in a coordinated read of the vault file once
    /// it is on this Mac; "Still downloading" shows meanwhile (APP-05.24,
    /// APP-05.30).
    private func onFile<T: Sendable>(_ body: @escaping @Sendable () -> T) async -> T {
        await FileAccess.run(.read, vault.path, downloading: { self.waits += $0 ? 1 : -1 }, body)
    }

    /// APP-06.3: a file that already fails without a key says so at once.
    /// Each read of the vault file is coordinated, off the main thread,
    /// once the file is on this Mac (APP-05.24).
    func checkHeader() async {
        let session = session
        let id = vault.id
        let found = await onFile {
            try? session.checkHeader(vault: id)
        }
        if message == nil, let found {
            message = found
        }
    }

    /// APP-06.10 to APP-06.13. `blank` is M06-05's link: the empty password.
    func unlock(blank: Bool = false) {
        guard !working else { return }
        // LD-277 (2): the lock count at the click; a lock or close after it
        // stops the attempt in Rust as well.
        guard let epoch = try? session.lockEpoch(vault: vault.id) else { return }
        let state = OSAllocatedUnfairLock(
            initialState: (stopped: false, typed: blank ? "" : (password.isEmpty ? nil : password)))
        password = ""
        reveal = false
        message = nil
        busy = true
        let key = keyFile.isEmpty ? nil : keyFile
        // APP-06.11 step 3: the chosen slot while the switch is on.
        let hardware = useKey ? pick : nil
        let session = session
        let id = vault.id
        // APP-06.16: a lock before Rust starts stops the attempt (stop());
        // once Rust runs, Rust's own lock stops it. The password leaves the
        // lock when Rust starts.
        let task = Task {
            let result = await onFile { () -> UnlockResult? in
                let (stopped, typed) = state.withLock { now in
                    defer { now.typed = nil }
                    return (now.stopped, now.typed)
                }
                guard !stopped else { return nil }
                return try? session.unlockWithKey(
                    vault: id, password: typed, keyFile: key, hardware: hardware, epoch: epoch)
            }
            // A stopped attempt ended at the stop; the window only reads
            // the session again.
            guard !state.withLock({ $0.stopped }) else { return onChange() }
            attempt = nil
            finish(result)
        }
        attempt = (state, task)
    }

    /// APP-06.14: "Unlock" runs the waiting attempt; "Cancel" wipes it.
    func answer(unlock yes: Bool) {
        question = nil
        let session = session
        let id = vault.id
        guard yes else {
            try? session.cancelUnlock(vault: id)
            return
        }
        busy = true
        Task {
            let result = await onFile {
                try? session.approveUnlock(vault: id)
            }
            finish(result)
        }
    }

    private func finish(_ result: UnlockResult?) {
        busy = false
        switch result {
        case .failed(let found):
            message = found
            if found.id == "M06-05" || found.id == "M06-06" {
                shakes += 1
            }
        case .ask(let text, let details):
            question = Question(message: text, details: details)
        case .unlocked, .ignored, nil:
            onChange()
        }
    }

    /// "Browse…": any file can be a key file (FMT-18).
    func chooseKeyFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.prompt = "Choose"
        panel.message = "Choose the key file of this vault."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        keyFile = url.path(percentEncoded: false)
    }

    /// LD-163 (2): "Remove Key File" and the Delete key clear UL-KEY: no
    /// key file (APP-06.7).
    func removeKeyFile() { keyFile = "" }

    /// LD-163 (2): a file dropped on the key file row is the key file; the
    /// FMT-18.24 checks run at unlock (APP-06.11).
    func useKeyFile(_ path: String) { keyFile = path }

    /// UL-KEY as the form shows it: "name · folder", home as `~`.
    var keyFileText: String? {
        guard !keyFile.isEmpty else { return nil }
        let path = (keyFile as NSString).expandingTildeInPath as NSString
        let folder = (path.deletingLastPathComponent as NSString).abbreviatingWithTildeInPath
        return path.lastPathComponent + " · " + folder
    }

    /// Drops everything typed (a lock, a vault switch, the window closing).
    /// An unlock that waits for its file goes on (APP-05.30): only stop()
    /// ends it.
    func clear() {
        password = ""
        reveal = false
        question = nil
    }

    /// A lock of every vault (APP-06.16, LD-277): the field clears, and an
    /// unlock that still waits for its file ends now: its password is wiped
    /// and it never reaches Rust (APP-06.5).
    func stop() {
        clear()
        guard let attempt else { return }
        attempt.state.withLock { $0 = (stopped: true, typed: nil) }
        attempt.task.cancel()
        self.attempt = nil
        busy = false
    }
}
