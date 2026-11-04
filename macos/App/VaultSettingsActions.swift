import AppCore
import Foundation

/// The Security page's credentials (MOD-12.10), the Recycle Bin and History
/// pages and the actions that act at once.
extension VaultSettingsModel {
    // MARK: Security: credentials (MOD-12.10)

    func askPassword() {
        clearPassword()
        sheet = .changePassword
    }

    func passwordTyped(_ text: String) {
        rating = try? core.setPassword(text: text)
        passwordLength = text.count
        if shownPassword != nil { shownPassword = text }
        match = core.repeatMatches()
        if match == true { mismatchShown = false }
    }

    func repeatTyped(_ text: String) {
        match = try? core.setRepeat(text: text)
        repeatLength = text.count
        if shownRepeat != nil { shownRepeat = text }
        if match != false { mismatchShown = false }
    }

    var mismatch: Bool { match == false || mismatchShown }

    func toggleShow() {
        if shownPassword == nil {
            shownPassword = core.password()
            shownRepeat = core.repeat()
        } else {
            shownPassword = nil
            shownRepeat = nil
        }
        fieldTurn += 1
    }

    /// The sheet closed: the typed passwords go (Rust wipes them).
    func clearPassword() {
        core.clearPassword()
        (rating, match, mismatchShown, shownPassword, shownRepeat) = (nil, nil, false, nil, nil)
        (passwordLength, repeatLength) = (0, 0)
        fieldTurn += 1
        if sheet == .changePassword { sheet = nil }
    }

    func changePassword() {
        let outcome = try? core.changePassword(answers: answers)
        if outcome == .done {
            clearPassword()
        }
        done(outcome, then: .password)
    }

    /// The key file menu's "New Key File…": "Create a key file".
    func askCreateKeyFile() {
        keyMenu = false
        sheet = .createKeyFile
    }

    func createKeyFile() {
        sheet = nil
        keyFile(keyFilePath.path(percentEncoded: false), new: true)
    }

    func changeKeyFilePath() {
        if let picked = NewVaultModel.keyFileSavePanel(keyFilePath) { keyFilePath = picked }
    }

    /// The key file menu's "Choose Key File…".
    func pickKeyFile() {
        keyMenu = false
        if let picked = NewVaultModel.openKeyFile() { keyFile(picked.path(percentEncoded: false), new: false) }
    }

    func keyFile(_ path: String, new: Bool) {
        let outcome =
            new
            ? try? core.newKeyFile(path: path, answers: answers)
            : try? core.chooseKeyFile(path: path, answers: answers)
        switch outcome {
        case .chosen: done(.done)
        case .then(let next): done(next, then: .keyFile(path, new: new))
        case nil: done(nil)
        }
    }

    func removeKeyFile() {
        done(try? core.removeKeyFile(answers: answers), then: .removeKeyFile)
    }

    /// The security key menu's item, or `nil` for Remove (F-126; MOD-12.10,
    /// INT-07.25): the next save asks the new key, or none. Off the main
    /// thread: Rust looks for the chosen key first (step 6, M06-17). The
    /// task holds the model, so a change Rust made is always handled (the
    /// save, and the forced prompt's end, MOD-13.9), even when the page or
    /// window closed meanwhile.
    func setSecurityKey(_ pick: KeyPick?) {
        securityKeyMenu = false
        let (core, answers) = (core, answers)
        keyTask = Task {
            let outcome = await Task.detached { try? core.setSecurityKey(pick: pick, answers: answers) }.value
            done(outcome, then: .securityKey(pick))
        }
    }

    /// The row's words: Option A's "… · slot <n> · challenge-response"
    /// (the vault keeps the serial, not the model), or "Not used".
    var securityKeyText: String {
        guard let key = view?.securityKey else { return "Not used" }
        let serial = key.serial == 0 ? "unknown" : String(key.serial)
        return "Serial \(serial) · slot \(key.slot) · challenge-response"
    }

    // MARK: Recycle Bin (MOD-12.6, MOD-04.12)

    func setBin(_ wanted: Bool) {
        if !wanted, (view?.binItems ?? 0) > 0 {
            sheet = .confirm(.binOff)
        } else {
            apply(Self.change(recycleBin: wanted))
        }
    }

    // MARK: History (MOD-12.5, MOD-03)

    /// "Keep earlier versions of entries": off keeps none (0 items), after
    /// the screen's confirmation; on keeps 10 (MOD-12.22).
    func setHistory(_ wanted: Bool) {
        if wanted {
            apply(Self.change(historyItems: 10))
        } else {
            sheet = .confirm(.historyOff)
        }
    }

    /// Versions per entry: 0 to 100,000, then no limit (−1).
    func stepItems(_ step: Int32) {
        guard let items = view?.historyItems else { return }
        let next: Int32 =
            items < 0 ? (step < 0 ? 100_000 : -1) : items + step > 100_000 ? -1 : max(0, items + step)
        apply(Self.change(historyItems: next))
    }

    /// History size per entry: 1 to 2,047 MiB, then no limit (−1).
    func stepSize(_ step: Int32) {
        guard let size = view?.historyMib else { return }
        let next: Int32 = size < 0 ? (step < 0 ? 2_047 : -1) : size + step > 2_047 ? -1 : max(1, size + step)
        apply(Self.change(historyMib: next))
    }

    // MARK: Actions that act at once (MOD-12.18, MOD-03.13)

    func confirmed(_ what: Confirm, yes: Bool = true) {
        sheet = nil
        switch what {
        case .binOff: apply(Self.change(recycleBin: false, deleteOldBin: yes))
        case .historyOff: if yes { apply(Self.change(historyItems: 0)) }
        case .deleteHistory: if yes { done((try? core.deleteAllHistory()).map { _ in .done }) }
        case .forgetSites: if yes { done((try? core.forgetSiteAccess()).map { _ in .done }) }
        case .disconnect(let name): if yes { done((try? core.disconnect(name: name)).map { _ in .done }) }
        }
    }
}
