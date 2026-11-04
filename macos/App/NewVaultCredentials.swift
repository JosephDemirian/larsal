import AppCore
import Foundation

/// The wizard's step 3: the password pair (APP-07.11), the key file part
/// (APP-07.13, APP-07.14) and the security key part (APP-07.15).
extension NewVaultModel {
    /// The Password field: straight to Rust (APP-07.11); the meter comes
    /// back.
    func passwordTyped(_ text: String) {
        rating = try? core.setPassword(text: text)
        passwordLength = text.count
        if shownPassword != nil { shownPassword = text }
        match = core.repeatMatches()
        if match == true { mismatchShown = false }
        createAnswers = []
    }

    func repeatTyped(_ text: String) {
        match = try? core.setRepeat(text: text)
        repeatLength = text.count
        if shownRepeat != nil { shownRepeat = text }
        if match != false { mismatchShown = false }
        createAnswers = []
    }

    /// The M07-20 line: while the repeat differs, or after Create Vault.
    var mismatch: Bool { match == false || mismatchShown }

    /// The eye button and Control-H: Show for both fields together.
    func toggleShow() {
        if shownPassword == nil {
            shownPassword = core.password()
            shownRepeat = core.repeat()
        } else {
            hidePasswords()
        }
        fieldTurn += 1
    }

    func hidePasswords() {
        shownPassword = nil
        shownRepeat = nil
    }

    /// The dice button and Control-G (FEA-02.17): a generated password in
    /// both fields, shown, so the user can keep it.
    func generate() {
        do {
            let value = try core.generate()
            rating = try? core.setPassword(text: value)
            match = true
            mismatchShown = false
            shownPassword = value
            shownRepeat = value
            passwordLength = value.count
            repeatLength = value.count
            fieldTurn += 1
            createAnswers = []
        } catch {
            sheet = .notice(id: "FEA-02", text: message(error))
        }
    }

    /// "New Key File…": "Create a key file" with "<name>.appkey" (APP-07.13).
    func askCreateKeyFile() {
        keyFilePath = keyFilePath.deletingLastPathComponent().appending(
            path: (name.isEmpty ? "Passwords" : name) + ".appkey")
        sheet = .createKeyFile
    }

    func createKeyFile() {
        let outcome = try? core.newKeyFile(path: keyFilePath.path(percentEncoded: false))
        keyFileDone(outcome)
    }

    func chooseKeyFile(_ path: String, answers: [Answer] = []) {
        let outcome = try? core.chooseKeyFile(path: path, answers: answers)
        keyFileDone(outcome, path: path)
    }

    func removeKeyFile() {
        core.removeKeyFile()
        keyFile = nil
        keyFileProblem = nil
        createAnswers = []
    }

    /// The key menu's item (APP-07.15, F-126): Rust keeps the key and
    /// slot; the challenge runs at Create Vault (APP-07.17).
    func chooseSecurityKey(_ item: KeyItem) {
        keyMenu = false
        core.setSecurityKey(pick: item.pick)
        securityKey = item
        createAnswers = []
    }

    /// "Remove": the security key part is empty again.
    func removeSecurityKey() {
        core.setSecurityKey(pick: nil)
        securityKey = nil
        createAnswers = []
    }

    func keyFileDone(_ outcome: KeyFileOutcome?, path: String = "") {
        createAnswers = []
        switch outcome {
        case .chosen(let file):
            keyFile = file
            keyFileProblem = nil
            sheet = nil
        case .then(.ask(let question)):
            sheet = .question(question, then: .chooseKeyFile(path))
        case .then(.refused(let id, let text)):
            // M07-27 under the row (the field stays empty); the rest alert.
            if id == "M07-27" {
                keyFile = nil
                core.removeKeyFile()
                keyFileProblem = text
                sheet = nil
            } else {
                sheet = .notice(id: id, text: text)
            }
        default:
            sheet = nil
        }
    }
}
