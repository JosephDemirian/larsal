import AppKit
import LarsalCore
import SwiftUI
import Testing

extension FileSuites {
    /// FIL-02-T12 to T23 in the Mac app (E22-S4), over the real Rust engine, demo
    /// files only; no panel is shown.
    @MainActor
    @Suite(.serialized)
    struct FileFlowMoreTests {
        init() { ParityDemo.setUp() }

        @Test("FIL-02-T13: a cancel during the work leaves no output and no staging folder")
        func cancelLeavesNothing() async throws {
            let window = try ParityDemo.window("files-t13")
            let (folder, source) = try FileDemo.folder("t13", bytes: 48_000_000)
            let flow = FileFlow(session: window.session, vault: nil)
            var closed = false
            flow.close = { closed = true }
            flow.dropped([source])
            flow.screen = .manual
            flow.saveManual = false
            flow.type(.passphrase, "demo cancel passphrase with many words in it")
            flow.type(.repeated, "demo cancel passphrase with many words in it")
            flow.useAnyway()
            #expect(flow.job != nil)
            // In the same turn: a wait here gives the main actor to suites running
            // side by side, and the job could end before the cancel. The key
            // derivation is still running, so its safe point stops the job.
            flow.cancel()
            try await FileDemo.settled(flow)
            #expect(closed)
            FileDemo.cancelled(flow)
            try FileDemo.onlySource(folder, flow)
        }

        @Test("FIL-02-T14: a lock revokes a running job that needs no vault; no late success shows")
        func lockRevokes() async throws {
            let window = try ParityDemo.window("files-t14")
            let (folder, source) = try FileDemo.folder("t14", bytes: 48_000_000)
            let restore = FileDemo.panels([source])
            defer { restore() }
            window.openFiles(encrypt: true)
            let flow = try #require(window.files)
            flow.screen = .manual
            flow.saveManual = false
            flow.type(.passphrase, "demo lock passphrase with many words in it")
            flow.type(.repeated, "demo lock passphrase with many words in it")
            flow.useAnyway()
            #expect(flow.job != nil)
            // In the same turn, as T13: the lock reaches the job before its end.
            window.lockAll()
            #expect(flow.revoked)
            #expect(!flow.hasPassphrase && !flow.hasRepeat)
            try await FileDemo.settled(flow)
            #expect(window.files == nil)
            FileDemo.cancelled(flow)
            try FileDemo.onlySource(folder, flow)
        }

        @Test("FIL-02-T17: a second request says one runs and keeps the first selection")
        func oneAtATime() throws {
            let window = try ParityDemo.window("files-t17")
            let (_, source) = try FileDemo.folder("t17")
            let restore = FileDemo.panels([source, source])
            defer { restore() }
            window.openFiles(encrypt: true)
            let flow = try #require(window.files)
            window.openFiles(encrypt: false)
            #expect(window.files === flow)
            #expect(flow.notice == "A file operation is already running.")
            #expect(flow.screen == .encrypt)
            flow.cancel()
        }

        @Test("FIL-02-T12: the progress words are the step's, with counts; no measure or estimate for an unknown total")
        func progressWords() throws {
            let window = try ParityDemo.window("files-t12")
            let flow = FileFlow(session: window.session, vault: nil)
            flow.progress = FileProgress(
                step: .checking, done: 2_480_000_000, total: 4_000_000_000, end: nil, finished: false)
            #expect(flow.stepTitle == "Checking the whole file")
            #expect(flow.countLine == "2.48 GB of 4 GB checked")
            #expect(flow.fraction == 0.62)
            flow.progress = FileProgress(step: .encrypting, done: 1_000_000, total: 0, end: nil, finished: false)
            #expect(flow.stepTitle == "Encrypting file")
            #expect(flow.countLine == "1 MB written")
            #expect(flow.fraction == nil)
            let steps: [FileStep] = [.savingPassphrase, .encrypting, .preparing, .checking, .saving]
            let words = steps.map(FileFlow.title(of:))
            #expect(
                words == [
                    "Saving passphrase", "Encrypting file", "Preparing encrypted copy", "Checking the whole file",
                    "Saving readable file",
                ])
            #expect(!words.joined().contains("remaining"))
        }

        @Test("FIL-02-T22: every creation, decrypt and success view states its limits")
        func limitsVisible() throws {
            let window = try ParityDemo.window("files-t22")
            let (_, source) = try FileDemo.folder("t22")
            let flow = FileFlow(session: window.session, vault: (window.main!.vault.id, "Personal"))
            flow.dropped([source])
            let views: [(FileFlow.Screen, String)] = [
                (.encrypt, fileLimits),
                (.manual, "Anyone with the encrypted file can test guesses."),
                (.recipients, "This does not prove who sent the file."),
                (.recipients, "These public keys do not protect against a future quantum computer."),
                (.decrypt, "The saved file is not encrypted. Keep it somewhere private."),
                (.decrypt, "This does not prove who sent the file."),
                (.complete, readableSaved),
                (.complete, fileLimits),
                (.complete, recipientLimits),
            ]
            for (index, (screen, words)) in views.enumerated() {
                flow.screen = screen
                if screen == .complete {
                    let step: FileStep = index == views.count - 3 ? .saving : .encrypting
                    flow.progress = FileProgress(step: step, done: 1, total: 1, end: nil, finished: true)
                    flow.mode = index == views.count - 1 ? .recipients : .passphrase
                }
                let host = QrDemo.placed(NSHostingView(rootView: FileDialog(flow: flow)))
                host.layoutSubtreeIfNeeded()
                let texts = QrDemo.texts(host)
                #expect(texts.contains { $0.contains(words) }, "\(screen): \(words)")
                for never in ["anonym", "guarantee", "securely erase", "never be decrypted", "cannot be lost"] {
                    #expect(!texts.contains { $0.lowercased().contains(never) }, "\(screen): \(never)")
                }
            }
            flow.cancel()
        }

        @Test("FIL-02-T23: after a revoke a late success never shows completion")
        func lateSuccessSuppressed() async throws {
            let window = try ParityDemo.window("files-t23")
            let (folder, _) = try FileDemo.folder("t23", bytes: 4_096)
            let flow = FileFlow(session: window.session, vault: nil)
            var closed = false
            flow.close = { closed = true }
            let release = try await FileDemo.endedUnseen(flow, folder)
            // The success is still to be delivered: the sheet's reading is held.
            flow.revoke()
            release()
            try await FileDemo.settled(flow)
            #expect(closed)
            #expect(flow.screen != .complete)
        }

        @Test("FIL-02-T13 C1R3-05: a Cancel that loses the race with the commit says Done and where the file is")
        func lateCancelSaysDone() async throws {
            let window = try ParityDemo.window("files-late-cancel")
            let (folder, _) = try FileDemo.folder("late-cancel", bytes: 4_096)
            let flow = FileFlow(session: window.session, vault: nil)
            var closed = false
            flow.close = { closed = true }
            let release = try await FileDemo.endedUnseen(flow, folder)
            let name = flow.name
            // The user's Cancel comes after the commit, before the sheet reads it.
            flow.cancel()
            release()
            try await FileDemo.settled(flow)
            #expect(!closed, "the sheet stays to say where the file is")
            #expect(flow.screen == .complete)
            #expect(flow.savedTo == "Documents / \(name)")
            #expect(try FileDemo.names(folder).contains(name))
        }

        @Test("FIL-02-T15: every action of the sheet is a named button, the weak-file and unprotected questions' too")
        func actionsNamed() throws {
            let window = try ParityDemo.window("files-t15")
            let (_, source) = try FileDemo.folder("t15")
            let flow = FileFlow(session: window.session, vault: (window.main!.vault.id, "Personal"))
            flow.dropped([source])
            let encrypt = ["Passphrase", "Recipients", "Choose My Own Passphrase…", "Choose Destination…"]
            let decrypt = ["Passphrase", "File Key", "Choose from Vault…", "Choose Key File…"]
            let actions: [(FileFlow.Screen, [String])] = [
                (.entry, ["Choose File to Encrypt…", "Choose File to Decrypt…", "Close"]),
                (.encrypt, encrypt + ["Cancel", "Encrypt File"]),
                (.manual, ["Cancel", "Encrypt File"]),
                (.recipients, ["Add Recipient…", "Add My File Key…", "Cancel", "Encrypt File"]),
                (.key, ["Cancel", "Create File Key"]),
                (.decrypt, decrypt + ["Cancel", "Save Readable File"]),
                (.weakFile, ["Cancel", "Save Readable File"]),
                (.unprotectedFile, ["Cancel", "Save Readable File"]),
                (.locked, ["Cancel", "Unlock Vault…"]),
            ]
            for (screen, titles) in actions {
                flow.screen = screen
                let host = QrDemo.placed(NSHostingView(rootView: FileDialog(flow: flow)))
                host.layoutSubtreeIfNeeded()
                let buttons = FileDemo.buttons(host)
                for title in titles {
                    #expect(buttons.contains(title), "\(screen): \(title) in \(buttons)")
                }
            }
            flow.cancel()
        }
    }
}

extension FileDemo {
    /// The sheet's next reading of its job waits while `held` is true (`FileFlow.pause`).
    @MainActor
    final class Hold {
        var held = true
        var reached = false
    }

    /// A decrypt into `folder` that ended in Rust, successfully, while `flow` has
    /// not read its end: the moment a late success arrives. Two hold points make
    /// it, never a turn of the main actor (F-440): the job waits on its weak-file
    /// question until the test answers, and the sheet's next reading waits on the
    /// test's hold. Returns the release: the caller acts, then lets the sheet read.
    @MainActor
    static func endedUnseen(_ flow: FileFlow, _ folder: URL) async throws -> () -> Void {
        let real = FileFlow.pause
        let hold = Hold()
        let release = {
            hold.held = false
            FileFlow.pause = real
        }
        do {
            let weak = try weakFile(in: folder)
            flow.dropped([weak], encrypt: false)
            flow.type(.decrypt, "password")
            let answer = panels([folder.appending(path: "late.bin")])
            flow.decrypt()
            answer()
            let job = try #require(flow.job)
            for _ in 0..<3_000 where flow.question == nil { try await Task.sleep(for: .milliseconds(10)) }
            try #require(flow.question != nil, "the job asks")
            // The question is shown; the sheet's next reading waits from here on.
            FileFlow.pause = {
                await real()
                while hold.held {
                    hold.reached = true
                    try? await Task.sleep(for: .milliseconds(5))
                }
            }
            for _ in 0..<3_000 where !hold.reached { try await Task.sleep(for: .milliseconds(10)) }
            try #require(hold.reached, "the sheet's reading is held")
            flow.answerWeak(save: true)
            for _ in 0..<3_000 where !job.progress().finished { try await Task.sleep(for: .milliseconds(10)) }
            guard case .done = job.progress().end else {
                Issue.record("the job did not succeed: \(String(describing: job.progress().end))")
                throw CancellationError()
            }
            #expect(flow.job === job && flow.screen == .progress, "the sheet has not read the end")
        } catch {
            release()
            throw error
        }
        return release
    }
}
