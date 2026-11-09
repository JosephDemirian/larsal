import AppKit
import LarsalCore
import SwiftUI
import Testing

extension FileSuites {
    /// E22-S4 round 3 (C1-05, C1-06, C1-08): the saved entry after a collision,
    /// the save panel of Decrypt, the space estimate and the unprotected-disk
    /// question, over the real Rust engine, demo files only; no panel is shown.
    @MainActor
    @Suite(.serialized)
    struct FileChoiceTests {
        init() { ParityDemo.setUp() }

        @Test("FIL-02-T06 C1-05: after a collision the saved entry is used again; a new generation, a new entry")
        func collisionReusesTheSavedEntry() async throws {
            let window = try ParityDemo.window("files-reuse")
            defer { window.lockAll() }
            let vault = try #require(window.main?.vault.id)
            let (folder, source) = try FileDemo.folder("reuse")
            try Data("demo sentinel".utf8).write(to: folder.appending(path: "Mountain photo.jpg.age"))
            let title = "File passphrase · Mountain photo.jpg"
            func entries() throws -> [FileKeyChoice] {
                try window.session.fileKeyChoices(vault: vault).filter { $0.title == title }
            }
            let flow = FileFlow(session: window.session, vault: (vault, "Personal"))
            flow.dropped([source])
            flow.encrypt()
            try await FileDemo.settled(flow)
            #expect(flow.screen == .collision)
            #expect(flow.savedKey, "the frame says Passphrase saved")
            let saved = try #require(flow.reuse, "the saved entry stays chosen")
            #expect(try entries().map(\.entry) == [saved.entry])
            // Choose Another Name…: the panel, then Encrypt with the saved entry, shown as chosen.
            let restore = FileDemo.panels([folder.appending(path: "Second.age")])
            defer { restore() }
            flow.chooseAnotherName()
            #expect(flow.screen == .encrypt && flow.reuse?.entry == saved.entry)
            let host = QrDemo.placed(NSHostingView(rootView: FileDialog(flow: flow)))
            host.layoutSubtreeIfNeeded()
            let texts = QrDemo.texts(host)
            #expect(texts.contains("Saved passphrase") && texts.contains(title), "\(texts)")
            #expect(FileDemo.buttons(host).contains("Use a New Passphrase"))
            flow.encrypt()
            #expect(flow.notice == nil, "never refused for an empty draft")
            try await FileDemo.settled(flow)
            #expect(flow.screen == .complete)
            #expect(try entries().count == 1, "no second entry")
            // The saved entry opens the second file.
            let back = FileFlow(session: window.session, vault: (vault, "Personal"))
            back.dropped([folder.appending(path: "Second.age")], encrypt: false)
            back.choose(try #require(try entries().first))
            let out = FileDemo.panels([folder.appending(path: "Back.jpg")])
            defer { out() }
            back.decrypt()
            try await FileDemo.settled(back)
            #expect(try Data(contentsOf: folder.appending(path: "Back.jpg")) == Data(contentsOf: source))
            // Use a New Passphrase: a new generation, a new entry.
            flow.screen = .encrypt
            flow.newPassphrase()
            #expect(flow.reuse == nil && flow.draft != nil)
            flow.name = "Third.age"
            flow.encrypt()
            try await FileDemo.settled(flow)
            #expect(flow.screen == .complete)
            #expect(try entries().count == 2, "a new generation is a new entry")
        }

        @Test("FIL-02-T11 C1-08: Save Readable File asks the save panel; only its answer is written, once")
        func decryptAsksThePanel() async throws {
            let window = try ParityDemo.window("files-panel")
            defer { window.lockAll() }
            let (folder, source) = try FileDemo.folder("panel")
            let phrase = "demo panel passphrase with many words in it"
            let sealed = try await FileDemo.sealed(window, source, phrase)
            let flow = FileFlow(session: window.session, vault: nil)
            flow.dropped([sealed], encrypt: false)
            flow.type(.decrypt, phrase)
            let none = FileDemo.panels([nil])
            flow.decrypt()
            none()
            #expect(flow.job == nil && flow.screen == .decrypt, "a cancelled panel writes nothing")
            #expect(flow.hasDecrypt, "the typed passphrase waits for the answer")
            let one = FileDemo.panels([folder.appending(path: "Chosen.jpg")])
            flow.decrypt()
            one()
            #expect(flow.name == "Chosen.jpg" && flow.job != nil)
            try await FileDemo.settled(flow)
            #expect(try Data(contentsOf: folder.appending(path: "Chosen.jpg")) == Data(contentsOf: source))
            #expect(!flow.confirmed, "the answer authorized that one output")
            // A destination the panel confirmed before is not asked again.
            let again = FileFlow(session: window.session, vault: nil)
            again.dropped([sealed], encrypt: false)
            let chosen = FileDemo.panels([folder.appending(path: "Before.jpg")])
            again.chooseDestination()
            chosen()
            #expect(again.confirmed)
            let empty = FileDemo.panels([])
            defer { empty() }
            again.type(.decrypt, phrase)
            again.decrypt()
            #expect(again.job != nil && again.name == "Before.jpg")
            try await FileDemo.settled(again)
            #expect(try FileDemo.names(folder).contains("Before.jpg"))
        }

        @Test("FIL-03-T12 C1-06: the free-space estimate warns in MSG-FILE-SPACE's words and refuses nothing")
        func spaceWarning() throws {
            let window = try ParityDemo.window("files-space")
            defer { window.lockAll() }
            let (folder, small) = try FileDemo.folder("space")
            let flow = FileFlow(session: window.session, vault: (window.main!.vault.id, "Personal"))
            flow.dropped([small])
            #expect(!flow.spaceShort)
            // A sparse demo file of 1 PiB: no disk here has that much free.
            for (file, encrypt) in [("Huge.bin", true), ("Huge.bin.age", false)] {
                let huge = folder.appending(path: file)
                _ = FileManager.default.createFile(atPath: huge.path, contents: nil)
                let handle = try FileHandle(forWritingTo: huge)
                try handle.truncate(atOffset: 1 << 50)
                try handle.close()
                defer { try? FileManager.default.removeItem(at: huge) }
                flow.dropped([huge], encrypt: encrypt)
                #expect(flow.spaceShort, "\(file)")
                let host = QrDemo.placed(NSHostingView(rootView: FileDialog(flow: flow)))
                host.layoutSubtreeIfNeeded()
                #expect(QrDemo.texts(host).contains { $0.contains(spaceWords) }, "\(file)")
                let action = encrypt ? "Encrypt File" : "Save Readable File"
                #expect(FileDemo.buttons(host).contains(action), "advisory: \(action) stays")
            }
            #expect(spaceWords == "There is not enough free space. Free some space or choose another disk.")
            flow.cancel()
        }

        @Test("FIL-03-T08 C1-06: the unprotected-disk question asks first, Cancel the default, in its frame's words")
        func unprotectedAsks() throws {
            let window = try ParityDemo.window("files-unprotected")
            defer { window.lockAll() }
            let flow = FileFlow(session: window.session, vault: nil)
            flow.asked(.askUnprotected(question: 1))
            #expect(flow.screen == .unprotectedFile && flow.question == 1)
            flow.asked(.askWeak(question: 2))
            #expect(flow.screen == .weakFile && flow.question == 2)
            flow.screen = .unprotectedFile
            let host = QrDemo.placed(NSHostingView(rootView: FileDialog(flow: flow)))
            host.layoutSubtreeIfNeeded()
            let texts = QrDemo.texts(host)
            for words in [
                "This disk cannot keep a decrypted file private",
                "Anyone who can use this disk may be able to read the saved file.",
                "The saved file is not encrypted. Choose another folder unless you trust this disk.",
            ] {
                #expect(texts.contains { $0.contains(words) }, "\(words)")
            }
            #expect(Set(["Cancel", "Save Readable File"]).isSubset(of: FileDemo.buttons(host)))
        }

        @Test("FIL-03-T08 C1R3-06: in the unprotected-disk frame Return is Cancel and writes nothing; Save writes")
        func unprotectedDefaultIsCancel() async throws {
            let window = try ParityDemo.window("files-unprotected-default")
            defer { window.lockAll() }
            let (folder, _) = try FileDemo.folder("unprotected-default")
            let weak = try FileDemo.weakFile(in: folder)
            // A real job waits on a question; the frame answers the number the sheet shows.
            for (press, writes) in [("Return", false), ("Save Readable File", true)] {
                let flow = FileFlow(session: window.session, vault: nil)
                flow.dropped([weak], encrypt: false)
                flow.type(.decrypt, "password")
                let answer = FileDemo.panels([folder.appending(path: "Readable.bin")])
                flow.decrypt()
                answer()
                for _ in 0..<3_000 where flow.question == nil { try await Task.sleep(for: .milliseconds(10)) }
                try #require(flow.question != nil, "the job asks")
                let host = QrDemo.placed(NSHostingView(rootView: FileUnprotectedFrame(flow: flow)))
                host.layoutSubtreeIfNeeded()
                try await Task.sleep(for: .milliseconds(150))
                host.layoutSubtreeIfNeeded()
                if press == "Return" {
                    let key = try QrDemo.key(36, "\r")
                    #expect(host.window?.performKeyEquivalent(with: key) == true, "Return is taken")
                } else {
                    let save = try #require(QrDemo.named(host, press).first, "\(press) is on screen")
                    #expect(save.accessibilityPerformPress?() == true)
                }
                try await FileDemo.settled(flow)
                #expect(try FileDemo.names(folder).contains("Readable.bin") == writes, "\(press)")
            }
        }

        @Test("FIL-02-T06 C1R3-04: after a collision in Choose My Own Passphrase, Choose Another Name goes back to it")
        func manualCollisionKeepsTyped() async throws {
            let window = try ParityDemo.window("files-manual-collision")
            defer { window.lockAll() }
            let (folder, source) = try FileDemo.folder("manual-collision")
            try Data("demo sentinel".utf8).write(to: folder.appending(path: "Mountain photo.jpg.age"))
            let flow = FileFlow(session: window.session, vault: nil)
            flow.dropped([source])
            flow.screen = .manual
            flow.saveManual = false
            let phrase = "demo manual collision passphrase with many words"
            flow.type(.passphrase, phrase)
            flow.type(.repeated, phrase)
            flow.useAnyway()
            try await FileDemo.settled(flow)
            #expect(flow.screen == .collision)
            let restore = FileDemo.panels([folder.appending(path: "Second.age")])
            defer { restore() }
            flow.chooseAnotherName()
            #expect(flow.screen == .manual, "back to the frame the work came from")
            #expect(flow.hasPassphrase && flow.hasRepeat, "the typed passphrase is kept")
            flow.useAnyway()
            try await FileDemo.settled(flow)
            #expect(flow.screen == .complete)
            #expect(!flow.hasPassphrase && !flow.hasRepeat, "gone once the work ended")
            // The kept text is the one typed: the second file opens with it.
            let back = FileFlow(session: window.session, vault: nil)
            back.dropped([folder.appending(path: "Second.age")], encrypt: false)
            back.type(.decrypt, phrase)
            let out = FileDemo.panels([folder.appending(path: "Back.jpg")])
            defer { out() }
            back.decrypt()
            try await FileDemo.settled(back)
            #expect(try Data(contentsOf: folder.appending(path: "Back.jpg")) == Data(contentsOf: source))
        }
    }
}

extension FileDemo {
    /// A published test file from another tool with a low work factor (passphrase
    /// "password"), in `folder`: its decrypt asks MSG-FILE-WEAK.
    static func weakFile(in folder: URL) throws -> URL {
        let vector = try Data(
            contentsOf: ParityDemo.root.appending(path: "crates/larsal-files/testdata/age-testkit/scrypt"))
        let blank = try #require(vector.range(of: Data("\n\n".utf8)))
        let file = folder.appending(path: "from another tool.bin")
        try vector[blank.upperBound...].write(to: file)
        return file
    }
}
