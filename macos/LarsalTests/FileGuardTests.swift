import AppKit
import LarsalCore
import SwiftUI
import Testing

extension FileSuites {
    /// E22-S4 round 3 (C1-01 to C1-08, S2-01 to S2-05) in the Mac app, over the
    /// real Rust engine, demo files only; no panel is shown and only private
    /// named pasteboards are touched (AGENTS.md rule 10).
    @MainActor
    @Suite(.serialized)
    struct FileGuardTests {
        init() { ParityDemo.setUp() }

        @Test("FIL-02-T14 C1-01 S2-02: a quit while a decrypt runs replies after the cleanup; nothing readable stays")
        func quitWaitsForCleanup() async throws {
            #expect(FileFlow.quitWait == 30_000, "the bound, as the card states it")
            let window = try ParityDemo.window("files-quit")
            defer { window.lockAll() }
            // 256 MB of zeros, sparse: the decrypt lasts seconds, not a turn.
            let (folder, source) = try FileDemo.folder("quit", bytes: 256_000_000)
            defer { try? FileManager.default.removeItem(at: folder.deletingLastPathComponent()) }
            let phrase = "demo quit passphrase with many words in it"
            let sealed = try await FileDemo.sealed(window, source, phrase)
            // The moment inside the readable write is Rust's test (fil02_t14_c1_01,
            // with its test-only hold). Here the wiring holds at any moment before the
            // end: the quit comes in the turn whose reading says the job runs, so no
            // turn of the main actor decides it (F-440). A job over at that reading
            // is counted and tried again, never failed.
            var (quits, over) = (0, 0)
            for _ in 0..<5 where quits == 0 {
                let restore = FileDemo.panels([sealed, folder.appending(path: "Readable.jpg")])
                window.openFiles(encrypt: false)
                let flow = try #require(window.files)
                flow.type(.decrypt, phrase)
                flow.decrypt()
                restore()
                let job = try #require(flow.job)
                guard !job.progress().finished else {
                    over += 1
                    try await FileDemo.settled(flow)
                    try? FileManager.default.removeItem(at: folder.appending(path: "Readable.jpg"))
                    window.files = nil
                    continue
                }
                quits += 1
                var replies: [Bool] = []
                var atReply: (finished: Bool, names: [String])?
                let answer = window.quitReply(asks: false) { may in
                    atReply = (job.progress().finished, (try? FileDemo.names(folder)) ?? [])
                    replies.append(may)
                }
                #expect(answer == .terminateLater, "the quit waits for the file job")
                for _ in 0..<6_000 where replies.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
                try await FileDemo.settled(flow)
                #expect(replies == [true], "one reply, and it lets the quit go on")
                #expect(atReply?.finished == true, "the reply came after the job ended")
                #expect(atReply?.names == ["Mountain photo.jpg", "Mountain photo.jpg.age"], "nothing readable stays")
                guard case .failed(let id, _, _) = job.progress().end else {
                    Issue.record("the quit did not stop the decrypt: \(String(describing: job.progress().end))")
                    return
                }
                #expect(id == "MSG-FILE-CANCELLED")
            }
            #expect(quits >= 1, "a quit came before the end (\(over) tries were over first)")
        }

        @Test("FIL-02-T03 S2-01: the shown passphrase is in the no-copy field: no selection, no copy, ⌘C too")
        func shownCannotBeCopied() throws {
            let window = try ParityDemo.window("files-nocopy")
            defer { window.lockAll() }
            let (_, source) = try FileDemo.folder("nocopy")
            let flow = FileFlow(session: window.session, vault: (window.main!.vault.id, "Personal"))
            flow.dropped([source])
            flow.toggleShow()
            let phrase = try #require(flow.shown)
            let host = QrDemo.placed(NSHostingView(rootView: FileDialog(flow: flow)))
            host.layoutSubtreeIfNeeded()
            let field = try #require(Self.find(NoCopyTextField.self, in: host), "the shown value's field")
            #expect(field.stringValue == phrase)
            #expect(!field.isEditable && !field.isSelectable && !field.acceptsFirstResponder)
            _ = field.window?.makeFirstResponder(field)
            #expect(field.window?.firstResponder !== field && field.currentEditor() == nil, "never focused or selected")
            // ⌘C: the key reaches the field and nothing takes the value out.
            let board = NSPasteboard(name: .init("larsal-test-\(UUID().uuidString)"))
            defer { board.releaseGlobally() }
            let before = board.changeCount
            let key = try #require(
                NSEvent.keyEvent(
                    with: .keyDown, location: .zero, modifierFlags: .command, timestamp: 0,
                    windowNumber: field.window?.windowNumber ?? 0, context: nil, characters: "c",
                    charactersIgnoringModifiers: "c", isARepeat: false, keyCode: 8))
            #expect(!field.performKeyEquivalent(with: key))
            // The editor its cell would hand out writes to no pasteboard and refuses Copy.
            let editor = try #require(field.cell?.fieldEditor(for: field) as? NoCopyEditor)
            editor.string = phrase
            editor.selectAll(nil)
            #expect(!editor.writeSelection(to: board, types: [.string]))
            let copy = NSMenuItem(title: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
            #expect(!editor.validateUserInterfaceItem(copy))
            #expect(board.changeCount == before && board.string(forType: .string) == nil)
            editor.string = ""
            flow.cancel()
        }

        @Test("S2-04: typed passphrases go to Rust on each change; the flow keeps no copy")
        func typedStaysInRust() throws {
            let window = try ParityDemo.window("files-typed")
            defer { window.lockAll() }
            let (_, source) = try FileDemo.folder("typed")
            let flow = FileFlow(session: window.session, vault: (window.main!.vault.id, "Personal"))
            flow.dropped([source])
            let secret = "demo-typed-secret-77"
            flow.type(.passphrase, secret)
            flow.type(.repeated, secret)
            flow.type(.decrypt, secret)
            #expect(flow.hasPassphrase && flow.hasRepeat && flow.hasDecrypt)
            #expect(!Self.holds(flow, secret), "no Swift property holds the typed text")
            flow.type(.passphrase, "")
            #expect(!flow.hasPassphrase)
            flow.cancel()
            #expect(!flow.hasRepeat && !flow.hasDecrypt)
        }

        @Test("FIL-02-T10 C1R3-03: Decrypt with a chosen key file takes its passphrase from the typed field")
        func typedKeyFile() async throws {
            let window = try ParityDemo.window("files-key-file")
            defer { window.lockAll() }
            let (folder, _) = try FileDemo.folder("key-file")
            let data = ParityDemo.root.appending(path: "crates/larsal-ffi/testdata")
            let flow = FileFlow(session: window.session, vault: nil)
            flow.dropped([data.appending(path: "to-key-a")], encrypt: false)
            let restore = FileDemo.panels([data.appending(path: "weak-key-file"), folder.appending(path: "Plain.txt")])
            defer { restore() }
            flow.chooseKeyFile()
            #expect(flow.credential == .fileKey)
            flow.type(.decrypt, "demo key file pass")
            flow.decrypt()
            #expect(!flow.hasDecrypt, "the typed text went to the job")
            // The key file's work factor is low: it asks first (C2R2-06); Save goes on.
            for _ in 0..<3_000 where flow.question == nil { try await Task.sleep(for: .milliseconds(10)) }
            #expect(flow.screen == .weakFile)
            flow.answerWeak(save: true)
            try await FileDemo.settled(flow)
            #expect(flow.screen == .complete)
            let plain = try Data(contentsOf: folder.appending(path: "Plain.txt"))
            #expect(plain == Data("demo payload for the file vectors\n".utf8))
        }

        @Test("S2-05: leaving Encrypt for Choose My Own Passphrase or Recipients drops the shown passphrase")
        func shownDroppedOnLeaving() throws {
            let window = try ParityDemo.window("files-leave")
            defer { window.lockAll() }
            let (_, source) = try FileDemo.folder("leave")
            let flow = FileFlow(session: window.session, vault: (window.main!.vault.id, "Personal"))
            flow.dropped([source])
            for (button, next) in [("Choose My Own Passphrase…", FileFlow.Screen.manual), ("Recipients", .recipients)] {
                flow.screen = .encrypt
                flow.toggleShow()
                let phrase = try #require(flow.shown)
                let host = QrDemo.placed(NSHostingView(rootView: FileDialog(flow: flow)))
                host.layoutSubtreeIfNeeded()
                let element = try #require(QrDemo.named(host, button).first, "\(button) is on screen")
                #expect(element.accessibilityPerformPress?() == true, "\(button) takes a press")
                #expect(flow.screen == next)
                #expect(flow.shown == nil, "\(button): the Swift copy is gone")
                #expect(!Self.holds(flow, phrase))
            }
            flow.cancel()
        }

        /// A view of `kind` under `root`.
        static func find<T: NSView>(_ kind: T.Type, in root: NSView) -> T? {
            if let hit = root as? T { return hit }
            for child in root.subviews { if let hit = find(kind, in: child) { return hit } }
            return nil
        }

        /// Whether any stored property of `flow`, two levels deep, holds `text`.
        static func holds(_ flow: FileFlow, _ text: String) -> Bool {
            func walk(_ value: Any, _ depth: Int) -> Bool {
                if let string = value as? String, string.contains(text) { return true }
                guard depth < 3 else { return false }
                return Mirror(reflecting: value).children.contains { walk($0.value, depth + 1) }
            }
            return walk(flow, 0)
        }
    }
}

extension FileDemo {
    /// `source` encrypted with `phrase` next to it, by the sheet's own path; the
    /// main actor is given back while it runs.
    @MainActor
    static func sealed(_ window: MainWindowModel, _ source: URL, _ phrase: String) async throws -> URL {
        let flow = FileFlow(session: window.session, vault: nil)
        flow.dropped([source])
        flow.screen = .manual
        flow.saveManual = false
        flow.type(.passphrase, phrase)
        flow.type(.repeated, phrase)
        flow.useAnyway()
        let job = try #require(flow.job)
        for _ in 0..<30_000 where !job.progress().finished { try await Task.sleep(for: .milliseconds(10)) }
        guard case .done = job.progress().end else {
            Issue.record("the demo file was not encrypted: \(String(describing: job.progress().end))")
            return source
        }
        return source.appendingPathExtension("age")
    }
}
