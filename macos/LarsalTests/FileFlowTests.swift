import AppKit
import LarsalCore
import SwiftUI
import Testing

/// Encrypt File and Decrypt File (FIL-02, E22-S4) over the real Rust engine,
/// with demo files only. No panel is shown: `FileFlow.choose` answers.
enum FileDemo {
    /// A fresh folder under target/ with one demo file in it: at most 4 KB written
    /// once, the rest sparse, so making it is a moment's work on any actor (F-440).
    static func folder(_ name: String, bytes: Int = 4_096, file: String = "Mountain photo.jpg") throws -> (URL, URL) {
        let top = ParityDemo.root.appending(path: "target/option-a/files-" + name)
        try? FileManager.default.removeItem(at: top)
        let place = top.appending(path: "Documents")
        try FileManager.default.createDirectory(at: place, withIntermediateDirectories: true)
        let source = place.appending(path: file)
        try Data(repeating: 0x5A, count: min(bytes, 4_096)).write(to: source)
        if bytes > 4_096 {
            let handle = try FileHandle(forWritingTo: source)
            try handle.truncate(atOffset: UInt64(bytes))
            try handle.close()
        }
        return (place, source)
    }

    /// The names in `folder`, hidden ones included, sorted.
    static func names(_ folder: URL) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: folder.path(percentEncoded: false)).sorted()
    }

    /// After a stop: the folder holds the source only, no output and no
    /// staging folder.
    @MainActor
    static func onlySource(_ folder: URL, _ flow: FileFlow) throws {
        let left = try names(folder)
        #expect(left == ["Mountain photo.jpg"], "left \(left), end \(String(describing: flow.end))")
    }

    /// The stop reached the job: it ended cancelled, not done before the stop.
    @MainActor
    static func cancelled(_ flow: FileFlow) {
        guard case .failed(let id, _, _) = flow.end else {
            Issue.record("the job was not stopped: \(String(describing: flow.end))")
            return
        }
        #expect(id == "MSG-FILE-CANCELLED")
    }

    /// Nothing of this test's folder was handed to another app. Tests run side
    /// by side and share the fake opener, so only this folder is looked at.
    @MainActor
    static func openedNothing(in folder: URL) {
        let mine = folder.deletingLastPathComponent().path(percentEncoded: false)
        #expect(!FakeOpener.opened.contains { $0.path(percentEncoded: false).hasPrefix(mine) })
    }

    /// The name of every button and menu button under `root`, as VoiceOver reads it.
    static func buttons(_ root: NSView) -> [String] {
        var out: [String] = []
        func walk(_ any: Any, _ depth: Int) {
            let element = any as AnyObject
            guard depth < 80 else { return }
            let role = element.accessibilityRole?() ?? nil
            if role == .button || role == .menuButton, let name = element.accessibilityLabel?() ?? nil {
                out.append(name)
            }
            for child in element.accessibilityChildren?() ?? [] { walk(child, depth + 1) }
        }
        walk(root, 0)
        return out
    }

    /// Answers the panels with `answers`, in order; restores the real ones.
    @MainActor
    static func panels(_ answers: [URL?]) -> () -> Void {
        let real = FileFlow.choose
        let left = Answers(answers)
        FileFlow.choose = { _ in left.next() }
        return { FileFlow.choose = real }
    }

    /// The panels' answers, in order.
    final class Answers {
        private var left: [URL?]
        init(_ answers: [URL?]) { left = answers }
        func next() -> URL? { left.isEmpty ? nil : left.removeFirst() }
    }

    /// Waits until the flow's job ended.
    @MainActor
    static func settled(_ flow: FileFlow) async throws {
        for _ in 0..<3_000 where flow.job != nil { try await Task.sleep(for: .milliseconds(10)) }
        #expect(flow.job == nil)
    }
}

/// Every file suite in one serialized tree: a file job is one per process
/// (FIL-02.17) and the panels seam `FileFlow.choose` is process-wide, so no
/// file test may run beside another (the F-440 lesson).
@MainActor
@Suite(.serialized)
enum FileSuites {}

extension FileSuites {
    @MainActor
    @Suite(.serialized)
    struct FileFlowTests {
        init() { ParityDemo.setUp() }

        @Test(
            "FIL-02-T01: with every vault locked Encrypt shows the unlock frame and writes nothing; Decrypt stays open"
        )
        func lockedApp() async throws {
            let window = try ParityDemo.window("files-t01", unlocked: [])
            let (folder, source) = try FileDemo.folder("t01")
            let restore = FileDemo.panels([source])
            defer { restore() }
            window.openFiles(encrypt: true)
            let flow = try #require(window.files)
            #expect(flow.screen == .locked)
            #expect(flow.draft == nil)
            flow.cancel()
            #expect(window.files == nil)
            #expect(try FileDemo.names(folder) == ["Mountain photo.jpg"])
            let again = FileDemo.panels([source])
            defer { again() }
            window.openFiles(encrypt: false)
            #expect(window.files?.screen == .decrypt)
        }

        @Test("FIL-02-T02: the drop target takes one regular file; two files, a folder and a link are refused in place")
        func dropTarget() throws {
            let window = try ParityDemo.window("files-t02")
            let (folder, source) = try FileDemo.folder("t02")
            let link = folder.appending(path: "link.jpg")
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: source)
            let flow = FileFlow(session: window.session, vault: (window.main!.vault.id, "Personal"))
            for refused in [[source, source], [folder], [link], [URL(string: "https://example.invalid/a.jpg")!]] {
                flow.dropped(refused)
                #expect(flow.screen == .entry)
                #expect(flow.notice == FileFlow.inputWords)
                #expect(flow.source == nil)
            }
            flow.dropped([source])
            #expect(flow.screen == .encrypt)
            #expect(flow.notice == nil)
            #expect(flow.name == "Mountain photo.jpg.age")
            FileDemo.openedNothing(in: folder)
        }

        @Test("FIL-02-T03: the generated passphrase is masked; only Show brings it, Hide drops it, Cancel forgets it")
        func generatedIsMasked() throws {
            let window = try ParityDemo.window("files-t03")
            let (_, source) = try FileDemo.folder("t03")
            let flow = FileFlow(session: window.session, vault: (window.main!.vault.id, "Personal"))
            flow.dropped([source])
            #expect(flow.shown == nil)
            let host = NSHostingView(rootView: FileDialog(flow: flow))
            _ = QrDemo.placed(host)
            flow.toggleShow()
            let phrase = try #require(flow.shown)
            #expect(phrase.split(separator: " ").count == 10)
            flow.toggleShow()
            #expect(flow.shown == nil)
            host.layoutSubtreeIfNeeded()
            #expect(!QrDemo.texts(host).contains { $0.contains(phrase) })
            let draft = try #require(flow.draft)
            flow.cancel()
            #expect(draft.show() == nil)
        }

        @Test(
            "FIL-02-T05 FIL-02-T06 FIL-02-T11: the generated passphrase is saved first, opens the file, opens nothing"
        )
        func roundTrip() async throws {
            let window = try ParityDemo.window("files-t05")
            let (folder, source) = try FileDemo.folder("t05", bytes: 300_000)
            let flow = FileFlow(session: window.session, vault: (window.main!.vault.id, "Personal"))
            flow.dropped([source])
            flow.toggleShow()
            let phrase = try #require(flow.shown)
            flow.encrypt()
            #expect(flow.shown == nil)
            try await FileDemo.settled(flow)
            #expect(flow.screen == .complete)
            #expect(flow.savedTo == "Documents / Mountain photo.jpg.age")
            let saved = try window.session.fileKeyChoices(vault: window.main!.vault.id)
            #expect(saved.contains { $0.title == "File passphrase · Mountain photo.jpg" && $0.recipient == nil })
            // Decrypt with the typed passphrase into a new name.
            let back = FileFlow(session: window.session, vault: nil)
            back.dropped([folder.appending(path: "Mountain photo.jpg.age")], encrypt: false)
            #expect(back.screen == .decrypt)
            #expect(back.name == "Mountain photo.jpg")
            // FIL-02.11: Save Readable File asks the save panel; its answer is the one output.
            let restore = FileDemo.panels([folder.appending(path: "Readable.jpg")])
            defer { restore() }
            back.type(.decrypt, phrase)
            #expect(back.hasDecrypt)
            back.decrypt()
            #expect(!back.hasDecrypt)
            #expect(back.name == "Readable.jpg")
            try await FileDemo.settled(back)
            #expect(back.screen == .complete)
            #expect(try Data(contentsOf: folder.appending(path: "Readable.jpg")) == Data(contentsOf: source))
            FileDemo.openedNothing(in: folder)
        }

        @Test("FIL-02-T07: a typed passphrase needs its repeat; a weak one asks with Cancel as the default")
        func manualPassphrase() async throws {
            let window = try ParityDemo.window("files-t07")
            let (folder, source) = try FileDemo.folder("t07")
            let flow = FileFlow(session: window.session, vault: (window.main!.vault.id, "Personal"))
            flow.dropped([source])
            flow.screen = .manual
            flow.type(.passphrase, "short")
            flow.type(.repeated, "shorts")
            flow.encrypt()
            #expect(flow.notice == "The passphrases do not match.")
            flow.type(.repeated, "short")
            flow.notice = nil
            flow.encrypt()
            #expect(flow.manualWeak)
            #expect(flow.job == nil)
            #expect(try FileDemo.names(folder) == ["Mountain photo.jpg"])
            flow.saveManual = false
            let host = NSHostingView(rootView: FileDialog(flow: flow))
            _ = QrDemo.placed(host)
            let texts = QrDemo.texts(host)
            #expect(texts.contains { $0.contains("Losing this passphrase means losing this file.") })
            #expect(texts.contains { $0.contains("This passphrase may be easy to guess.") })
            let vault = window.main!.vault.id
            let before = try window.session.fileKeyChoices(vault: vault).count
            flow.useAnyway()
            try await FileDemo.settled(flow)
            #expect(flow.screen == .complete)
            // C2R5-01, FIL-02.7: with Save in vault off, no entry is added.
            #expect(try window.session.fileKeyChoices(vault: vault).count == before)
        }

        @Test("FIL-02-T08: Encrypt for recipients waits for a valid key and both checks")
        func recipients() async throws {
            let window = try ParityDemo.window("files-t08")
            let (_, source) = try FileDemo.folder("t08")
            let flow = FileFlow(session: window.session, vault: (window.main!.vault.id, "Personal"))
            flow.dropped([source])
            flow.mode = .recipients
            flow.recipientDraft = "age1notakey"
            flow.addRecipient()
            #expect(flow.recipients.isEmpty)
            #expect(flow.notice != nil)
            await flow.createKey()
            #expect(flow.recipients.count == 1)
            #expect(!flow.recipientsReady)
            flow.checkedWithOwner = true
            #expect(!flow.recipientsReady)
            flow.mayNotDecrypt = true
            #expect(flow.recipientsReady)
            flow.encrypt()
            try await FileDemo.settled(flow)
            #expect(flow.screen == .complete)
        }
    }
}
