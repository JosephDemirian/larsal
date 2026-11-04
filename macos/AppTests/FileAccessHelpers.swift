import Darwin
import Foundation
import Testing
import os

/// The FileAccess seam for the Personal demo vault in one test's folder:
/// dataless until the test says so, the downloads started, the tick's
/// read (`probe`) and the thread's fetch policy it ran under, and whether
/// any of it ran on the main thread. Every other file gets the system.
nonisolated final class FakeFiles: Sendable {
    struct State {
        var dataless = true
        var probe: Int32 = 0
        var downloads = 0
        var policy: Int32 = -1
        var onMain = false
    }

    let state = OSAllocatedUnfairLock(initialState: State())

    init(_ folder: String) {
        let system = FileAccess.Files.system
        let mine: @Sendable (String) -> Bool = { $0.hasSuffix("/\(folder)/Personal.appvault") }
        let state = state
        FileAccess.files.withLock {
            $0 = FileAccess.Files(
                dataless: { path in
                    guard mine(path) else { return system.dataless(path) }
                    return state.withLock { now in
                        now.onMain = now.onMain || Thread.isMainThread
                        return now.dataless
                    }
                },
                download: { path in
                    guard mine(path) else { return system.download(path) }
                    state.withLock { now in
                        now.onMain = now.onMain || Thread.isMainThread
                        now.downloads += 1
                    }
                },
                probe: { path in
                    guard mine(path) else { return system.probe(path) }
                    let policy = getiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD)
                    return state.withLock { now in
                        now.onMain = now.onMain || Thread.isMainThread
                        now.policy = policy
                        return now.probe
                    }
                })
        }
    }

    func remove() { FileAccess.files.withLock { $0 = .system } }
}

extension ParitySavingTests {
    /// The coordinated accesses of `kind` recorded for `Personal.appvault`
    /// or its Save As copy `Copy.appvault` in the test's `folder`.
    func accessCount(_ kind: FileAccess.Kind, _ folder: String) -> Int {
        FileAccess.accesses.withLock { $0 ?? [] }.filter { seen in
            seen.kind == kind && ["Personal", "Copy"].contains { seen.path.hasSuffix("/\(folder)/\($0).appvault") }
        }.count
    }

    /// T72: `run` makes exactly one coordinated access of `kind` more; it
    /// waits up to 10 s for it.
    func oneAccess(
        _ kind: FileAccess.Kind, _ folder: String, _ step: String, _ run: () async throws -> Void
    ) async throws {
        let before = accessCount(kind, folder)
        try await run()
        for _ in 0..<400 where accessCount(kind, folder) == before { try await Task.sleep(for: .milliseconds(25)) }
        #expect(accessCount(kind, folder) == before + 1, "\(step)")
    }
}

/// A file presenter in another process (T72): a small helper the test
/// compiles and starts. It says what it is told, one word a line, and on
/// `write <file>` writes that file's bytes over the vault in place, in a
/// coordinated write: half, "writing", 2 s, the rest, "wrote".
final class OtherProcess {
    private let process = Process()
    private let input = Pipe()
    private let heard = OSAllocatedUnfairLock(initialState: "")
    private let folder = FileManager.default.temporaryDirectory.appending(path: "app-presenter-\(UUID().uuidString)")

    init(presenting path: String) async throws {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let source = folder.appending(path: "presenter.swift").path(percentEncoded: false)
        let program = folder.appending(path: "presenter").path(percentEncoded: false)
        try Self.source.write(toFile: source, atomically: true, encoding: .utf8)
        let built = await Task.detached { () -> Int32 in
            let compile = Process()
            compile.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
            compile.arguments = ["swiftc", "-o", program, source]
            compile.environment = ProcessInfo.processInfo.environment.merging(
                ["DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer"]) { set, _ in set }
            guard (try? compile.run()) != nil else { return -1 }
            compile.waitUntilExit()
            return compile.terminationStatus
        }.value
        try #require(built == 0, "the helper compiled")
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: program)
        process.arguments = [path]
        process.standardInput = input
        process.standardOutput = output
        let heard = heard
        output.fileHandleForReading.readabilityHandler = { handle in
            let text = String(bytes: handle.availableData, encoding: .utf8) ?? ""
            heard.withLock { $0 += text }
        }
        try process.run()
        for _ in 0..<400 where !said("ready") { try await Task.sleep(for: .milliseconds(25)) }
        try #require(said("ready"), "the helper presents the vault file")
        try await Task.sleep(for: .milliseconds(500))
    }

    func said(_ word: String) -> Bool { heard.withLock { $0.split(separator: "\n").contains(Substring(word)) } }

    func send(_ line: String) { input.fileHandleForWriting.write(Data((line + "\n").utf8)) }

    /// Ends the helper (it exits when its input closes), by its own PID only.
    func stop() {
        try? input.fileHandleForWriting.close()
        for _ in 0..<100 where process.isRunning { usleep(20_000) }
        if process.isRunning { process.terminate() }
        try? FileManager.default.removeItem(at: folder)
    }

    private static let source = #"""
        import Foundation

        final class Presenter: NSObject, NSFilePresenter {
            let presentedItemURL: URL?
            let presentedItemOperationQueue = OperationQueue()
            init(_ url: URL) { presentedItemURL = url }
            func relinquishPresentedItem(toReader reader: @escaping @Sendable ((@Sendable () -> Void)?) -> Void) {
                say("read")
                reader(nil)
            }
            func relinquishPresentedItem(toWriter writer: @escaping @Sendable ((@Sendable () -> Void)?) -> Void) {
                say("write")
                writer(nil)
            }
            func presentedItemDidChange() { say("changed") }
        }

        func say(_ word: String) { FileHandle.standardOutput.write(Data((word + "\n").utf8)) }

        let url = URL(fileURLWithPath: CommandLine.arguments[1])
        let presenter = Presenter(url)
        NSFileCoordinator.addFilePresenter(presenter)
        say("ready")
        Thread.detachNewThread {
            while let line = readLine() {
                let file = String(line.dropFirst(6))
                guard line.hasPrefix("write "), let bytes = FileManager.default.contents(atPath: file) else { continue }
                let coordinator = NSFileCoordinator(filePresenter: presenter)
                coordinator.coordinate(writingItemAt: url, options: [], error: nil) { at in
                    guard let handle = try? FileHandle(forWritingTo: at) else { return }
                    try? handle.truncate(atOffset: 0)
                    try? handle.write(contentsOf: bytes.prefix(bytes.count / 2))
                    try? handle.synchronize()
                    say("writing")
                    Thread.sleep(forTimeInterval: 2)
                    try? handle.write(contentsOf: bytes.dropFirst(bytes.count / 2))
                    try? handle.close()
                }
                say("wrote")
            }
            exit(0)
        }
        RunLoop.main.run()
        """#
}
