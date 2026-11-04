import Darwin
import Foundation
import Testing
import os

/// F-125 (LD-228 (3)): the disk watch opens what it watches without
/// blocking, so a FIFO put at a vault's path does not hold its queue.
struct DiskWatchTests {
    @Test("F-125: a FIFO at the watched path does not hold the watch; a change in its folder is still seen")
    func f125FifoDoesNotHoldTheWatch() async throws {
        let folder = ParityDemo.temporaryDirectory.appending(path: "larsal-f125-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let fifo = folder.appending(path: "Personal.larsalvault").path(percentEncoded: false)
        #expect(mkfifo(fifo, 0o600) == 0)
        let looks = OSAllocatedUnfairLock(initialState: 0)
        let watch = DiskWatch(path: fifo) { _ in looks.withLock { $0 += 1 } }
        try await Task.sleep(for: .milliseconds(300))  // armed
        try Data("demo".utf8).write(to: folder.appending(path: "other.txt"))
        for _ in 0..<100 where looks.withLock({ $0 }) == 0 { try await Task.sleep(for: .milliseconds(50)) }
        let seen = looks.withLock { $0 }
        // A blocking open waits for a writer: this one frees the queue.
        let writer = open(fifo, O_RDWR | O_NONBLOCK)
        if writer >= 0 { close(writer) }
        #expect(seen > 0, "the folder change reached the watch")
        withExtendedLifetime(watch) {}
    }
}
