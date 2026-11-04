import Darwin
import Foundation
import Testing
import os

/// The Swift parts of card APP-09. These files are compiled into AppTests too
/// (target membership in the Xcode project).
struct PlatformTests {
    @Test("APP-09.23, APP-09.25: file URLs become paths in order; other URLs are ignored")
    func fileURLsBecomePaths() {
        let urls = [
            URL(fileURLWithPath: "/tmp/spec-app09/a.appvault"),
            URL(string: "app://open?file=/tmp/spec-app09/b.appvault")!,
            URL(fileURLWithPath: "/tmp/spec-app09/with space.appvault"),
        ]
        #expect(FileOpen.paths(urls) == ["/tmp/spec-app09/a.appvault", "/tmp/spec-app09/with space.appvault"])
        #expect(FileOpen.paths([URL(string: "https://example.org/")!]).isEmpty)
    }

    @Test("APP-09.26-a, AT-E06: a drop opens vault files only")
    func dropsOpenVaultFilesOnly() {
        let other = String([0x6B, 0x64, 0x62, 0x78].map { Character(Unicode.Scalar(UInt8($0))) }).uppercased()
        let urls = [
            URL(fileURLWithPath: "/tmp/spec-app09/b.appvault"),
            URL(fileURLWithPath: "/tmp/spec-app09/notes.txt"),
            URL(fileURLWithPath: "/tmp/spec-app09/c.\(other)"),
            URL(fileURLWithPath: "/tmp/spec-app09/no-extension"),
        ]
        #expect(FileOpen.droppedVaults(urls) == ["/tmp/spec-app09/b.appvault", "/tmp/spec-app09/c.\(other)"])
        #expect(FileOpen.droppedVaults([URL(fileURLWithPath: "/tmp/spec-app09/notes.txt")]).isEmpty)
    }

    /// APP-09.27 apart from the main actor (LD-249 (4)): the sources answer
    /// on the main queue, which the other suites keep busy under load. The
    /// wait, and the test's end, run off it, so the test ends itself well
    /// inside the time limit, whose overrun restarts the whole test process;
    /// the defaults come back only once every signal sent was seen, so one
    /// still on its way finds the signals ignored and cannot end the run.
    nonisolated struct Signals {
        @Test("APP-09.27-a, -b: SIGINT, SIGTERM and SIGQUIT quit; SIGHUP is ignored", .timeLimit(.minutes(1)))
        @concurrent func quitSignals() async throws {
            let seen = OSAllocatedUnfairLock(initialState: 0)
            await QuitSignals.install { seen.withLock { $0 += 1 } }
            let quitting = await QuitSignals.quitting
            kill(getpid(), SIGHUP)
            let deadline = ContinuousClock.now + .seconds(40)
            for (index, number) in quitting.enumerated() {
                kill(getpid(), number)
                while seen.withLock({ $0 }) <= index, ContinuousClock.now < deadline {
                    try await Task.sleep(for: .milliseconds(20))
                }
                #expect(seen.withLock { $0 } > index, "signal \(number)")
            }
            guard seen.withLock({ $0 }) == quitting.count else { return }
            for number in quitting + [SIGHUP] {
                signal(number, SIG_DFL)
            }
        }
    }
}
