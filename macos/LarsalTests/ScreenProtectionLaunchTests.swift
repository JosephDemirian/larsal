import AppKit
import Testing

/// F-131 (LD-249 (3)): a window AppKit makes for Larsal (the text input window
/// a focused field brings, 500 × 500) is adopted as the window server
/// numbers it, inside its init, not one run loop pass later; a window Larsal
/// makes is deferred, so the window server has none for it until it is
/// ordered in.
extension ScreenProtectionTests {
    @Test("F-131: a window AppKit makes is protected as the window server numbers it, before its init returns")
    func f131AdoptedWhenNumbered() {
        let center = NotificationCenter()
        let protection = ScreenProtection()
        protection.windows = { [] }
        protection.start(allowCapture: false, center: center)
        // AppKit posts the notice on the default center; it reaches this
        // test's own protection only while this synchronous block runs, so
        // no other suite's window is touched.
        let forward = NotificationCenter.default.addObserver(
            forName: ScreenProtection.numbered, object: nil, queue: nil
        ) { center.post($0) }
        let window = NSWindow(contentRect: Self.frame, styleMask: [.titled], backing: .buffered, defer: false)
        NotificationCenter.default.removeObserver(forward)
        #expect(window.windowNumber > 0, "the window server has it")
        #expect(window.sharingType == .none, "protected before its init returned")
    }

    @Test("F-131: a window Larsal makes has no window server window until it is ordered in, and is protected first")
    func f131OwnWindowDeferred() {
        let window = ScreenProtection().window(Self.frame, style: [.titled])
        #expect(window.windowNumber <= 0, "deferred: the window server has no window for it yet")
        #expect(window.sharingType == .none)
    }

    /// The F-131 row's steps as a test: Larsal launched by `open -n -g -j` with
    /// LARSAL_TEST_HIDDEN, a throwaway HOME under /tmp and the debug snapshot,
    /// which renders the main view in a window never ordered in and focuses
    /// its unlock field, so AppKit makes its text input window. Larsal records
    /// its own windows' listing (`WindowListing`): from another process
    /// without screen capture access every window reads sharing 0. Metadata
    /// only, never pixels. Larsal reports its PID; only that PID is stopped.
    /// A window AppKit makes may list sharing 1 at 0 × 0 before its init
    /// returns (the row's residual); never with a size or on screen. Larsal's
    /// own window (the snapshot's, 1320 × 820) is deferred and never ordered
    /// in, so the window server has no window for it at all.
    @Test(
        "F-131: in a hidden launch Larsal's listing shows no capturable window with a size, on screen, or its own"
    )
    @concurrent nonisolated func f131HiddenLaunchListings() async throws {
        let products = try #require(Bundle.allBundles.first { $0.bundleURL.pathExtension == "xctest" })
            .bundleURL.deletingLastPathComponent()
        let dir = ParityDemo.temporaryDirectory.appending(path: "a-f131-\(getpid())")
        try? FileManager.default.removeItem(at: dir)
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: dir) }
        let vault = dir.appending(path: "v.larsalvault")
        let demo = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appending(path: "../../testdata/option-a-personal.larsalvault")
        try FileManager.default.copyItem(at: demo, to: vault)
        let shot = dir.appending(path: "shot.png")
        let env = [
            "LARSAL_TEST_HIDDEN=1", "LARSAL_TEST_INSTANCE_DIR=\(dir.path)", "HOME=\(dir.path)",
            "TMPDIR=\(dir.path)/", "CFFIXED_USER_HOME=\(dir.path)",
            "LARSAL_DEBUG_SNAPSHOT=\(shot.path)", "LARSAL_TEST_WINDOW_LISTING=1",
        ]
        let app = products.appending(path: "Larsal.app")
        let open = try Process.run(
            URL(fileURLWithPath: "/usr/bin/open"),
            arguments: ["-n", "-g", "-j"] + env.flatMap { ["--env", $0] } + [app.path, "--args", vault.path])
        open.waitUntilExit()
        #expect(open.terminationStatus == 0, "open launched Larsal")
        let file = dir.appending(path: WindowListing.listing)
        let read = { (try? String(contentsOf: file, encoding: .utf8))?.split(separator: "\n").map(String.init) ?? [] }
        var pid: Int32?
        let deadline = ContinuousClock.now + .seconds(45)
        while ContinuousClock.now < deadline, pid.map({ kill($0, 0) == 0 }) ?? true {
            pid = pid ?? read().first.flatMap { $0.firstMatch(of: /^pid (\d+),/).flatMap { Int32($0.1) } }
            try await Task.sleep(for: .milliseconds(50))
        }
        let executable = app.appending(path: "Contents/MacOS/Larsal").resolvingSymlinksInPath().path
        if let pid, kill(pid, 0) == 0, Self.executable(of: pid) == executable {
            Issue.record("Larsal did not end after its snapshot")
            kill(pid, SIGKILL)
        }
        #expect(pid != nil, "Larsal wrote its listing: \(read())")
        #expect(FileManager.default.fileExists(atPath: shot.path), "the snapshot ran, so its windows were made")
        Self.check(listing: read())
    }

    /// The listing's rules: started before the first window; Larsal's own
    /// window not in it; a window AppKit makes capturable only at 0 × 0;
    /// none on screen.
    nonisolated static func check(listing lines: [String]) {
        #expect(lines.first?.hasSuffix(", windows 0") == true, "the listing started before the first window")
        var listings: [Int: [String]] = [:]
        for line in lines.dropFirst() {
            let parts = line.split(separator: " ", maxSplits: 1).map(String.init)
            if parts.count == 2, let number = Int(parts[0]) { listings[number, default: []].append(parts[1]) }
        }
        #expect(!listings.isEmpty, "the text input window AppKit makes for the focused field is listed")
        for (number, lines) in listings {
            let own = lines.contains { $0.contains("[1320, 820]") }
            #expect(!own, "Larsal's own window \(number) is in the window server, so it can list sharing 1: \(lines)")
            for line in lines where !line.hasPrefix("sharing 0,") {
                #expect(line.hasPrefix("sharing 1, [0, 0],"), "window \(number) capturable with a size: \(lines)")
            }
            #expect(!lines.contains { $0.hasSuffix("on screen true") }, "window \(number) on screen: \(lines)")
        }
    }

    /// A process's executable path (no arguments, no environment).
    nonisolated static func executable(of pid: Int32) -> String {
        var path = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let count = Int(proc_pidpath(pid, &path, UInt32(path.count)))
        guard count > 0 else { return "" }
        let text = String(bytes: path.prefix(count), encoding: .utf8) ?? ""
        return URL(fileURLWithPath: text).resolvingSymlinksInPath().path
    }
}
