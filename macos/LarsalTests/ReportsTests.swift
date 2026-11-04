import AppKit
import LarsalCore
import SwiftUI
import Testing

/// The Reports frames of design/option-a/manifest.json (section `reports`,
/// E5-S7), light and dark.
enum ReportFrame: String, CaseIterable, CustomTestStringConvertible {
    case health = "reports-reports-health-check"
    case breach = "reports-reports-breach-check"
    case stats = "reports-reports-statistics"
    case passkeys = "reports-reports-passkeys"
    case browser = "reports-reports-browser"

    var testDescription: String { rawValue }

    var tab: ReportsModel.Tab {
        switch self {
        case .health: .health
        case .breach: .breach
        case .stats: .stats
        case .passkeys: .passkeys
        case .browser: .browser
        }
    }
}

/// Values a test saw, in order.
private final class Seen<Value> {
    var values: [Value] = []
}

/// Calls `note` on the main actor right after each change of the reports'
/// rating progress.
private func afterEachProgress(_ reports: ReportsModel, _ note: @escaping @MainActor @Sendable () -> Void) {
    withObservationTracking {
        _ = reports.progress
    } onChange: {
        Task { @MainActor in
            note()
            afterEachProgress(reports, note)
        }
    }
}

/// The Personal demo vault with the mockup's save time (08:50, the
/// sidebar's "Saved at" and the Statistics' "Last saved"), rated, with the
/// Reports screen open and computed. Nothing leaves this Mac: the breach
/// results are the frame's, set as the screen state (the online check
/// itself is tested in Rust with a fake service, reports.rs).
@MainActor
private func reportsWindow(_ folder: String, tab: ReportsModel.Tab = .health) async throws -> ReportsWindow {
    ParityDemo.setUp()
    let session = try ParityDemo.session()
    var ids: [UInt64] = []
    for index in 0..<3 {
        let path = try ParityDemo.path(index, folder: folder)
        if index == 0 {
            let saved = Date(timeIntervalSince1970: 1_793_093_400 - 100 * 60)
            try FileManager.default.setAttributes([.modificationDate: saved], ofItemAtPath: path)
        }
        ids.append(try session.open(path: path))
    }
    #expect(try session.unlock(vault: ids[0], password: "demo-pass-7", keyFile: nil) == .unlocked)
    try session.switchTo(vault: ids[0])
    let window = MainWindowModel(session: session)
    window.refresh()
    try ParityDemo.rate(window)
    let main = try #require(window.main)
    main.openReports(tab)
    let reports = try #require(main.reports)
    for _ in 0..<400 where reports.stats == nil { try await Task.sleep(for: .milliseconds(25)) }
    #expect(reports.health != nil && reports.stats != nil)
    return ReportsWindow(window: window, main: main, reports: reports)
}

/// The window, its vault's screen and the open Reports screen.
@MainActor
private struct ReportsWindow {
    let window: MainWindowModel
    let main: VaultModel
    let reports: ReportsModel
}

@MainActor
@Suite(.serialized)
struct ReportsTests {
    init() { ParityDemo.setUp() }

    @Test("Option A reports frame, offscreen, light and dark", arguments: ReportFrame.allCases)
    func frame(_ frame: ReportFrame) async throws {
        let open = try await reportsWindow("reports-\(frame.rawValue)", tab: frame.tab)
        let (window, main, reports) = (open.window, open.main, open.reports)
        if frame == .breach { reports.breach = .done(try mockupFindings(main)) }
        let shots = SnapshotTests()
        let size = NSRect(origin: .zero, size: CGSize(width: 1320, height: 820))
        let host = NSHostingView(rootView: MainWindow(model: window).frame(width: size.width, height: size.height))
        host.frame = size
        // Never ordered front (AGENTS.md rule 10).
        let offscreen = NSWindow(
            contentRect: size.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless], backing: .buffered,
            defer: false
        )
        offscreen.colorSpace = .sRGB
        offscreen.contentView = host
        for (folder, look) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            offscreen.appearance = NSAppearance(named: look)
            let png = try await shots.render(host)
            let out = ParityDemo.shotsDirectory.appending(path: "\(folder)/\(frame.rawValue).png")
            try FileManager.default.createDirectory(
                at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
            try png.write(to: out)
            #expect(png.count > 10_000, "\(out.path)")
            try shots.accessibilityTree(host).write(to: out.deletingPathExtension().appendingPathExtension("ax.json"))
        }
        offscreen.contentView = nil
        window.lockAll()
    }

    /// The frame's four findings (mockup.js `REPS.breach`), with the card's
    /// exposure words (FEA-06.9), checked at 10:28.
    private func mockupFindings(_ main: VaultModel) throws -> BreachReport {
        let rows = (try main.session.list(vault: main.vault.id, view: .all)).rows
        let finding = { (title: String, count: UInt64, words: String) throws -> BreachRow in
            BreachRow(entry: try #require(rows.first { $0.title == title }), count: count, exposure: words)
        }
        let findings = [
            try finding("Router admin", 214_876, "Seen 100,001 to 1,000,000 times"),
            try finding("Amazon", 18_442, "Seen 10,001 to 100,000 times"),
            try finding("eBay", 18_442, "Seen 10,001 to 100,000 times"),
            try finding("Reddit", 3_107, "Seen 1,001 to 10,000 times"),
        ]
        let checked = UInt32(rows.filter(\.hasPassword).count)
        return BreachReport(
            rows: findings, checked: checked, largest: 214_876, checkedAt: 1_793_093_400 - 120, error: nil,
            progress: BreachProgress(done: 17, total: 17, finished: true))
    }

    @Test("Parity reports-reports-health-check: Password health opens it; the tabs switch; another place closes it")
    func opensFromTheSidebar() async throws {
        ParityDemo.setUp()
        let model = try ParityDemo.window("reports-open")
        try ParityDemo.rate(model)
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Password health")
        let reports = try #require(main.reports)
        #expect(reports.tab == .health)
        try await screen.wait { reports.health != nil }
        await screen.settle()
        let strings = screen.strings()
        for text in ["Reports", "Health check", "Breach check", "Statistics", "Passkeys", "Browser", "Check again"] {
            #expect(strings.contains { $0.contains(text) }, "\(text)")
        }
        // LD-163 (4): the tab counts what the sidebar counts.
        #expect(reports.health?.rows.count == Int(main.sidebar?.attention ?? 0))
        // The tabs' row (the sidebar has a Passkeys item too).
        for tab in ReportsModel.Tab.allCases.reversed() {
            let node = try #require(
                screen.nodes().first { element in
                    let label = (element.accessibilityLabel?() ?? nil) ?? ""
                    let box = screen.box(element)
                    return (label == tab.rawValue || label.hasPrefix(tab.rawValue + ", ")) && box.minY > 130
                        && box.minY < 190 && box.minX > 260
                })
            #expect(node.accessibilityPerformPress?() == true)
            await screen.settle()
            #expect(reports.tab == tab)
        }
        try await screen.press("All entries")
        #expect(main.reports == nil)
    }

    @Test("Parity reports-reports-statistics: the progress note shows until the ratings are in (FEA-07.17)")
    func progressFirst() async throws {
        ParityDemo.setUp()
        let model = try ParityDemo.window("reports-progress")
        let main = try #require(model.main)
        main.openReports(.stats)
        let reports = try #require(main.reports)
        // Each progress value right after it is set, with whether the
        // statistics were still missing then (LD-137 (4)).
        let seen = Seen<(RateProgress?, Bool)>()
        afterEachProgress(reports) { seen.values.append((reports.progress, reports.stats == nil)) }
        let screen = Screen(model)
        host(screen)
        #expect(screen.strings().contains("Checking your passwords"))
        try await screen.wait { reports.stats != nil }
        await screen.settle()
        #expect(seen.values.contains { ($0.0?.total ?? 0) > 0 && $0.1 }, "progress before the statistics")
        #expect(!screen.strings().contains("Checking your passwords"))
        #expect(reports.progress == nil && reports.checkedAt != nil)
    }

    private func host(_ screen: Screen) { screen.host.layoutSubtreeIfNeeded() }

    @Test("Parity reports-reports-breach-check: the page starts at the consent text; nothing is sent until the press")
    func breachWaitsForThePress() async throws {
        let open = try await reportsWindow("reports-breach", tab: .breach)
        let (window, main, reports) = (open.window, open.main, open.reports)
        let screen = Screen(window)
        await screen.settle()
        #expect(reports.breach == .consent)
        #expect(try main.session.breachReport(vault: main.vault.id) == nil)
        // The button is there and enabled; this test never presses it: a
        // press would ask the real service (AGENTS.md rule 7).
        let button = try #require(screen.node("Check passwords online"))
        #expect(button.isAccessibilityEnabled?() != false)
        #expect(screen.strings().contains { $0.contains("Have I Been Pwned") })
        // Every other tab and Check again send nothing either.
        for tab in ReportsModel.Tab.allCases { reports.choose(tab) }
        reports.checkAgain()
        try await screen.wait { reports.progress == nil && reports.stats != nil }
        #expect(try main.session.breachReport(vault: main.vault.id) == nil)
        #expect(reports.breach == .consent)
    }

    @Test("Parity reports-reports-breach-check: Turn off drops the results; Change password opens the editor")
    func breachResults() async throws {
        let open = try await reportsWindow("reports-turn-off", tab: .breach)
        let (window, main, reports) = (open.window, open.main, open.reports)
        reports.breach = .done(try mockupFindings(main))
        let screen = Screen(window)
        await screen.settle()
        #expect(screen.node("Check with a downloaded list instead")?.isAccessibilityEnabled?() == false)
        try await screen.press("Change password of Router admin")
        #expect(main.editor?.view.title == "Router admin")
        #expect(reports.editedFromBreach == main.editor?.view.id)
        main.closeEditor()
        await screen.settle()
        try await screen.press("Turn off")
        #expect(reports.breach == .consent)
        #expect(screen.node("Check passwords online") != nil)
    }

    @Test("Parity reports-reports-browser: entries with site settings in title order, then the connected browsers")
    func browser() async throws {
        let open = try await reportsWindow("reports-browser", tab: .browser)
        let screen = Screen(open.window)
        await screen.settle()
        let titles = open.reports.browser?.rows.map(\.entry.title).sorted()
        #expect(titles == ["Amazon", "Figma", "GitHub", "Google"])
        let strings = screen.strings()
        #expect(strings.contains { $0.contains("Connected browsers: Firefox on MacBook (since Oct 12) · Safari") })
        for host in ["gist.github.com", "github.com", "www.amazon.com", "fill, no submit"] {
            #expect(strings.contains { $0.contains(host) }, "\(host)")
        }
    }

    @Test("FEA-06.12, AT-E07: a lock closes the reports and drops every report")
    func lockDropsTheReports() async throws {
        let open = try await reportsWindow("reports-lock", tab: .breach)
        let (window, main, reports) = (open.window, open.main, open.reports)
        reports.breach = .done(try mockupFindings(main))
        window.lock(main.vault.id)
        #expect(main.reports == nil)
        #expect(reports.health == nil && reports.stats == nil && reports.passkeys == nil && reports.browser == nil)
        #expect(reports.breach == .consent)
        #expect(window.main == nil)
    }

    @Test("FEA-05.18: Skip in Reports hides an entry; Show Skipped Entries lists it again")
    func skipInReports() async throws {
        let open = try await reportsWindow("reports-skip")
        let (main, reports) = (open.main, open.reports)
        let amazon = try #require(reports.health?.rows.first { $0.entry.title == "Amazon" })
        main.toggleSkipFromReport(amazon.entry.id)
        for _ in 0..<400 where reports.health?.anySkipped != true { try await Task.sleep(for: .milliseconds(25)) }
        #expect(reports.health?.rows.contains { $0.entry.title == "Amazon" } == false)
        reports.setShowSkipped(true)
        for _ in 0..<400 where reports.health?.rows.contains(where: { $0.excluded }) != true {
            try await Task.sleep(for: .milliseconds(25))
        }
        #expect(reports.health?.rows.first { $0.entry.title == "Amazon" }?.excluded == true)
    }

    @Test("Parity reports-reports-health-check: More opens the row menu (FEA-05.18); Skip in Reports hides the row")
    func rowMenu() async throws {
        let open = try await reportsWindow("reports-menu")
        let (window, reports) = (open.window, open.reports)
        let screen = Screen(window)
        await screen.settle()
        let first = try #require(reports.health?.rows.first)
        try await screen.press("More")
        #expect(reports.menu == first.entry.id)
        for item in ["Edit Entry", "Expire Now", "Skip in Reports", "Delete Entry"] {
            #expect(screen.node(item) != nil, "\(item)")
        }
        try await screen.press("Skip in Reports")
        #expect(reports.menu == nil)
        try await screen.wait { reports.health?.anySkipped == true }
        #expect(reports.health?.rows.contains { $0.entry.id == first.entry.id } == false)
    }

    @Test("Parity reports-reports-passkeys: Remove asks MI04-34, then the passkey leaves the report")
    func removePasskey() async throws {
        let open = try await reportsWindow("reports-passkeys", tab: .passkeys)
        let (window, main, reports) = (open.window, open.main, open.reports)
        #expect(reports.passkeys?.map(\.entry.title) == ["Apple Account", "GitHub", "Linear", "Mastodon"])
        let screen = Screen(window)
        await screen.settle()
        try await screen.press("Remove the passkey of Linear")
        #expect(main.dialog == .removePasskey(site: "linear.app"))
        try await screen.press("Remove Passkey")
        try await screen.wait { reports.passkeys?.count == 3 }
        #expect(reports.passkeys?.contains { $0.entry.title == "Linear" } == false)
    }

    @Test("LD-137, LD-139: an is:weak search runs again once the ratings are in")
    func weakSearchRunsAgain() async throws {
        ParityDemo.setUp()
        let model = try ParityDemo.window("reports-weak")
        let main = try #require(model.main)
        let id = main.vault.id
        // A cold cache: the screen thread rates nothing; the limit notice shows.
        main.setSearch("is:weak")
        #expect(main.sidebar?.attention == nil)
        #expect(main.notice == "A pattern in this search is not valid or is too large.")
        #expect(main.rows.isEmpty)
        #expect(try main.session.ratingProgress(vault: id).done == 0)
        // The background fill ends in rated(), which runs the search again.
        try ParityDemo.rate(model)
        let weak = (try main.session.list(vault: id, view: .weak)).rows.map(\.id)
        #expect(main.search == "is:weak" && main.notice == nil)
        #expect(Set(main.rows.map(\.id)) == Set(weak))
        #expect(!weak.isEmpty)
    }
}
