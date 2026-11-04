import AppCore
import Foundation
import Observation

/// The Reports screen of one vault (E5-S7, mockup `reportsView`): Health
/// Check, the opt-in breach check, Statistics, Passkeys and Browser. Every
/// number comes from Rust (reports.rs over app-core); rows hold entry ids,
/// titles, ratings, counts and reasons, never a secret (AGENTS.md rule 4).
/// The work runs off the screen thread with progress, and a lock or close
/// cancels it and drops every report (FEA-05.18, FEA-06.12, FEA-07.17).
@Observable
final class ReportsModel {
    /// The tabs (mockup `REP`).
    enum Tab: String, CaseIterable {
        case health = "Health check"
        case breach = "Breach check"
        case stats = "Statistics"
        case passkeys = "Passkeys"
        case browser = "Browser"
    }

    /// One computation's reports.
    private struct Computed {
        let health: HealthReport
        let stats: StatsReport
        let passkeys: [PasskeyRow]
        let browser: BrowserReport
    }

    /// The breach page (FEA-06): the consent text until the user presses
    /// "Check passwords online", the progress, then the results.
    enum Breach: Equatable {
        case consent
        case running(BreachProgress)
        case done(BreachReport)
    }

    let session: Session
    let vault: VaultInfo
    private(set) var tab: Tab
    /// The rating cache's progress while Health Check and Statistics wait
    /// for it (LD-137 (4)); `nil` once they are in.
    private(set) var progress: RateProgress?
    /// When the reports were last computed (the title row's "checked at").
    private(set) var checkedAt: Date?
    private(set) var health: HealthReport?
    private(set) var stats: StatsReport?
    private(set) var passkeys: [PasskeyRow]?
    private(set) var browser: BrowserReport?
    var breach = Breach.consent
    /// `SET-HC-SHOW-EXCLUDED` "Show Skipped Entries": off each time the
    /// report opens, never saved (FEA-05.15).
    private(set) var showSkipped = false
    /// The entry whose row menu is open (the ⋯ of a Health check row).
    var menu: String?
    /// The entry whose passkey the Remove question is about (INT-04.46).
    var passkeyTarget: String?
    /// The entry opened from the breach results (FEA-06.11).
    @ObservationIgnored var editedFromBreach: String?
    @ObservationIgnored private var work: Task<Void, Never>?
    @ObservationIgnored private var breachWork: Task<Void, Never>?
    @ObservationIgnored private let offset = Int32(TimeZone.current.secondsFromGMT())

    init(session: Session, vault: VaultInfo, tab: Tab = .health) {
        self.session = session
        self.vault = vault
        self.tab = tab
        refresh()
    }

    /// FEA-07.17: Statistics are computed each time their tab opens.
    func choose(_ next: Tab) {
        let again = next == .stats && tab != .stats
        tab = next
        if again { refresh() }
    }

    func setShowSkipped(_ shown: Bool) {
        showSkipped = shown
        refresh()
    }

    /// Computes every report off the screen thread: first the rating cache
    /// in small steps with progress, then the reports from it. A lock stops
    /// the steps (Rust answers `Locked`); `close` cancels them.
    func refresh() {
        work?.cancel()
        let (session, id, offset, skipped) = (session, vault.id, offset, showSkipped)
        work = Task { [weak self] in
            while !Task.isCancelled {
                let step = await Task.detached { () -> (Bool, RateProgress)? in
                    guard let done = try? session.rate(vault: id, max: 25, utcOffset: offset),
                        let progress = try? session.ratingProgress(vault: id)
                    else { return nil }
                    return (done, progress)
                }.value
                guard let step, !Task.isCancelled else { return }
                if self?.health == nil || self?.progress != nil { self?.progress = step.1 }
                if step.0 { break }
            }
            let reports = await Task.detached { () -> Computed? in
                guard let health = try? session.healthReport(vault: id, showSkipped: skipped, utcOffset: offset),
                    let stats = try? session.statisticsReport(vault: id, utcOffset: offset),
                    let passkeys = try? session.passkeysReport(vault: id),
                    let browser = try? session.browserReport(vault: id)
                else { return nil }
                return Computed(health: health, stats: stats, passkeys: passkeys, browser: browser)
            }.value
            guard let self, let reports, !Task.isCancelled else { return }
            (health, stats, browser) = (reports.health, reports.stats, reports.browser)
            // INT-04.52: by title, ascending, as Finder orders names.
            passkeys = reports.passkeys.sorted {
                $0.entry.title.localizedStandardCompare($1.entry.title) == .orderedAscending
            }
            progress = nil
            checkedAt = Clock.now()
            if case .running = breach {} else { loadBreach() }
        }
    }

    /// `ACT-BREACH-RUN` "Check passwords online" (FEA-06.1): the only way a
    /// request leaves App. Requests go out in steps off the screen thread.
    func startBreach() {
        if case .running = breach { return }
        let (session, id) = (session, vault.id)
        breachWork?.cancel()
        breachWork = Task { [weak self] in
            guard let start = try? session.breachStart(vault: id) else { return }
            self?.breach = .running(start)
            await self?.runBreach(start)
        }
    }

    /// Sends the waiting requests until the check is finished or stopped.
    private func runBreach(_ start: BreachProgress) async {
        let (session, id) = (session, vault.id)
        var step = start
        while !step.finished, !Task.isCancelled {
            guard let next = await Task.detached(operation: { try? session.breachStep(vault: id) }).value else {
                break
            }
            step = next
            if !Task.isCancelled { breach = .running(step) }
        }
        if !Task.isCancelled { loadBreach() }
    }

    /// The results Rust holds; none means the consent text (FEA-06.12).
    func loadBreach() {
        guard let found = (try? session.breachReport(vault: vault.id)) ?? nil else {
            breach = .consent
            return
        }
        breach = found.progress.finished ? .done(found) : .running(found.progress)
    }

    /// "Turn off" (FEA-06.12): the check and its findings go.
    func turnOffBreach() {
        breachWork?.cancel()
        breachWork = nil
        try? session.breachStop(vault: vault.id)
        breach = .consent
    }

    /// "Check again": the local reports again. The online check never runs
    /// from here: only "Check passwords online" sends (FEA-06.1).
    func checkAgain() { refresh() }

    /// After entry `id` was saved from the editor: when it was opened from
    /// the breach results, its old password leaves the findings and a new
    /// one gets one request (FEA-06.11).
    func edited(_ id: String, passwordChanged: Bool) {
        defer { editedFromBreach = nil }
        guard editedFromBreach == id, case .done = breach,
            let step = (try? session.breachAfterEdit(vault: vault.id, entry: id, passwordChanged: passwordChanged))
                ?? nil
        else { return }
        if step.finished {
            loadBreach()
            return
        }
        breach = .running(step)
        breachWork = Task { [weak self] in await self?.runBreach(step) }
    }

    /// Closing the reports or a lock: the work stops and every report goes;
    /// Rust drops the breach check with its hashes and counts (FEA-06.12).
    func close() {
        work?.cancel()
        breachWork?.cancel()
        (work, breachWork) = (nil, nil)
        try? session.breachStop(vault: vault.id)
        (health, stats, passkeys, browser, progress) = (nil, nil, nil, nil, nil)
        breach = .consent
        (passkeyTarget, menu) = (nil, nil)
        editedFromBreach = nil
    }
}

extension VaultModel {
    /// Opens the Reports screen (the sidebar's Password health, the
    /// notice's Open report, ⇧⌘R).
    func openReports(_ tab: ReportsModel.Tab = .health) {
        overlay = nil
        if let reports {
            reports.choose(tab)
        } else {
            reports = ReportsModel(session: session, vault: vault, tab: tab)
        }
    }

    func closeReports() {
        guard let reports else { return }  // no write: typing must not redraw the window
        reports.close()
        self.reports = nil
    }

    /// Remove on the Passkeys tab, after the question (INT-04.46).
    func removeReportPasskey() {
        guard let id = reports?.passkeyTarget else { return }
        reports?.passkeyTarget = nil
        do {
            try session.removeEntryPasskey(vault: vault.id, entry: id)
            afterChange(select: nil)
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    /// `ACT-HC-EXPIRE` (FEA-05.18).
    func expireFromReport(_ id: String) {
        do {
            _ = try session.expireEntries(vault: vault.id, entries: [id])
            afterChange(select: nil)
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    /// `ACT-HC-EXCLUDE` "Skip in Reports" (FEA-05.18).
    func toggleSkipFromReport(_ id: String) {
        do {
            _ = try session.toggleSkipInReports(vault: vault.id, entries: [id])
            afterChange(select: nil)
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    /// `ACT-HC-DELETE` (FEA-05.18): with the usual question, MOD-04.
    func deleteFromReport(_ id: String, title: String) {
        if askBeforeBin {
            dialog = .moveToBin(id: id, title: title)
        } else {
            delete(id)
        }
    }
}
