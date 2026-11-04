import AppCore
import SwiftUI

/// The mockup's Reports sheet (`reportsView`, frames `reports-reports-*`):
/// the title row with Check again, the five tabs, and the tab's report in a
/// scrolling `.rep`. Behaviour from FEA-05, FEA-06, FEA-07, INT-04.52 and
/// INT-02.32; their words where they differ from the mockup.
struct ReportsView: View {
    let model: VaultModel
    let reports: ReportsModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            titleRow
            tabsRow.padding(.top, 18)
            ScrollView(.vertical) {
                content
                    .padding(.top, 20)
                    .padding(.bottom, 28)
                    .frame(maxWidth: .infinity, alignment: .topLeading)
            }
            .scrollIndicators(.never)
        }
        .padding(.horizontal, 25)
        .padding(.top, 23)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Tok.surface, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Tok.border))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlayPreferenceValue(RowMenuAnchor.self) { anchors in
            GeometryReader { space in
                if let anchor = anchors.first, let row = openRow {
                    MenuLayer(
                        close: { reports.menu = nil },
                        menu: {
                            RowMenuPanel(model: model, reports: reports, row: row)
                                .offset(x: space[anchor].maxX - 232, y: space[anchor].maxY + 4)
                        })
                }
            }
        }
    }

    /// The Health check row whose ⋯ menu is open.
    private var openRow: HealthRow? { reports.health?.rows.first { $0.entry.id == reports.menu } }

    /// `.trow`: "Reports", what was checked when, and Check again.
    private var titleRow: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: "Reports")
                    .font(.sans(22, .semibold))
                    .tracking(-0.22)
                    .frame(height: 28)
                    .accessibilityAddTraits(.isHeader)
                Text(verbatim: subtitle).font(.sans(14)).num().foregroundStyle(Tok.muted).frame(height: 20)
            }
            Spacer(minLength: 0)
            Button(action: reports.checkAgain) { BtnLabel(glyph: "arrows-clockwise", title: "Check again") }
                .buttonStyle(Btn(size: .large))
                .disabled(reports.progress != nil)
        }
    }

    private var subtitle: String {
        let entries = Formats.count(Int(model.sidebar?.all ?? 0), "entry", "entries")
        guard let checked = reports.checkedAt else { return model.vault.name + " · " + entries }
        return model.vault.name + " · " + entries + " checked at " + Formats.time(Int64(checked.timeIntervalSince1970))
    }

    /// `.tabsrow`: the five tabs; Health check carries its count.
    private var tabsRow: some View {
        HStack(spacing: 24) {
            ForEach(ReportsModel.Tab.allCases, id: \.self) { tab in
                let count = tab == .health ? reports.health.map { $0.rows.count }.flatMap { $0 > 0 ? $0 : nil } : nil
                TabButton(title: tab.rawValue, count: count, alert: count != nil, selected: reports.tab == tab) {
                    reports.choose(tab)
                }
            }
        }
        .accessibilityElement(children: .contain)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .bottom) { Rectangle().fill(Tok.border).frame(height: 1) }
    }

    @ViewBuilder
    private var content: some View {
        switch reports.tab {
        case .health:
            if let health = reports.health {
                HealthTab(model: model, reports: reports, health: health)
            } else {
                waiting
            }
        case .breach: BreachTab(model: model, reports: reports)
        case .stats:
            if let stats = reports.stats { StatsTab(stats: stats) } else { waiting }
        case .passkeys:
            if let rows = reports.passkeys { PasskeysTab(model: model, reports: reports, rows: rows) } else { waiting }
        case .browser:
            if let browser = reports.browser { BrowserTab(report: browser) } else { waiting }
        }
    }

    /// `MSG-HC-WAIT` with the rating cache's progress (FEA-05.18, FEA-07.17).
    private var waiting: some View {
        let done = Double(reports.progress?.done ?? 0)
        let total = Double(max(reports.progress?.total ?? 1, 1))
        return VStack(alignment: .leading, spacing: 8) {
            Text(verbatim: "Checking your passwords…").font(.sans(13)).foregroundStyle(Tok.muted)
            ProgressView(value: min(done, total), total: total)
                .progressViewStyle(.linear)
                .tint(Tok.accent)
                .frame(width: 240)
                .accessibilityLabel(Text(verbatim: "Checking your passwords"))
            Text(verbatim: "\(Int(done)) of \(Int(total)) passwords rated").font(.sans(12)).num().foregroundStyle(
                Tok.muted)
        }
        .padding(.horizontal, 10)
    }
}

// MARK: - Health check (FEA-05.11 to FEA-05.18)

private struct HealthTab: View {
    let model: VaultModel
    let reports: ReportsModel
    let health: HealthReport

    var body: some View {
        let rows = health.rows
        VStack(alignment: .leading, spacing: 0) {
            Kpis(cells: [
                .init(
                    label: "Need attention", value: "\(rows.count)", sub: "of \(health.passwords) passwords",
                    bad: true),
                .init(label: "Reused", value: "\(reused.count)", sub: reusedWords, bad: false),
                // FEA-05.4: below Good is a score under 75.
                .init(label: "Weak", value: "\(weak.count)", sub: "under 75 bits", bad: false),
                .init(
                    label: "Expired", value: "\(rows.filter(\.expired).count)", sub: "past their date", bad: false),
            ])
            if rows.isEmpty {
                // MSG-HC-ALL-HEALTHY.
                ReportNote(text: "No password needs attention right now.").padding(.top, 16)
            } else {
                ReportTable(columns: Self.columns) {
                    ForEach(rows, id: \.entry.id) { row in
                        ReportRow(widths: Self.columns.map(\.width)) {
                            EntryCell(row: row.entry, subtitle: row.entry.subtitle)
                            problem(row)
                            StrengthCell(bits: row.bits, segments: row.segments, expired: row.expired)
                            Text(verbatim: Formats.modified(row.entry.modified))
                                .font(.sans(13)).num().foregroundStyle(Tok.muted)
                                .frame(maxWidth: .infinity, alignment: .trailing)
                            actions(row)
                        }
                    }
                }
                .padding(.top, 20)
            }
            ReportNote(text: footnote).padding(.top, 16)
        }
    }

    static let columns: [ReportColumn] = [
        .init(title: "Entry", width: 227.5), .init(title: "Problem", width: nil),
        .init(title: "Strength", width: 105), .init(title: "Changed", width: 77.5, trailing: true),
        .init(title: "", width: 178.5),
    ]

    private var reused: [HealthRow] { health.rows.filter { $0.problem == "Reused" } }
    private var weak: [HealthRow] { health.rows.filter { $0.problem != "Reused" && !$0.expired } }

    private var reusedWords: String {
        Formats.count(Int(health.reusedPasswords), "password", "passwords") + ", "
            + Formats.count(reused.count, "entry", "entries")
    }

    private var footnote: String {
        Formats.count(Int(health.healthy), "other password is", "other passwords are")
            + " strong, unique and current. Entries you exclude are listed under the ⋯ menu."
    }

    /// The pill and the card's reasons (FEA-05.17); details on hover.
    private func problem(_ row: HealthRow) -> some View {
        HStack(spacing: 4) {
            Pill(text: row.problem, kind: row.expired ? .warning : .negative)
            Text(verbatim: row.reasons.map { $0 + "." }.joined(separator: " "))
                .font(.sans(13))
                .foregroundStyle(Tok.muted)
                .lineLimit(1)
                .truncationMode(.tail)
        }
        .help(Text(verbatim: ([row.levelTip] + row.details).filter { !$0.isEmpty }.joined(separator: "\n")))
        .accessibilityElement(children: .combine)
    }

    private func actions(_ row: HealthRow) -> some View {
        HStack(spacing: 3) {
            Button("Change password") {
                reports.editedFromBreach = nil
                model.edit(row.entry.id)
            }
            .buttonStyle(Btn(size: .small))
            .accessibilityLabel(Text(verbatim: "Change password of \(row.entry.title)"))
            // The mockup's inline cell sets the button 3 points below the ⋯.
            .padding(.top, 6)
            RowMenu(reports: reports, row: row.entry)
        }
    }
}

// MARK: - Breach check (FEA-06)

private struct BreachTab: View {
    let model: VaultModel
    let reports: ReportsModel

    var body: some View {
        switch reports.breach {
        case .consent: consent(running: nil)
        case .running(let progress): consent(running: progress)
        case .done(let report): results(report)
        }
    }

    /// `MSG-BREACH-CONSENT` and `ACT-BREACH-RUN` (FEA-06.1): nothing is
    /// sent before the press; the press is the consent, every time.
    @ViewBuilder
    private func consent(running: BreachProgress?) -> some View {
        if !coreHasNetwork() {
            // SN-05 (F-093): a build without network code says so in place of the check.
            Notice(glyph: "info", fill: Tok.raised, ink: Tok.text) {
                Text(verbatim: "This build of App has no network code, so it cannot check passwords online.")
                    .font(.sans(13))
            }
        } else {
            consentForm(running: running)
        }
    }

    private func consentForm(running: BreachProgress?) -> some View {
        VStack(alignment: .leading, spacing: 20) {
            Notice(glyph: "shield-check", fill: Tok.raised, ink: Tok.text) {
                Text(verbatim: "Check your passwords against known leaks. ").font(.sans(13, .semibold))
                    + Text(
                        verbatim:
                            "App sends information to the online Have I Been Pwned service: each password is hashed "
                            + "with SHA-1 and only the first 5 characters of each hash are sent, over HTTPS, so your "
                            + "vault cannot be rebuilt from them. The service learns how many passwords are checked "
                            + "and this Mac's IP address. Nothing is sent until you press the button."
                    )
            }
            HStack(spacing: 16) {
                Button(action: reports.startBreach) { BtnLabel(glyph: "shield-check", title: "Check passwords online") }
                    .buttonStyle(Btn(kind: .primary, size: .large))
                    .disabled(running != nil)
                if let running {
                    ProgressView(value: Double(running.done), total: Double(max(running.total, 1)))
                        .progressViewStyle(.linear)
                        .tint(Tok.accent)
                        .frame(width: 200)
                        .accessibilityLabel(Text(verbatim: "Checking passwords online"))
                    Text(verbatim: "\(running.done) of \(running.total)").font(.sans(13)).num().foregroundStyle(
                        Tok.muted)
                }
            }
        }
    }

    private func results(_ report: BreachReport) -> some View {
        let time = report.checkedAt.map { Formats.time($0) } ?? ""
        let found = report.rows.count
        return VStack(alignment: .leading, spacing: 0) {
            Notice(glyph: "shield-check", fill: Tok.raised, ink: Tok.text) {
                Text(verbatim: "Checked online at \(time).").font(.sans(13, .semibold))
                    + Text(
                        verbatim:
                            " App sent only the first 5 characters of each password's SHA-1 hash. "
                            + "The service never saw a password or a username.")
                HStack(spacing: 12) {
                    // FEA-06: the downloaded list is checked by the command
                    // line tool only.
                    LinkAction(title: "Check with a downloaded list instead") {}
                        .later("Checking with a downloaded list is in the command line tool: app analyze.")
                    LinkAction(title: "Turn off", action: reports.turnOffBreach)
                }
                .padding(.top, 6)
            }
            .padding(.bottom, 20)
            Kpis(cells: [
                .init(label: "Found in breaches", value: "\(found)", sub: "passwords", bad: true),
                .init(label: "Not found", value: "\(Int(report.checked) - found)", sub: "passwords", bad: false),
                .init(label: "Largest count", value: groupedDigits(report.largest), sub: "times seen", bad: false),
            ])
            if found > 0 {
                table(report.rows).padding(.top, 20)
            } else if report.error == nil {
                // MSG-BREACH-NONE.
                ReportNote(text: "None of your passwords turned up in known leaks.").padding(.top, 16)
            }
            if let error = report.error {
                // MSG-BREACH-FAILED, in the error colour (FEA-06.8).
                Text(verbatim: error).font(.sans(13)).foregroundStyle(Tok.negative).padding(.top, 16)
                    .padding(.horizontal, 10)
            }
        }
    }

    /// The findings (FEA-06.9) with the row actions of FEA-06.11.
    private func table(_ rows: [BreachRow]) -> some View {
        ReportTable(columns: Self.columns) {
            ForEach(rows, id: \.entry.id) { row in
                ReportRow(widths: Self.columns.map(\.width)) {
                    EntryCell(row: row.entry, subtitle: row.entry.subtitle)
                    // MSG-BREACH-COUNT-*, in the error colour (FEA-06.9).
                    Text(verbatim: row.exposure)
                        .font(.sans(14, .medium))
                        .num()
                        .lineLimit(1)
                        .foregroundStyle(Tok.negative)
                        .help(Text(verbatim: groupedDigits(row.count) + " times"))
                        .frame(maxWidth: .infinity, alignment: .trailing)
                    Text(verbatim: advice(row.entry))
                        .font(.sans(13))
                        .foregroundStyle(Tok.muted)
                        .lineLimit(1)
                    Button("Change password") {
                        reports.editedFromBreach = row.entry.id
                        model.edit(row.entry.id)
                    }
                    .buttonStyle(Btn(size: .small))
                    .accessibilityLabel(Text(verbatim: "Change password of \(row.entry.title)"))
                    .frame(maxWidth: .infinity, alignment: .trailing)
                }
                .contextMenu {
                    Button("Edit Entry") {
                        reports.editedFromBreach = row.entry.id
                        model.edit(row.entry.id)
                    }
                    Button("Expire Now") { model.expireFromReport(row.entry.id) }
                    Button("Skip in Reports") { model.toggleSkipFromReport(row.entry.id) }
                    Button("Delete Entry") { model.deleteFromReport(row.entry.id, title: row.entry.title) }
                }
            }
        }
    }

    /// Wider than the mockup's: the card's exposure words (FEA-06.9).
    static let columns: [ReportColumn] = [
        .init(title: "Entry", width: 220), .init(title: "Seen in breaches", width: 250, trailing: true),
        .init(title: "What to do", width: nil), .init(title: "", width: 147.5),
    ]

    private func advice(_ entry: EntryRow) -> String {
        entry.host.isEmpty
            ? "Attackers try this password first. Change it."
            : "Attackers try this password first. Change it on \(entry.host)."
    }
}
