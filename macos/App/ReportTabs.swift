import AppCore
import SwiftUI

// MARK: - Statistics (FEA-07)

struct StatsTab: View {
    let stats: StatsReport

    var body: some View {
        HStack(alignment: .top, spacing: 24) {
            VStack(spacing: 0) {
                ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                    HStack(spacing: 16) {
                        Text(verbatim: row.0).foregroundStyle(Tok.muted)
                        Spacer(minLength: 0)
                        Text(verbatim: row.1).font(.sans(14, .medium)).num().lineLimit(1)
                    }
                    .font(.sans(14))
                    .frame(height: 20)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                    .overlay(alignment: .top) {
                        if index > 0 { Rectangle().fill(Tok.rule).frame(height: 1) }
                    }
                    .padding(.top, index > 0 ? 1 : 0)
                    .accessibilityElement(children: .combine)
                }
            }
            .padding(1)
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
            .frame(maxWidth: .infinity, alignment: .top)
            VStack(alignment: .leading, spacing: 0) {
                heading("Password length")
                Bars(bars: stats.lengths, fill: Tok.accent, faded: false).padding(.top, 14)
                heading("Last changed").padding(.top, 28)
                Bars(bars: stats.ages, fill: Tok.muted, faded: true).padding(.top, 14)
            }
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
    }

    private func heading(_ text: String) -> some View {
        Text(verbatim: text).font(.sans(15, .semibold)).frame(height: 20).accessibilityAddTraits(.isHeader)
    }

    /// The frame's rows; numbers from FEA-07 where the card counts them.
    private var rows: [(String, String)] {
        let saved = stats.lastSaved.map { Formats.used($0) } ?? "—"
        let withPassword = stats.uniquePw + stats.reusedPw
        return [
            ("File", stats.fileName),
            ("Size", stats.size.map { Formats.size($0) } ?? "—"),
            ("Format", stats.version.isEmpty ? "—" : "Version " + stats.version),
            ("Encryption", stats.encryption),
            ("Entries", "\(stats.entries) (\(stats.inBin) in the Recycle Bin)"),
            ("Groups", "\(stats.groups)"),
            ("Attachments", "\(stats.attachments) · " + Formats.size(stats.attachmentBytes)),
            ("Unique passwords", "\(stats.uniquePw) of \(withPassword)"),
            // FEA-07.12: whole characters, halves rounded up.
            ("Average length", Formats.count(Int(stats.avgLen), "character", "characters")),
            ("Last saved", saved),
        ]
    }
}

/// `.hbar`: label, bar and count, 30 apart.
struct Bars: View {
    let bars: [Bar]
    let fill: Color
    let faded: Bool

    var body: some View {
        let most = max(bars.map(\.count).max() ?? 0, 1)
        VStack(spacing: 10) {
            ForEach(bars, id: \.label) { bar in
                HStack(spacing: 12) {
                    Text(verbatim: bar.label).frame(width: 110, alignment: .leading)
                    GeometryReader { space in
                        Capsule()
                            .fill(fill)
                            .opacity(faded ? 0.5 : 1)
                            .frame(width: space.size.width * CGFloat(bar.count) / CGFloat(most), height: 8)
                            .frame(maxHeight: .infinity, alignment: .center)
                    }
                    .accessibilityHidden(true)
                    Text(verbatim: "\(bar.count)").num().foregroundStyle(Tok.muted).frame(
                        width: 40, alignment: .trailing)
                }
                .font(.sans(13))
                .frame(height: 20)
                .accessibilityElement(children: .combine)
            }
        }
    }
}

// MARK: - Passkeys (INT-04.52, INT-04.53)

struct PasskeysTab: View {
    let model: VaultModel
    let reports: ReportsModel
    let rows: [PasskeyRow]

    var body: some View {
        if rows.isEmpty {
            // MI04-35.
            ReportNote(text: "No passkeys in this vault yet.")
        } else {
            ReportTable(columns: Self.columns) {
                ForEach(rows, id: \.entry.id) { row in
                    ReportRow(widths: Self.columns.map(\.width)) {
                        EntryCell(row: row.entry, subtitle: row.site)
                        MaskedUser(user: row.user).font(.sans(14)).lineLimit(1)
                        HStack(spacing: 4) {
                            if row.hasPassword { Pill(text: "password", kind: .neutral) }
                            if row.hasTotp { Pill(text: "one-time code", kind: .neutral) }
                            if !row.hasPassword && !row.hasTotp {
                                Text(verbatim: "passkey only").font(.sans(14)).foregroundStyle(Tok.muted)
                            }
                        }
                        Text(verbatim: Formats.day(row.entry.modified)).font(.sans(13)).num().foregroundStyle(
                            Tok.muted
                        )
                        .frame(maxWidth: .infinity, alignment: .trailing)
                        Button("Remove") {
                            reports.passkeyTarget = row.entry.id
                            model.dialog = .removePasskey(site: row.site)
                        }
                        .buttonStyle(Btn(size: .small))
                        .accessibilityLabel(Text(verbatim: "Remove the passkey of \(row.entry.title)"))
                        .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                    .contextMenu {
                        Button("Edit Entry") { model.edit(row.entry.id) }
                        Button("Delete Entry") { model.deleteFromReport(row.entry.id, title: row.entry.title) }
                        // INT-04.50, until W-12 draws Export under the table.
                        Button("Export Passkeys…") { model.askPasskeyExport() }
                    }
                }
            }
        }
    }

    static let columns: [ReportColumn] = [
        .init(title: "Site", width: 239), .init(title: "User", width: 286.5),
        .init(title: "Entry also has", width: nil), .init(title: "Added", width: 90, trailing: true),
        .init(title: "", width: 90),
    ]
}

// MARK: - Browser (INT-02.32)

struct BrowserTab: View {
    let report: BrowserReport

    var body: some View {
        let rows = report.rows.sorted {
            $0.entry.title.localizedStandardCompare($1.entry.title) == .orderedAscending
        }
        VStack(alignment: .leading, spacing: 0) {
            if !rows.isEmpty {
                ReportTable(columns: Self.columns) {
                    ForEach(rows, id: \.entry.id) { row in
                        ReportRow(widths: Self.columns.map(\.width)) {
                            EntryCell(row: row.entry, subtitle: row.entry.host)
                            hosts(row.allow)
                            hosts(row.deny)
                            if row.options.isEmpty {
                                Dash()
                            } else {
                                Pill(text: row.options.joined(separator: ", "), kind: .neutral)
                            }
                        }
                    }
                }
            }
            ReportNote(text: connected).padding(.top, rows.isEmpty ? 0 : 16)
        }
    }

    static let columns: [ReportColumn] = [
        .init(title: "Entry", width: 280.5), .init(title: "Also allowed on", width: 327),
        .init(title: "Never on", width: 223), .init(title: "Options", width: nil),
    ]

    @ViewBuilder
    private func hosts(_ list: [String]) -> some View {
        if list.isEmpty {
            Dash()
        } else {
            HStack(spacing: 3.5) {
                ForEach(list, id: \.self) { Chip(text: $0) }
            }
        }
    }

    /// MI02-15: the vault's connected browsers with their dates.
    private var connected: String {
        guard !report.browsers.isEmpty else {
            return "No browser is connected to this vault. Connect one from the App extension."
        }
        let names = report.browsers.map { browser -> String in
            if let since = browser.since { return "\(browser.name) (since \(Formats.day(since)))" }
            if !browser.sinceText.isEmpty { return "\(browser.name) (since \(browser.sinceText))" }
            return browser.name
        }
        return "Connected browsers: " + names.joined(separator: " · ") + ". Manage them in Vault Settings."
    }
}
