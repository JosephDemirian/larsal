import AppCore
import SwiftUI

// MARK: - Parts

/// One column of a `.rtbl`: its head and width (`nil`: takes the rest).
struct ReportColumn {
    let title: String
    let width: CGFloat?
    var trailing = false
}

/// `.rtbl`: the heads (12, muted, 8 above the first rule) and the rows.
struct ReportTable<Rows: View>: View {
    let columns: [ReportColumn]
    @ViewBuilder let rows: Rows

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ColumnsLayout(widths: columns.map(\.width)) {
                ForEach(Array(columns.enumerated()), id: \.offset) { _, column in
                    Text(verbatim: column.title)
                        .font(.sans(12))
                        .foregroundStyle(Tok.muted)
                        .frame(maxWidth: .infinity, alignment: column.trailing ? .trailing : .leading)
                        .accessibilityAddTraits(.isHeader)
                }
            }
            .frame(height: 20)
            .padding(.bottom, 8)
            rows
        }
    }
}

/// `.rtbl tr`: a hairline, then 10 + 38 + 10 points of cells.
struct ReportRow<Cells: View>: View {
    let widths: [CGFloat?]
    @ViewBuilder let cells: Cells

    var body: some View {
        VStack(spacing: 0) {
            Rectangle().fill(Tok.rule).frame(height: 1)
            ColumnsLayout(widths: widths) { cells }
                .frame(height: 58)
        }
        .accessibilityElement(children: .contain)
    }
}

/// The table's columns: fixed widths, the `nil` ones share the rest; each
/// cell sits 10 points in from its column's sides, centred vertically.
struct ColumnsLayout: Layout {
    let widths: [CGFloat?]

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let height = subviews.map { $0.sizeThatFits(.unspecified).height }.max() ?? 0
        return CGSize(width: proposal.width ?? 0, height: proposal.height ?? height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let fixed = widths.compactMap { $0 }.reduce(0, +)
        let flexible = max(widths.filter { $0 == nil }.count, 1)
        let share = max(bounds.width - fixed, 0) / CGFloat(flexible)
        var left = bounds.minX
        for (index, subview) in subviews.enumerated() {
            let width = (index < widths.count ? widths[index] : nil) ?? share
            subview.place(
                at: CGPoint(x: left + 10, y: bounds.midY), anchor: .leading,
                proposal: ProposedViewSize(width: max(width - 20, 0), height: nil))
            left += width
        }
    }
}

/// `.idc`: the 24-point logo, the title and its second line; the row's own
/// second line is masked as the list's (S-VIEW-06, LD-219 (1)).
struct EntryCell: View {
    let row: EntryRow
    let subtitle: String

    var body: some View {
        HStack(spacing: 12) {
            EntryLogo(title: row.title, host: row.host, icon: row.icon, custom: row.customIcon, size: .tiny)
            VStack(alignment: .leading, spacing: 0) {
                Text(verbatim: row.title).font(.sans(14, .medium)).frame(height: 20)
                Group {
                    if subtitle == row.subtitle && row.subtitleIsUser {
                        MaskedUser(user: subtitle)
                    } else {
                        Text(verbatim: subtitle.isEmpty ? "—" : subtitle)
                    }
                }
                .font(.sans(12)).foregroundStyle(Tok.muted).frame(height: 18)
            }
            .lineLimit(1)
            .accessibilityElement(children: .combine)
            .accessibilitySortPriority(1)
        }
    }
}

/// `.hl`: the strength in bits and the four-part meter (FEA-05.4).
struct StrengthCell: View {
    let bits: UInt32
    let segments: UInt8
    let expired: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(verbatim: "\(bits) bits")
                .font(.sans(12, .medium))
                .num()
                .foregroundStyle(expired ? Tok.warning : Tok.negative)
                .frame(height: 14)
            HStack(spacing: 2) {
                ForEach(0..<4, id: \.self) { index in
                    RoundedRectangle(cornerRadius: 2)
                        .fill(index < Int(segments) ? (expired ? Tok.orange : Tok.negative) : Tok.active)
                        .frame(width: 14, height: 3)
                }
            }
            .accessibilityHidden(true)
        }
    }
}

/// `.kpis`: equal cells with hairlines between, in a 10-point box.
struct Kpis: View {
    struct Cell {
        let label: String
        let value: String
        let sub: String
        let bad: Bool
    }

    let cells: [Cell]

    var body: some View {
        HStack(spacing: 0) {
            ForEach(Array(cells.enumerated()), id: \.offset) { index, cell in
                if index > 0 { Rectangle().fill(Tok.rule).frame(width: 1) }
                VStack(alignment: .leading, spacing: 0) {
                    Text(verbatim: cell.label).font(.sans(13)).foregroundStyle(Tok.muted).frame(height: 20)
                    Text(verbatim: cell.value)
                        .font(.sans(26, .medium))
                        .num()
                        .foregroundStyle(cell.bad ? Tok.negative : Tok.text)
                        .frame(height: 32)
                        .padding(.top, 4)
                    Text(verbatim: cell.sub).font(.sans(13)).num().foregroundStyle(Tok.muted).frame(height: 20)
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityElement(children: .combine)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
        .padding(1)
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
    }
}

/// `.dash`: nothing there.
struct Dash: View {
    var body: some View {
        Text(verbatim: "—").font(.sans(14)).foregroundStyle(Tok.muted)
    }
}

/// The muted note under a table (13 points, 10 in from the left).
struct ReportNote: View {
    let text: String

    var body: some View {
        Text(verbatim: text)
            .font(.sans(13))
            .num()
            .foregroundStyle(Tok.muted)
            .frame(minHeight: 20)
            .padding(.horizontal, 10)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// `.notice .acts button`: bold and underlined.
struct LinkAction: View {
    let title: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(verbatim: title).font(.sans(13, .semibold)).underline().foregroundStyle(Tok.text).frame(height: 18)
        }
        .buttonStyle(Bare())
    }
}

/// `214876` as `214,876`, whatever the Mac's region (the mockup's format).
func groupedDigits(_ number: UInt64) -> String {
    let digits = String(number)
    var out = ""
    for (index, digit) in digits.enumerated() {
        if index > 0 && (digits.count - index) % 3 == 0 { out.append(",") }
        out.append(digit)
    }
    return out
}

// MARK: - The row menu

/// The row's ⋯ (`.ibtn.sm`, "More"): opens the row menu under it.
struct RowMenu: View {
    let reports: ReportsModel
    let row: EntryRow

    var body: some View {
        IconButton(glyph: "dots-three", label: "More", size: 28) {
            reports.menu = reports.menu == row.id ? nil : row.id
        }
        .anchorPreference(key: RowMenuAnchor.self, value: .bounds) { reports.menu == row.id ? [$0] : [] }
    }
}

/// Where the open row menu hangs.
struct RowMenuAnchor: PreferenceKey {
    static let defaultValue: [Anchor<CGRect>] = []
    static func reduce(value: inout [Anchor<CGRect>], nextValue: () -> [Anchor<CGRect>]) {
        value += nextValue()
    }
}

/// The row menu (FEA-05.18 actions), drawn in the window as the app's
/// other menus: Edit, Expire Now, Skip in Reports, Delete; and Show Skipped
/// Entries when some entry is skipped (FEA-05.15).
struct RowMenuPanel: View {
    let model: VaultModel
    let reports: ReportsModel
    let row: HealthRow

    var body: some View {
        MenuPanel(width: 232) {
            item("pencil-simple", "Edit Entry") { model.edit(row.entry.id) }
            item("clock", "Expire Now") { model.expireFromReport(row.entry.id) }
            MenuItem(lead: .check(row.excluded), title: "Skip in Reports") {
                close { model.toggleSkipFromReport(row.entry.id) }
            }
            MenuSeparator()
            MenuItem(lead: .glyph("trash"), title: "Delete Entry", negative: true) {
                close { model.deleteFromReport(row.entry.id, title: row.entry.title) }
            }
            if reports.health?.anySkipped == true {
                MenuSeparator()
                MenuItem(lead: .check(reports.showSkipped), title: "Show Skipped Entries") {
                    close { reports.setShowSkipped(!reports.showSkipped) }
                }
            }
        }
    }

    private func item(_ glyph: String, _ title: String, _ action: @escaping () -> Void) -> some View {
        MenuItem(lead: .glyph(glyph), title: title) { close(action) }
    }

    private func close(_ action: () -> Void) {
        reports.menu = nil
        action()
    }
}
