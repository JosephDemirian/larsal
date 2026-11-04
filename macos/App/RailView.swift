import AppCore
import SwiftUI

/// The mockup's detail rail (`rail()`): head, quick actions, the health
/// notice, the field panels and the footer. Vault text is plain text
/// (`Text(verbatim:)`, AT-E01); a secret shows only after Show (AT-E07).
struct RailView: View {
    let model: VaultModel
    @Environment(\.detailOptions) private var options

    var body: some View {
        ScrollView {
            if let entry = model.detail {
                VStack(alignment: .leading, spacing: 0) {
                    head(entry)
                    actions(entry)
                    if let rating = entry.rating, rating.attention, !entry.inBin {
                        HealthNotice(rating: rating, change: { model.edit() }, open: { model.openReports() })
                            .padding(.bottom, 12)
                    }
                    Panel(rows: EntryFields(model: model, entry: entry, options: options).rows)
                    Panel(rows: MoreFields(model: model, entry: entry, options: options).rows).padding(.top, 12)
                    foot(entry)
                }
                .padding(.horizontal, 2)
                .padding(.top, 4)
                .padding(.bottom, 24)
            }
        }
        .scrollIndicators(.never)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text(verbatim: "Entry details"))
    }

    private func url(_ entry: EntryDetail) -> String { entry.fields.first { $0.kind == .url }?.value ?? "" }

    /// `.rhead`.
    private func head(_ entry: EntryDetail) -> some View {
        let link = url(entry)
        return HStack(alignment: .center, spacing: 14) {
            EntryLogo(title: entry.title, host: entry.host, icon: entry.icon, custom: entry.customIcon, size: .large)
            VStack(alignment: .leading, spacing: 0) {
                Text(verbatim: entry.title)
                    .font(.sans(18, .semibold))
                    .frame(minHeight: 24)
                    .accessibilityAddTraits(.isHeader)
                if !link.isEmpty && !link.lowercased().hasPrefix("ssh") {
                    Button {
                        model.openURL(entry: entry.id)
                    } label: {
                        HStack(spacing: 4) {
                            Text(verbatim: entry.host)
                            Glyph(name: "arrow-square-out")
                        }
                        .font(.sans(13))
                        .foregroundStyle(Tok.accent)
                    }
                    .buttonStyle(Bare())
                    .accessibilityLabel(Text(verbatim: "Open " + entry.host))
                    .frame(height: 18)
                } else {
                    Text(verbatim: entry.group).font(.sans(13)).foregroundStyle(Tok.muted).frame(height: 20)
                }
            }
            .frame(minWidth: 0)
            Spacer(minLength: 0)
            HStack(spacing: 2) {
                if !entry.inBin {
                    IconButton(glyph: "pencil-simple", label: "Edit entry (⌘E)") { model.edit() }
                }
                IconButton(glyph: "dots-three", label: "More actions") {
                    model.overlay = model.overlay == .more ? nil : .more
                }
            }
            .frame(maxHeight: .infinity, alignment: .top)
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    /// `.quick`, the bin notice, or a 16-point gap.
    @ViewBuilder
    private func actions(_ entry: EntryDetail) -> some View {
        let link = url(entry)
        if entry.inBin {
            // `.notice` 16 below the head, `.notice + .panel` 12 above the panel.
            BinNotice(entry: entry, restore: { model.restore(entry.id) }, delete: { model.askDelete(entry.id) })
                .padding(.top, 16).padding(.bottom, 12)
        } else if entry.kind == .login || entry.kind == .ssh {
            HStack(spacing: 8) {
                if let password = entry.fields.first(where: { $0.kind == .password }) {
                    quick("copy", "Copy password") { model.copy(password.name) }
                }
                if !link.isEmpty && !link.lowercased().hasPrefix("ssh") {
                    quick("arrow-square-out", "Open site") { model.openURL(entry: entry.id) }
                }
                if entry.kind == .ssh {
                    quick("terminal-window", "Load key") {}.later(Later.sshAgent)
                } else {
                    quick("keyboard", "Type login") {}.later(Later.autoType)
                }
            }
            .padding(.vertical, 16)
        } else {
            Color.clear.frame(height: 16)
        }
    }

    private func quick(_ glyph: String, _ title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Glyph(name: glyph)
                Text(verbatim: title).font(.sans(13, .medium))
            }
            .fixedSize()
            .frame(maxWidth: .infinity)
        }
        .buttonStyle(Btn(size: .medium, wide: true, pad: 8))
    }

    /// `.rfoot`.
    private func foot(_ entry: EntryDetail) -> some View {
        HStack {
            Text(verbatim: "Modified \(Formats.day(entry.modified)), \(Formats.time(entry.modified))")
            Spacer()
            if entry.history > 0 {
                Button {
                    model.edit()
                    model.editor?.page = .history
                } label: {
                    Text(verbatim: Formats.count(Int(entry.history), "earlier version", "earlier versions"))
                        .foregroundStyle(Tok.accent)
                }
                .buttonStyle(Bare())
                .disabled(entry.inBin)
            } else {
                Text(verbatim: "No earlier versions")
            }
        }
        .font(.sans(12))
        .num()
        .foregroundStyle(Tok.muted)
        .frame(height: 20)
        .padding(.horizontal, 4)
        .padding(.top, 12)
    }
}

/// `.notice` for an entry that needs attention (FEA-05.13 to FEA-05.15).
private struct HealthNotice: View {
    let rating: Rating
    let change: () -> Void
    let open: () -> Void

    var body: some View {
        let text = rating.reasons.map { $0 + "." }.joined(separator: " ")
        let ink = rating.expired ? Tok.warnInk : Tok.negInk
        Notice(glyph: "warning-circle", fill: rating.expired ? Tok.warnBg : Tok.negBg, ink: ink) {
            (Text(verbatim: rating.issue).font(.sans(13, .semibold)) + Text(verbatim: " " + text))
            HStack(spacing: 12) {
                NoticeAction(title: "Change password", color: ink, action: change)
                NoticeAction(title: "Open report", color: ink, action: open)
            }
            .padding(.top, 6)
        }
    }
}

/// `.notice.neu` of an entry in the bin (MOD-04.10).
private struct BinNotice: View {
    let entry: EntryDetail
    let restore: () -> Void
    let delete: () -> Void

    var body: some View {
        Notice(glyph: "trash", fill: Tok.raised, ink: Tok.text) {
            if let from = entry.deletedFrom {
                Text(verbatim: "Deleted on \(Formats.day(entry.deleted ?? entry.modified)) from ")
                    + Text(verbatim: from).font(.sans(13, .semibold)) + Text(verbatim: ".")
            } else {
                Text(verbatim: "Deleted on \(Formats.day(entry.deleted ?? entry.modified)).")
            }
            HStack(spacing: 12) {
                NoticeAction(title: "Restore", color: Tok.text, action: restore)
                NoticeAction(title: "Delete forever", color: Tok.negative, action: delete)
            }
            .padding(.top, 6)
        }
    }
}

/// The mockup's `.notice`: an icon and text on a tinted box.
struct Notice<Content: View>: View {
    let glyph: String
    let fill: Color
    let ink: Color
    @ViewBuilder let content: Content

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Glyph(name: glyph).padding(.top, 1)
            VStack(alignment: .leading, spacing: 0) { content }
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(.sans(13))
        .lineBox(13, 18)
        .foregroundStyle(ink)
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(fill, in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .contain)
    }
}

/// `.notice .acts button`: bold, underlined.
struct NoticeAction: View {
    let title: String
    let color: Color
    var action: () -> Void = {}

    var body: some View {
        Button(action: action) {
            Text(verbatim: title).font(.sans(13, .semibold)).underline().foregroundStyle(color).frame(height: 18)
        }
        .buttonStyle(Bare())
    }
}

/// `.panel` with `.fld` rows and hairlines between them.
struct Panel: View {
    let rows: [AnyView]

    var body: some View {
        if !rows.isEmpty {
            // `.fld` is at least 58 tall with its 1-point rule (`.fld + .fld`),
            // inside the panel's 1-point border.
            VStack(spacing: 0) {
                ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                    row.padding(.top, index > 0 ? 1 : 0)
                        .frame(minHeight: 58)
                        .overlay(alignment: .top) {
                            if index > 0 { Rectangle().fill(Tok.rule).frame(height: 1) }
                        }
                }
            }
            .padding(1)
            .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
        }
    }
}

/// `.fld`: a label over a value, tools on the right, at least 58 points.
struct Fld<Value: View, Tools: View>: View {
    let label: String
    @ViewBuilder let value: Value
    @ViewBuilder let tools: Tools

    var body: some View {
        HStack(spacing: 4) {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: label).font(.sans(12)).foregroundStyle(Tok.muted).frame(height: 16)
                value.font(.sans(14)).foregroundStyle(Tok.text).frame(minHeight: 20)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            tools
        }
        .padding(.leading, 16)
        .padding(.trailing, 8)
        .padding(.vertical, 9)
        .accessibilityElement(children: .contain)
    }
}

extension Fld where Tools == EmptyView {
    init(label: String, @ViewBuilder value: () -> Value) {
        self.init(label: label, value: value) { EmptyView() }
    }
}

/// A simple wrapping row (`.chips`: wraps, 6 apart).
struct Flow: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        place(proposal.width ?? .infinity, subviews).size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        for (view, point) in zip(subviews, place(bounds.width, subviews).points) {
            view.place(at: CGPoint(x: bounds.minX + point.x, y: bounds.minY + point.y), proposal: .unspecified)
        }
    }

    private func place(_ width: CGFloat, _ subviews: Subviews) -> (points: [CGPoint], size: CGSize) {
        var points: [CGPoint] = []
        var left: CGFloat = 0
        var top: CGFloat = 0
        var line: CGFloat = 0
        var widest: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if left > 0 && left + size.width > width {
                left = 0
                top += line + spacing
                line = 0
            }
            points.append(CGPoint(x: left, y: top))
            left += size.width + spacing
            line = max(line, size.height)
            widest = max(widest, left - spacing)
        }
        return (points, CGSize(width: widest, height: top + line))
    }
}
