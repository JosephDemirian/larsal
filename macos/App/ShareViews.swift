import AppCore
import SwiftUI

// The shared-group indicators of W-15 (E11-S5, INT-08.20, INT-08.24,
// INT-08.31): the badge, the label under the entry list, the result banner
// and the Approve sheet. Paths are in IBM Plex Mono, whole, never cut short.

extension View {
    /// INT-08.24: the share badge on a share group's own tile, a third of
    /// it outside the bottom-right corner, ringed in `ring` (the ground the
    /// tile sits on). `nil`: no badge.
    func shareMark(_ active: Bool?, large: Bool = false, ring: Color = Tok.surface) -> some View {
        overlay(alignment: .bottomTrailing) {
            if let active {
                let size: CGFloat = large ? 22 : 13
                let name = active ? "Share active" : "Share inactive"
                Circle()
                    .fill(active ? Tok.tileColor("green") : Tok.gray)
                    .overlay(
                        Glyph(name: active ? "share-network" : "pause", size: (size * 0.62).rounded(), fill: true)
                            .foregroundStyle(.white)
                    )
                    .frame(width: size, height: size)
                    .background(Circle().fill(ring).padding(-2))
                    .offset(x: (size / 3).rounded(), y: (size / 3).rounded())
                    .help(name)
                    .accessibilityElement()
                    .accessibilityLabel(Text(verbatim: name))
                    .accessibilityAddTraits(.isImage)
            }
        }
    }
}

/// A path as stored or resolved: mono, broken anywhere, whole.
struct SharePath: View {
    let path: String
    var size: CGFloat = 13

    var body: some View {
        Text(verbatim: path).font(.mono(size)).fixedSize(horizontal: false, vertical: true)
    }
}

/// The three notice looks of W-15 (`.notice`, `.notice.warn`, `.notice.neu`).
enum ShareTone {
    case error, warning, neutral

    var fill: Color {
        switch self {
        case .error: Tok.negBg
        case .warning: Tok.warnBg
        case .neutral: Tok.raised
        }
    }

    var ink: Color {
        switch self {
        case .error: Tok.negInk
        case .warning: Tok.warnInk
        case .neutral: Tok.text
        }
    }
}

/// The label under the entry list (INT-08.24, MI08-24, MI08-16, MI08-15,
/// MI08-25, MI08-18 with Approve).
struct ShareLabelNotice: View {
    let label: ShareLabel
    var approve: () -> Void = {}

    static func verb(_ mode: ShareMode) -> String {
        switch mode {
        case .import: "Shared: imports from "
        case .export: "Shared: exports to "
        default: "Shared: syncs with "
        }
    }

    static func modeName(_ mode: ShareMode) -> String {
        switch mode {
        case .inactive: "Inactive"
        case .import: "Import"
        case .export: "Export"
        case .synchronize: "Synchronize"
        }
    }

    var body: some View {
        switch label.state {
        case .running:
            let tone: ShareTone = label.importOff || label.exportOff ? .warning : .neutral
            Notice(glyph: "share-network", fill: tone.fill, ink: tone.ink) {
                Text(verbatim: Self.verb(label.mode)) + Text(verbatim: label.path).font(.mono(13))
                if label.importOff { Text(verbatim: "Import is turned off in App's settings.") }
                if label.exportOff { Text(verbatim: "Export is turned off in App's settings.") }
            }
        case .off:
            Notice(glyph: "pause-circle", fill: Tok.raised, ink: Tok.text) {
                Text(verbatim: "Sharing is off for this group: its settings are inactive or cannot be read.")
            }
        case .waiting:
            Notice(glyph: "pause-circle", fill: Tok.warnBg, ink: Tok.warnInk) {
                Text(verbatim: "Sharing is paused for this group: its settings were not made on this Mac.")
                Text(verbatim: Self.modeName(label.mode) + ": ") + Text(verbatim: label.fullPath).font(.mono(13))
                NoticeAction(title: "Approve", color: Tok.warnInk, action: approve).padding(.top, 6)
            }
        }
    }
}

/// INT-08.20: one banner per pass at the top of the sheet; each line starts
/// with its path as stored.
struct ShareBannerNotice: View {
    let banner: ShareBanner
    let close: () -> Void

    var body: some View {
        let (glyph, tone): (String, ShareTone) =
            switch banner.level {
            case .error: ("warning-circle", .error)
            case .warning: ("warning", .warning)
            case .success: ("check-circle", .neutral)
            }
        Notice(glyph: glyph, fill: tone.fill, ink: tone.ink) {
            ForEach(Array(banner.lines.enumerated()), id: \.offset) { index, line in
                let path = index < banner.paths.count ? banner.paths[index] : ""
                if !path.isEmpty, line.hasPrefix(path) {
                    Text(verbatim: path).font(.mono(13)) + Text(verbatim: String(line.dropFirst(path.count)))
                } else {
                    Text(verbatim: line)
                }
            }
        }
        .overlay(alignment: .topTrailing) {
            IconButton(glyph: "x", label: "Close", size: 28, action: close).foregroundStyle(tone.ink).padding(6)
        }
        .accessibilityAddTraits(.updatesFrequently)
    }
}

extension View {
    /// The banner over the sheet's title row, 16 above it.
    func shareBanner(_ model: VaultModel) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            if let banner = model.sharing.banner {
                ShareBannerNotice(banner: banner) { model.sharing.banner = nil }.padding(.bottom, 16)
            }
            self
        }
    }

    /// The label under the entry list (8 above, 16 below).
    func shareLabel(_ model: VaultModel) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            self
            if let label = model.sharing.label {
                ShareLabelNotice(label: label) { model.dialog = .approveShare(label) }
                    .padding(.top, 8)
                    .padding(.bottom, 16)
            }
        }
    }
}

/// INT-08.31: the Approve sheet; it shows the group, the Type and the full
/// path, never cut short. Approve is the default button (LD-270 (3)).
struct ApproveShareSheet: View {
    let model: VaultModel
    let label: ShareLabel

    var body: some View {
        let name = label.name
        let text =
            switch label.mode {
            case .import: "App reads changes from this file into \(name)."
            case .export: "App writes \(name) to this file after every save of the vault."
            default:
                "App reads changes from this file into \(name), and writes \(name) to it after every save of the vault."
            }
        DialogCard(
            tint: "green", glyph: "share-network", title: "Approve sharing for “\(name)”?",
            text: "Its sharing settings were not made on this Mac. After you approve, " + text, wide: true
        ) {
            DialogBody {
                Panel(rows: [
                    AnyView(
                        Fld(label: "Group") {
                            HStack(spacing: 8) {
                                ShareGroupTile(model: model, group: label.group)
                                Text(verbatim: name)
                            }
                        }),
                    AnyView(Fld(label: "Type") { Text(verbatim: ShareLabelNotice.modeName(label.mode)) }),
                    AnyView(Fld(label: "Path") { SharePath(path: label.fullPath, size: 14) }),
                ])
            }
        } foot: {
            SheetButton(title: "Cancel", cancel: true) { model.dialog = nil }
            SheetButton(title: "Approve", kind: .primary) { model.approveShare(label) }
        }
    }
}

/// A group's own tile, with its share badge when it is a share group.
struct ShareGroupTile: View {
    let model: VaultModel
    let group: String
    var large = false
    var ring = Tok.surface

    var body: some View {
        let row = model.sidebar?.groups.first { $0.id == group }
        let look = row.flatMap { SymbolIcon.look($0.icon, $0.customIcon) } ?? ("folder-simple", Tok.tileColor("blue"))
        Tile(color: look.color, glyph: look.glyph, size: large ? 44 : 22)
            .shareMark(model.sharing.marks[group], large: large, ring: ring)
    }
}

/// INT-08.25 (W-15 `vaultShares`, MOD-12.1): read only, one row per share
/// group in tree order; no signer or certificate columns (option b only).
struct SettingsShares: View {
    let model: VaultSettingsModel

    var body: some View {
        let rows = (try? model.session.shareRows(vault: model.vault.id)) ?? []
        let columns = [MiniColumn(title: "Group"), MiniColumn(title: "Type"), MiniColumn(title: "Path")]
        VStack(alignment: .leading, spacing: 0) {
            ShareTable(
                header: columns,
                rows: rows.map { row in
                    let look = SymbolIcon.look(row.icon, row.customIcon) ?? ("folder-simple", Tok.tileColor("blue"))
                    return [
                        AnyView(
                            HStack(spacing: 10) {
                                Tile(color: look.color, glyph: look.glyph).shareMark(row.active)
                                Text(verbatim: row.names)
                            }
                            .fixedSize()),
                        AnyView(Text(verbatim: ShareLabelNotice.modeName(row.mode)).fixedSize()),
                        AnyView(SharePath(path: row.path)),
                    ]
                })
            Text(
                verbatim: "Every group of this vault that is shared as a file, in the order of the group tree. "
                    + "To change one, edit the group and open its Sharing page."
            )
            .font(.sans(12)).foregroundStyle(Tok.muted).lineBox(12, 16)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 2)
            .padding(.top, 10)
        }
    }
}

/// `.mini` whose first columns take their content's width and whose last
/// one wraps (the path, never cut short).
private struct ShareTable: View {
    let header: [MiniColumn]
    let rows: [[AnyView]]

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 20, verticalSpacing: 0) {
            GridRow {
                ForEach(header.indices, id: \.self) { index in
                    Text(verbatim: header[index].title).font(.sans(12)).foregroundStyle(Tok.muted).frame(height: 20)
                }
            }
            .padding(.bottom, 8)
            ForEach(rows.indices, id: \.self) { row in
                if row > 0 { Rectangle().fill(Tok.rule).frame(height: 1).gridCellUnsizedAxes(.horizontal) }
                GridRow(alignment: .firstTextBaseline) {
                    ForEach(rows[row].indices, id: \.self) { index in
                        rows[row][index].frame(
                            maxWidth: index == rows[row].count - 1 ? .infinity : nil, alignment: .leading)
                    }
                }
                .padding(.vertical, 10)
                .frame(minHeight: 40)
            }
        }
        .font(.sans(13))
        .padding(.horizontal, 17)
        .padding(.top, 7)
        .padding(.bottom, 3)
        .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
    }
}
