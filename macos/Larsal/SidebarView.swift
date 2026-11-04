import LarsalCore
import SwiftUI

/// The mockup's sidebar (`.sb`): the vault switcher, the library, groups,
/// tags, the Recycle Bin, Settings and the save state.
struct SidebarView: View {
    let model: VaultModel
    let window: MainWindowModel

    /// Tag dot colours, in the order of the vault tag list (MOD-07.5).
    static let tagColors = [
        "teal", "purple", "green", "orange", "slate", "blue", "pink", "brown", "cyan", "mint", "yellow", "red",
    ]

    var body: some View {
        GeometryReader { geometry in
            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: 0) {
                    switcher
                    library.padding(.top, 14)
                    header("Groups") {
                        IconButton(glyph: "plus", label: "New group", size: 22, glyphSize: 13) {
                            model.dialog = .newGroup(name: "")
                        }
                    }
                    groups
                    tags
                    Spacer(minLength: 16)
                    foot
                }
                .padding(.horizontal, 12)
                .padding(.bottom, 12)
                .frame(minHeight: geometry.size.height, alignment: .top)
            }
            .scrollIndicators(.never)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text(verbatim: "Sidebar"))
    }

    private func current(_ place: VaultModel.Place) -> Bool { model.reports == nil && model.place == place }

    /// `.vsw`.
    private var switcher: some View {
        Button {
            window.vaultMenu.toggle()
        } label: {
            HStack(spacing: 10) {
                Tile(color: model.vault.tileColor, glyph: model.vault.tileGlyph, size: 32)
                VStack(alignment: .leading, spacing: 0) {
                    Text(verbatim: model.vault.name).font(.sans(14, .semibold)).frame(height: 18)
                    Text(verbatim: model.vault.fileName).font(.sans(12)).foregroundStyle(Tok.muted).frame(height: 16)
                }
                .lineLimit(1)
                Spacer(minLength: 0)
                Glyph(name: "caret-up-down").foregroundStyle(Tok.muted)
            }
            .foregroundStyle(Tok.text)
            .padding(9)
            .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .accessibilityLabel(Text(verbatim: "Switch vault"))
        .accessibilityValue(Text(verbatim: model.vault.name))
    }

    private var library: some View {
        let side = model.sidebar
        let empty = model.empty
        return VStack(spacing: 0) {
            SidebarItem(title: "All entries", current: current(.all), lead: tile("blue", "tray")) {
                Count(value: empty ? 0 : side?.all ?? 0)
            } action: {
                model.choose(.all)
            }
            SidebarItem(title: "Favorites", current: current(.favorites), lead: tile("orange", "star")) {
                Count(value: empty ? 0 : side?.favorites ?? 0)
            } action: {
                model.choose(.favorites)
            }
            SidebarItem(title: "One-time codes", current: current(.codes), lead: tile("teal", "clock-countdown")) {
                Count(value: empty ? 0 : side?.codes ?? 0)
            } action: {
                model.choose(.codes)
            }
            SidebarItem(title: "Passkeys", current: current(.passkeys), lead: tile("purple", "fingerprint")) {
                Count(value: empty ? 0 : side?.passkeys ?? 0)
            } action: {
                model.choose(.passkeys)
            }
            SidebarItem(title: "Password health", current: model.reports != nil, lead: tile("red", "shield-warning")) {
                if let attention = side?.attention, attention > 0, !empty {
                    Text(verbatim: "\(attention)")
                        .font(.sans(11, .semibold))
                        .num()
                        .foregroundStyle(Tok.badgeInk)
                        .padding(.horizontal, 6)
                        .frame(minWidth: 20, minHeight: 18)
                        .background(Tok.negative, in: Capsule())
                        .accessibilityLabel(Text(verbatim: "\(attention) need attention"))
                } else if side?.attention != nil || empty {
                    Count(value: 0)
                }
            } action: {
                model.openReports()
            }
        }
    }

    private func tile(_ color: String, _ glyph: String) -> AnyView {
        AnyView(Tile(color: Tok.tileColor(color), glyph: glyph))
    }

    @ViewBuilder
    private var groups: some View {
        if model.empty {
            Text(verbatim: "No groups yet")
                .font(.sans(12))
                .foregroundStyle(Tok.muted)
                .padding(.horizontal, 8)
                .padding(.vertical, 2)
        } else {
            VStack(spacing: 0) {
                ForEach(model.sidebar?.groups ?? [], id: \.id) { group in
                    let look = SymbolIcon.look(group.icon, group.customIcon) ?? ("folder-simple", Tok.tileColor("blue"))
                    let ring = current(.group(group.id)) ? Tok.active : Tok.ground
                    let mark = Tile(color: look.color, glyph: look.glyph)  // INT-08.24: a share's badge
                        .shareMark(model.sharing.marks[group.id], ring: ring)
                    SidebarItem(
                        title: group.name, current: current(.group(group.id)), lead: AnyView(mark),
                        indent: CGFloat(min(group.depth, 4)) * 20
                    ) {
                        Count(value: group.count)
                    } action: {
                        model.choose(.group(group.id))
                    }
                    .contextMenu { GroupContextMenu(model: model, group: group) }
                }
            }
        }
    }

    @ViewBuilder
    private var tags: some View {
        Button {
            model.tagsOpen.toggle()
        } label: {
            HStack(spacing: 4) {
                Glyph(name: model.tagsOpen ? "caret-down" : "caret-right", size: 11)
                Text(verbatim: "Tags")
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .modifier(SectionHeader())
        .accessibilityValue(Text(verbatim: model.tagsOpen ? "open" : "closed"))
        if model.tagsOpen && !model.empty {
            VStack(spacing: 0) {
                ForEach(Array((model.sidebar?.tags ?? []).enumerated()), id: \.element.name) { index, tag in
                    let dot = Circle()
                        .fill(Tok.tileColor(Self.tagColors[index % Self.tagColors.count]))
                        .frame(width: 10, height: 10)
                        .padding(.horizontal, 6)
                    SidebarItem(title: tag.name, current: current(.tag(tag.name)), lead: AnyView(dot)) {
                        Count(value: tag.count)
                    } action: {
                        model.choose(.tag(tag.name))
                    }
                }
            }
        }
    }

    private func header<Trailing: View>(_ title: String, @ViewBuilder trailing: () -> Trailing) -> some View {
        HStack(spacing: 4) {
            Text(verbatim: title).accessibilityAddTraits(.isHeader)
            Spacer(minLength: 0)
            trailing()
        }
        .modifier(SectionHeader())
    }

    private var foot: some View {
        VStack(alignment: .leading, spacing: 0) {
            SidebarItem(title: "Recycle Bin", current: current(.bin), lead: tile("gray", "trash")) {
                Count(value: model.empty ? 0 : model.sidebar?.bin ?? 0)
            } action: {
                model.choose(.bin)
            }
            SidebarItem(title: "Settings", current: false, lead: tile("graphite", "gear-six")) {
                Kbd(keys: "⌘,")
            } action: {
                LarsalSettingsWindow.show(session: model.session)
            }
            let saved = model.savedWords
            HStack(spacing: 6) {
                Glyph(name: saved.dirty ? "circle" : "check-circle", size: 13)
                    .foregroundStyle(saved.dirty ? Tok.warning : Tok.positive)
                Text(verbatim: saved.text).num().help(Text(verbatim: model.saveStatus?.failure ?? ""))
            }
            .font(.sans(12))
            .foregroundStyle(Tok.muted)
            .frame(height: 20)
            .padding(.horizontal, 8)
            .padding(.top, 8)
        }
    }

}

/// `.sb-h`.
private struct SectionHeader: ViewModifier {
    func body(content: Content) -> some View {
        content
            .font(.sans(12, .semibold))
            .foregroundStyle(Tok.muted)
            .frame(minHeight: 16)
            .padding(.horizontal, 8)
            .padding(.top, 20)
            .padding(.bottom, 6)
    }
}

/// `.cnt`.
struct Count: View {
    let value: UInt32

    var body: some View {
        Text(verbatim: "\(value)").font(.sans(12)).num().foregroundStyle(Tok.muted)
    }
}

/// `.si`: a 32-point sidebar row.
struct SidebarItem<Trailing: View>: View {
    let title: String
    let current: Bool
    let lead: AnyView
    var indent: CGFloat = 0
    @ViewBuilder let trailing: Trailing
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                lead
                Text(verbatim: title)
                    .font(.sans(14, current ? .medium : .regular))
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .frame(maxWidth: .infinity, alignment: .leading)
                trailing
            }
            .foregroundStyle(Tok.text)
            .padding(.leading, 8 + indent)
            .padding(.trailing, 8)
            .frame(height: 32)
            .background(
                current ? Tok.active : hover ? Tok.sidebarHover : .clear, in: RoundedRectangle(cornerRadius: 8)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .padding(.bottom, 2)
        .onHover { hover = $0 }
        .accessibilityAddTraits(current ? .isSelected : [])
    }
}
