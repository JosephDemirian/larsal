import SwiftUI

/// The mockup's `.menu`: a panel drawn inside the window (so it shows in
/// offscreen snapshots), with items, headers and separators. Escape or a
/// click outside closes it (`MenuLayer`).
struct MenuPanel<Content: View>: View {
    var width: CGFloat?
    var minWidth: CGFloat = 232
    @ViewBuilder let content: Content
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }
            .padding(6)
            .frame(width: width)
            .frame(minWidth: width == nil ? minWidth : nil, alignment: .leading)
            .fixedSize(horizontal: width == nil, vertical: true)
            // The menu's own box (its fill), before its shadow draws outside.
            .background { RoundedRectangle(cornerRadius: 10).fill(Tok.menu).accessibilityHidden(true) }
            .accessibilityElement(children: .contain)
            .accessibilityAddTraits(.isModal)
            .popShadow(scheme)
    }
}

/// `.mi`: a 30-point row with a lead, a title and a shortcut.
struct MenuItem: View {
    enum Lead {
        case glyph(String)
        case tile(Color, String)
        case check(Bool)
    }

    let lead: Lead
    let title: String
    var keys: String?
    var keyGlyph: String?
    /// `.mi.on`: the current vault.
    var current = false
    var negative = false
    var hint: String?
    let action: () -> Void
    @State private var hover = false
    @Environment(\.isEnabled) private var enabled

    var body: some View {
        let lit = current || (hover && enabled)
        let ink: Color = lit ? (negative ? .white : Tok.onAccent) : negative ? Tok.negative : Tok.text
        Button(action: action) {
            HStack(spacing: 10) {
                switch lead {
                case .glyph(let name): Glyph(name: name).foregroundStyle(lit ? ink : Tok.muted)
                case .tile(let color, let glyph): Tile(color: color, glyph: glyph, size: 20)
                case .check(let checked):
                    Glyph(name: "check").foregroundStyle(lit ? ink : Tok.accent).opacity(checked ? 1 : 0)
                }
                Text(verbatim: title).font(.sans(14))
                Spacer(minLength: 10)
                if let keys { Text(verbatim: keys).font(.sans(13)).foregroundStyle(lit ? ink.opacity(0.8) : Tok.muted) }
                if let keyGlyph { Glyph(name: keyGlyph).foregroundStyle(lit ? ink.opacity(0.8) : Tok.muted) }
            }
            .foregroundStyle(ink)
            .padding(.horizontal, 10)
            .frame(height: 30)
            .background(
                lit ? (negative && hover ? Tok.negative : Tok.accent) : .clear, in: RoundedRectangle(cornerRadius: 6)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .onHover { hover = $0 }
        .help(hint ?? "")
        .accessibilityHint(Text(verbatim: hint ?? ""))
    }
}

/// `.msep`.
struct MenuSeparator: View {
    var body: some View {
        Rectangle().fill(Tok.menuRule).frame(height: 1).padding(.horizontal, 4).padding(.vertical, 6)
    }
}

/// `.mh`.
struct MenuHeader: View {
    let title: String

    var body: some View {
        Text(verbatim: title)
            .font(.sans(12, .semibold))
            .foregroundStyle(Tok.muted)
            .frame(height: 20)
            .padding(.leading, 10)
            .padding(.top, 6)
            .padding(.bottom, 4)
            .accessibilityAddTraits(.isHeader)
    }
}

/// An open menu over the window: a click outside or Escape closes it.
struct MenuLayer<Menu: View>: View {
    let close: () -> Void
    @ViewBuilder let menu: Menu

    var body: some View {
        ZStack(alignment: .topLeading) {
            Color.clear
                .contentShape(Rectangle())
                .onTapGesture(perform: close)
                .accessibilityHidden(true)
            menu
        }
        .onExitCommand(perform: close)
    }
}
