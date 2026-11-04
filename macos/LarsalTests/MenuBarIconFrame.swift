import AppKit
import LarsalCore
import SwiftUI

/// The frame's picture (mockup `menuBarWin`): a desktop, the macOS menu bar
/// with Larsal's first menus and its icon, and the icon's menu drawn from the
/// real NSMenu with Option A's menu parts. The desktop and the bar are
/// macOS's, so their colours are the mockup's literal ones and live here,
/// not in the app; the live menu is drawn by macOS (APP-08.25).
struct MenuBarIconFrame: View {
    let icon: MenuBarIcon
    let vaults: [VaultInfo]
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        let dark = scheme == .dark
        ZStack(alignment: .topLeading) {
            LinearGradient(
                stops: dark
                    ? [
                        .init(color: rgb(0x1c2a30), location: 0), .init(color: rgb(0x10161a), location: 0.6),
                        .init(color: rgb(0x15191b), location: 1),
                    ]
                    : [
                        .init(color: rgb(0x9fb4bf), location: 0), .init(color: rgb(0xc9d3d1), location: 0.6),
                        .init(color: rgb(0xb9c4c6), location: 1),
                    ],
                // CSS 160deg over 720 × 392.
                startPoint: UnitPoint(x: 0.354, y: -0.237), endPoint: UnitPoint(x: 0.646, y: 1.237)
            )
            .padding(.top, 28)
            .accessibilityHidden(true)
            bar(dark)
            panel.padding(.leading, 312).padding(.top, 32)
        }
        .frame(width: 720, height: 420, alignment: .topLeading)
        .background(Tok.ground)
        .foregroundStyle(Tok.text)
    }

    private func rgb(_ hex: Int) -> Color {
        Color(red: Double(hex >> 16 & 255) / 255, green: Double(hex >> 8 & 255) / 255, blue: Double(hex & 255) / 255)
    }

    /// `.mbar`: Larsal's first menus in the menu bar's order, then the icon.
    private func bar(_ dark: Bool) -> some View {
        HStack(spacing: 16) {
            Color.clear.frame(width: 0)
            Text(verbatim: "Larsal").font(.sans(13, .semibold))
            ForEach(["File", "Edit", "View", "Vault", "Entry"], id: \.self) { Text(verbatim: $0) }
            Spacer(minLength: 0)
            Glyph(name: "keyhole", fill: true)
                .padding(.horizontal, 6)
                .padding(.vertical, 4)
                .background(Tok.active, in: RoundedRectangle(cornerRadius: 5))
                .accessibilityElement()
                .accessibilityLabel(Text(verbatim: "Larsal"))
                .accessibilityValue(Text(verbatim: icon.toolTip))
            Glyph(name: "wifi-high")
            Text(verbatim: "Tue 27 Oct 10:30").num()
        }
        .font(.sans(13))
        .padding(.horizontal, 14)
        .frame(height: 28)
        .frame(maxWidth: .infinity)
        .background(dark ? rgb(0x1a1a1d) : Tok.ground)
        .overlay(alignment: .bottom) { Rectangle().fill(Tok.border).frame(height: 1).accessibilityHidden(true) }
    }

    /// The icon's menu, item by item from the NSMenu.
    private var panel: some View {
        MenuPanel(width: 290) {
            ForEach(Array(icon.menu.items.enumerated()), id: \.offset) { _, item in
                if item.isSeparatorItem {
                    MenuSeparator()
                } else if item.isSectionHeader {
                    MenuHeader(title: item.title)
                } else if let id = item.representedObject as? UInt64, let vault = vaults.first(where: { $0.id == id }) {
                    MenuItem(
                        lead: .tile(vault.tileColor, vault.tileGlyph), title: item.title,
                        keys: vault.locked ? nil : "Unlocked", keyGlyph: vault.locked ? "lock-simple" : nil
                    ) {}
                } else {
                    let glyph = icon.items().first { $0.id == item.identifier?.rawValue }?.glyph ?? ""
                    MenuItem(lead: .glyph(glyph), title: item.title, keys: MenuLine.keys(item)) {}
                        .disabled(!item.isEnabled)
                }
            }
        }
    }
}
