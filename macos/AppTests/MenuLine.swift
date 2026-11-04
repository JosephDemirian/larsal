import AppKit
import SwiftUI

/// One native menu item: what the menu bar shows of it.
struct MenuLine: Equatable, CustomStringConvertible {
    let title: String
    let keys: String
    let enabled: Bool
    let checked: Bool
    let submenu: [MenuLine]

    var description: String { "\(title) \(keys)\(enabled ? "" : " (off)")\(checked ? " ✓" : "")" }

    /// The native menu SwiftUI makes from `content`.
    static func read(_ content: some View) async -> [MenuLine] {
        guard #available(macOS 14.4, *) else { return [] }
        let menu = NSHostingMenu(rootView: content)
        menu.update()
        try? await Task.sleep(for: .milliseconds(30))
        menu.update()
        return lines(menu)
    }

    static func lines(_ menu: NSMenu) -> [MenuLine] {
        menu.update()
        return menu.items.filter { !$0.isHidden }.map { item in
            let submenu = item.submenu.map(lines)
            // A submenu acts when one of its items does.
            return MenuLine(
                title: item.isSeparatorItem ? "-" : item.title, keys: item.isSeparatorItem ? "" : keys(item),
                enabled: item.isEnabled && (submenu?.contains { $0.enabled && $0.title != "-" } ?? true),
                checked: item.state == .on, submenu: submenu ?? [])
        }
    }

    /// The shortcut as the card writes it: ⌃⌥⇧⌘, then the key.
    static func keys(_ item: NSMenuItem) -> String {
        guard !item.keyEquivalent.isEmpty else { return "" }
        let flags = item.keyEquivalentModifierMask
        let marks: [(NSEvent.ModifierFlags, String)] = [
            (.control, "⌃"), (.option, "⌥"), (.shift, "⇧"), (.command, "⌘"),
        ]
        let names: [String: String] = [
            "\u{8}": "⌫", "\u{7f}": "⌫", "\t": "Tab", " ": "Space", "\u{F700}": "↑", "\u{F701}": "↓",
        ]
        let key = names[item.keyEquivalent] ?? item.keyEquivalent.uppercased()
        return marks.filter { flags.contains($0.0) }.map(\.1).joined() + key
    }
}

extension [MenuLine] {
    func line(_ title: String) -> MenuLine? { first { $0.title == title } }
    var titles: [String] { map(\.title) }
}
