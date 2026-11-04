import AppCore
import AppKit
import SwiftUI

/// Where the menu bar icon lives: the system status bar in the app, a
/// recorder in tests, so a test never adds an item to the owner's menu bar
/// (AGENTS.md rule 10).
protocol StatusSlot: AnyObject {
    func show(image: NSImage, toolTip: String, menu: NSMenu)
    func remove()
}

/// The real status item (APP-08.20).
final class SystemStatusSlot: StatusSlot {
    private var item: NSStatusItem?

    func show(image: NSImage, toolTip: String, menu: NSMenu) {
        let item = item ?? NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        self.item = item
        item.button?.image = image
        item.button?.toolTip = toolTip
        item.button?.setAccessibilityLabel("App")
        // A click on the icon (any button) opens the menu (APP-08.21).
        item.menu = menu
    }

    func remove() {
        if let item { NSStatusBar.system.removeStatusItem(item) }
        item = nil
    }
}

/// No status item: a hidden launch (tests, Verify drivers, Mac QA
/// snapshots) never adds one to the owner's menu bar, as `AuxWindows.present`
/// shows no window then (AGENTS.md rule 10).
final class NoStatusSlot: StatusSlot {
    func show(image: NSImage, toolTip: String, menu: NSMenu) {}
    func remove() {}
}

/// APP-08.20 to APP-08.22: the optional menu bar icon and its menu, with
/// Option A's items (menubar-menu-bar-icon) and the card's words and rules.
/// The menu is native, so VoiceOver and the keyboard work as in every menu
/// (APP-08.25). It never shows a secret; the tooltip never names a vault.
@MainActor
final class MenuBarIcon: NSObject, NSMenuDelegate {
    /// One item of the menu after the vaults: its glyph (for the drawn
    /// frame), title, key and modifiers.
    struct Item {
        let id: String
        let glyph: String
        let title: String
        let key: String
        let modifiers: NSEvent.ModifierFlags
    }

    let window: MainWindowModel
    let rules: WindowRules
    private let slot: StatusSlot
    let menu = NSMenu(title: "App")
    private(set) var shown = false
    private(set) var image = NSImage()
    private(set) var toolTip = ""

    init(window: MainWindowModel, rules: WindowRules = .shared, slot: StatusSlot) {
        self.window = window
        self.rules = rules
        self.slot = slot
        super.init()
        menu.delegate = self
        menu.autoenablesItems = false
        build()
    }

    /// The app's slot: the system status bar, or none in a hidden launch.
    static func slot(hidden: Bool = launchHidden()) -> StatusSlot { hidden ? NoStatusSlot() : SystemStatusSlot() }

    /// S-UI-10, S-UI-11 and the lock state: on every lock and unlock signal
    /// and after the settings change (APP-08.20).
    func update() {
        let store = window.session.settings()
        let show = store.flag(key: "menubar_icon.show")
        let unlocked = window.vaults.filter { !$0.locked }.count
        toolTip = Self.toolTip(unlocked: unlocked)
        image = Self.image(unlocked: unlocked > 0, colorful: store.text(key: "menubar_icon.style") == "colorful")
        if show {
            slot.show(image: image, toolTip: toolTip, menu: menu)
        } else {
            slot.remove()
            if shown { rules.iconTurnedOff() }
        }
        shown = show
    }

    /// M08-03: how many vaults are unlocked, never their names.
    static func toolTip(unlocked: Int) -> String {
        switch unlocked {
        case 0: "App: all vaults locked"
        case 1: "App: 1 vault unlocked"
        default: "App: \(unlocked) vaults unlocked"
        }
    }

    // MARK: The menu (APP-08.21)

    func menuNeedsUpdate(_ menu: NSMenu) { build() }

    /// The items in the frame's order: the vaults, then search, generator
    /// and lock, then the window, settings and quit.
    func items() -> [Item] {
        [
            Item(
                id: "search", glyph: "magnifying-glass", title: "Search Entries…", key: " ",
                modifiers: [.option, .command]),
            Item(
                id: "generator", glyph: "password", title: "Password Generator", key: "g",
                modifiers: [.option, .command]),
            Item(
                id: "action.lock_all", glyph: "lock-key", title: "Lock Everything", key: "l",
                modifiers: [.shift, .command]),
            Item(
                id: "action.toggle_window", glyph: "app-window", title: rules.inFront ? "Hide Window" : "Show Window",
                key: "", modifiers: []),
            Item(id: "action.settings", glyph: "gear-six", title: "Settings…", key: ",", modifiers: .command),
            Item(id: "action.quit", glyph: "power", title: "Quit App", key: "q", modifiers: .command),
        ]
    }

    /// Whether the item can act now.
    func enabled(_ id: String) -> Bool {
        let state = MenuState(window: window)
        switch id {
        case "search": return state.vault != nil
        case "generator": return state.list != nil
        case "action.lock_all": return state.anyUnlocked
        default: return true
        }
    }

    func build() {
        menu.removeAllItems()
        menu.addItem(.sectionHeader(title: "Vaults"))
        for vault in window.vaults {
            let item = NSMenuItem(title: vault.name, action: #selector(showVault(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = vault.id
            item.image = Self.tile(vault)
            item.badge = NSMenuItemBadge(string: vault.locked ? "Locked" : "Unlocked")
            item.state = vault.shown ? .on : .off
            menu.addItem(item)
        }
        for (index, entry) in items().enumerated() {
            if index == 0 || entry.id == "action.toggle_window" { menu.addItem(.separator()) }
            let item = NSMenuItem(title: entry.title, action: #selector(choose(_:)), keyEquivalent: entry.key)
            item.keyEquivalentModifierMask = entry.modifiers
            item.target = self
            item.identifier = NSUserInterfaceItemIdentifier(entry.id)
            item.image = Self.glyph(entry.glyph, size: 16)
            item.isEnabled = enabled(entry.id)
            menu.addItem(item)
        }
    }

    @objc private func showVault(_ item: NSMenuItem) {
        guard let id = item.representedObject as? UInt64 else { return }
        window.switchTo(id)
        rules.bring()
    }

    @objc private func choose(_ item: NSMenuItem) {
        let state = MenuState(window: window)
        switch item.identifier?.rawValue {
        case "search":
            rules.bring()
            NotificationCenter.default.post(name: .appFind, object: nil)
        case "generator":
            rules.bring()
            state.list?.openGenerator(fromEditor: false)
        case "action.lock_all": window.lockAll(asks: true)
        case "action.toggle_window":
            if rules.inFront { rules.hideToIcon() } else { rules.bring() }
        case "action.settings":
            AppSettingsWindow.show(session: window.session)
            rules.calls.activate()
        case "action.quit": rules.calls.quit()
        default: break
        }
    }

    // MARK: Images

    /// Monochrome: a template image, so macOS colours it for the menu bar;
    /// the keyhole while a vault is unlocked, the lock otherwise. Colourful:
    /// App's mark, in grey while every vault is locked.
    static func image(unlocked: Bool, colorful: Bool) -> NSImage {
        guard colorful else {
            return glyph(unlocked ? "keyhole" : "lock-simple", size: 18, fill: true)
        }
        let mark = glyph("keyhole", size: 12, fill: true)
        let tint = unlocked ? NSColor(Tok.tileColor("teal")) : NSColor.systemGray
        let out = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { rect in
            tint.setFill()
            NSBezierPath(roundedRect: rect.insetBy(dx: 1, dy: 1), xRadius: 4, yRadius: 4).fill()
            NSColor.white.set()
            mark.draw(in: rect.insetBy(dx: 3, dy: 3), from: .zero, operation: .destinationOut, fraction: 1)
            return true
        }
        out.accessibilityDescription = "App"
        return out
    }

    /// A Phosphor glyph as a template image.
    static func glyph(_ name: String, size: CGFloat, fill: Bool = false) -> NSImage {
        let point = Glyphs.points[name].flatMap(UnicodeScalar.init).map { String(Character($0)) } ?? " "
        let font = NSFont(name: fill ? "Phosphor-Fill" : "Phosphor", size: size) ?? .systemFont(ofSize: size)
        let text = NSAttributedString(string: point, attributes: [.font: font, .foregroundColor: NSColor.black])
        let out = NSImage(size: NSSize(width: size, height: size), flipped: false) { rect in
            let box = text.size()
            text.draw(at: NSPoint(x: rect.midX - box.width / 2, y: rect.midY - box.height / 2))
            return true
        }
        out.isTemplate = true
        return out
    }

    /// The vault's tile (`.tile`, 20 points) for its row.
    static func tile(_ vault: VaultInfo) -> NSImage {
        let renderer = ImageRenderer(content: Tile(color: vault.tileColor, glyph: vault.tileGlyph, size: 20))
        renderer.scale = 2
        return renderer.nsImage ?? NSImage()
    }
}
