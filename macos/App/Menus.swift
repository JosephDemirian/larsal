import AppCore
import SwiftUI

/// The vault menu (mockup `overlay === 'vault'`): the open vaults, then
/// open, lock and the later items.
struct VaultMenu: View {
    let window: MainWindowModel

    var body: some View {
        let shown = window.shown
        MenuPanel(width: 300) {
            MenuHeader(title: "Open vaults")
            ForEach(window.vaults, id: \.id) { vault in
                MenuItem(
                    lead: .tile(vault.tileColor, vault.tileGlyph), title: vault.name, keys: vault.locked ? nil : "Open",
                    keyGlyph: vault.locked ? "lock-simple" : nil, current: vault.shown
                ) { window.switchTo(vault.id) }
                .accessibilityLabel(Text(verbatim: vault.name + (vault.locked ? ", locked" : ", open")))
            }
            MenuSeparator()
            MenuItem(lead: .glyph("plus-circle"), title: "New Vault…", keys: "⇧⌘N") {
                window.vaultMenu = false
                AuxWindows.newVault(window)
            }
            MenuItem(lead: .glyph("folder-open"), title: "Open Vault…", keys: "⌘O") {
                window.vaultMenu = false
                window.chooseVault()
            }
            MenuItem(lead: .glyph("download-simple"), title: "Import…", hint: Later.importer) {}
                .disabled(true)
            MenuSeparator()
            MenuItem(lead: .glyph("sliders-horizontal"), title: "Vault Settings…", keys: "⇧⌘,") {
                window.vaultMenu = false
                AuxWindows.vaultSettings(window)
            }
            .disabled(shown?.locked ?? true)
            MenuItem(lead: .glyph("lock-simple"), title: "Lock " + (shown?.name ?? ""), keys: "⌘L") {
                if let shown { window.lock(shown.id) }
            }
            .disabled(shown?.locked ?? true)
            MenuItem(lead: .glyph("lock-key"), title: "Lock Everything", keys: "⇧⌘L") { window.lockAll(asks: true) }
        }
    }
}

/// The entry menu (mockup `overlay === 'more'`, APP-08 shortcuts). Most
/// items belong to later stories: drawn, disabled, with a hint.
struct MoreMenu: View {
    let model: VaultModel

    var body: some View {
        let url = model.detail?.fields.first { $0.kind == .url }?.value ?? ""
        MenuPanel(width: 244) {
            MenuItem(lead: .glyph("copy"), title: "Copy Username", keys: "⌘B") { model.copy("UserName") }
                .disabled(!model.canCopy("UserName"))
            MenuItem(lead: .glyph("copy"), title: "Copy Password", keys: "⌘C") { model.copy("Password") }
                .disabled(model.detail == nil)
            MenuItem(lead: .glyph("link"), title: "Copy URL", keys: "⇧⌘U") { model.copy("URL") }
                .disabled(!model.canCopy("URL"))
            MenuItem(lead: .glyph("clock-countdown"), title: "Copy One-Time Code", keys: "⌘T") { model.copyCode() }
                .disabled(model.detail?.hasTotp != true)
            MenuSeparator()
            MenuItem(lead: .glyph("keyboard"), title: "Type Login", keys: "⇧⌘V", hint: Later.autoType) {}
                .disabled(true)
            MenuItem(lead: .glyph("arrow-square-out"), title: "Open URL", keys: "⌘U") {
                model.overlay = nil
                model.openURL()
            }
            .disabled(url.isEmpty)
            MenuItem(lead: .glyph("qr-code"), title: "Show Code as QR", keys: "", hint: Later.dialogs) {}
                .disabled(true)
            MenuSeparator()
            MenuItem(lead: .glyph("copy-simple"), title: "Clone Entry…", keys: "⌘D") { model.askClone() }
                .disabled(model.detail == nil || model.detail?.inBin == true)
            MenuItem(lead: .glyph("folder-simple"), title: "Move to Group ▸", keys: "", hint: Later.editor) {}
                .disabled(true)
            MenuItem(lead: .glyph("clock-counter-clockwise"), title: "History", keys: "") {
                model.edit()
                model.editor?.page = .history
            }
            .disabled(model.detail == nil || model.detail?.inBin == true || model.detail?.history == 0)
            MenuSeparator()
            MenuItem(lead: .glyph("trash"), title: "Move to Recycle Bin", keys: "⌘⌫", negative: true) {
                model.askDelete()
            }
            .disabled(model.detail == nil)
        }
    }
}

/// The sort menu (mockup `overlay === 'sort'`).
struct SortMenu: View {
    let model: VaultModel

    var body: some View {
        MenuPanel(minWidth: 200) {
            MenuHeader(title: "Sort by")
            ForEach(VaultModel.Sort.allCases, id: \.self) { key in
                MenuItem(lead: .check(model.sort == key), title: key.rawValue) { model.setSort(key) }
                    .accessibilityAddTraits(model.sort == key ? .isSelected : [])
            }
            MenuSeparator()
            MenuItem(lead: .check(!model.ascending), title: "Newest first") { model.setAscending(false) }
                .accessibilityAddTraits(model.ascending ? [] : .isSelected)
            MenuItem(lead: .check(model.ascending), title: "Oldest first") { model.setAscending(true) }
                .accessibilityAddTraits(model.ascending ? .isSelected : [])
        }
    }
}
