import AppKit
import LarsalCore
import SwiftUI

/// APP-08.5: the Vault menu.
struct VaultMenuItems: View {
    let window: MainWindowModel

    var body: some View {
        let state = MenuState(window: window)
        let shown = window.shown
        Button("Lock " + (shown?.name ?? "Vault")) { shown.map { window.lock($0.id) } }
            .keyboardShortcut("l")
            .disabled(window.main == nil)
        Button("Lock Everything") { window.lockAll(asks: true) }.keyboardShortcut("l", modifiers: [.command, .shift])
            .disabled(!state.anyUnlocked)
        Divider()
        Button("Vault Settings…") { AuxWindows.vaultSettings(window) }
            .keyboardShortcut(",", modifiers: [.command, .shift])
            .disabled(state.vault == nil)
        Button("Change Credentials…") {
            AuxWindows.vaultSettings(window)
            AuxWindows.settings?.model.page = .security
        }
        .disabled(state.vault == nil)
        Button("Reports") { state.vault?.openReports() }.keyboardShortcut("r", modifiers: [.command, .shift])
            .disabled(state.list == nil)
        // INT-04: the passkey list is the Reports page of that name.
        Button("Passkeys…") { state.vault?.openReports(.passkeys) }.disabled(state.list == nil)
        // INT-04 import and MOD-11 merge come with their stories.
        Button("Import Passkey…") {}.disabled(true)
        Button("Merge Another Vault…") {}.disabled(true)
    }
}

/// APP-08.6: the Entry menu. "One entry" is the list's selection; the copy
/// items also act on the entry the editor shows.
struct EntryMenuItems: View {
    let window: MainWindowModel

    var body: some View {
        let state = MenuState(window: window)
        let model = state.list
        let entry = state.entry
        let usable = entry != nil && entry?.inBin != true
        Button("New Entry") { model?.newEntry() }.keyboardShortcut("n").disabled(model == nil || model?.place == .bin)
        Button("Edit Entry") { model?.edit() }.keyboardShortcut("e").disabled(!usable)
        Button("Clone Entry…") { model?.askClone() }.keyboardShortcut("d").disabled(!usable)
        Button("Expire Entry") { entry.map { model?.expire($0.id) } }.disabled(entry == nil)
        Button("Delete Entry") { model?.askDelete() }.keyboardShortcut(.delete, modifiers: .command)
            .disabled(entry == nil)
        if let entry, entry.inBin {
            Button("Restore Entry") { model?.restore(entry.id) }.keyboardShortcut("r")
        }
        Divider()
        EntryCopyItems(state: state)
        Divider()
        Button("Open URL") { state.list?.openURL() }.keyboardShortcut("u")
            .disabled(state.url.isEmpty)
        // MOD-06.11 (F-094): only while S-ENTRY-11 is on (Rust says so).
        Button("Fetch Site Icon") { state.list?.fetchSiteIcon() }.keyboardShortcut("d", modifiers: [.command, .shift])
            .disabled(state.url.isEmpty)
        // INT-05 (Auto-Type) comes with its story.
        Button("Type Login") {}.keyboardShortcut("v", modifiers: [.command, .shift]).disabled(true)
        Button("Auto-Type Username Only") {}.disabled(true)
        Button("Auto-Type Password Only") {}.disabled(true)
        // INT-06: shown for an entry with an SSH key while the agent is on.
        if entry?.ssh != nil, window.session.settings().flag(key: "ssh.enabled") {
            Button("Load into SSH Agent") {}.keyboardShortcut("h", modifiers: .control).disabled(true)
            Button("Remove from SSH Agent") {}.keyboardShortcut("h", modifiers: [.control, .shift]).disabled(true)
        }
        // INT-04.46: removing from the list needs its question outside the
        // editor and the reports; the editor's Remove does it for now.
        if entry?.passkey != nil {
            Button("Remove Passkey") {}.disabled(true)
        }
        // Move Up and Move Down are hidden while the list is sorted, and
        // Larsal's list is always sorted (FEA-01), so they never show.
    }
}

/// The Entry menu's copy items (APP-03).
struct EntryCopyItems: View {
    let state: MenuState

    var body: some View {
        let model = state.vault
        let entry = state.copyEntry
        Button("Copy Username") { model?.copy("UserName") }.keyboardShortcut("b")
            .disabled(!(model?.canCopy("UserName") ?? false))
        // ⌘C runs through Edit > Copy, the first item with that key (APP-08.4).
        Button("Copy Password") { model?.copy("Password") }.keyboardShortcut("c").disabled(entry == nil)
        Button("Copy URL") { model?.copy("URL") }.keyboardShortcut("u", modifiers: [.command, .shift])
            .disabled(!(model?.canCopy("URL") ?? false))
        Menu("Copy Field") {
            Button("Title") { model?.copy("Title") }.keyboardShortcut("i")
            Button("Notes") { model?.copy("Notes") }.disabled(!(model?.canCopy("Notes") ?? false))
            ForEach(entry?.fields.filter { $0.kind == .custom }.map(\.name) ?? [], id: \.self) { name in
                Button(name) { model?.copy(name) }
            }
        }
        .disabled(entry == nil)
        Menu("One-Time Password") {
            let code = entry?.hasTotp == true
            Button("Copy One-Time Password") { model?.copyCode() }.keyboardShortcut("t").disabled(!code)
            // FEA-04: these come with their dialogs from the list.
            Button("Copy Password with Code") {}.keyboardShortcut("y").disabled(true)
            Button("Show Code") {}.keyboardShortcut("t", modifiers: [.command, .shift]).disabled(true)
            Button("Show as QR Code") {}.disabled(true)
            Button(code ? "Change One-Time Code…" : "Add One-Time Code…") {}.disabled(true)
        }
        .disabled(entry == nil)
        // MOD-07.7: tags are changed in the editor for now.
        Menu("Tags") {}.disabled(true)
    }
}

/// APP-08.7: the Group menu.
struct GroupMenuItems: View {
    let window: MainWindowModel

    var body: some View {
        let state = MenuState(window: window)
        let model = state.list
        let group: GroupRow? = {
            guard case .group(let id) = model?.place else { return nil }
            return model?.sidebar?.groups.first { $0.id == id }
        }()
        Button("New Group…") { model?.dialog = .newGroup(name: "") }.disabled(!state.group)
        // MOD-02, MOD-10, MOD-04 and MOD-06 group actions come with their
        // stories; Edit Group… opens the Sharing page (E11-S5), All entries
        // the root group's (F-178).
        let edited = model?.place == .all ? model?.sidebar?.root : group?.id
        Button("Edit Group…") { edited.map { model?.editGroup($0) } }.disabled(edited == nil)
        Button("Clone Group…") {}.disabled(true)
        Button("Delete Group…") {}.disabled(true)
        if group?.hasChildren == true {
            Button("Arrange Subgroups A to Z") {}.disabled(true)
            Button("Arrange Subgroups Z to A") {}.disabled(true)
        }
        // APP-08: the group (or the root, All entries) has entries and is
        // not the bin.
        let icons: ListView? =
            if let group { group.count > 0 ? .group(id: group.id) : nil } else {
                model?.place == .all && (model?.sidebar?.all ?? 0) > 0 ? .all : nil
            }
        Button("Fetch Site Icons for Group…") { icons.map { model?.fetchSiteIcons(in: $0) } }.disabled(icons == nil)
        if model?.place == .bin {
            Divider()
            Button("Empty Recycle Bin…") { model?.askEmptyBin() }.disabled((model?.sidebar?.bin ?? 0) == 0)
        }
    }
}

/// APP-08.8: the View menu's own items; macOS adds Enter Full Screen.
struct ViewMenuItems: View {
    let window: MainWindowModel

    var body: some View {
        let view = window.view
        Picker("Appearance", selection: Binding(get: { view.theme }, set: { view.setTheme($0, window.session) })) {
            Text("System").tag("auto")
            Text("Light").tag("light")
            Text("Dark").tag("dark")
        }
        Divider()
        Button(view.sidebar ? "Hide Sidebar" : "Show Sidebar") {
            view.set("ui.show_groups", !view.sidebar, window.session)
        }
        .keyboardShortcut("s", modifiers: [.control, .command])
        Button(view.details ? "Hide Details" : "Show Details") {
            view.set("ui.show_preview", !view.details, window.session)
        }
        Divider()
        toggle("Mask User Names", "display.hide_usernames", view.maskUserNames)
            .keyboardShortcut("b", modifiers: [.command, .shift])
        toggle("Mask Passwords", "display.hide_passwords", view.maskPasswords)
            .keyboardShortcut("c", modifiers: [.command, .shift])
        toggle("Keep Window on Top", "window.always_on_top", view.keepOnTop)
            .keyboardShortcut("a", modifiers: [.command, .shift])
        // APP-10.4: unchecked at every start unless F07; applies at once to
        // every window and is never saved.
        Toggle(
            "Permit Screen Capture",
            isOn: Binding(get: { ScreenProtection.shared.allowed }, set: { ScreenProtection.shared.allow($0) }))
    }

    private func toggle(_ title: String, _ key: String, _ value: Bool) -> some View {
        Toggle(title, isOn: Binding(get: { value }, set: { window.view.set(key, $0, window.session) }))
    }
}

/// APP-08.9: the Tools menu.
struct ToolsMenuItems: View {
    let window: MainWindowModel

    var body: some View {
        let list = MenuState(window: window).list
        // FEA-02: the toolbar's generator; its own small window for no
        // unlocked vault is not drawn in Option A (LD-214 (4)).
        Button("Password Generator") {
            Front.bring()
            list?.openGenerator(fromEditor: false)
        }
        .keyboardShortcut("g", modifiers: [.option, .command])
        .disabled(list == nil)
        if window.session.settings().flag(key: "ssh.enabled") {
            // INT-06: M08-04 and the agent call come with E9.
            Button("Remove All Keys from SSH Agent…") {}.disabled(true)
        }
    }
}

extension VaultModel {
    /// Entry > Expire Entry (MOD-09): expires now, the entry stays selected.
    func expire(_ id: String) {
        do {
            _ = try session.expireEntries(vault: vault.id, entries: [id])
            afterChange(select: id)
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }
}
