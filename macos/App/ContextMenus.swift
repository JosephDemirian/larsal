import AppCore
import SwiftUI

/// APP-08.13: the right-click menu of an entry row, with the items of
/// "More actions" in its order and words (states-more-menu). Each item acts
/// on the clicked row, which it selects first.
struct EntryContextMenu: View {
    let model: VaultModel
    let row: EntryRow

    var body: some View {
        if model.place == .bin {
            item("Restore entry") { model.restore(row.id) }
            item("Delete permanently") { model.askDelete() }
        } else {
            item("Copy Username") { model.copy("UserName") }
            item("Copy Password") { model.copy("Password") }
            item("Copy URL") { model.copy("URL") }
            item("Copy One-Time Code") { model.copyCode() }.disabled(!row.hasTotp)
            Divider()
            Button("Type Login") {}.disabled(true)
            item("Open URL") { model.openURL() }.disabled(row.host.isEmpty)
            Button("Show Code as QR") {}.disabled(true)
            Divider()
            item("Clone Entry…") { model.askClone() }
            Button("Move to Group") {}.disabled(true)
            item("History") {
                model.edit()
                model.editor?.page = .history
            }
            Divider()
            item("Move to Recycle Bin") { model.askDelete() }
        }
    }

    private func item(_ title: String, _ action: @escaping () -> Void) -> some View {
        Button(title) {
            model.select(row.id)
            action()
        }
        .disabled(model.editor != nil)
    }
}

/// APP-08.13: the right-click menu of a sidebar group: the Group menu's
/// items for that group, which it shows first.
struct GroupContextMenu: View {
    let model: VaultModel
    let group: GroupRow

    var body: some View {
        Button("New Group…") {
            model.choose(.group(group.id))
            model.dialog = .newGroup(name: "")
        }
        .disabled(model.editor != nil)
        Button("Edit Group…") { model.editGroup(group.id) }
            .disabled(model.editor != nil || model.sharing.editor != nil)
        Button("Clone Group…") {}.disabled(true)
        Button("Delete Group…") {}.disabled(true)
        if group.hasChildren {
            Button("Arrange Subgroups A to Z") {}.disabled(true)
            Button("Arrange Subgroups Z to A") {}.disabled(true)
        }
        // APP-08: the group has entries (the bin is no row here).
        Button("Fetch Site Icons for Group…") { model.fetchSiteIcons(in: .group(id: group.id)) }
            .disabled(model.editor != nil || group.count == 0)
    }
}

extension View {
    /// APP-08.14: in the entry list, Return edits the selected entry; ⌫ and
    /// ⌦ delete it (with the question of MOD-04).
    func entryKeys(_ model: VaultModel) -> some View {
        onKeyPress(.return) {
            guard model.detail?.inBin == false else { return .ignored }
            model.edit()
            return .handled
        }
        .onKeyPress(keys: [.delete, .deleteForward]) { _ in
            guard model.detail != nil else { return .ignored }
            model.askDelete()
            return .handled
        }
    }
}
