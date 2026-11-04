import AppCore
import SwiftUI

/// UL-HW and the remembered key parts (APP-06.8, APP-06.9; F-080, F-107).
/// Only the list items and the chosen serial and slot live here; the
/// challenge and its answer stay in Rust.
extension UnlockModel {
    /// APP-06.9: the remembered key file and slot (S-START-08), then the
    /// key watch (APP-06.8, F-126): a look now, another 0.5 s after a key
    /// is plugged in while this screen shows.
    func prefillKeys() {
        if let remembered = try? session.rememberedKeys(vault: vault.id) {
            if keyFile.isEmpty, let path = remembered.keyFile { keyFile = path }
            rememberedPick = remembered.hardware
        }
        keyPicker.afterLook = { [weak self] in self?.chooseKey() }
        keyPicker.start()
    }

    /// APP-06.8 after each look: one item is chosen; a remembered slot in
    /// the list is chosen with the switch on; no item turns the switch off.
    func chooseKey() {
        let picks = keyPicker.keys.map(\.pick)
        let same = { (lhs: KeyPick, rhs: KeyPick) in lhs.serial == rhs.serial && lhs.slot == rhs.slot }
        if let remembered = rememberedPick, let found = picks.first(where: { same($0, remembered) }) {
            pick = found
            useKey = true
        } else if let current = pick, let found = picks.first(where: { same($0, current) }) {
            pick = found
        } else {
            pick = picks.count == 1 ? picks.first : nil
        }
        if picks.isEmpty { useKey = false }
    }

    /// UL-HW's second line: the chosen item, or why nothing can be chosen.
    var keyText: String {
        if keyPicker.looking { return "Looking for keys…" }
        if let pick, let item = keyPicker.keys.first(where: { $0.pick == pick }) { return item.label }
        return keyPicker.keys.isEmpty ? "No security key found" : "Choose a key and slot"
    }
}

/// UL-HW (APP-06.8, F-107): Option A's row (icon, name, chosen item,
/// switch); the list and "Look for keys again" are its context menu.
struct SecurityKeyRow: View {
    let model: UnlockModel

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image("brand-yubico", bundle: appBundle).resizable().frame(width: 16, height: 16)
                    .accessibilityLabel(Text(verbatim: "Yubico"))
                VStack(alignment: .leading, spacing: 0) {
                    Text(verbatim: "Security key").frame(height: 20)
                    Text(verbatim: model.useKey || model.keyPicker.looking ? model.keyText : "Not used")
                        .font(.sans(12)).foregroundStyle(Tok.muted).lineLimit(1).frame(height: 20)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                // APP-06.8 (F-107): switching on with no key found looks again.
                Toggle(isOn: Binding(get: { model.useKey }, set: { useKey($0) })) {
                    Text(verbatim: "Use a security key")
                }
                .toggleStyle(SwitchStyle())
                .disabled(model.keyPicker.looking)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .padding(.top, 1)
            .overlay(alignment: .top) { Rectangle().fill(Tok.rule).frame(height: 1) }
            .contentShape(Rectangle())
            .contextMenu {
                // UL-HW's list and "Look for keys again" (Option A draws only the row).
                ForEach(model.keyPicker.keys, id: \.pick) { item in
                    Button(item.label) {
                        model.pick = item.pick
                        model.useKey = true
                    }
                }
                Button("Look for Keys Again", action: model.keyPicker.lookAgain)
            }
            if let note = model.keyPicker.note {
                Text(verbatim: note).font(.sans(12)).foregroundStyle(Tok.muted)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12).padding(.bottom, 8)
            }
        }
    }

    /// Switching on with no key found looks again; a look that finds none
    /// turns it off.
    private func useKey(_ wanted: Bool) {
        model.useKey = wanted
        if wanted, model.keyPicker.keys.isEmpty { model.keyPicker.lookAgain() }
    }
}
