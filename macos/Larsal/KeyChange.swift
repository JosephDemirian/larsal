import LarsalCore
import Observation
import SwiftUI

/// MOD-13.8 (F-074): the forced key change prompt, in place of the vault's
/// screen until a new master key is applied; nothing of the vault's content
/// is read for it, and Rust counts the vault as locked for Auto-Type and the
/// SSH agents meanwhile. Change Now opens the credentials page alone
/// (MOD-12.10: the password, key file and security key rows of the vault
/// settings); its Cancel returns here; Lock locks the vault again.
@Observable
final class KeyChangeModel {
    let vault: VaultInfo
    let words: String
    /// The credentials page, after Change Now.
    private(set) var settings: VaultSettingsModel?
    @ObservationIgnored private weak var window: MainWindowModel?

    init(window: MainWindowModel, vault: VaultInfo, words: String) {
        self.window = window
        self.vault = vault
        self.words = words
    }

    func changeNow() {
        guard let window, settings == nil else { return }
        let model = VaultSettingsModel(session: window.session, vault: vault)
        model.changed = { [weak self] in self?.applied() }
        settings = model
    }

    /// The credentials page's Cancel (MOD-13.8): back to the prompt, the
    /// typed passwords wiped.
    func cancel() {
        settings?.clearPassword()
        settings = nil
    }

    func lock() { window?.lock(vault.id) }

    /// The new key is applied: the vault saves, then opens; a failed save
    /// still opens it, marked unsaved, with the save error (MOD-13.9).
    private func applied() {
        guard let window else { return }
        let (session, id, file) = (window.session, vault.id, vault.path)
        Task { [weak window] in
            let status = await FileAccess.run(.replace, file) { try? session.save(vault: id) }
            guard let window, (try? session.endKeyChange(vault: id)) == true else { return }
            window.refresh()
            if let status { window.main?.saved(status, asks: true) }
        }
    }
}

/// The prompt (`keychange.msg.forced`): the reason in Rust's words, Change
/// Now (the default) and Lock.
struct KeyChangeView: View {
    let model: KeyChangeModel

    var body: some View {
        ZStack(alignment: .top) {
            Tok.ground
            DialogCard(
                tint: "orange", glyph: "key", title: "Change the master key of “\(model.vault.name)”", text: model.words
            ) {
                SheetButton(title: "Lock", action: model.lock)
                SheetButton(title: "Change Now", kind: .primary, action: model.changeNow)
            }
            .padding(.top, 52)
            if let settings = model.settings {
                ZStack(alignment: .top) {
                    Tok.scrim.contentShape(Rectangle()).accessibilityHidden(true)
                    DialogCard(
                        tint: "blue", glyph: "lock-key", title: "Credentials",
                        text: "Change at least one part. The vault opens after Larsal saves the new master key.",
                        wide: true
                    ) {
                        CredentialRows(model: settings).padding(.top, 18)
                    } foot: {
                        SheetButton(title: "Cancel", action: model.cancel)
                    }
                    .padding(.top, 52)
                    .onExitCommand(perform: model.cancel)
                    SettingsSheet(model: settings)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// MOD-13.10 (F-074): the recommended key change in the vault view, once per
/// unlock; the vault stays usable. Change Now opens the vault settings'
/// password sheet, Later hides it until the next unlock.
struct KeyChangeNotice: View {
    let model: VaultModel
    let window: MainWindowModel

    var body: some View {
        if let text = model.keyChangeNotice {
            HStack(spacing: 12) {
                Glyph(name: "key").foregroundStyle(Tok.warning)
                Text(verbatim: text).lineLimit(2).fixedSize(horizontal: false, vertical: true)
                Button("Change Now") {
                    model.keyChangeNotice = nil
                    AuxWindows.vaultSettings(window)
                    AuxWindows.settings?.model.page = .security
                    AuxWindows.settings?.model.askPassword()
                }
                .buttonStyle(Btn(size: .small))
                Button("Later") { model.keyChangeNotice = nil }.buttonStyle(Btn(size: .small))
            }
            .font(.sans(13))
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .frame(maxWidth: 620)
            .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
            .accessibilityElement(children: .contain)
            .accessibilityAddTraits(.updatesFrequently)
        }
    }
}
