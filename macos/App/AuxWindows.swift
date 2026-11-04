import AppCore
import AppKit
import SwiftUI

/// The new vault wizard's and the vault settings' own windows (E5-S8): one
/// of each at a time (APP-07.1); a second start brings it to the front.
/// Tests never order a window front: they put a fake in `present`, and a
/// hidden test launch shows none (AGENTS.md rule 10).
enum AuxWindows {
    /// Orders a window front; tests replace it.
    static var present: (NSWindow) -> Void = { window in
        guard !launchHidden() else { return }
        window.makeKeyAndOrderFront(nil)
    }

    private(set) static var wizard: (model: NewVaultModel, window: NSWindow)?
    private(set) static var settings: (model: VaultSettingsModel, window: NSWindow)?
    private static let closer = Closer()

    /// File > New Vault…, ⇧⌘N, the vault menu and the welcome screen.
    static func newVault(_ main: MainWindowModel) {
        if let wizard {
            present(wizard.window)
            return
        }
        let model = NewVaultModel(session: main.session)
        let window = make("New Vault", width: 720, height: 720, root: NewVaultView(model: model))
        model.created = { [weak main] id in
            guard let main else { return }
            main.refresh()
            if let made = main.vaults.first(where: { $0.id == id }) {
                let path = (made.path as NSString).expandingTildeInPath
                // APP-07.18: the new path tops the recent list.
                main.recents.removeAll { $0.path == path }
                main.recents.insert(.init(look: vaultLook(path: path), path: path, opened: Clock.now()), at: 0)
            }
        }
        model.closed = {
            wizard?.window.close()
            wizard = nil
        }
        wizard = (model, window)
        present(window)
    }

    /// Vault Settings…, ⇧⌘, (MOD-12.21: only for an unlocked vault).
    static func vaultSettings(_ main: MainWindowModel) {
        // MOD-13.8: not behind the forced key change prompt.
        guard let shown = main.shown, !shown.locked, shown.keyChange == nil else { return }
        if let settings, settings.model.vault.id == shown.id {
            present(settings.window)
            return
        }
        settings?.window.close()
        let model = VaultSettingsModel(session: main.session, vault: shown)
        model.changed = { [weak main] in
            main?.refresh()
            main?.main?.afterChange(select: main?.main?.selection)
        }
        let window = make("Vault Settings", width: 900, height: 640, root: VaultSettingsWindow(model: model))
        settings = (model, window)
        present(window)
    }

    /// The session changed: the settings of a vault that locked or closed
    /// go (MOD-12.21).
    static func sessionChanged(_ main: MainWindowModel) {
        guard let settings else { return }
        let vault = main.vaults.first { $0.id == settings.model.vault.id }
        if vault == nil || vault?.locked == true {
            settings.model.clearPassword()
            settings.window.close()
            self.settings = nil
        }
    }

    /// The window's close button: the wizard's Cancel; the settings go.
    fileprivate static func closing(_ window: NSWindow) -> Bool {
        if let wizard, wizard.window === window {
            wizard.model.cancel()
            return false
        }
        if let settings, settings.window === window {
            settings.model.clearPassword()
            self.settings = nil
        }
        return true
    }

    private static func make(_ title: String, width: CGFloat, height: CGFloat, root: some View) -> NSWindow {
        let window = ScreenProtection.shared.window(
            NSRect(x: 0, y: 0, width: width, height: height),
            style: [.titled, .closable, .miniaturizable, .fullSizeContentView])
        window.title = title
        window.isReleasedWhenClosed = false
        window.contentViewController = NSHostingController(rootView: root.frame(width: width, height: height))
        window.delegate = closer
        window.center()
        return window
    }

    private final class Closer: NSObject, NSWindowDelegate {
        func windowShouldClose(_ sender: NSWindow) -> Bool { AuxWindows.closing(sender) }
    }
}

extension Later {
    /// The Recycle Bin page's age rule: no card owns it yet (E5-S8 report).
    static let autoEmpty = "Emptying the Recycle Bin by age comes later."
}

/// The wizard's panels (never shown by tests, AGENTS.md rule 10).
extension NewVaultModel {
    /// Save in's Change…: a folder.
    static var chooseFolder: (URL) -> URL? = { start in
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.directoryURL = start
        panel.prompt = "Choose"
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// "Create a key file"'s Change…: where the new key file goes.
    static var keyFileSavePanel: (URL) -> URL? = { start in
        let panel = NSSavePanel()
        panel.directoryURL = start.deletingLastPathComponent()
        panel.nameFieldStringValue = start.lastPathComponent
        panel.canCreateDirectories = true
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// "Choose Key File…" (APP-07.14): any file.
    static var openKeyFile: () -> URL? = {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.directoryURL = URL(fileURLWithPath: NSHomeDirectory())
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// APP-07.17: the extension is always `.appvault`.
    nonisolated static func withVaultExtension(_ url: URL) -> URL {
        url.pathExtension.lowercased() == "appvault" ? url : url.appendingPathExtension("appvault")
    }

    func changeFolder() {
        if let picked = NewVaultModel.chooseFolder(folder) { folder = picked }
    }

    func changeKeyFilePath() {
        if let picked = NewVaultModel.keyFileSavePanel(keyFilePath) { keyFilePath = picked }
    }

    func pickKeyFile() {
        if let picked = NewVaultModel.openKeyFile() { chooseKeyFile(picked.path(percentEncoded: false)) }
    }
}
