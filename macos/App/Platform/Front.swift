import AppCore
import AppKit

/// APP-09.22, the one way to front for every trigger: the channel's
/// `activate` and `open`, the Dock icon, App becoming active, the menu bar
/// icon's menu and the menus that show a vault (WindowRules.swift).
enum Front {
    static func bring() { WindowRules.shared.bring() }
}

/// The window side of the instance channel and the session. Rust calls it
/// on its own threads; the work runs on the main actor.
nonisolated final class WindowEvents: AppEvents {
    private let window: MainWindowModel

    init(window: MainWindowModel) {
        self.window = window
    }

    func bringToFront() {
        Task { @MainActor in Front.bring() }
    }

    func sessionChanged() {
        Task { @MainActor [window] in
            // M06-35 (INT-07.19): a touch wait starts or ends with a change.
            KeyTouch.shared.waits = securityKeyWaits()
            window.refresh()
        }
    }

    /// APP-09.12 `lock` (LD-217 (4)): the channel has answered; the lock
    /// runs as the lock signals' (APP-02.16): save, recovery copy, lock.
    func lockAll() {
        Task { @MainActor [window] in window.lockAll() }
    }

    /// LD-277 (4): an F06 passed-in unlock reads its file in a coordinated
    /// read off the main thread, once the file is on this Mac.
    func onFile(path: String, work: FileWork) {
        Task { @MainActor in await FileAccess.run(.read, path) { work.run() } }
    }
}
