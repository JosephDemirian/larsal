import AppCore
import AppKit
import SwiftUI

/// The settings window (⌘, and the sidebar's Settings): one at a time,
/// 900 by 680, its buttons over the nav as Option A draws them. Closing is
/// OK (APP-01.3: stores every page; a store failure keeps it open with the
/// error, APP-01.12); Escape is Cancel.
@MainActor
final class AppSettingsWindow: NSObject, NSWindowDelegate {
    private static var current: AppSettingsWindow?
    private let window: NSWindow
    private let model: AppSettingsModel
    private var cancelled = false

    private init(session: Session) {
        model = AppSettingsModel(session: session)
        window = ScreenProtection.shared.window(
            NSRect(x: 0, y: 0, width: 900, height: 680),
            style: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView])
        super.init()
        window.isReleasedWhenClosed = false
        window.title = "Settings"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        window.contentMinSize = NSSize(width: 760, height: 520)
        window.delegate = self
        window.contentView = NSHostingView(
            rootView: AppSettingsView(model: model) { [weak self] in self?.closeCancelled() })
    }

    /// Opens the settings, at `page` when one is given (Help > Keyboard
    /// Shortcuts shows the Shortcuts page, APP-08.11).
    static func show(session: Session, page: AppSettingsPage? = nil) {
        if let current {
            if let page { current.model.go(page) }
            current.window.makeKeyAndOrderFront(nil)
            return
        }
        let shown = AppSettingsWindow(session: session)
        current = shown
        if let page { shown.model.go(page) }
        shown.window.center()
        shown.window.makeKeyAndOrderFront(nil)
    }

    private func closeCancelled() {
        cancelled = true
        window.close()
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        cancelled || model.ok()
    }

    func windowWillClose(_ notification: Notification) {
        if cancelled { model.cancel() }
        Self.current = nil
    }
}
