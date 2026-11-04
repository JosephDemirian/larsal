import AppKit
import SwiftUI

/// The Mac app: one window with a hidden title bar over the Rust core.
/// Started from main.swift once Rust has made this process the primary.
struct LarsalMain: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        Window("Larsal", id: "main") {
            MainWindow(model: delegate.window)
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1320, height: 820)
        .commands { LarsalCommands(window: delegate.window) }
    }
}
