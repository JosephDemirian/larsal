#if DEBUG
    import LarsalCore
    import AppKit
    import SwiftUI

    /// Debug builds only: Mac QA screenshots without a window on screen
    /// (owner, 2026-10-27). In a hidden launch (`LARSAL_TEST_HIDDEN`) with
    /// `LARSAL_DEBUG_SNAPSHOT=<file.png>`, Larsal waits for the session to settle
    /// (passed-in unlocks, the header look), renders the real main window
    /// view offscreen at the mockup's 1320 × 820 points (2× pixels), writes
    /// the PNG and quits. The screen state comes from `LARSAL_DEBUG_UI` and
    /// `LARSAL_DEBUG_APPEARANCE` (DebugUI); passwords only through F06.
    enum Snapshot {
        static func startIfAsked(_ window: MainWindowModel) {
            guard launchHidden(), let out = ProcessInfo.processInfo.environment["LARSAL_DEBUG_SNAPSHOT"] else { return }
            Task {
                try? await Task.sleep(for: .seconds(1))
                for _ in 0..<100 where window.vaults.contains(where: \.unlocking) {
                    try? await Task.sleep(for: .milliseconds(100))
                }
                window.refresh()
                let host = NSHostingView(rootView: MainWindow(model: window).frame(width: 1320, height: 820))
                host.frame = NSRect(x: 0, y: 0, width: 1320, height: 820)
                // Never ordered front: it only gives the view a backing store.
                let offscreen = ScreenProtection.shared.window(
                    NSRect(x: -20_000, y: -20_000, width: 1320, height: 820), style: [.borderless])
                offscreen.appearance = NSApp.appearance
                offscreen.contentView = host
                host.layoutSubtreeIfNeeded()
                try? await Task.sleep(for: .milliseconds(800))
                write(host, to: out)
                exit(0)
            }
        }

        private static func write(_ view: NSView, to path: String) {
            guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { exit(1) }
            view.cacheDisplay(in: view.bounds, to: rep)
            guard let png = rep.representation(using: .png, properties: [:]) else { exit(1) }
            do {
                try png.write(to: URL(fileURLWithPath: path))
            } catch {
                exit(1)
            }
        }
    }
#endif
