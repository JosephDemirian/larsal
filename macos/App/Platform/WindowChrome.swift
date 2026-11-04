import AppKit
import SwiftUI

/// The main window's chrome (LD-163 (1)), the standard way: an empty unified
/// toolbar makes the title bar 52 points tall, so macOS centres the window
/// buttons in the top bar; the content runs under it (full-size content
/// view, transparent title bar, no title).
enum WindowChrome {
    static func apply(to window: NSWindow) {
        guard window.toolbar == nil else { return }
        window.styleMask.insert(.fullSizeContentView)
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.toolbar = NSToolbar(identifier: "main")
        window.toolbarStyle = .unified
    }
}

/// Applies `WindowChrome` to the window that shows it; the main window also
/// takes App's close and minimize rules (WindowRules).
struct WindowChromeView: NSViewRepresentable {
    var main = false

    func makeNSView(context: Context) -> NSView { Host(main: main) }
    func updateNSView(_ view: NSView, context: Context) {}

    private final class Host: NSView {
        let main: Bool

        init(main: Bool) {
            self.main = main
            super.init(frame: .zero)
        }

        required init?(coder: NSCoder) { nil }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard let window else { return }
            // APP-10.1: the main window, made by SwiftUI, before it draws.
            ScreenProtection.shared.adopt(window)
            WindowChrome.apply(to: window)
            if main { WindowRules.shared.attach(window) }
        }
    }
}
