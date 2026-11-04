import AppKit

/// A debug-only launch for tests and Mac QA snapshots (`APP_TEST_HIDDEN`,
/// read by Rust, ignored in release builds): the app delegate runs as usual
/// (start-up, the session, the instance channel, Finder opens), but there is
/// no window and the app may never become active, so a test run never takes
/// the owner's screen.
enum HiddenLaunch {
    /// NSApplication keeps its delegate weakly.
    private static var delegate: AppDelegate?

    static func run() {
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        let appDelegate = AppDelegate()
        delegate = appDelegate
        app.delegate = appDelegate
        app.run()
    }
}
