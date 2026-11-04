import AppCore
import AppKit

#if !DEBUG
    // A Release app never runs a debug core: its debug lock and socket names
    // and the test variable must not run under the release bundle id.
    if coreIsDebug() {
        let line =
            "App cannot start: this release build holds a debug core. "
            + "Build it with scripts/build-core.sh --release.\n"
        FileHandle.standardError.write(Data(line.utf8))
        exit(1)
    }
#endif

// APP-09.1: steps 1 to 9 run in Rust before anything of AppKit exists:
// hardening, flags, help, version, debug info, the single-instance check, the
// crypto self-test and the F06 password lines, which stay in Rust. Rust prints
// every message; Swift only exits, shows the M09-06 alert, or runs the app.
switch start() {
case .exit(let code):
    exit(code)
case .refuse(let message, let alert):
    if alert {
        NSApplication.shared.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        // APP-10.1: protected like every window of App.
        let box = ScreenProtection.shared.alert()
        box.alertStyle = .critical
        box.messageText = message
        box.runModal()
    }
    exit(1)
case .run:
    // File arguments are F01, handled in Rust; AppKit must not also turn them
    // into open events (APP-09.6, APP-09.23).
    UserDefaults.standard.register(defaults: ["NSTreatUnknownArgumentsAsOpen": "NO"])
    QuitSignals.install { NSApp.terminate(nil) }
    if launchHidden() {
        HiddenLaunch.run()
    } else {
        AppMain.main()
    }
}
