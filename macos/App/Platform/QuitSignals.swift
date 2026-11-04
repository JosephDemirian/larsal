import Darwin
import Dispatch

/// Quit by signal (APP-09.27), as Apple's dispatch documentation asks
/// (`man dispatch_source_create`): each signal is ignored, so its default
/// action never ends the process, and a dispatch source on the main queue sees
/// it and starts the orderly quit. SIGHUP is only ignored, so closing the
/// Terminal that launched App leaves App running.
enum QuitSignals {
    /// The signals that quit App.
    static let quitting: [Int32] = [SIGINT, SIGTERM, SIGQUIT]

    /// The sources, kept for the life of the process.
    private static var sources: [any DispatchSourceSignal] = []
    /// A quit signal came: the quit asks nothing (APP-02.16, E5-S10).
    static var received = false

    /// Call once, before the app runs. `onQuit` runs on the main actor for
    /// each SIGINT, SIGTERM or SIGQUIT.
    static func install(onQuit: @escaping @MainActor () -> Void) {
        signal(SIGHUP, SIG_IGN)
        sources = quitting.map { number in
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler {
                MainActor.assumeIsolated {
                    received = true
                    onQuit()
                }
            }
            source.resume()
            return source
        }
    }
}
