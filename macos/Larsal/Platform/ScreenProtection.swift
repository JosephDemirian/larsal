import AppKit
import LarsalCore
import Observation

/// Screen protection (SC-05, AT-D04, APP-10.1 to APP-10.7): every window of
/// Larsal has sharing type none (`NSWindowSharingNone`) from its creation, so
/// the window server keeps its pixels from other processes, unless capture
/// is allowed for this run: F07 or View > Permit Screen Capture, never saved.
/// How each capture path honours it on this Mac is Mac QA (V-A10-1).
///
/// One rule (`adopt`), three ways in: the windows Larsal makes come from
/// `window(_:style:)` (deferred: the window server makes each one only when
/// it is needed, and AppKit gives it the type set here before its size or
/// content, F-131) and `alert()`, protected before anything can order
/// them in; the main window adopts itself as its content moves in
/// (`WindowChromeView`); the windows AppKit and SwiftUI make for Larsal
/// (alerts, sheets, popovers, tooltips, menus, the About panel, open and
/// save panels, the text input window) are adopted as the window server
/// numbers them (F-131), on every pass of the main run loop before Core
/// Animation sends a frame, and as a sheet or popover is about to show.
@MainActor
@Observable
final class ScreenProtection {
    static let shared = ScreenProtection()

    /// M10-01 (APP-10.6).
    static let refusedText = "Warning: screen capture could not be blocked for one of Larsal's windows."
    /// Before Core Animation's commit (order 2,000,000), which sends each
    /// window's frame to the window server.
    static let order = 1_999_999
    /// F-131: AppKit's notice, posted inside each window's init once the
    /// window server has numbered it (a deferred one: before it has a
    /// number). Not in AppKit's headers, so the run loop pass stays as the
    /// net, and `f131AdoptedWhenNumbered` fails if AppKit stops posting it.
    static let numbered = Notification.Name("_NSWindowDidChangeWindowNumber")

    /// ACT-ALLOW-CAPTURE: capture is allowed until quit (F07 at start).
    private(set) var allowed = false
    /// Shows M10-01 in the main window (set by the app delegate).
    @ObservationIgnored var refused: () -> Void = {}
    /// Every window of Larsal; tests give their own.
    @ObservationIgnored var windows: () -> [NSWindow] = { NSApp?.windows ?? [] }
    @ObservationIgnored private var watching = false
    @ObservationIgnored private let reported = NSHashTable<NSWindow>.weakObjects()

    /// The sharing type of every window now (APP-10.2).
    var sharing: NSWindow.SharingType { allowed ? .readOnly : .none }

    /// APP-09.1 step 10, before the first window: F07, then the watch for
    /// windows Larsal does not make itself.
    func start(allowCapture: Bool, center: NotificationCenter = .default) {
        allowed = allowCapture
        #if DEBUG
            WindowListing.startIfAsked()  // F-131's check, before the first window
        #endif
        sweep()
        guard !watching else { return }
        watching = true
        let pass = CFRunLoopActivity([.beforeWaiting, .exit]).rawValue
        let observer = CFRunLoopObserverCreateWithHandler(nil, pass, true, Self.order) { [weak self] _, _ in
            MainActor.assumeIsolated { self?.sweep() }
        }
        CFRunLoopAddObserver(CFRunLoopGetMain(), observer, .commonModes)
        for name in [NSWindow.willBeginSheetNotification, NSPopover.willShowNotification] {
            center.addObserver(forName: name, object: nil, queue: nil) { [weak self] _ in
                MainActor.assumeIsolated { self?.sweep() }
            }
        }
        // F-131: each window as it is made, before its init returns.
        center.addObserver(forName: Self.numbered, object: nil, queue: nil) { [weak self] note in
            // Not public: one posted off the main thread is left to the pass.
            guard Thread.isMainThread, let window = note.object as? NSWindow else { return }
            MainActor.assumeIsolated { self?.adopt(window) }
        }
    }

    /// ACT-ALLOW-CAPTURE (APP-10.4): applies at once to every open window;
    /// later windows follow. Never saved.
    func allow(_ capture: Bool) {
        allowed = capture
        reported.removeAllObjects()
        sweep()
    }

    /// Sets one window's sharing type and reads it back (APP-10.6): AppKit's
    /// setter reports no failure, so a window still capturable while capture
    /// is not allowed shows M10-01, once per window. The window stays open.
    func adopt(_ window: NSWindow) {
        let wanted = sharing
        if window.sharingType != wanted { window.sharingType = wanted }
        guard !allowed, window.sharingType != .none, !reported.contains(window) else { return }
        reported.add(window)
        refused()
    }

    func sweep() {
        for window in windows() { adopt(window) }
    }

    /// The one way Larsal makes a window (APP-10.1): protected before it can be
    /// ordered in or drawn. Deferred (F-131): the window server makes no
    /// window for it until it is needed (ordered in), and AppKit gives that
    /// window the type set here before its size or content.
    func window(_ frame: NSRect, style: NSWindow.StyleMask) -> NSWindow {
        let window = NSWindow(contentRect: frame, styleMask: style, backing: .buffered, defer: true)
        adopt(window)
        return window
    }

    /// An alert Larsal runs itself, protected before it shows.
    func alert() -> NSAlert {
        let alert = NSAlert()
        adopt(alert.window)
        return alert
    }
}

#if DEBUG
    /// F-131's check, debug builds only. In a hidden launch with
    /// `LARSAL_TEST_WINDOW_LISTING=1`, a background thread started before the
    /// first window reads Larsal's own windows in the window server's list every
    /// 0.5 ms and appends each change to `listing` in `LARSAL_TEST_INSTANCE_DIR`:
    /// number, sharing state, size, on screen. Metadata only, never pixels or
    /// names. Only Larsal itself reads its windows' true sharing state: another
    /// process without screen capture access reads 0 for every window.
    nonisolated enum WindowListing {
        static let listing = "window-listing.txt"

        static func startIfAsked() {
            let env = ProcessInfo.processInfo.environment
            guard launchHidden(), env["LARSAL_TEST_WINDOW_LISTING"] == "1", let dir = env["LARSAL_TEST_INSTANCE_DIR"]
            else { return }
            let path = URL(fileURLWithPath: dir).appending(path: listing).path
            guard FileManager.default.createFile(atPath: path, contents: nil),
                let out = FileHandle(forWritingAtPath: path)
            else { return }
            let pid = getpid()
            Thread.detachNewThread {
                var seen: [Int: String] = [:]
                var first = true
                while true {
                    let all = CGWindowListCopyWindowInfo([.optionAll], kCGNullWindowID) as? [[String: Any]] ?? []
                    let mine = all.filter { ($0[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value == pid }
                    var text = first ? "pid \(pid), windows \(mine.count)\n" : ""
                    first = false
                    for info in mine {
                        let (number, line) = entry(info)
                        if seen[number] != line {
                            seen[number] = line
                            text += "\(number) \(line)\n"
                        }
                    }
                    if !text.isEmpty { out.write(Data(text.utf8)) }
                    usleep(500)
                }
            }
        }

        /// One window: sharing state, size and whether it is on screen.
        private static func entry(_ info: [String: Any]) -> (Int, String) {
            let value = { (key: CFString) in (info[key as String] as? NSNumber)?.intValue ?? -1 }
            let bounds = info[kCGWindowBounds as String] as? [String: Any] ?? [:]
            let size = ["Width", "Height"].map { (bounds[$0] as? NSNumber)?.intValue ?? -1 }
            let shown = value(kCGWindowIsOnscreen) == 1
            return (value(kCGWindowNumber), "sharing \(value(kCGWindowSharingState)), \(size), on screen \(shown)")
        }
    }
#endif
