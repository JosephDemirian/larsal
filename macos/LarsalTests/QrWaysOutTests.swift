import AppKit
import LarsalCore
import SwiftUI
import Testing

/// What ends a code from outside the dialog (FEA-10.15): a confirmed panel, a
/// chosen share service, the window's own ways off the screen, macOS's saved
/// state and the screen lock. Fake panels, fake windows, private centers; never
/// a real panel, picker or notification (AGENTS.md rule 10).
@MainActor
@Suite(.serialized)
struct QrWaysOutTests {
    init() { ParityDemo.setUp() }

    @Test("QR-T18 FEA-10.15: a confirmed panel stays when covered, with no pixels; blur, hide, a vault switch end it")
    func confirmedSystemUI() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        var closed = 0
        VaultModel.qrSavePanel = { _ in { closed += 1 } }
        let fake = NSWindow(contentRect: .zero, styleMask: [.borderless], backing: .buffered, defer: true)
        seams.mainWindow = fake
        let demo = try QrDemo.window("qr-system-ui")
        defer { demo.window.lockAll() }
        let (main, id) = (demo.main, demo.entry)
        let local = seams.centers.local
        func exporting() async throws -> QrPopup {
            main.showQr()
            let popup = try await QrDemo.painted(main)
            popup.ask(.save)
            popup.confirm()
            return popup
        }
        var popup = try await exporting()
        #expect(popup.stage == .exporting && popup.symbol == nil && main.dialog == nil, "pixels cleared first")
        #expect(popup.live())
        local.post(name: NSWindow.didChangeOcclusionStateNotification, object: fake)
        #expect(popup.stage == .exporting, "what the panel itself causes: only the action stays")
        local.post(name: NSApplication.didHideNotification, object: nil)
        #expect(popup.stage == .closed && closed == 1, "the panel closes with it")
        // An unrelated blur or app switch: the panel holds no focus away.
        popup = try await exporting()
        local.post(name: NSApplication.didResignActiveNotification, object: nil)
        #expect(popup.stage == .closed && closed == 2, "blur")
        popup = try await exporting()
        seams.centers.workspace.post(name: NSWorkspace.sessionDidResignActiveNotification, object: nil)
        #expect(popup.stage == .closed && closed == 3, "user switch")
        // A vault switch: the panel does not outlive the vault's screen.
        popup = try await exporting()
        main.leave()
        #expect(popup.stage == .closed && closed == 4, "vault switch")
        main.select(id)
        // The deadline also ends it, panel and all.
        popup = try await exporting()
        seams.elapsed = .seconds(44)
        popup.tick()
        #expect(popup.stage == .closed && closed == 5)
    }

    @Test("QR-T18 FEA-10.15: a chosen share service may take the focus once; anything else ends the share")
    func shareHandOff() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        VaultModel.qrShareRoutes = [.sendViaAirDrop]
        var answer: ((Bool) -> Void)?
        VaultModel.qrSharePresenter = { _, done in
            answer = done
            return {}
        }
        let demo = try QrDemo.window("qr-hand-off")
        defer { demo.window.lockAll() }
        let main = demo.main
        let blur = { seams.centers.local.post(name: NSApplication.didResignActiveNotification, object: nil) }
        func sharing() async throws -> QrPopup {
            main.showQr()
            let popup = try await QrDemo.painted(main)
            popup.ask(.share)
            popup.confirm()
            #expect(popup.stage == .exporting)
            return popup
        }
        var popup = try await sharing()
        blur()
        #expect(popup.stage == .closed, "the picker is open and no service was chosen")
        popup = try await sharing()
        answer?(true)
        #expect(popup.stage == .exporting)
        blur()
        #expect(popup.stage == .exporting && popup.live(), "the chosen service came up")
        blur()
        #expect(popup.stage == .closed, "a second blur is the user going elsewhere")
        popup = try await sharing()
        answer?(false)
        #expect(popup.stage == .closed, "the picker was dismissed")
    }

    /// A window that says what the pop-up's stage was as it left the screen.
    private final class LeavingWindow: NSWindow {
        var left: () -> Void = {}
        override func orderOut(_ sender: Any?) { left() }
        override func miniaturize(_ sender: Any?) { left() }
    }

    @Test("QR-T18 C2-3: each way out of the window ends the code before the system acts")
    func waysOut() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-ways-out")
        defer { demo.window.lockAll() }
        let main = demo.main
        let rules = WindowRules()
        let fake = FakeApp()
        rules.calls = fake.calls
        let window = LeavingWindow(contentRect: .zero, styleMask: [.titled], backing: .buffered, defer: true)
        rules.attach(window)
        seams.mainWindow = window
        let dock = WindowRules.Settings(closeHides: true)
        let icon = WindowRules.Settings(closeHides: true, icon: true, minimizeToIcon: true)
        let ways: [(String, () -> Void)] = [
            ("minimize", { rules.minimize() }), ("close", { rules.close() }), ("start", { rules.startMinimized() }),
        ]
        for (rule, place) in [(dock, "Dock"), (icon, "icon")] {
            for (name, leave) in ways + (rule.icon ? [("hide", { rules.hideToIcon() })] : []) {
                main.showQr()
                let popup = try await QrDemo.painted(main)
                var stages: [QrPopup.Stage] = []
                window.left = { stages.append(popup.stage) }
                rules.settings = { rule }
                leave()
                #expect(stages == [.closed], "\(name) to the \(place)")
                #expect(popup.symbol == nil, "\(name) to the \(place)")
            }
        }
    }

    /// The code's view under `root`, if it is still in the window.
    private func codeViews(_ root: NSView) -> Int {
        (root is QrCodeNSView ? 1 : 0) + root.subviews.reduce(0) { $0 + codeViews($1) }
    }

    @Test("QR-T18 FEA-10.15: the code's view has left the window when each way out goes on, not a run-loop turn later")
    func flushed() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-flushed")
        defer { demo.window.lockAll() }
        let main = demo.main
        let rules = WindowRules()
        rules.calls = FakeApp().calls
        rules.settings = { WindowRules.Settings(closeHides: true) }
        let window = LeavingWindow(
            contentRect: NSRect(x: -20_000, y: -20_000, width: 640, height: 860), styleMask: [.titled],
            backing: .buffered, defer: false)
        rules.attach(window)
        seams.mainWindow = window
        let local = seams.centers.local
        let ways: [(String, () -> Void)] = [
            ("the rules' minimize", { rules.minimize() }),
            ("Dock minimize", { local.post(name: NSWindow.willMiniaturizeNotification, object: window) }),
            ("app hide", { local.post(name: NSApplication.willHideNotification, object: nil) }),
        ]
        for (name, leave) in ways {
            main.showQr()
            let popup = try await QrDemo.answered(main)
            let host = QrDemo.placed(NSHostingView(rootView: QrDemo.root(popup)), window: window)
            try await QrDemo.render(host)
            #expect(codeViews(host) == 1, "\(name): painted first")
            leave()
            #expect(popup.stage == .closed, "\(name)")
            #expect(codeViews(host) == 0, "\(name): the view is gone now")
        }
    }

    @Test("QR-T18 C2-4: macOS saves no state of the main window, the real path included")
    func noRestoration() async throws {
        let rules = WindowRules()
        rules.calls = FakeApp().calls
        let window = NSWindow(contentRect: .zero, styleMask: [.titled], backing: .buffered, defer: true)
        #expect(window.isRestorable, "AppKit's own default")
        rules.attach(window)
        #expect(!window.isRestorable)
        let model = try ParityDemo.window("qr-restore")
        defer { model.lockAll() }
        let screen = Screen(model)
        await screen.settle()
        #expect(!screen.window.isRestorable, "attached as the app attaches it")
    }

    @Test("QR-T18 C2-5: the screen-lock signal comes at once, also with Larsal in the background")
    func screenLockAtOnce() throws {
        let spy = SpyCenter()
        var heard: [QrSignal] = []
        let watch = QrWatch(
            centers: QrCenters(workspace: NotificationCenter(), distributed: spy, local: NotificationCenter()),
            window: { nil }, signal: { heard.append($0) })
        let added = try #require(spy.added.first)
        #expect(spy.added.count == 1 && added.name == LockSignals.screenIsLocked)
        #expect(added.behaviour == .deliverImmediately)
        let relay = try #require(added.observer, "the watch keeps its relay alive")
        _ = relay.perform(added.selector, with: Notification(name: LockSignals.screenIsLocked))
        #expect(heard == [.hard])
        withExtendedLifetime(watch) {}
    }
}
