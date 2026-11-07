import AppKit
import LarsalCore
import Testing

/// The timer, the revocations and the exports (FEA-10.14 to .19): a fake
/// clock, private centers, fake panels and pickers, demo files under the
/// test's own folder. No real panel, picker or notification (AGENTS.md
/// rule 10).
@MainActor
@Suite(.serialized)
struct QrLifeTests {
    init() { ParityDemo.setUp() }

    @Test("QR-T17 FEA-10.14: the count reads 44, 43, 1 by elapsed time; at 44 nothing paints or saves")
    func timer() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-timer")
        defer { demo.window.lockAll() }
        let main = demo.main
        main.showQr()
        let popup = try await QrDemo.painted(main)
        #expect(popup.seconds == 44)
        for (elapsed, shown) in [(0, 44), (1, 43), (43, 1)] {
            seams.elapsed = .seconds(elapsed)
            popup.tick()
            #expect(popup.seconds == shown)
        }
        #expect(QrText.closing(1) == "1 second until this window closes")
        #expect(QrText.closing(44) == "44 seconds until this window closes")
        // A stalled repaint between ticks: the paint itself refuses.
        seams.elapsed = .milliseconds(43_500)
        popup.tick()
        #expect(popup.seconds == 1, "ceil of half a second")
        seams.elapsed = .seconds(44)
        #expect(!popup.live())
        #expect(popup.paintable() == nil)
        popup.ask(.save)
        #expect(popup.stage != .warning(.save), "no warning past the deadline")
        popup.tick()
        #expect(popup.stage == .closed && popup.symbol == nil && main.dialog == nil && main.qrPopup == nil)
        #expect(popup.tick() == nil, "the timer stops")
    }

    @Test("QR-T17 FEA-10.14: the warning runs on the same deadline; an answer past it fails closed")
    func warningKeepsDeadline() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        var saved: URL?
        VaultModel.qrSavePanel = { done in
            saved = URL(fileURLWithPath: "/nonexistent")
            done(nil)
            return {}
        }
        let demo = try QrDemo.window("qr-warning-time")
        defer { demo.window.lockAll() }
        let main = demo.main
        main.showQr()
        let popup = try await QrDemo.painted(main)
        seams.elapsed = .seconds(10)
        popup.ask(.save)
        #expect(popup.stage == .warning(.save))
        popup.tick()
        popup.cancelWarning()
        popup.tick()
        #expect(popup.stage == .code && popup.seconds == 34, "no restart on Cancel")
        popup.ask(.save)
        seams.elapsed = .seconds(44)
        popup.confirm()
        #expect(popup.stage == .closed && saved == nil, "past the deadline: no panel")
    }

    private func signals(_ seams: QrSeams, _ fake: NSWindow) -> [(String, () -> Void)] {
        let centers = seams.centers
        return [
            ("hide", { centers.local.post(name: NSApplication.didHideNotification, object: nil) }),
            ("blur", { centers.local.post(name: NSApplication.didResignActiveNotification, object: nil) }),
            ("will hide", { centers.local.post(name: NSApplication.willHideNotification, object: nil) }),
            ("quit", { centers.local.post(name: NSApplication.willTerminateNotification, object: nil) }),
            ("miniaturize", { centers.local.post(name: NSWindow.didMiniaturizeNotification, object: fake) }),
            ("will miniaturize", { centers.local.post(name: NSWindow.willMiniaturizeNotification, object: fake) }),
            ("close", { centers.local.post(name: NSWindow.willCloseNotification, object: fake) }),
            ("occlusion", { centers.local.post(name: NSWindow.didChangeOcclusionStateNotification, object: fake) }),
            ("sleep", { centers.workspace.post(name: NSWorkspace.willSleepNotification, object: nil) }),
            ("screens", { centers.workspace.post(name: NSWorkspace.screensDidSleepNotification, object: nil) }),
            ("switch", { centers.workspace.post(name: NSWorkspace.sessionDidResignActiveNotification, object: nil) }),
            ("lock screen", { centers.distributed.post(name: LockSignals.screenIsLocked, object: nil) }),
        ]
    }

    @Test("QR-T18 E21-S2: it hides on hide, blur, miniaturize, close, occlusion, sleep, switch, lock")
    func hiddenWindow() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let fake = NSWindow(contentRect: .zero, styleMask: [.borderless], backing: .buffered, defer: true)
        seams.mainWindow = fake
        let demo = try QrDemo.window("qr-signals")
        defer { demo.window.lockAll() }
        let main = demo.main
        for (name, post) in signals(seams, fake) {
            main.showQr()
            let popup = try await QrDemo.painted(main)
            #expect(popup.symbol != nil, "\(name)")
            post()
            #expect(popup.stage == .closed && popup.symbol == nil && main.dialog == nil, "\(name)")
        }
        // Another window's change means nothing.
        main.showQr()
        let popup = try await QrDemo.painted(main)
        let other = NSWindow(contentRect: .zero, styleMask: [.borderless], backing: .buffered, defer: true)
        seams.centers.local.post(name: NSWindow.didMiniaturizeNotification, object: other)
        seams.centers.local.post(name: NSWindow.willMiniaturizeNotification, object: other)
        seams.centers.local.post(name: NSWindow.didChangeOcclusionStateNotification, object: other)
        #expect(popup.stage == .code)
        popup.revoke()
    }

    @Test("QR-T18 E21-S2: a lock request revokes before its question; cancelling brings nothing back")
    func lockRequests() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-locks")
        let (window, main, id) = (demo.window, demo.main, demo.entry)
        let vault = demo.vault
        // With unsaved edits the lock asks first: the pop-up is already gone.
        main.edit(id)
        try #require(main.editor).set(.title, "QR demo edited")
        main.showDraftQr(field: "Password")
        let asked = try await QrDemo.painted(main)
        let ticket = try #require(asked.liveTicket)
        window.lock(vault)
        #expect(asked.stage == .closed && asked.symbol == nil, "before the question")
        #expect(main.dialog == .lockDiscardEdit, "the question is up")
        #expect(!window.session.qrIsCurrent(vault: vault, ticket: ticket))
        main.afterLeave = nil
        main.dialog = nil  // Cancel: the vault stays unlocked, nothing returns
        #expect(main.qrPopup == nil && asked.stage == .closed)
        main.closeEditor()
        // Each other door.
        let doors: [(String, () -> Void)] = [
            ("lock", { window.lock(vault) }), ("lockNow", { window.lockNow(vault) }), ("lockAll", { window.lockAll() }),
        ]
        for (name, open) in doors {
            let id = try reopen(window, vault, name)
            let again = try #require(window.main)
            again.select(id)
            again.showQr()
            let popup = try await QrDemo.painted(again)
            #expect(popup.stage == .code && popup.live(), "\(name): live before the door")
            // A lock that saves first waits with no question; the revoke comes before that wait.
            _ = try QrDemo.entry(window.session, vault, [("Title", "Another " + name)])
            #expect(try window.session.saveStatus(vault: vault).changes > 0, "\(name): a save to wait for")
            open()
            #expect(popup.stage == .closed && popup.symbol == nil, "\(name)")
            for _ in 0..<400 where window.main != nil { try await Task.sleep(for: .milliseconds(5)) }
            #expect(window.main == nil, "\(name): locked at the end")
        }
        window.lockAll()
    }

    private func reopen(_ window: MainWindowModel, _ vault: UInt64, _ name: String) throws -> String {
        if window.main == nil {
            #expect(try window.session.unlock(vault: vault, password: "demo-pass-7", keyFile: nil) == .unlocked)
            window.refresh()
        }
        let main = try #require(window.main)
        let id = try QrDemo.entry(window.session, vault, [("Title", name), ("Password", "demo-pass")])
        main.afterChange(select: id)
        return id
    }

    @Test("QR-T18 QR-T29 FEA-10.14: a same-entry edit, a new selection and a dialog's end drop the code")
    func sourceChanges() async throws {
        let seams = await QrSeams.begin()
        defer { seams.restore() }
        let demo = try QrDemo.window("qr-source")
        defer { demo.window.lockAll() }
        let (window, main, id) = (demo.window, demo.main, demo.entry)
        let (session, vault) = (window.session, main.vault.id)
        main.showQr()
        var popup = try await QrDemo.painted(main)
        _ = try session.beginEdit(vault: vault, entry: id)
        _ = try session.setPassword(vault: vault, value: "changed-demo")
        _ = try session.commitEdit(vault: vault)
        #expect(popup.paintable() == nil, "stale before paint")
        popup.tick()
        #expect(popup.stage == .closed)
        main.afterChange(select: id)
        // A new selection.
        main.showQr()
        popup = try await QrDemo.painted(main)
        main.select(try #require(main.rows.first { $0.id != id }?.id))
        #expect(popup.stage == .closed && main.dialog == nil)
        main.select(id)
        // Done, by the dialog's own way out.
        main.showQr()
        popup = try await QrDemo.painted(main)
        main.dialog = nil
        #expect(popup.stage == .closed && main.qrPopup == nil)
        // An unrelated new dialog cannot replace a live pop-up and keep it.
        main.showQr()
        popup = try await QrDemo.painted(main)
        main.dialog = .discard
        #expect(popup.stage == .closed)
        main.dialog = nil
    }
}
