import AppCore
import AppKit
import Foundation
import SwiftUI
import Testing

/// A demo vault of testdata/ (passwords in testdata/README.md).
private func testdata(_ name: String) -> String {
    URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appending(path: "../../testdata/\(name)")
        .standardizedFileURL
        .path(percentEncoded: false)
}

/// Waits until `done` holds, up to 10 seconds.
@MainActor
private func waitUntil(_ done: () -> Bool) async throws {
    for _ in 0..<400 where !done() {
        try await Task.sleep(for: .milliseconds(25))
    }
}

struct URLOpenerTests {
    /// Only `allowed` is tested: the real `open` would start apps on the
    /// owner's screen (AGENTS.md rule 10).
    @Test("AT-E02: only http and https with a host are opened")
    func onlyWebLinks() {
        let allowed = [
            "https://example.com/login", "http://192.168.178.1", "HTTPS://Example.com/x", " https://example.com/ ",
        ]
        for text in allowed {
            #expect(URLOpener.allowed(text) != nil, "\(text)")
        }
        let refused = [
            "javascript:alert(1)", "JavaScript:alert(1)", " javascript:alert(1)", "java\tscript:alert(1)",
            "file:///etc/hosts", "FILE:///etc/hosts", "data:text/html,<b>x</b>", "vbscript:x", "about:blank",
            "ftp://example.com", "ssh://203.0.113.10", "cmd://open", "mailto:demo@example.com", "app://open",
            "https://", "http:/", "example.com", "", "//example.com",
            "file://localhost/etc/hosts", "javascript://example.com/%0Aalert(1)", "data://example.com/x",
        ]
        for text in refused {
            #expect(URLOpener.allowed(text) == nil, "\(text)")
        }
    }
}

@MainActor
struct ScreenTests {
    @Test(
        "APP-06.11, AT-E07: the password field clears when an unlock starts; Hide, entry change, lock drop shown values"
    )
    func secretsLeaveTheScreen() async throws {
        let session = try ParityDemo.session()  // the expired entry's notice off
        let window = MainWindowModel(session: session)
        await window.open(testdata("rich-v4.appvault"))
        let unlock = try #require(window.unlock)
        unlock.password = "demo-pass-5"
        unlock.unlock()
        #expect(unlock.password.isEmpty)
        try await waitUntil { window.main != nil }
        let main = try #require(window.main)
        let full = try #require(main.rows.first { $0.title == "Full demo entry" })
        let other = try #require(main.rows.first { $0.id != full.id })
        main.select(full.id)
        await main.toggleShow("Password")
        #expect(main.shown["Password"]?.isEmpty == false)
        await main.toggleShow("Password")
        #expect(main.shown.isEmpty, "Hide")
        await main.toggleShow("Password")
        main.select(other.id)
        #expect(main.shown.isEmpty, "entry change")
        main.select(full.id)
        await main.toggleShow("Password")
        main.tick()
        #expect(main.codes[full.id]?.code.isEmpty == false, "FEA-04 live code")
        // A vault switch: the vault left behind drops its Show value and live
        // code, and its code timer stops.
        await window.open(testdata("rich-v3.appvault"))
        #expect(window.shown?.name == "rich-v3")
        #expect(main.shown.isEmpty && main.codes.isEmpty, "switch")
        try await Task.sleep(for: .milliseconds(1300))
        #expect(main.codes.isEmpty, "the code timer stopped")
        window.switchTo(main.vault.id)
        #expect(window.main === main)
        await main.toggleShow("Password")
        window.lock(main.vault.id)
        #expect(main.shown.isEmpty && main.codes.isEmpty && main.detail == nil && main.rows.isEmpty, "lock")
        #expect(window.main == nil)
        #expect(window.unlock?.password.isEmpty == true)
    }

    @Test("AT-E07: a Show that finishes after a vault switch or an entry change drops its value")
    func lateShowIsDropped() async throws {
        let session = try ParityDemo.session()  // the expired entry's notice off
        let window = MainWindowModel(session: session)
        await window.open(testdata("rich-v4.appvault"))
        let unlock = try #require(window.unlock)
        unlock.password = "demo-pass-5"
        unlock.unlock()
        try await waitUntil { window.main != nil }
        let main = try #require(window.main)
        let full = try #require(main.rows.first { $0.title == "Full demo entry" })
        let other = try #require(main.rows.first { $0.id != full.id })
        main.select(full.id)
        // Each Show waits on the Rust call; the change happens before its
        // result comes back to the screen thread.
        let late = Task { await main.toggleShow("Password") }
        await Task.yield()
        main.select(other.id)
        main.select(full.id)
        await late.value
        #expect(main.shown.isEmpty, "an entry change in between drops it")
        main.select(other.id)  // each part starts with nothing shown
        main.select(full.id)
        let show = Task { await main.toggleShow("Password") }
        await Task.yield()
        await window.open(testdata("rich-v3.appvault"))
        await show.value
        #expect(main.shown.isEmpty, "the vault left behind holds no Show value")
        window.switchTo(main.vault.id)
        #expect(main.shown.isEmpty, "nor once it is back on screen")
    }

    @Test("APP-06: a wrong password shows M06-06 and leaves the field empty")
    func wrongPassword() async throws {
        let session = Session()
        let window = MainWindowModel(session: session)
        await window.open(testdata("rich-v4.appvault"))
        let unlock = try #require(window.unlock)
        unlock.password = "wrong"
        unlock.unlock()
        try await waitUntil { unlock.message != nil }
        #expect(unlock.message?.id == "M06-06")
        #expect(unlock.password.isEmpty && unlock.shakes == 1)
        // APP-06.5: a lock event clears what was typed.
        unlock.password = "typed"
        window.lockAll()
        #expect(unlock.password.isEmpty)
    }

    /// The worst list update of the FEA-01.34 queries.
    private func worstSearch(_ model: VaultModel) -> Duration {
        var worst = Duration.zero
        for query in ["Entry 0999", "user01 -Entry", "t:Entry u:user0 9 99 999", "*t:^Entry 1", "zzz", "e"] {
            model.setSearch(query)
            worst = max(worst, model.lastUpdate)
        }
        return worst
    }

    @Test("FEA-01.34: a search on big-10000 updates the list in under 50 ms, before and after rating")
    func searchSpeed() throws {
        let session = Session()
        let id = try session.open(path: testdata("big-10000.appvault"))
        #expect(try session.unlock(vault: id, password: "demo-pass-6", keyFile: nil) == .unlocked)
        let model = VaultModel(session: session, vault: session.vaults()[0])
        #expect(model.rows.count == 10_000)
        let before = worstSearch(model)
        #expect(before < .milliseconds(50), "worst \(before)")
        // Checker E5-S4 (2): rows carry ratings once rated; a search must
        // stay as fast.
        var done = false
        while !done { done = try session.rate(vault: id, max: 1000, utcOffset: 0) }
        model.setSearch("")
        model.rated()
        #expect(model.rows.allSatisfy { $0.rating != nil || !$0.hasPassword })
        let after = worstSearch(model)
        let times = "FEA-01.34 search worst: \(before) before rating, \(after) after rating\n"
        FileHandle.standardError.write(Data(times.utf8))
        #expect(after < .milliseconds(50), "worst after rating \(after)")
        model.setSearch("")
        model.setSort(.title)
        #expect(model.rows.first?.title == "Entry 00001")
    }

    /// The Option A Personal demo vault, unlocked, as the main window shows it.
    private func personal() throws -> VaultModel {
        let session = Session()
        let id = try session.open(path: testdata("option-a-personal.appvault"))
        #expect(try session.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        return VaultModel(session: session, vault: session.vaults()[0])
    }

    @Test("APP-03.7, APP-03.15, APP-03.21: Edit > Copy copies the password; the notice goes; quit locks every vault")
    func copyNoticeAndQuit() async throws {
        let before = PasteboardProof.count()
        let session = Session()
        let id = try session.open(path: testdata("option-a-personal.appvault"))
        #expect(try session.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        let window = MainWindowModel(session: session)
        let main = try #require(window.main)
        // No key window and no text selected: ⌘C copies the password.
        window.copyCommand()
        #expect(main.toast == .init(glyph: "check", text: "Password copied.", note: "Clears in 10 s."))
        try await Task.sleep(for: .milliseconds(2000))
        #expect(main.toast != nil, "the notice lasts 2.6 s")
        try await waitUntil { main.toast == nil }
        #expect(main.toast == nil, "then it goes")
        main.copy("UserName")
        #expect(main.toast?.text == "Username copied.")
        window.lock(id)
        #expect(main.toast == nil, "a lock drops the notice")
        #expect(try session.unlock(vault: id, password: "demo-pass-7", keyFile: nil) == .unlocked)
        window.refresh()
        try #require(window.main).copy("Password")
        window.quit()
        #expect(session.vaults().allSatisfy { $0.locked }, "quit locks first, then clears (SC-03)")
        // AGENTS.md rule 10: `Session()` copies to a private pasteboard (LD-206).
        PasteboardProof.expectOnlyPrivate(session, before: before)
    }

    @Test("Checker E5-S4 (3): codes are asked only for rows on screen and the entry shown")
    func codesOnlyOnScreen() async throws {
        let model = try personal()
        let github = try #require(model.rows.first { $0.title == "GitHub" })
        let google = try #require(model.rows.first { $0.title == "Google" })
        model.select(github.id)
        model.tick()
        #expect(Set(model.codes.keys) == [github.id], "only the entry shown")
        model.rowAppeared(google.id)
        try await waitUntil { model.codes[google.id] != nil }
        #expect(Set(model.codes.keys) == [github.id, google.id])
        model.rowDisappeared(google.id)
        model.tick()
        #expect(Set(model.codes.keys) == [github.id])
    }

    @Test("Checker E5-S4 (4): leaving the screen cancels the rating worker; no late reload")
    func leaveCancelsRating() async throws {
        let model = try personal()
        model.enter()
        model.leave()
        try await Task.sleep(for: .milliseconds(600))
        #expect(model.sidebar?.attention == nil)
    }

    @Test("LD-163 (2): the key file row takes a dropped file and clears with Remove Key File")
    func keyFileDropAndRemove() async throws {
        let window = MainWindowModel(session: Session())
        await window.open(testdata("password-only.appvault"))
        let unlock = try #require(window.unlock)
        unlock.useKeyFile(testdata("key-hex64.appkey"))
        #expect(unlock.keyFileText?.hasPrefix("key-hex64.appkey · ") == true)
        unlock.removeKeyFile()
        #expect(unlock.keyFile.isEmpty && unlock.keyFileText == nil)
    }

    @Test("LD-163 (1): the window buttons sit centred in the 52-point top bar, which still takes clicks")
    func windowChrome() async throws {
        let frame = NSRect(x: -20_000, y: -20_000, width: 1320, height: 820)
        let window = NSWindow(
            contentRect: frame, styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered,
            defer: false
        )
        WindowChrome.apply(to: window)
        let host = NSHostingView(rootView: Color.clear.frame(width: 1320, height: 820))
        host.sizingOptions = []
        window.contentView = host
        window.setFrame(frame, display: false)
        try await Task.sleep(for: .milliseconds(100))
        let top = try #require(host.superview)
        let close = try #require(window.standardWindowButton(.closeButton))
        let box = close.convert(close.bounds, to: top)
        #expect(abs((top.bounds.height - box.midY) - 26) <= 1, "centre \(top.bounds.height - box.midY) from the top")
        // Never ordered front (AGENTS.md rule 10); a hit test needs no screen.
        let hit = top.hitTest(NSPoint(x: 1250, y: top.bounds.height - 26))
        var view = hit
        while let current = view, current !== host { view = current.superview }
        #expect(view === host, "the top bar's controls get the click")
    }
}
