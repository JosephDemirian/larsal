import AppCore
import AppKit
import SwiftUI
import Testing

// Design parity (Verify, 2026-10-28), check 6, section states: the state
// frames reached by pressing the real controls through the accessibility
// tree, offscreen (see ParityTests.swift).
@MainActor
@Suite(.serialized)
struct ParityStatesTests {
    init() { ParityDemo.setUp() }

    @Test("Parity states-needs-attention: the Needs attention tab lists only entries that need attention")
    func attention() async throws {
        let model = try ParityDemo.window("parity-states")
        let main = try #require(model.main)
        try ParityDemo.rate(model)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Needs attention")
        #expect(main.tab == .attention && !main.rows.isEmpty)
        #expect(main.rows.allSatisfy { $0.rating?.attention == true })
        try await screen.press("Amazon")
        #expect(screen.strings().contains { $0.hasPrefix("Reused password.") })
    }

    @Test("Parity states-card: Banking and Visa Debit show the card; Show card number reveals it")
    func card() async throws {
        let model = try ParityDemo.window("parity-states")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Banking")
        try await screen.press("Visa Debit")
        #expect(main.detail?.title == "Visa Debit")
        try await screen.press("Show card number")
        try await screen.wait { !main.shown.isEmpty }  // Show runs off the screen thread
        #expect(main.shown.isEmpty == false)
    }

    @Test("Parity states-server-with-ssh-key: Servers and the server entry show the SSH key; Show password reveals it")
    func server() async throws {
        let model = try ParityDemo.window("parity-states")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Servers")
        try await screen.press("Server root · web-01")
        try await screen.press("Show password")
        try await screen.wait { main.shown["Password"] != nil }
        await screen.settle()
        #expect(main.shown["Password"]?.isEmpty == false)
        #expect(screen.strings().contains { $0.hasPrefix("SSH key · ") })
    }

    @Test("Parity states-wi-fi: Devices and Home Wi-Fi show the network fields")
    func wifi() async throws {
        let model = try ParityDemo.window("parity-states")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Devices")
        try await screen.press("Home Wi-Fi")
        #expect(main.detail?.title == "Home Wi-Fi")
        #expect(screen.strings().contains("Network name"))
    }

    @Test("Parity states-favorites-tags-open: Favorites lists the starred entries; Tags opens the tag list")
    func favorites() async throws {
        let model = try ParityDemo.window("parity-states")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Favorites")
        try await screen.press("Proton Mail")
        try await screen.press("Tags")
        #expect(main.place == .favorites && main.tagsOpen && main.detail?.title == "Proton Mail")
        #expect(screen.node("finance") != nil)
    }

    @Test("Parity states-search-tips: the tips show with an empty search; a tip fills the search")
    func tips() async throws {
        let model = try ParityDemo.window("parity-states")
        let main = try #require(model.main)
        main.tips = true
        let screen = Screen(model)
        await screen.settle()
        #expect(screen.node("Search tips") != nil)
        try await screen.press("tag:2fa")
        #expect(main.search == "tag:2fa" && main.rows.count == 7)
    }

    @Test("Parity states-search-with-no-result: a search with no hit keeps the frame; Clear search ends it")
    func noResult() async throws {
        let model = try ParityDemo.window("parity-states")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.type("dropbox", into: "Search entries")
        #expect(main.search == "dropbox" && main.rows.isEmpty)
        #expect(screen.node("Entries") != nil)
        try await screen.press("Clear search")
        #expect(main.search.isEmpty && !main.rows.isEmpty)
    }

    @Test("Parity states-more-menu: the entry menu lists its items; items of later stories are disabled")
    func moreItems() async throws {
        let model = try ParityDemo.window("parity-states")
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("More actions")
        // Clone and Move to Recycle Bin work since E5-S5.
        for name in [
            "Copy Username", "Copy Password", "Copy URL", "Copy One-Time Code", "Open URL", "Clone Entry…",
            "Move to Recycle Bin",
        ] {
            #expect(screen.node(name)?.isAccessibilityEnabled?() == true, "\(name)")
        }
        #expect(screen.node("Type Login")?.isAccessibilityEnabled?() == false)
    }

    @Test("Parity states-copied: Copy password shows the notice with its label and seconds; no value on screen")
    func copied() async throws {
        let model = try ParityDemo.window("parity-states")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        let before = PasteboardProof.count()
        try await screen.press("Copy password")
        #expect(main.toast == .init(glyph: "check", text: "Password copied.", note: "Clears in 10 s."))
        #expect(screen.strings().contains("Password copied. Clears in 10 s."))
        // APP-03.2: the value never reaches the screen layer.
        let value = try model.session.showField(vault: main.vault.id, entry: main.selection ?? "", field: "Password")
        #expect(!value.isEmpty && !screen.strings().contains { $0.contains(value) })
        // AGENTS.md rule 10: `Session()` copies to a private pasteboard (LD-206).
        PasteboardProof.expectOnlyPrivate(model.session, before: before)
    }

    @Test("Parity states-copied: each field's Copy and the entry menu's copy items copy and name the field")
    func copyItems() async throws {
        let model = try ParityDemo.window("parity-states")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Copy username")
        #expect(main.toast?.text == "Username copied.")
        for (item, label) in [("Copy Username", "Username"), ("Copy Password", "Password"), ("Copy URL", "URL")] {
            try await screen.press("More actions")
            try await screen.press(item)
            #expect(main.toast?.text == label + " copied." && main.overlay == nil, "\(item)")
        }
        try await screen.press("Banking")
        try await screen.press("Visa Debit")
        try await screen.press("Copy card number")
        #expect(main.toast?.text == "Card number copied.")
    }

    @Test("Parity states-copied: Copy one-time code, Copy One-Time Code and Copy fingerprint copy in Rust")
    func copyCodeAndFingerprint() async throws {
        let model = try ParityDemo.window("parity-states")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        let before = PasteboardProof.count()
        try await screen.press("Copy one-time code")
        #expect(main.toast == .init(glyph: "check", text: "One-time password copied.", note: "Clears in 10 s."))
        try await screen.press("More actions")
        try await screen.press("Copy One-Time Code")
        #expect(main.toast?.text == "One-time password copied." && main.overlay == nil)
        try await screen.press("Servers")
        try await screen.press("Server root · web-01")
        try await screen.press("Copy fingerprint")
        #expect(main.toast == .init(glyph: "check", text: "Fingerprint copied.", note: "Clears in 10 s."))
        // No one-time password here: the menu item is off (APP-03.4).
        try await screen.press("More actions")
        #expect(screen.node("Copy One-Time Code")?.isAccessibilityEnabled?() == false)
        // AGENTS.md rule 10: `Session()` copies to a private pasteboard (LD-206).
        PasteboardProof.expectOnlyPrivate(model.session, before: before)
    }

    @Test("Parity states-copied: an empty value copies nothing and says so (APP-03.5)")
    func copyEmpty() async throws {
        let model = try ParityDemo.window("parity-states")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Mastodon")
        try await screen.press("More actions")
        try await screen.press("Copy Password")
        #expect(main.toast == .init(glyph: "info", text: "Password is empty. Nothing to copy."))
    }

    @Test("Parity states-vault-switcher: the vault menu lists the open vaults; Lock Personal locks it; Work switches")
    func vaultMenu() async throws {
        let model = try ParityDemo.window("parity-states")
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Switch vault")
        #expect(model.vaultMenu && screen.node("Family") != nil)
        #expect(screen.node("Open Vault…")?.isAccessibilityEnabled?() == true)
        try await screen.press("Lock Personal")
        #expect(model.unlock?.vault.name == "Personal" && !model.vaultMenu)
        try await screen.press("Switch vault")
        try await screen.press("Work")
        #expect(model.shown?.name == "Work")
    }

    @Test("Parity states-sort-menu: Oldest first turns the order; the chosen key and order are marked")
    func sortOrder() async throws {
        let model = try ParityDemo.window("parity-states")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Sort by Modified")
        try await screen.press("Title")
        try await screen.press("Sort by Title")
        #expect(screen.node("Title")?.isAccessibilitySelected?() == true)
        try await screen.press("Newest first")
        #expect(!main.ascending && main.rows.first?.title == "Zalando")
    }

    @Test("Parity states-recycle-bin: Recycle Bin lists deleted entries; Restore moves it back (E5-S5)")
    func bin() async throws {
        let model = try ParityDemo.window("parity-states")
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        try await screen.press("Recycle Bin")
        try await screen.press("Twitter (old account)")
        #expect(main.place == .bin && main.detail?.title == "Twitter (old account)")
        #expect(screen.node("Empty Recycle Bin")?.isAccessibilityEnabled?() == true)
        let bin = main.sidebar?.bin ?? 0
        try await screen.press("Restore")
        #expect(main.sidebar?.bin == bin - 1)
    }

    @Test("Parity states-new-empty-vault: an empty vault shows the three first steps; Import waits for FEA-08")
    func empty() async throws {
        let model = try ParityDemo.window("parity-states", unlocked: [2], shown: 2)
        let main = try #require(model.main)
        let screen = Screen(model)
        await screen.settle()
        #expect(main.empty)
        // New entry and New group work since E5-S5.
        #expect(screen.node("Import")?.isAccessibilityEnabled?() == false)
        try await screen.press("New entry")
        #expect(main.editor?.view.new == true)
    }
}
