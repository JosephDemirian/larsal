import AppCore
import AppKit
import SwiftUI
import Testing
import Vision

/// Renders `view` offscreen (a window that is never ordered front, AGENTS.md
/// rule 10) and reads the drawn text back with on-device text recognition.
@MainActor
private func drawnText(_ view: some View) throws -> [String] {
    let size = NSRect(x: 0, y: 0, width: 900, height: 520)
    let host = NSHostingView(rootView: view.frame(width: size.width, height: size.height).background(.white))
    host.frame = size
    host.appearance = NSAppearance(named: .aqua)
    let offscreen = NSWindow(
        contentRect: size.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless], backing: .buffered,
        defer: false
    )
    offscreen.contentView = host
    host.layoutSubtreeIfNeeded()
    let rep = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
    host.cacheDisplay(in: host.bounds, to: rep)
    let image = try #require(rep.cgImage)
    let request = VNRecognizeTextRequest()
    request.recognitionLevel = .accurate
    request.usesLanguageCorrection = false
    try VNImageRequestHandler(cgImage: image).perform([request])
    return (request.results ?? []).compactMap { $0.topCandidates(1).first?.string }
}

@MainActor
struct PlainTextTests {
    @Test("AT-E01: Markdown, links and control characters in vault text are shown as they are")
    func vaultTextIsShownLiterally() throws {
        Fonts.register()
        let hostile = "**bold** [link](https://example.com) <b>x</b>\u{0007}\u{0000}"
        let row = EntryRow(
            id: String(repeating: "a", count: 32), title: hostile, subtitle: hostile, icon: 0,
            customIcon: nil, created: 0, modified: 0, expired: false, host: "", favorite: false, hasTotp: false,
            passkey: false,
            kind: .login, hasPassword: false, rating: nil, deleted: nil
        )
        let vault = VaultInfo(
            id: 1, name: "demo", path: "", hue: 0, locked: false, unlocking: false, shown: true, colour: nil, icon: -1,
            lockedAt: nil, keyChange: nil
        )
        let model = VaultModel(session: Session(), vault: vault)
        let detail = EntryDetail(
            id: row.id, title: hostile, icon: 0, path: [], inBin: false,
            fields: [
                FieldView(name: "Notes", kind: .notes, value: hostile, protected: false),
                FieldView(name: hostile, kind: .custom, value: hostile, protected: false),
            ],
            hasTotp: false, attachments: [], tags: [], expires: nil, expired: false, created: 0, modified: 0,
            accessed: 0, history: 0, kind: .login, host: "", favorite: false, group: "demo", groupIcon: -1,
            customIcon: nil, groupCustomIcon: nil, deleted: nil, deletedFrom: nil, passkey: nil, ssh: nil, rating: nil
        )
        let lines = try drawnText(
            VStack(spacing: 8) {
                EntryRowView(row: row, code: nil, selected: false, rule: false) {}
                Panel(
                    rows: EntryFields(model: model, entry: detail).rows + MoreFields(model: model, entry: detail).rows)
            }
        )
        // The row's title and subtitle, the custom field's name and value, the
        // notes: each drawn with its asterisks, brackets and tags, never as
        // bold text or a link.
        let literal = lines.filter { $0.contains("**bold**") && $0.contains("[link](https://example.com)") }
        #expect(literal.count >= 5, "\(lines)")
        #expect(lines.allSatisfy { $0.contains("**bold**") || !$0.contains("bold") }, "\(lines)")
    }
}
