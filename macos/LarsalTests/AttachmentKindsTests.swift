import AppKit
import Foundation
import Testing
import UniformTypeIdentifiers

/// F-103 (LD-225 (1)): Larsal's ask-first list, `RISKY` in
/// crates/larsal-core/src/attachments.rs, follows macOS's own kinds. Each listed
/// extension's kin must be listed too: the other extensions of its type
/// (`UTType` tags), and the other extensions of its document type in its
/// default app when that app is one of the Mac's own (under /System).
/// LaunchServices only says which app would open a demo file; nothing opens.
struct AttachmentKindsTests {
    static let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appending(path: "../../crates/larsal-core/src/attachments.rs").standardizedFileURL

    /// The quoted words of the `RISKY` array.
    static func listed() throws -> Set<String> {
        let text = try String(contentsOf: source, encoding: .utf8)
        let start = try #require(text.range(of: "const RISKY"))
        let end = try #require(text.range(of: "];", range: start.upperBound..<text.endIndex))
        return Set(text[start.upperBound..<end.lowerBound].matches(of: #/"([^"]+)"/#).map { String($0.1) })
    }

    static func extensions(_ type: UTType) -> [String] { type.tags[.filenameExtension] ?? [] }

    /// The document types of the app that would open `file`, when it is one of the Mac's own.
    static func documentTypes(opening file: URL) -> [[String: Any]] {
        guard let app = NSWorkspace.shared.urlForApplication(toOpen: file), app.path.hasPrefix("/System/") else {
            return []
        }
        return Bundle(url: app)?.infoDictionary?["CFBundleDocumentTypes"] as? [[String: Any]] ?? []
    }

    @Test("F-103: each listed type's other extensions, and its document type's in its default app, ask first")
    func kinAreListed() throws {
        let listed = try Self.listed()
        #expect(listed.contains("pkg"), "the list is read")
        let dir = ParityDemo.temporaryDirectory.appending(path: "larsal-kinds-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        var missing = Set<String>()
        for ext in listed {
            var kin = UTType(filenameExtension: ext).map(Self.extensions) ?? []
            let file = dir.appending(path: "demo.\(ext)")
            try Data("demo".utf8).write(to: file)
            for kind in Self.documentTypes(opening: file) {
                let types = (kind["LSItemContentTypes"] as? [String] ?? []).compactMap { UTType($0) }
                let all = (kind["CFBundleTypeExtensions"] as? [String] ?? []) + types.flatMap(Self.extensions)
                if all.contains(where: { $0.lowercased() == ext }) { kin += all }
            }
            for other in kin.map({ $0.lowercased() }) where other != "*" && !listed.contains(other) {
                missing.insert("\(ext): \(other)")
            }
        }
        #expect(missing.isEmpty, "\(missing.sorted())")
    }
}
