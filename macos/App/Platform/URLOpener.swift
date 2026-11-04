import AppKit
import Foundation

/// A plain link outside an entry's URL field (AT-E02): only `http` and
/// `https` with a host; `javascript:`, `file:`, `data:` and every other
/// scheme are refused. An entry's URL opens through Rust's MOD-08.31 rules
/// instead (OpenURL.swift, F-080).
enum URLOpener {
    /// The URL to open for `text`, or `nil` when App refuses it.
    static func allowed(_ text: String) -> URL? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed),
            let scheme = url.scheme?.lowercased(),
            scheme == "http" || scheme == "https",
            let host = url.host(percentEncoded: false), !host.isEmpty
        else { return nil }
        return url
    }

    /// Opens `text` in the default browser when [`allowed`]; returns whether
    /// it did.
    @discardableResult
    static func open(_ text: String) -> Bool {
        guard let url = allowed(text) else { return false }
        return NSWorkspace.shared.open(url)
    }
}
