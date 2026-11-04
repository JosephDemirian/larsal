import AppCore
import Foundation

/// Files macOS asks App to open (APP-09.23).
enum FileOpen {
    /// The paths of the file URLs, in order. Every other URL is dropped: App
    /// has no URL scheme and ignores URL-open events (APP-09.25).
    static func paths(_ urls: [URL]) -> [String] {
        urls.filter(\.isFileURL).map { $0.path(percentEncoded: false) }
    }

    /// The vault files among `urls` that a drop on the window may open
    /// (APP-09.26, LD-153 D-APP09-7): `.appvault` and the reference app's
    /// vault extension, without letter case. Every other drop is refused.
    static func droppedVaults(_ urls: [URL]) -> [String] {
        paths(urls.filter { vaultExtensions.contains($0.pathExtension.lowercased()) })
    }

    /// The reference's extension is stored as bytes (AGENTS.md rule 1).
    static let vaultExtensions: Set<String> = [
        "appvault", String([0x6B, 0x64, 0x62, 0x78].map { Character(Unicode.Scalar(UInt8($0))) }),
    ]
}

extension MainWindowModel {
    /// APP-09.23: `paths` open in order once every open asked for before
    /// them is done, so the last one asked for is shown.
    @discardableResult
    func open(_ paths: [String]) -> Task<Void, Never> {
        let before = opening
        let task = Task {
            await before?.value
            for path in paths { await openNow(path) }
        }
        opening = task
        return task
    }

    func open(_ path: String) async { await open([path]).value }

    /// APP-09.15: adds the file to the session and shows it. Rust reads its
    /// header for the locked look in a coordinated access off the main
    /// thread (APP-05.24), with fetching off: a dataless file gives no look
    /// and is not fetched here; its unlock screen shows "Still downloading"
    /// (APP-05.30).
    private func openNow(_ path: String) async {
        let session = session
        let opened = await FileAccess.run(.tick, path) { Result { try session.open(path: path) } }
        if case .failure(let error) = opened { banner = message(error) }
        refresh()
    }
}
