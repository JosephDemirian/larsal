import Darwin
import Foundation
import os

/// APP-05.24 coordinated access and "Still downloading" (E15-S3;
/// spec/research/sync-server.md P18 (1), (2)). Every read of a vault file
/// runs in a coordinated read, and a save in a coordinated read and a
/// replacing write (`.forReplacing`), each with its own `NSFileCoordinator`
/// on a background queue and the Rust file I/O inside the accessor: a cloud
/// service's file provider and other processes' file presenters see only
/// coordinated access, and file calls on a cloud or network folder can take
/// an unknown time, so none runs on the main thread. A dataless file
/// (`SF_DATALESS`) is fetched before it is read; the 30-second tick never
/// fetches one.
nonisolated enum FileAccess {
    enum Kind: Sendable {
        /// The unlock read, a reload or merge read, a watch event's checksum.
        case read
        /// A save: the pre-save checksum and the rename over the vault file.
        case replace
        /// The 30-second tick's checksum, and the header look read when a
        /// vault opens: fetching is off on its thread, so a dataless file
        /// reads as `EDEADLK` and is never fetched.
        case tick
    }

    /// The file calls behind the dataless state; tests replace them (real
    /// clouds: E15-S5).
    struct Files: Sendable {
        /// `SF_DATALESS` in the file's `st_flags`.
        var dataless: @Sendable (String) -> Bool
        /// Starts the download of a dataless file.
        var download: @Sendable (String) -> Void
        /// The tick's read of the first byte, fetching off: its `errno`,
        /// 0 when it read.
        var probe: @Sendable (String) -> Int32

        static let system = Files(
            dataless: { path in
                var info = stat()
                return stat(path, &info) == 0 && info.st_flags & UInt32(SF_DATALESS) != 0
            },
            download: { path in
                let url = URL(fileURLWithPath: path)
                if (try? FileManager.default.startDownloadingUbiquitousItem(at: url)) != nil { return }
                // Not an iCloud item (another file provider): a coordinated
                // read fetches it, on a queue of its own.
                DispatchQueue.global(qos: .utility).async {
                    NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: nil) { found in
                        _ = try? FileHandle(forReadingFrom: found).read(upToCount: 1)
                    }
                }
            },
            probe: { path in
                let file = open(path, O_RDONLY | O_NONBLOCK)
                guard file >= 0 else { return errno }
                defer { close(file) }
                var byte: UInt8 = 0
                return read(file, &byte, 1) < 0 ? errno : 0
            })
    }

    static let files = OSAllocatedUnfairLock(initialState: Files.system)

    /// APP-05.17's calls on the conflict copies; tests replace them (no
    /// test touches the owner's Trash; real iCloud: E15-S5).
    struct Cloud: Sendable {
        /// The files of the unresolved iCloud conflict versions of `path`.
        var unresolved: @Sendable (String) -> [String]
        /// Marks the versions of `path` whose files are `done` resolved,
        /// then removes the other versions once none is left unresolved.
        var resolve: @Sendable (_ path: String, _ done: [String]) -> Void
        /// Moves the file at `path` to the Trash; true when it went.
        var trash: @Sendable (String) -> Bool

        static let system = Cloud(
            unresolved: { path in
                (NSFileVersion.unresolvedConflictVersionsOfItem(at: URL(fileURLWithPath: path)) ?? [])
                    .map { $0.url.path(percentEncoded: false) }
            },
            resolve: { path, done in
                let url = URL(fileURLWithPath: path)
                for version in NSFileVersion.unresolvedConflictVersionsOfItem(at: url) ?? []
                where done.contains(version.url.path(percentEncoded: false)) {
                    version.isResolved = true
                }
                if (NSFileVersion.unresolvedConflictVersionsOfItem(at: url) ?? []).isEmpty {
                    try? NSFileVersion.removeOtherVersionsOfItem(at: url)
                }
            },
            trash: { path in
                (try? FileManager.default.trashItem(at: URL(fileURLWithPath: path), resultingItemURL: nil)) != nil
            })
    }

    static let cloud = OSAllocatedUnfairLock(initialState: Cloud.system)

    /// One access as its accessor ran, and whether on the main thread.
    struct Access: Sendable {
        let kind: Kind
        let path: String
        let main: Bool
    }

    /// Tests: every access; `nil` records nothing.
    static let accesses = OSAllocatedUnfairLock<[Access]?>(initialState: nil)

    /// `body` in a coordinated access of `path` (`~` is the home folder,
    /// links resolved), on a background queue, never on the calling thread.
    static func coordinate(_ kind: Kind, _ path: String, _ body: @escaping @Sendable () -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            // The `stat` and the link resolving below are file calls too.
            let started = Thread.isMainThread
            let url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath).resolvingSymlinksInPath()
            let access: @Sendable () -> Void = {
                let main = started || Thread.isMainThread
                accesses.withLock { $0?.append(Access(kind: kind, path: url.path, main: main)) }
                if kind == .tick { withoutFetching(body) } else { body() }
            }
            // F-101: the coordinator opens what it coordinates, so a pipe
            // or a device at the path would hold it, and with it every
            // coordinated access of App. Rust refuses such a path itself.
            // ponytail: one swapped in after this `stat` still can; an
            // open-free coordinator would close that gap.
            var info = stat()
            if stat(url.path, &info) == 0, info.st_mode & S_IFMT != S_IFREG { return access() }
            let intents: [NSFileAccessIntent] =
                switch kind {
                case .read: [.readingIntent(with: url)]
                case .replace: [.readingIntent(with: url), .writingIntent(with: url, options: .forReplacing)]
                // Never asks the file provider for the contents.
                case .tick: [.readingIntent(with: url, options: .immediatelyAvailableMetadataOnly)]
                }
            // An error means the coordination failed (a presenter or the file
            // provider refused): Rust's own checks still guard the file, so
            // the access goes on.
            NSFileCoordinator().coordinate(with: intents, queue: OperationQueue()) { _ in access() }
        }
    }

    /// `body`'s result in a coordinated access of `path`, once the file is
    /// on this Mac: a dataless file first calls `downloading(true)`, starts
    /// the download and waits for it off the main thread, then calls
    /// `downloading(false)`. A `tick` never waits for a download.
    @MainActor
    static func run<T: Sendable>(
        _ kind: Kind, _ path: String, downloading: (Bool) -> Void = { _ in }, _ body: @escaping @Sendable () -> T
    ) async -> T {
        if kind != .tick { await whole(path, downloading) }
        return await withCheckedContinuation { done in coordinate(kind, path) { done.resume(returning: body()) } }
    }

    /// The 30-second tick: `body`'s result, or `nil` (no change) when the
    /// file is dataless, or turned dataless after that test (`EDEADLK`).
    /// It starts no download and shows nothing.
    static func tick<T: Sendable>(_ path: String, _ body: @escaping @Sendable () -> T) async -> T? {
        let files = files.withLock { $0 }
        let file = (path as NSString).expandingTildeInPath
        return await withCheckedContinuation { done in
            coordinate(.tick, path) {
                done.resume(returning: files.dataless(file) || files.probe(file) == EDEADLK ? nil : body())
            }
        }
    }

    /// Waits until the file at `path` is on this Mac. ponytail: a `stat`
    /// every 0.5 s while it downloads, with no time limit (a download may
    /// take long); a download-state watch if that ever matters.
    @MainActor
    private static func whole(_ path: String, _ downloading: (Bool) -> Void) async {
        guard await dataless(path) else { return }
        downloading(true)
        defer { downloading(false) }
        let files = files.withLock { $0 }
        let file = (path as NSString).expandingTildeInPath
        DispatchQueue.global(qos: .utility).async { files.download(file) }
        while await dataless(path) {
            guard (try? await Task.sleep(for: .milliseconds(500))) != nil else { return }
        }
    }

    /// `SF_DATALESS` at `path`, tested off the main thread.
    static func dataless(_ path: String) async -> Bool {
        let files = files.withLock { $0 }
        let file = (path as NSString).expandingTildeInPath
        return await Task.detached { files.dataless(file) }.value
    }

    /// The end of the launch (`launchFinished`, APP-09.1 steps 11 to 13),
    /// fetching off: Rust reads each reopened vault's header here, on the
    /// main thread, and a dataless one gives no look and is never fetched;
    /// its unlock screen shows "Still downloading" (APP-05.24, APP-05.30).
    /// ponytail: the header of a file that is on this Mac is still read on
    /// the main thread at launch; a coordinated reopen (E15-S5) moves it.
    @MainActor
    static func launch(_ finish: () -> Void) { withoutFetching(finish) }

    /// TN3150: a read of a dataless file on this thread gives `EDEADLK`
    /// instead of fetching it; the thread's old policy comes back after.
    private static func withoutFetching(_ body: () -> Void) {
        let type = IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES
        let old = getiopolicy_np(type, IOPOL_SCOPE_THREAD)
        setiopolicy_np(type, IOPOL_SCOPE_THREAD, IOPOL_MATERIALIZE_DATALESS_FILES_OFF)
        defer { if old >= 0 { setiopolicy_np(type, IOPOL_SCOPE_THREAD, old) } }
        body()
    }
}
