import Foundation

/// APP-05.24: tells when a vault file may have changed on disk. It watches
/// with kqueue vnode sources (`DispatchSource.makeFileSystemObjectSource`)
/// on the folder, because a writer that swaps in a new file (an atomic
/// rename, as sync services and Larsal itself do) or leaves a conflict copy
/// changes the folder, and on the file itself, for a writer that edits it
/// in place, deletes or moves it. Events within 500 ms join into one, and a
/// 30-second tick catches what the system misses (a share that was away).
/// It only says "look", and whether a tick says it (a tick never fetches a
/// dataless file, FileAccess.swift): Rust compares the file's checksum and
/// decides (saving.rs `check_disk`), so Larsal's own saves raise nothing.
nonisolated final class DiskWatch: @unchecked Sendable {
    /// All state below is touched on this queue only.
    private let queue = DispatchQueue(label: "app.larsal.desktop.disk-watch")
    private let file: String
    private let look: @Sendable (_ tick: Bool) -> Void
    private let timer: DispatchSourceTimer
    private var sources: [DispatchSourceFileSystemObject] = []
    private var join: DispatchWorkItem?

    /// Watches `path` (`~` is the home folder); `look` runs on a background
    /// queue, told whether the tick (every `tick`, 30 s) called it.
    init(path: String, tick: DispatchTimeInterval = .seconds(30), look: @escaping @Sendable (_ tick: Bool) -> Void) {
        file = (path as NSString).expandingTildeInPath
        self.look = look
        timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + tick, repeating: tick)
        timer.setEventHandler { look(true) }
        timer.resume()
        queue.async { [weak self] in self?.arm() }
    }

    deinit {
        timer.cancel()
        join?.cancel()
        for source in sources { source.cancel() }
    }

    /// Opens the folder and the file again: after a rename the path names
    /// a new file, and the old descriptor watches the old one.
    private func arm() {
        for source in sources { source.cancel() }
        let folder = (file as NSString).deletingLastPathComponent
        sources = [watch(folder, .write), watch(file, [.write, .extend, .delete, .rename, .attrib])].compactMap { $0 }
    }

    private func watch(_ path: String, _ events: DispatchSource.FileSystemEvent) -> DispatchSourceFileSystemObject? {
        // O_EVTONLY: for events only; it never keeps a volume from ejecting.
        // O_NONBLOCK (F-125): a FIFO swapped in at the path does not hold
        // the watch's queue until another process opens it.
        let descriptor = open(path, O_EVTONLY | O_NONBLOCK)
        guard descriptor >= 0 else { return nil }
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: descriptor, eventMask: events, queue: queue)
        source.setEventHandler { [weak self] in self?.changed() }
        source.setCancelHandler { close(descriptor) }
        source.resume()
        return source
    }

    private func changed() {
        join?.cancel()
        let item = DispatchWorkItem { [weak self] in
            self?.arm()
            self?.look(false)
        }
        join = item
        queue.asyncAfter(deadline: .now() + .milliseconds(500), execute: item)
    }
}
