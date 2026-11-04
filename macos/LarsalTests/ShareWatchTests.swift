import Foundation
import LarsalCore
import Testing

/// INT-08.15 (LD-216, F-157): every share container path Rust names gets a
/// `DiskWatch` of its own. Rust's half, one path per approved importing
/// share, is share.rs `int08_15_each_approved_importing_share_is_one_path_to_watch`;
/// no Swift call can put a share item on a group before E11-S5. Demo
/// vaults only, copied to target/.
@MainActor
@Suite(.serialized)
struct ShareWatchTests {
    init() { ParityDemo.setUp() }

    @Test("LD-216: two share paths get two watches; a path still named keeps its watch, one no longer named stops")
    func oneWatchPerSharePath() throws {
        let model = try ParityDemo.window("share-watch")
        let main = try #require(model.main)
        let folder = ParityDemo.temporaryDirectory.appending(path: "larsal-share-watch-\(getpid())")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let team = folder.appending(path: "team.larsalvault").path(percentEncoded: false)
        let home = folder.appending(path: "home.larsalvault").path(percentEncoded: false)
        main.watch(sharePaths: [team, home])
        #expect(Set(main.disk.shareWatches.keys) == [team, home])
        let first = try #require(main.disk.shareWatches[team])
        let second = try #require(main.disk.shareWatches[home])
        #expect(first !== second, "each path has a watch of its own")
        main.watch(sharePaths: [team, home])
        #expect(main.disk.shareWatches[team] === first, "a refresh keeps the watch")
        main.watch(sharePaths: [home])
        #expect(Set(main.disk.shareWatches.keys) == [home])
        #expect(main.disk.shareWatches[home] === second)
        main.watch(sharePaths: [])
        #expect(main.disk.shareWatches.isEmpty)
    }
}
