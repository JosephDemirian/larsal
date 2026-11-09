import AppKit
import LarsalCore
import SwiftUI
import Testing

/// The e22-s1 frames FIL-02-T16 renders.
enum FileFrame: String, CaseIterable, CustomTestStringConvertible {
    case entry = "e22-s1-entry"
    case encrypt = "e22-s1-encrypt"
    case manual = "e22-s1-manual"
    case recipients = "e22-s1-recipients"
    case key = "e22-s1-key"
    case decrypt = "e22-s1-decrypt"
    case progress = "e22-s1-progress"
    case complete = "e22-s1-complete"
    case error = "e22-s1-error"
    case collision = "e22-s1-collision"
    case cleanup = "e22-s1-cleanup"
    case locked = "e22-s1-locked"
    case weakFile = "e22-s1-weak"
    case unprotected = "e22-s1-unprotected"

    var testDescription: String { rawValue }
}

extension FileSuites {
    /// The e22-s1 frames (design/option-a/proposals.html), offscreen, never
    /// ordered in, light and dark (BUILD-AND-VERIFY.md).
    @MainActor
    @Suite(.serialized)
    struct FileSnapshotTests {
        init() { ParityDemo.setUp() }

        @Test("FIL-02-T16 frames E22-S1, offscreen, light and dark", arguments: FileFrame.allCases)
        func frame(_ frame: FileFrame) async throws {
            let window = try ParityDemo.window("files-shot-" + frame.rawValue)
            defer { window.lockAll() }
            let readable: [FileFrame] = [.decrypt, .progress, .complete, .error, .collision, .cleanup]
            let encrypt = !readable.contains(frame)
            let file = encrypt ? "Mountain photo.jpg" : "Mountain photo.jpg.age"
            let (_, source) = try FileDemo.folder("shot-" + frame.rawValue, bytes: 12_400_000, file: file)
            let flow = FileFlow(session: window.session, vault: (window.main!.vault.id, "Personal"))
            flow.dropped([source], encrypt: encrypt)
            state(frame, flow)
            let host = NSHostingView(rootView: FileDialog(flow: flow).font(.sans(14)).foregroundStyle(Tok.text))
            host.frame = NSRect(origin: .zero, size: host.fittingSize)
            let offscreen = NSWindow(
                contentRect: host.frame.offsetBy(dx: -20_000, dy: -20_000), styleMask: [.borderless],
                backing: .buffered, defer: false)
            offscreen.colorSpace = .sRGB
            offscreen.backgroundColor = .clear
            offscreen.contentView = host
            let shots = SnapshotTests()
            for (folder, look) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
                offscreen.appearance = NSAppearance(named: look)
                host.layoutSubtreeIfNeeded()
                host.frame = NSRect(origin: .zero, size: host.fittingSize)
                try await Task.sleep(for: .milliseconds(200))
                host.layoutSubtreeIfNeeded()
                let rep = try #require(host.bitmapImageRepForCachingDisplay(in: host.bounds))
                host.cacheDisplay(in: host.bounds, to: rep)
                let png = try #require(rep.retagging(with: .sRGB)?.representation(using: .png, properties: [:]))
                let out = ParityDemo.shotsDirectory.appending(path: "\(folder)/\(frame.rawValue).png")
                try FileManager.default.createDirectory(
                    at: out.deletingLastPathComponent(), withIntermediateDirectories: true)
                try png.write(to: out)
                #expect(png.count > 2_000, "\(out.path)")
                let tree = out.deletingPathExtension().appendingPathExtension("ax.json")
                try shots.accessibilityTree(host).write(to: tree)
            }
            offscreen.contentView = nil
        }

        /// The screen of each frame, and the failure the end frames show.
        static let screens: [FileFrame: FileFlow.Screen] = [
            .entry: .entry, .manual: .manual, .recipients: .recipients, .key: .key, .progress: .progress,
            .complete: .complete, .error: .error, .collision: .collision, .cleanup: .cleanup, .locked: .locked,
            .weakFile: .weakFile, .unprotected: .unprotectedFile,
        ]
        static let failures: [FileFrame: String] = [
            .error: "MSG-FILE-DECRYPT", .collision: "MSG-FILE-EXISTS", .cleanup: "MSG-FILE-CLEANUP",
        ]

        private func state(_ frame: FileFrame, _ flow: FileFlow) {
            let checked: [FileFrame] = [.progress, .complete, .error, .collision, .cleanup]
            if checked.contains(frame) {
                flow.progress = FileProgress(
                    step: .checking, done: 2_480_000_000, total: 4_000_000_000, end: nil, finished: false)
            }
            if let id = Self.failures[frame] {
                flow.end = .failed(id: id, text: Self.words(id), savedKey: false)
            }
            if frame == .complete {
                flow.end = .done(savedTo: "Documents / Mountain photo.jpg", bytes: 12_400_000)
            }
            if frame == .manual {
                flow.screen = .manual
                flow.type(.passphrase, "illustration")
                flow.type(.repeated, "illustration")
                flow.encrypt()
                flow.saveManual = true
            }
            if frame == .recipients {
                flow.recipients = ["age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"]
            }
            if let screen = Self.screens[frame] { flow.screen = screen }
        }

        /// FIL-03's words, as Rust gives them.
        static func words(_ id: String) -> String {
            switch id {
            case "MSG-FILE-DECRYPT": "This file could not be decrypted. Check the passphrase or file key and try again."
            case "MSG-FILE-EXISTS": "A file already exists with this name. Choose a different name."
            default:
                "Larsal could not remove an incomplete file. It may contain readable data. "
                    + "Check the destination before you leave."
            }
        }
    }
}
