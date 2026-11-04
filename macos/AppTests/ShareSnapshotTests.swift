import AppCore
import AppKit
import SwiftUI
import Testing

// E11-S5: W-15's shared-group screens (design/option-a/proposals.html,
// section W-15), offscreen, and the demo the share flows use
// (ShareFlowTests.swift). Demo vaults only, copied to target/option-a; every
// copy goes to the session's private pasteboard (LD-206), and no window is
// ever shown (AGENTS.md rule 10).

/// W-15's frames.
enum ShareFrame: String, CaseIterable, CustomTestStringConvertible {
    case sync = "w-15-sharing-sync"
    case inactive = "w-15-sharing-inactive"
    case messages = "w-15-messages-labels"
    case banner = "w-15-list-banner"
    case kinds = "w-15-banner-kinds"
    case inside = "w-15-list-inside-share"
    case approval = "w-15-list-approval"
    case vaultSettings = "w-15-vault-settings"

    var testDescription: String { rawValue }
}

/// W-15's demo (`withShares`): Personal with Household (Synchronize;
/// Streaming inside it, Netflix moved there) and Devices (Import, set up in
/// another session, so not approved in this one).
@MainActor
enum ShareDemo {
    static let stored = "Shared/Household.appvault"
    static let devices = "/Users/alex/Library/Mobile Documents/com~apple~CloudDocs/Family/Devices.appvault"
    static let password = "M2ciPK%tX7UctF=A"

    /// The three demo vaults, Personal dressed and unlocked. `household`:
    /// Household has its share item; `allow`: import and export on.
    static func window(_ folder: String, household: Bool = true, allow: Bool = false) throws -> MainWindowModel {
        let file = try ParityDemo.path(0, folder: folder)
        try elsewhere(file)
        let session = try ParityDemo.session()
        try session.saveSettings(changes: [AppSetting(key: "save.after_every_change", value: .flag(on: false))])
        var ids: [UInt64] = [try session.open(path: file)]
        for index in 1..<3 { ids.append(try session.open(path: try ParityDemo.path(index, folder: folder))) }
        #expect(try session.unlock(vault: ids[0], password: "demo-pass-7", keyFile: nil) == .unlocked)
        try session.switchTo(vault: ids[0])
        let window = MainWindowModel(session: session)
        window.refresh()
        let main = try #require(window.main)
        main.addGroup(name: "Household", parent: nil, glyph: "house-line", colour: "purple")
        let home = try group(main, "Household")
        main.addGroup(name: "Streaming", parent: home, glyph: "film-strip", colour: "red")
        let streaming = try group(main, "Streaming")
        let morgan = "family.morgan@posteo.de"
        try entry(main, home, ["Electricity", morgan, "Kv7!mQ2#Ld9@Wx4$", "https://portal.example.com"])
        try entry(main, home, ["Alarm system", "morgan-home", "Ha3@rT8!pZ5#nV1$", "https://alarm.example.com"])
        try entry(main, streaming, ["Spotify Family", morgan, "Sp6#Wq1!Xr8@Kt3$", "https://www.spotify.com"])
        let netflix = try row(main, "Netflix")
        _ = try session.beginEdit(vault: main.vault.id, entry: netflix)
        try session.setGroup(vault: main.vault.id, group: streaming)
        _ = try session.commitEdit(vault: main.vault.id)
        if household { try share(main, home, .synchronize, stored) }
        _ = try session.save(vault: main.vault.id)  // saved before sharing runs: nothing exports
        if allow { try flags(session, true) }
        main.afterChange(select: nil)
        main.shareRefresh()
        return window
    }

    /// A share made in a session of its own (another Mac) and saved to the
    /// file: its approval is not in the window's session (INT-08.31).
    /// Devices' Import share by default.
    static func elsewhere(
        _ file: String, group: String = "Devices", mode: ShareMode = .import, path: String = devices
    ) throws {
        let other = Session()
        let id = try other.open(path: file)
        _ = try other.unlock(vault: id, password: "demo-pass-7", keyFile: nil)
        let target = try #require(try other.sidebar(vault: id).groups.first { $0.name == group }?.id)
        _ = try other.shareEdit(vault: id, group: target)
        _ = try other.shareEditChange(vault: id, change: .mode(mode: mode))
        _ = try other.shareEditChange(vault: id, change: .path(path: path))
        _ = try other.shareEditPassword(vault: id, value: "Dv4!kT9#mQ2@xL7$")
        try other.shareEditSave(vault: id)
        _ = try other.save(vault: id)
        try? other.close(vault: id)
    }

    static func flags(_ session: Session, _ allowed: Bool) throws {
        try session.saveSettings(
            changes: ["share.import", "share.export"].map { AppSetting(key: $0, value: .flag(on: allowed)) })
    }

    /// A share made on the Sharing page's model.
    static func share(_ main: VaultModel, _ group: String, _ mode: ShareMode, _ path: String) throws {
        main.editGroup(group)
        let editor = try #require(main.sharing.editor)
        editor.change(.mode(mode: mode))
        editor.change(.path(path: path))
        editor.typed(password)
        main.saveGroup()
        #expect(main.sharing.editor == nil, "\(editor.problem ?? "")")
    }

    static func group(_ main: VaultModel, _ name: String) throws -> String {
        try #require(main.sidebar?.groups.first { $0.name == name }?.id, "\(name)")
    }

    static func row(_ main: VaultModel, _ title: String) throws -> String {
        let rows = try main.session.list(vault: main.vault.id, view: .all).rows
        return try #require(rows.first { $0.title == title }?.id, "\(title)")
    }

    /// A new entry: title, user name, password, URL.
    private static func entry(_ main: VaultModel, _ group: String, _ fields: [String]) throws {
        let (session, id) = (main.session, main.vault.id)
        _ = try session.beginNew(vault: id, group: group)
        try session.setText(vault: id, field: .title, value: fields[0])
        try session.setText(vault: id, field: .userName, value: fields[1])
        _ = try session.setPassword(vault: id, value: fields[2])
        try session.setText(vault: id, field: .url, value: fields[3])
        _ = try session.commitEdit(vault: id)
    }

    /// Paths with their links resolved (/tmp is /private/tmp).
    static func real(_ paths: [String]) -> [String] {
        paths.map { path in
            let url = URL(fileURLWithPath: path)
            let folder = url.deletingLastPathComponent().resolvingSymlinksInPath()
            return folder.appending(path: url.lastPathComponent).path(percentEncoded: false)
        }
    }

    /// Waits up to 10 s for a share pass on its worker.
    static func until(_ done: () throws -> Bool) async throws {
        for _ in 0..<400 where try !done() { try await Task.sleep(for: .milliseconds(25)) }
    }
}

@MainActor
@Suite(.serialized)
struct ShareSnapshotTests {
    init() { ParityDemo.setUp() }

    @Test("W-15 frame, offscreen, light and dark", arguments: ShareFrame.allCases)
    func frame(_ frame: ShareFrame) async throws {
        let window = try ShareDemo.window("share-shots", household: frame != .inactive, allow: Self.allowed(frame))
        let main = try #require(window.main)
        try ParityDemo.rate(window)
        let root: AnyView
        switch frame {
        case .messages: root = AnyView(ShareCards.messages(main))
        case .kinds: root = AnyView(ShareCards.kinds)
        case .vaultSettings:
            let shown = try #require(window.shown)
            let settings = VaultSettingsModel(session: window.session, vault: shown)
            settings.page = .shares
            root = AnyView(VaultSettingsWindow(model: settings).frame(width: 900, height: 640))
        default:
            try state(frame, main)
            root = AnyView(MainWindow(model: window).frame(width: 1320, height: 820))
        }
        let card = frame == .messages || frame == .kinds
        let size = try await Shots.write(
            root.font(.sans(14)).foregroundStyle(Tok.text), size: card ? nil : Self.size(frame), frame: frame.rawValue)
        #expect(size.width > 600)
        // F-175: the card's words, with its straight apostrophe (U+0027).
        let tree = ParityDemo.root.appending(path: "app-shots/light/\(frame.rawValue).ax.json")
        let text = try String(contentsOf: tree, encoding: .utf8)
        #expect(!text.contains("\u{2019}") && !text.contains("\\u2019"), "\(frame)")
        // F-214 (BUILD-AND-VERIFY checks 3 and 4): the title tile is W-15's
        // `tile lg`, 44 points, so the heading starts at 333 and the badge
        // sits on the tile's corner; the help lines keep their 16-point line
        // box, so Keep group structure's switch is where W-15 draws it.
        if frame == .sync || frame == .inactive {
            let boxes = try Self.boxes(tree)
            #expect(boxes["AXHeading Edit group"]?.first == 333, "\(boxes["AXHeading Edit group"] ?? [])")
            if frame == .sync {
                #expect(boxes["AXImage Share inactive"] == [300, 102, 26, 26])
                let keep = try #require(boxes["AXCheckBox Keep group structure"])
                #expect(abs(keep[1] - 575.5) <= 1, "\(keep)")
            }
        }
        window.lockAll()
    }

    /// A shot's tree as boxes [x, y, width, height] by "role label", the
    /// first node of each.
    static func boxes(_ tree: URL) throws -> [String: [Double]] {
        var out: [String: [Double]] = [:]
        func walk(_ node: [String: Any]) {
            if let box = node["frame"] as? [Double], let label = node["label"] as? String {
                let key = "\(node["role"] as? String ?? "") \(label)"
                if out[key] == nil { out[key] = box }
            }
            (node["children"] as? [[String: Any]] ?? []).forEach(walk)
        }
        walk(try #require(JSONSerialization.jsonObject(with: Data(contentsOf: tree)) as? [String: Any]))
        return out
    }

    static func allowed(_ frame: ShareFrame) -> Bool {
        [.banner, .approval, .vaultSettings].contains(frame)
    }

    static func size(_ frame: ShareFrame) -> CGSize {
        frame == .vaultSettings ? CGSize(width: 900, height: 640) : CGSize(width: 1320, height: 820)
    }

    /// mockup `shareWin` and `editWin` states.
    private func state(_ frame: ShareFrame, _ main: VaultModel) throws {
        switch frame {
        case .sync, .inactive:
            main.choose(.group(try ShareDemo.group(main, "Household")))
            main.editGroup(try ShareDemo.group(main, "Household"))
            if frame == .inactive { #expect(main.sharing.editor?.view.item == false) }
        case .banner:
            main.choose(.group(try ShareDemo.group(main, "Household")))
            main.select(try ShareDemo.row(main, "Electricity"))
            // INT-08.20's error banner as one pass leaves it (Hide sync
            // success messages on): a warning, then the error.
            main.sharing.banner = ShareBanner(
                level: .error,
                lines: [
                    ShareDemo.stored + ": 2 items were not imported because they belong outside this shared group.",
                    ShareDemo.stored
                        + ": export failed. The file could not be written: there is no space left on the disk.",
                ], paths: [ShareDemo.stored, ShareDemo.stored])
        case .inside:
            main.choose(.group(try ShareDemo.group(main, "Streaming")))
            main.select(try ShareDemo.row(main, "Netflix"))
        case .approval:
            main.choose(.group(try ShareDemo.group(main, "Devices")))
            main.select(try ShareDemo.row(main, "Home Wi-Fi"))
            let label = try #require(main.sharing.label)
            #expect(label.state == .waiting)
            main.dialog = .approveShare(label)
        default: break
        }
        main.sharing.banner = frame == .banner ? main.sharing.banner : nil
    }
}

/// The two card frames, from the app's own views.
@MainActor
enum ShareCards {
    static func sheet(_ width: CGFloat, _ items: [(String, AnyView)]) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(items.indices, id: \.self) { index in
                Lab(title: items[index].0)
                items[index].1.padding(.bottom, 16)
            }
        }
        .padding([.horizontal, .top], 20)
        .padding(.bottom, 4)
        .frame(width: width, alignment: .leading)
        .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
    }

    static func messages(_ main: VaultModel) -> some View {
        let path = ShareDemo.stored
        let warnings: [(String, ShareWarning)] = [
            ("Path ends in no name App can share", .extension), ("Another group exports to this file", .otherExports),
            ("Another group imports this file", .otherImports),
            ("One group imports it, another exports it", .importAndExport),
            ("Import and export both off", .bothOff), ("Only import allowed", .exportOff),
            ("Only export allowed", .importOff), ("Path is the file of an open vault", .openVault),
        ]
        let label = { (state: ShareState, mode: ShareMode, off: (Bool, Bool), full: String) in
            ShareLabel(
                group: "", name: "Household", state: state, mode: mode, path: path, fullPath: full, importOff: off.0,
                exportOff: off.1)
        }
        let labels: [(String, ShareLabel)] = [
            ("Synchronize, running", label(.running, .synchronize, (false, false), "")),
            ("Import with import turned off", label(.running, .import, (true, false), "")),
            ("Export with export turned off", label(.running, .export, (false, true), "")),
            ("Inactive, or settings that cannot be read", label(.off, .inactive, (false, false), "")),
            ("Settings not made on this Mac", label(.waiting, .import, (false, false), ShareDemo.devices)),
        ]
        let badges = HStack(spacing: 24) {
            ForEach([true, false], id: \.self) { active in
                HStack(spacing: 12) {
                    Tile(color: Tok.tileColor("purple"), glyph: "house-line").shareMark(active)
                    Tile(color: Tok.tileColor("purple"), glyph: "house-line", size: 44).shareMark(active, large: true)
                    Text(verbatim: active ? "Share active" : "Share inactive")
                }
            }
        }
        return HStack(alignment: .top, spacing: 32) {
            sheet(
                700,
                warnings.map { ($0.0, AnyView(ShareWarningNotice(warning: $0.1, path: path))) } + [
                    ("Under Share password, empty or weak", AnyView(ShareWarningNotice.weak))
                ])
            sheet(624, [("Badges", AnyView(badges))] + labels.map { ($0.0, AnyView(ShareLabelNotice(label: $0.1))) })
        }
        .padding(1)
    }

    static var kinds: some View {
        let path = ShareDemo.stored
        let banner = { (level: ShareLevel, lines: [(String, String)]) in
            AnyView(
                ShareBannerNotice(
                    banner: ShareBanner(level: level, lines: lines.map { $0 + $1 }, paths: lines.map(\.0))
                ) {})
        }
        let several =
            ": imported by several groups (Household, Holiday flat), so none of them is updated until only one "
            + "imports it."
        return sheet(
            1016,
            [
                ("Success", banner(.success, [(path, ": changes imported."), (path, ": exported.")])),
                ("Warning", banner(.warning, [(path, several)])),
                (
                    "Error",
                    banner(
                        .error,
                        [
                            (path, ": changes imported."),
                            ("Shared/Parents.appvault", ": import failed. There is no file at this path."),
                            ("Shared/Car.appvault", ": import failed. It is not a share file (unknown file kind)."),
                            (
                                "Shared/Partner.appvault",
                                ": exported by several groups (Banking, Shopping), so nothing was exported. "
                                    + "Give each group its own file."
                            ),
                        ])
                ),
            ]
        )
        .padding(1)
    }
}
