#if DEBUG
    import AppKit
    import Foundation

    /// Debug builds only: sets the screen state for Mac QA screenshots, as UI
    /// scripting is not available on the build Mac. Never a password: vaults
    /// are unlocked through F06 (`--password-stdin`). The values come from the
    /// environment:
    /// - `APP_DEBUG_APPEARANCE`: `light` or `dark`;
    /// - `APP_DEBUG_UI`: `;`-separated `place=group:NAME|tag:NAME|bin|fav|codes|passkeys`,
    ///   `select=TITLE`, `show=FIELD`, `search=TEXT`, `tips=1`.
    enum DebugUI {
        private static let settings: [String: String] = {
            let text = ProcessInfo.processInfo.environment["APP_DEBUG_UI"] ?? ""
            var out: [String: String] = [:]
            for part in text.split(separator: ";") {
                let pair = part.split(separator: "=", maxSplits: 1).map(String.init)
                if pair.count == 2 { out[pair[0]] = pair[1] }
            }
            return out
        }()

        static func appearance() {
            switch ProcessInfo.processInfo.environment["APP_DEBUG_APPEARANCE"] {
            case "light": NSApp.appearance = NSAppearance(named: .aqua)
            case "dark": NSApp.appearance = NSAppearance(named: .darkAqua)
            default: break
            }
        }

        static func apply(to model: VaultModel) {
            if let place = settings["place"] {
                let groups = model.sidebar?.groups ?? []
                if place.hasPrefix("group:"), let row = groups.first(where: { "group:" + $0.name == place }) {
                    model.choose(.group(row.id))
                } else if place.hasPrefix("tag:") {
                    model.choose(.tag(String(place.dropFirst(4))))
                } else if let simple = [
                    "bin": VaultModel.Place.bin, "fav": .favorites, "codes": .codes, "passkeys": .passkeys,
                ][place] {
                    model.choose(simple)
                }
            }
            if let search = settings["search"] {
                model.setSearch(search)
            }
            if let title = settings["select"], let row = model.rows.first(where: { $0.title == title }) {
                model.select(row.id)
            }
            if let field = settings["show"] {
                Task { await model.toggleShow(field) }
            }
            model.tips = settings["tips"] == "1"
        }
    }
#endif
