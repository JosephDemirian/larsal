import AppKit
import LarsalCore
import SwiftUI

/// The Simple Icons brand logos (CC0) Larsal ships, as vector assets
/// `brand-<key>`, and Larsal's rule for an entry's logo until the editor stores
/// one (E5-S5): the URL host's site name only. The browser and security key
/// marks show where the mockup draws them (settings, unlock).
enum Brands {
    static let titles: [String: String] = [
        "github": "GitHub", "apple": "Apple", "google": "Google", "hetzner": "Hetzner",
        "protonmail": "Proton Mail", "paypal": "PayPal", "instagram": "Instagram", "wise": "Wise",
        "figma": "Figma", "mastodon": "Mastodon", "linear": "Linear", "visa": "Visa", "zalando": "Zalando",
        "deutschebahn": "Deutsche Bahn", "ebay": "eBay", "netflix": "Netflix", "reddit": "Reddit", "x": "X",
        "jira": "Jira", "postgresql": "PostgreSQL", "googlechrome": "Google Chrome",
        "firefoxbrowser": "Firefox Browser", "safari": "Safari", "brave": "Brave", "vivaldi": "Vivaldi",
        "yubico": "Yubico", "opera": "Opera",
    ]
    /// Site names whose brand key differs.
    private static let aliases = ["proton": "protonmail", "bahn": "deutschebahn"]

    static func match(host: String) -> String? {
        let labels = host.split(separator: ":").first.map { $0.split(separator: ".").map(String.init) } ?? []
        guard labels.count >= 2, !labels.allSatisfy({ $0.allSatisfy(\.isNumber) }) else { return nil }
        let site = labels[labels.count - 2].lowercased()
        let key = aliases[site] ?? site
        return titles[key] == nil ? nil : key
    }
}

/// Pictures for the standard icon numbers (MOD-06.1): a Phosphor glyph and
/// a tile colour each. Larsal's own table until the editor's symbol picker
/// (E5-S5).
enum StandardIcons {
    static let table: [(glyph: String, color: String)] = [
        ("key", "gray"), ("globe-simple", "blue"), ("warning", "orange"), ("hard-drives", "slate"),
        ("push-pin", "red"), ("users-three", "pink"), ("squares-four", "purple"), ("note", "yellow"),
        ("plug", "gray"), ("identification-card", "blue"), ("file-text", "gray"), ("camera", "gray"),
        ("wifi-high", "cyan"), ("key", "orange"), ("lightning", "yellow"), ("scan", "gray"),
        ("star", "yellow"), ("disc", "gray"), ("monitor", "blue"), ("envelope-simple", "blue"),
        ("gear-six", "graphite"), ("clipboard-text", "gray"), ("file-plus", "gray"), ("desktop", "gray"),
        ("lightning", "orange"), ("tray", "blue"), ("floppy-disk", "gray"), ("hard-drive", "gray"),
        ("file", "gray"), ("terminal", "graphite"), ("terminal-window", "graphite"), ("printer", "gray"),
        ("squares-four", "purple"), ("play", "green"), ("wrench", "gray"), ("globe", "blue"),
        ("archive", "brown"), ("bank", "green"), ("hard-drive", "blue"), ("clock", "gray"),
        ("magnifying-glass", "blue"), ("flag", "red"), ("cpu", "gray"), ("trash", "gray"),
        ("note-pencil", "yellow"), ("x-circle", "red"), ("info", "blue"), ("shopping-bag", "orange"),
        ("folder-simple", "blue"), ("folder-open", "blue"), ("archive-box", "brown"), ("lock-open", "green"),
        ("lock-simple", "graphite"), ("check-circle", "green"), ("pen", "gray"), ("image", "purple"),
        ("book-open", "brown"), ("list-bullets", "gray"), ("user-circle", "blue"), ("briefcase", "brown"),
        ("house-line", "orange"), ("star", "orange"), ("linux-logo", "gray"), ("feather", "gray"),
        ("apple-logo", "gray"), ("article", "gray"), ("currency-dollar", "green"), ("certificate", "blue"),
        ("device-mobile", "gray"),
    ]

    /// The first standard icon number drawn with `glyph`, if any.
    static func number(_ glyph: String) -> Int32? {
        table.firstIndex { $0.glyph == glyph }.map { Int32($0) }
    }

    /// The tile colour's token name for `number`.
    static func colorName(_ number: Int32) -> String? {
        number >= 0 && Int(number) < table.count ? table[Int(number)].color : nil
    }

    /// The glyph and tile colour for `number`; `nil` for a custom icon.
    static func look(_ number: Int32) -> (glyph: String, color: Color)? {
        guard number >= 0, Int(number) < table.count else { return nil }
        let item = table[Int(number)]
        return (item.glyph, Tok.tileColor(item.color))
    }
}

/// Larsal's own custom icons (LD-192 (1)): a symbol and a colour, stored as a
/// 128-point PNG of the tile (MOD-06.8) named "<symbol> <colour>", so Larsal
/// draws it as the tile again and other apps show the image.
enum SymbolIcon {
    static let colours = ["blue", "teal", "green", "orange", "pink", "red", "purple", "brown", "slate", "gray", "cyan"]

    static func name(_ glyph: String, _ color: String) -> String { glyph + " " + color }

    static func parse(_ name: String?) -> (glyph: String, color: String)? {
        guard let parts = name?.split(separator: " ").map(String.init), parts.count == 2,
            Glyphs.points[parts[0]] != nil, colours.contains(parts[1])
        else { return nil }
        return (parts[0], parts[1])
    }

    /// An icon's glyph and tile colour: Larsal's symbol icon, else a standard one.
    static func look(_ icon: Int32, _ custom: String?) -> (glyph: String, color: Color)? {
        if let symbol = parse(custom) { return (symbol.glyph, Tok.tileColor(symbol.color)) }
        return StandardIcons.look(icon)
    }

    /// The tile as PNG bytes at the custom icon size (128 pixels).
    @MainActor
    static func png(_ glyph: String, _ color: String) -> Data? {
        let tile = Glyph(name: glyph, size: 68, fill: true)
            .foregroundStyle(.white)
            .frame(width: 128, height: 128)
            .background(Tok.tileColor(color), in: RoundedRectangle(cornerRadius: 32))
        let renderer = ImageRenderer(content: tile)
        renderer.scale = 1
        guard let image = renderer.cgImage else { return nil }
        return NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])
    }
}

/// A vault's tile (FMT-03.23): Larsal's vault icon set and the vault settings'
/// colour swatches.
enum VaultLooks {
    static let icons = ["keyhole", "briefcase", "users-three", "house-line", "user", "heart", "star", "shield-check"]
    static let swatches = ["teal", "blue", "green", "orange", "pink", "purple", "slate"]

    static func glyph(_ icon: Int32) -> String {
        icon >= 0 && Int(icon) < icons.count ? icons[Int(icon)] : icons[0]
    }

    /// The swatch nearest the public colour, else one picked from the
    /// path's hue (UL-TILE).
    static func color(_ public: UInt32?, hue: UInt32) -> Color {
        guard let rgb = `public` else { return Tok.tileColor(swatches[Int(hue) * swatches.count / 360]) }
        let want = [Double((rgb >> 16) & 0xFF), Double((rgb >> 8) & 0xFF), Double(rgb & 0xFF)].map { $0 / 255 }
        let nearest = swatches.min { distance($0, want) < distance($1, want) } ?? swatches[0]
        return Tok.tileColor(nearest)
    }

    private static func distance(_ name: String, _ want: [Double]) -> Double {
        guard let color = NSColor(named: name, bundle: appBundle)?.usingColorSpace(.sRGB) else { return .infinity }
        let have = [color.redComponent, color.greenComponent, color.blueComponent].map(Double.init)
        return zip(have, want).map { ($0 - $1) * ($0 - $1) }.reduce(0, +)
    }
}

extension VaultInfo {
    var tileColor: Color { VaultLooks.color(colour, hue: hue) }
    var tileGlyph: String { VaultLooks.glyph(icon) }
    /// "Personal.larsalvault".
    var fileName: String { (path as NSString).lastPathComponent }
}

/// The mockup's entry logo (`logo()`): the brand logo, else the standard
/// icon's tinted tile, else the letter tile.
struct EntryLogo: View {
    enum Size { case tiny, medium, large }

    let title: String
    let host: String
    let icon: Int32
    /// The custom icon's name; Larsal's symbol icons draw as their tile.
    var custom: String?
    var size = Size.medium
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        // Box, corner radius, logo, glyph and letter sizes (`.logo.xs`,
        // `.logo`, `.logo.lg`).
        let metrics: [CGFloat] =
            switch size {
            case .tiny: [24, 6, 14, 13, 11]
            case .medium: [32, 8, 18, 17, 14]
            case .large: [48, 12, 26, 24, 20]
            }
        let (box, radius, mark, glyph, letter) = (metrics[0], metrics[1], metrics[2], metrics[3], metrics[4])
        let shape = RoundedRectangle(cornerRadius: radius)
        Group {
            if let symbol = SymbolIcon.parse(custom) {
                Glyph(name: symbol.glyph, size: glyph, fill: true)
                    .foregroundStyle(.white)
                    .frame(width: box, height: box)
                    .background(Tok.tileColor(symbol.color), in: shape)
                    .accessibilityHidden(true)
            } else if let brand = Brands.match(host: host) {
                Image("brand-" + brand, bundle: appBundle)
                    .resizable()
                    .frame(width: mark, height: mark)
                    .frame(width: box, height: box)
                    .background(Tok.tile, in: shape)
                    .overlay(shape.strokeBorder(Tok.border))
                    // LD-166: a brand logo is named with its brand, as the
                    // mockup's `role="img"`.
                    .accessibilityElement()
                    .accessibilityLabel(Text(verbatim: Brands.titles[brand] ?? brand))
                    .accessibilityAddTraits(.isImage)
            } else if icon > 0, let look = StandardIcons.look(icon) {
                Glyph(name: look.glyph, size: glyph, fill: true)
                    .foregroundStyle(.white)
                    .frame(width: box, height: box)
                    .background(look.color, in: shape)
                    .accessibilityHidden(true)
            } else {
                let hue = Self.hue(title)
                let dark = scheme == .dark
                Text(verbatim: title.first.map { String($0) } ?? "")
                    .font(.sans(letter, .semibold))
                    .foregroundStyle(dark ? Color(hsl: hue, 0.70, 0.78) : Color(hsl: hue, 0.48, 0.30))
                    .frame(width: box, height: box)
                    .background(dark ? Color(hsl: hue, 0.32, 0.20) : Color(hsl: hue, 0.72, 0.90), in: shape)
                    .accessibilityHidden(true)
            }
        }
    }

    /// The mockup's `hue()`: h = (h × 31 + code) mod 360 over the title.
    static func hue(_ title: String) -> Double {
        var hue = 0
        for scalar in title.unicodeScalars {
            hue = (hue * 31 + Int(String(scalar).utf16.first ?? 0)) % 360
        }
        return Double(hue)
    }
}

extension Color {
    /// CSS `hsl(h s l)`: hue in degrees, saturation and lightness 0 to 1.
    init(hsl hue: Double, _ saturation: Double, _ lightness: Double) {
        let chroma = (1 - abs(2 * lightness - 1)) * saturation
        let part = hue.truncatingRemainder(dividingBy: 360) / 60
        let second = chroma * (1 - abs(part.truncatingRemainder(dividingBy: 2) - 1))
        let rgb: [Double] =
            switch part {
            case ..<1: [chroma, second, 0]
            case ..<2: [second, chroma, 0]
            case ..<3: [0, chroma, second]
            case ..<4: [0, second, chroma]
            case ..<5: [second, 0, chroma]
            default: [chroma, 0, second]
            }
        let match = lightness - chroma / 2
        self.init(.sRGB, red: rgb[0] + match, green: rgb[1] + match, blue: rgb[2] + match)
    }
}

/// A browser's logo from the first word of its name (INT-02.29), else a
/// globe.
struct BrowserLogo: View {
    let name: String

    static let brands = [
        "firefox": "firefoxbrowser", "safari": "safari", "chrome": "googlechrome", "brave": "brave",
        "opera": "opera", "vivaldi": "vivaldi",
    ]

    var body: some View {
        let word = name.split(separator: " ").first.map { $0.lowercased() } ?? ""
        if let brand = Self.brands[word] {
            Image("brand-" + brand, bundle: appBundle)
                .resizable()
                .frame(width: 18, height: 18)
                .accessibilityElement()
                .accessibilityLabel(Text(verbatim: Brands.titles[brand] ?? brand))
                .accessibilityAddTraits(.isImage)
        } else {
            Glyph(name: "globe-simple", size: 18).foregroundStyle(Tok.muted)
        }
    }
}
