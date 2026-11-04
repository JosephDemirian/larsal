import CoreText
import SwiftUI

/// The bundle that holds App's resources: the app, or the test bundle that
/// compiles the same files.
private final class BundleToken {}
let appBundle = Bundle(for: BundleToken.self)

/// The Option A design tokens (design/option-a/app.css `.win.light`,
/// `.win.dark`, `:root`): one colour asset each, Any and Dark appearances,
/// made by scripts/make-option-a-assets.py. No other colours in the app.
enum Tok {
    static func color(_ name: String) -> Color { Color(name, bundle: appBundle) }
    static let ground = color("ground")
    static let surface = color("surface")
    static let raised = color("raised")
    static let active = color("active")
    static let hover = color("hover")
    static let border = color("border")
    static let rule = color("rule")
    static let control = color("control")
    static let field = color("field")
    static let tile = color("tile")
    static let text = color("text")
    static let muted = color("muted")
    static let primary = color("primary")
    static let onPrimary = color("on-primary")
    static let primaryHover = color("primary-hover")
    static let accent = color("accent")
    static let accentSoft = color("accent-soft")
    static let digit = color("digit")
    static let symbol = color("symbol")
    static let positive = color("positive")
    static let negative = color("negative")
    static let warning = color("warning")
    static let negBg = color("neg-bg")
    static let negInk = color("neg-ink")
    static let warnBg = color("warn-bg")
    static let warnInk = color("warn-ink")
    static let posBg = color("pos-bg")
    static let posInk = color("pos-ink")
    static let chipBg = color("chip-bg")
    static let chipInk = color("chip-ink")
    static let scrim = color("scrim")
    // The mockup's literal colours (`.si:hover`, `.menu`, `.msep`, `.mi:hover`, `.toast`).
    static let sidebarHover = color("sidebar-hover")
    static let menu = color("menu")
    static let menuRule = color("menu-rule")
    static let onAccent = color("on-accent")
    static let onDanger = color("on-danger")
    static let pressed = color("pressed")
    static let badgeInk = color("badge-ink")
    /// `.toast` text and its glyph; the toast's fill is `primary`.
    static let toastInk = color("toast-ink")
    static let toastIcon = color("toast-icon")
    /// `.dlg`'s fill (dark #1a1a1d; light keeps `surface`).
    static let dialog = color("dialog")
    /// `.srow + .srow`'s rule (dark #232327; light keeps `border`).
    static let srowRule = color("srow-rule")
    /// The browser's range track (`.range`) and its 1-point edge.
    static let rangeTrack = color("range-track")
    static let rangeEdge = color("range-edge")
    // Sidebar tile colours (`:root`), the same in both themes.
    static let orange = color("orange")
    static let gray = color("gray")
    static let pink = color("pink")
    static let graphite = color("graphite")

    /// A tile colour by its token name (`blue` … `graphite`).
    static func tileColor(_ name: String) -> Color { color(name) }
}

/// IBM Plex Sans and Mono (OFL) and the Phosphor fonts (MIT), bundled as
/// WOFF2 and registered for this process.
enum Fonts {
    private static var done = false

    static func register() {
        guard !done else { return }
        done = true
        for url in appBundle.urls(forResourcesWithExtension: "woff2", subdirectory: nil) ?? [] {
            CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
        }
    }
}

extension Font {
    /// IBM Plex Sans at the mockup's size: 400, 500 (`.medium`) or 600
    /// (`.semibold`).
    static func sans(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        let name =
            switch weight {
            case .medium: "IBMPlexSans-Medium"
            case .semibold, .bold: "IBMPlexSans-SemiBold"
            default: "IBMPlexSans-Regular"
            }
        return .custom(name, fixedSize: size)
    }

    /// IBM Plex Mono: secrets, codes, keys, paths.
    static func mono(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        .custom(weight == .regular ? "IBMPlexMono-Regular" : "IBMPlexMono-Medium", fixedSize: size)
    }
}

/// A Phosphor glyph (`ph ph-NAME` or `ph-fill ph-NAME`), never read aloud.
struct Glyph: View {
    let name: String
    var size: CGFloat = 16
    var fill = false

    var body: some View {
        let point = Glyphs.points[name].flatMap(UnicodeScalar.init) ?? " "
        Text(verbatim: String(Character(point)))
            .font(.custom(fill ? "Phosphor-Fill" : "Phosphor", fixedSize: size))
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }
}

/// The mockup's `.tile`: a coloured rounded square with a white fill glyph.
struct Tile: View {
    let color: Color
    let glyph: String
    var size: CGFloat = 22

    var body: some View {
        let (radius, glyphSize): (CGFloat, CGFloat) =
            switch size {
            case ..<21: (5, 12)
            case ..<23: (6, 13)
            case ..<27: (7, 15)
            case ..<33: (8, 18)
            case ..<45: (11, 24)
            default: (16, 34)
            }
        RoundedRectangle(cornerRadius: radius)
            .fill(color)
            .overlay(RoundedRectangle(cornerRadius: radius).strokeBorder(.black.opacity(0.08), lineWidth: 0.5))
            .overlay(Glyph(name: glyph, size: glyphSize, fill: true).foregroundStyle(.white))
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }
}

/// The mockup's `.kbd`: a shortcut in a small raised box.
struct Kbd: View {
    let keys: String
    var plain = false

    var body: some View {
        Text(verbatim: keys)
            .font(.sans(12))
            .foregroundStyle(Tok.muted)
            .padding(.horizontal, plain ? 0 : 6)
            .frame(height: 20)
            .background(plain ? .clear : Tok.raised, in: RoundedRectangle(cornerRadius: 5))
    }
}

extension View {
    /// The mockup's `--pop-shadow`: a hairline ring and a soft drop (light
    /// `0 12px 32px rgba(0,0,0,.16)`, dark `0 16px 40px rgba(0,0,0,.6)`),
    /// cast by the panel's shape only, never by its text.
    func popShadow(_ scheme: ColorScheme) -> some View {
        let dark = scheme == .dark
        return
            self
            .background {
                ZStack {
                    BoxShadow(radius: 10, drop: dark ? 16 : 12, blur: dark ? 40 : 32, alpha: dark ? 0.6 : 0.16)
                    RoundedRectangle(cornerRadius: 10).fill(Tok.menu)
                }
            }
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .strokeBorder(dark ? Color.white.opacity(0.08) : Color.black.opacity(0.06))
            )
    }

    /// Tabular figures (`.num`).
    func num() -> some View { monospacedDigit() }

    /// The mockup's CSS line box for wrapping text: `lineHeight` per line
    /// for IBM Plex at `size` (its own line is 1.3 em), the extra split
    /// above and below each line as CSS does.
    func lineBox(_ size: CGFloat, _ lineHeight: CGFloat) -> some View {
        let extra = max(lineHeight - 1.3 * size, 0)
        return lineSpacing(extra).padding(.vertical, extra / 2)
    }
}

/// CSS `box-shadow` drawn with plain fills: rings of the shape, 2 points
/// apart, whose summed alpha follows the Gaussian blur's edge (σ = blur / 2).
/// No filter, so it looks the same on screen and in a bitmap (a `.shadow`
/// offset turns upward there, and a `.blur` is not drawn at all).
struct BoxShadow: View {
    let radius: CGFloat
    /// The vertical offset.
    let drop: CGFloat
    let blur: CGFloat
    let alpha: Double

    var body: some View {
        let sigma = blur / 2
        // Rings deeper inside lie under the shape's opaque fill; on a box
        // shorter than the blur they would make this stack taller than it.
        let outsets = Array(stride(from: -3 * sigma, through: 3 * sigma, by: 2)).filter { $0 > -2 }
        ZStack {
            ForEach(outsets.indices, id: \.self) { index in
                let outset = outsets[index]
                let inner = coverage(outset, sigma)
                let outer = index + 1 < outsets.count ? coverage(outsets[index + 1], sigma) : 0
                RoundedRectangle(cornerRadius: max(radius + outset, 0))
                    .fill(.black.opacity(1 - (1 - inner) / (1 - outer)))
                    .padding(-outset)
            }
        }
        .offset(y: drop)
        .accessibilityHidden(true)
    }

    /// The shadow's alpha at `distance` outside the shape's edge.
    private func coverage(_ distance: CGFloat, _ sigma: CGFloat) -> Double {
        alpha * 0.5 * erfc(Double(distance / sigma) / 2.squareRoot())
    }
}
