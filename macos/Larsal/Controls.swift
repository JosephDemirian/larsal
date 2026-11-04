import SwiftUI

/// The mockup's `.btn` and its kinds and sizes.
struct Btn: ButtonStyle {
    enum Kind { case plain, primary, ghost, danger }
    enum Size { case small, medium, large, huge }

    var kind = Kind.plain
    var size = Size.medium
    var wide = false
    /// `.quick .btn` and others set their own side padding.
    var pad: CGFloat?
    @State private var hover = false

    /// Height, side padding, font size and corner radius of each size.
    private var metrics: [CGFloat] {
        switch size {
        case .small: [28, 10, 13, 8]
        case .medium: [32, 12, 14, 8]
        case .large: [36, 14, 14, 8]
        case .huge: [44, 18, 15, 10]
        }
    }

    private func fill(_ pressed: Bool) -> Color {
        switch kind {
        case .primary: hover ? Tok.primaryHover : Tok.primary
        case .danger: Tok.negative
        case .ghost: hover ? Tok.hover : .clear
        case .plain: pressed ? Tok.active : hover ? Tok.hover : Tok.surface
        }
    }

    private var ink: Color {
        switch kind {
        case .primary: Tok.onPrimary
        case .danger: Tok.onDanger
        case .ghost: hover ? Tok.text : Tok.muted
        case .plain: Tok.text
        }
    }

    private var line: Color {
        switch kind {
        case .primary: Tok.primary
        case .danger: Tok.negative
        case .ghost: .clear
        case .plain: Tok.control
        }
    }

    func makeBody(configuration: Configuration) -> some View {
        let size = metrics
        let shape = RoundedRectangle(cornerRadius: size[3])
        return configuration.label
            .font(.sans(size[2], .medium))
            .lineLimit(1)
            .foregroundStyle(ink)
            // The 1-point border is part of the width, as CSS's border box.
            .padding(.horizontal, (pad ?? size[1]) + 1)
            .frame(maxWidth: wide ? .infinity : nil, minHeight: size[0], maxHeight: size[0])
            .background(fill(configuration.isPressed), in: shape)
            .overlay(shape.strokeBorder(line))
            .contentShape(shape)
            .onHover { hover = $0 }
    }
}

/// A button's content: a glyph, its title and an optional shortcut, 6 apart.
struct BtnLabel: View {
    var glyph: String?
    let title: String
    var keys: String?

    var body: some View {
        HStack(spacing: 6) {
            if let glyph { Glyph(name: glyph) }
            Text(verbatim: title)
            if let keys { Text(verbatim: keys).font(.sans(12)).opacity(0.6) }
        }
    }
}

/// The mockup's `.ibtn`: a 32-point (28 for `.sm`) icon button with a name
/// and a tooltip.
struct IconButton: View {
    let glyph: String
    let label: String
    var size: CGFloat = 32
    var glyphSize: CGFloat = 16
    var hint: String?
    let action: () -> Void
    @State private var hover = false
    @Environment(\.isEnabled) private var enabled

    var body: some View {
        Button(action: action) {
            // A button whose whole label is hidden from VoiceOver cannot take
            // the focus (AT-K06); the button's own name is what is read.
            Glyph(name: glyph, size: glyphSize)
                .accessibilityHidden(false)
                .foregroundStyle(hover && enabled ? Tok.text : Tok.muted)
                .frame(width: size, height: size)
                .background(hover && enabled ? Tok.active : .clear, in: RoundedRectangle(cornerRadius: 8))
                .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .onHover { hover = $0 }
        .help(hint ?? label)
        .accessibilityLabel(Text(verbatim: label))
        .accessibilityHint(hint.map { Text(verbatim: $0) } ?? Text(verbatim: ""))
    }
}

/// A button that draws only its label. Unlike `.plain` it adds no dimming,
/// so a later story's control looks as drawn; it stays disabled for clicks
/// and for VoiceOver.
struct Bare: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View { configuration.label }
}

/// The mockup's `.sw` switch, 34 by 20.
struct SwitchStyle: ToggleStyle {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        Button {
            configuration.isOn.toggle()
        } label: {
            Capsule()
                .fill(configuration.isOn ? Tok.accent : Tok.control)
                .frame(width: 34, height: 20)
                .overlay(alignment: configuration.isOn ? .trailing : .leading) {
                    Circle()
                        .fill(.white)
                        .shadow(color: .black.opacity(0.25), radius: 1, y: 1)
                        .frame(width: 16, height: 16)
                        .padding(2)
                }
                .animation(reduceMotion ? nil : .easeOut(duration: 0.15), value: configuration.isOn)
        }
        .buttonStyle(Bare())
        .accessibilityRepresentation { Toggle(isOn: configuration.$isOn) { configuration.label } }
    }
}

/// Later stories' controls are drawn exactly but do nothing yet: disabled,
/// with a tooltip and an accessible hint that say when they come.
extension View {
    func later(_ hint: String) -> some View {
        disabled(true)
            .help(hint)
            .accessibilityHint(Text(verbatim: hint))
    }
}

/// When each later control comes (plan/epics.md).
enum Later {
    static let editor = "Editing comes with the entry editor (E5-S5)."
    static let newVault = "New vaults come with the new vault wizard (E5-S8)."
    static let vaultSettings = "Vault settings come in E5-S8."
    static let settings = "Settings come in E5-S9."
    static let saving = "Restore and delete come with saving (E5-S10)."
    static let touchID = "Touch ID comes with quick unlock (E6-S3)."
    static let autoType = "Auto-Type comes in E7."
    static let sshAgent = "The SSH agent comes in E9."
    static let importer = "Import comes with the import assistant (FEA-08)."
    static let dialogs = "This dialog comes with its story."
    static let favorites = "Favorites and groups are changed in the editor (E5-S5)."
    static let browser = "Browser options come with the browser extension (E7)."
    static let attachmentOpen = "Opening attachments in place comes with the attachment viewer (MOD-05)."
    static let iconColour = "A colour of your own needs a custom icon; the colour comes with the symbol for now."
    static let autoTypeWindows = "Adding windows comes with Auto-Type (E8)."
    static let groupPages = "The group editor's other pages come with group editing (MOD-02)."
}
