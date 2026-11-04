import AppKit
import LarsalCore
import SwiftUI

/// The mockup's `.gen`: the head with the two tabs, the value with New
/// password and Copy, the strength line, the options, and the two buttons.
struct GeneratorPanel: View {
    let model: GeneratorModel
    let vault: VaultModel
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        let phrase = model.options.passphrase
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 0) {
                Text(verbatim: "Generator").font(.sans(15, .semibold)).frame(height: 20)
                    .accessibilityAddTraits(.isHeader)
                Spacer(minLength: 0)
                Segments(items: ["Password", "Passphrase"], selected: phrase ? 1 : 0) { index in
                    model.change { $0.passphrase = index == 1 }
                }
            }
            output.padding(.top, 14)
            StrengthLine(rating: model.rating).padding(.top, 10)
            if phrase { phraseOptions } else { passwordOptions }
            HStack(spacing: 8) {
                Button(action: vault.copyGenerated) { BtnLabel(glyph: "copy", title: "Copy") }
                    .buttonStyle(Btn(wide: true))
                    .disabled(model.value.isEmpty)
                if model.fromEditor {
                    Button(action: vault.useGenerated) { Text(verbatim: "Use password") }
                        .buttonStyle(Btn(kind: .primary, wide: true))
                        .keyboardShortcut(.return, modifiers: .command)
                        .disabled(model.value.isEmpty)
                } else {
                    Button(action: vault.newEntryWithGenerated) { BtnLabel(glyph: "plus", title: "New entry with it") }
                        .buttonStyle(Btn(kind: .primary, wide: true))
                        .disabled(model.value.isEmpty)
                }
            }
            .padding(.top, 18)
        }
        .font(.sans(14))
        .foregroundStyle(Tok.text)
        .padding(16)
        .frame(width: 404)
        .background(Tok.dialog, in: RoundedRectangle(cornerRadius: 12))
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text(verbatim: "Password generator"))
        .background {
            let dark = scheme == .dark
            // `--pop-shadow`: the soft drop and the hairline ring outside.
            BoxShadow(radius: 12, drop: dark ? 16 : 12, blur: dark ? 40 : 32, alpha: dark ? 0.6 : 0.16)
            RoundedRectangle(cornerRadius: 13)
                .strokeBorder(dark ? Color.white.opacity(0.08) : Color.black.opacity(0.06))
                .padding(-1)
        }
    }

    /// `.out`: the value (or why there is none), New password and Copy.
    private var output: some View {
        HStack(spacing: 4) {
            Group {
                if let problem = model.problem {
                    Text(verbatim: problem).font(.sans(13)).foregroundStyle(Tok.muted)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    GeneratedField(text: model.value, made: model.made) { model.edited($0) }
                        .accessibilityLabel(Text(verbatim: "Generated password"))
                }
            }
            .frame(maxWidth: .infinity, minHeight: 24, alignment: .leading)
            IconButton(glyph: "arrows-clockwise", label: "New password") { model.regenerate() }
            IconButton(glyph: "copy", label: "Copy", action: vault.copyGenerated)
                .disabled(model.value.isEmpty)
        }
        .padding(.leading, 14)
        .padding(.trailing, 6)
        .padding(.vertical, 12)
        .background(Tok.raised, in: RoundedRectangle(cornerRadius: 10))
    }

    private var passwordOptions: some View {
        VStack(alignment: .leading, spacing: 0) {
            RangeRow(label: "Length", value: Int(model.options.length), range: 8...64) { length in
                model.change { $0.length = UInt32(length) }
            }
            .padding(.top, 18)
            // `.sets`: the five chips, 6 apart.
            HStack(spacing: 6) {
                SetChip(title: "A–Z", isOn: model.options.upper) { model.toggle(\.upper) }
                SetChip(title: "a–z", isOn: model.options.lower) { model.toggle(\.lower) }
                SetChip(title: "0–9", isOn: model.options.digits) { model.toggle(\.digits) }
                SetChip(title: "!@#$", isOn: model.options.special) { model.toggle(\.special) }
                SetChip(title: "Äéß", isOn: model.options.extended) { model.toggle(\.extended) }
            }
            .padding(.top, 14)
            LookAlikes(isOn: model.options.excludeLookalike) { model.change { $0.excludeLookalike.toggle() } }
                .padding(.top, 12)
        }
    }

    /// The separators and cases the mockup offers, with their values.
    private static let separators = [("-", "-"), (".", "."), ("space", " "), ("_", "_")]
    private static let cases: [(String, WordCase)] = [("lower", .lower), ("Title", .title), ("UPPER", .upper)]

    private var phraseOptions: some View {
        VStack(alignment: .leading, spacing: 0) {
            RangeRow(label: "Words", value: Int(model.options.words), range: 3...10) { words in
                model.change { $0.words = UInt32(words) }
            }
            .padding(.top, 18)
            OptionRow(label: "Separator") {
                Segments(
                    items: Self.separators.map(\.0),
                    selected: Self.separators.firstIndex { $0.1 == model.options.separator } ?? -1, mono: true
                ) { index in model.change { $0.separator = Self.separators[index].1 } }
            }
            .padding(.top, 18)
            OptionRow(label: "Case") {
                Segments(
                    items: Self.cases.map(\.0), selected: Self.cases.firstIndex { $0.1 == model.options.case } ?? -1
                ) { index in model.change { $0.case = Self.cases[index].1 } }
            }
            .padding(.top, 18)
        }
    }
}

/// `.gen .str`: the level in its colour, the bar of 130 bits, the bits.
private struct StrengthLine: View {
    let rating: Rating?

    var body: some View {
        let bits = rating?.bits ?? 0
        let color = (rating?.segments ?? 0) >= 3 ? Tok.positive : rating?.segments == 2 ? Tok.warning : Tok.negative
        HStack(spacing: 10) {
            Text(verbatim: rating?.level ?? "").font(.sans(12, .medium)).foregroundStyle(color)
            Capsule()
                .fill(Tok.active)
                .frame(height: 4)
                .overlay(alignment: .leading) {
                    GeometryReader { box in
                        Capsule().fill(color).frame(width: box.size.width * min(1, CGFloat(bits) / 130))
                    }
                }
                .clipShape(Capsule())
                .accessibilityHidden(true)
            Text(verbatim: "\(bits) bits").font(.sans(12)).foregroundStyle(Tok.muted)
        }
        .num()
        .frame(height: 20)
    }
}

/// `.gen .row2` with a control of its own width: a 70-point label, 12 apart.
private struct OptionRow<Control: View>: View {
    let label: String
    @ViewBuilder let control: Control

    var body: some View {
        HStack(spacing: 12) {
            Text(verbatim: label).font(.sans(13, .medium)).frame(width: 70, alignment: .leading)
            control
        }
    }
}

/// `.gen .row2` with the range: the browser shrinks the 70-point label and
/// the 36-point value with the full-width range, so the label is 50.4, the
/// range 271.7 (2 of margin each side) and the value 25.9 (app.css flex).
private struct RangeRow: View {
    let label: String
    let value: Int
    let range: ClosedRange<Int>
    let set: (Int) -> Void

    var body: some View {
        HStack(spacing: 12) {
            Text(verbatim: label).font(.sans(13, .medium)).frame(width: 50.4, alignment: .leading)
                .accessibilityHidden(true)
            RangeSlider(label: label, value: value, range: range, set: set)
                .padding(.horizontal, 2)
                .frame(width: 271.7)
            Text(verbatim: "\(value)").font(.sans(13)).num().frame(width: 25.9, alignment: .trailing)
                .accessibilityHidden(true)
        }
        .frame(height: 20)
    }
}

/// The mockup's `input.range` as the browser draws it: an 8-point track
/// with a 1-point edge, the accent up to a 16-point accent thumb. Drag,
/// click, arrow keys and VoiceOver's adjust change it; a value outside the
/// range (a field's length, FEA-02.17) puts the thumb at the end. Also
/// the vault settings' and the new vault wizard's unlock time (E5-S8).
struct RangeSlider: View {
    let label: String
    let value: Int
    let range: ClosedRange<Int>
    let set: (Int) -> Void
    @FocusState private var focused: Bool

    var body: some View {
        GeometryReader { box in
            let width = box.size.width
            let span = CGFloat(range.upperBound - range.lowerBound)
            let share = CGFloat(min(max(value, range.lowerBound), range.upperBound) - range.lowerBound) / span
            let thumb = 8 + share * (width - 16)
            ZStack(alignment: .leading) {
                Capsule().fill(Tok.rangeTrack).frame(height: 8)
                Capsule().fill(Tok.accent).frame(width: thumb, height: 8)
                Capsule().strokeBorder(Tok.rangeEdge).frame(height: 8)
                Circle().fill(Tok.accent).frame(width: 16, height: 16)
                    .overlay {
                        // `.win :focus-visible`: a 2-point accent ring, 1 out.
                        if focused { Circle().strokeBorder(Tok.accent, lineWidth: 2).padding(-3) }
                    }
                    .offset(x: thumb - 8)
            }
            .frame(height: 20)
            .contentShape(Rectangle())
            .gesture(
                DragGesture(minimumDistance: 0).onChanged { drag in
                    let part = min(max((drag.location.x - 8) / max(width - 16, 1), 0), 1)
                    step(to: range.lowerBound + Int((part * span).rounded()))
                })
        }
        .frame(height: 20)
        .focusable()
        .focusEffectDisabled()
        .focused($focused)
        .onKeyPress(keys: [.leftArrow, .downArrow]) { _ in
            step(to: value - 1)
            return .handled
        }
        .onKeyPress(keys: [.rightArrow, .upArrow]) { _ in
            step(to: value + 1)
            return .handled
        }
        // VoiceOver: a system slider of the same range and value.
        .accessibilityRepresentation {
            Slider(
                value: Binding(get: { Double(value) }, set: { step(to: Int($0.rounded())) }),
                in: Double(range.lowerBound)...Double(range.upperBound), step: 1
            ) { Text(verbatim: label) }
        }
    }

    private func step(to next: Int) {
        let clamped = min(max(next, range.lowerBound), range.upperBound)
        if clamped != value { set(clamped) }
    }
}

/// `.gen .sets button`: a 30-point chip in mono, the accent when on.
private struct SetChip: View {
    let title: String
    let isOn: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(verbatim: title)
                .font(.mono(13, isOn ? .medium : .regular))
                .foregroundStyle(isOn ? Tok.accent : Tok.text)
                .padding(.horizontal, 13)
                .frame(height: 30)
                .background(isOn ? Tok.accentSoft : .clear, in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(isOn ? Tok.accent : Tok.control))
                .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .accessibilityLabel(Text(verbatim: title))
        .accessibilityAddTraits(isOn ? .isSelected : [])
    }
}

/// `.chkrow`: Leave out look-alikes, the left-out characters in mono.
private struct LookAlikes: View {
    let isOn: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 10) {
                CheckMark(isOn: isOn).padding(.top, 1)
                (Text(verbatim: "Leave out look-alikes ")
                    + Text(verbatim: "l I 1 O 0").font(.mono(14)).foregroundColor(Tok.muted))
                    .frame(maxWidth: .infinity, minHeight: 20, alignment: .leading)
            }
            .padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .accessibilityLabel(Text(verbatim: "Leave out look-alikes l I 1 O 0"))
        .accessibilityValue(Text(verbatim: isOn ? "on" : "off"))
        .accessibilityAddTraits(isOn ? .isSelected : [])
    }
}

/// `.gen .out .pw`: the value in IBM Plex Mono 17 on 24-point lines,
/// digits and symbols coloured, broken anywhere (`word-break: break-all`).
/// The user may type over it (FEA-02.16); the field never lets it out
/// (`NoCopyTextField`, APP-03.19), and secure input is on while it has
/// focus (SR-06).
private struct GeneratedField: NSViewRepresentable {
    let text: String
    /// A new value from Rust replaces what the field shows.
    let made: Int
    let typed: (String) -> Void

    static let font =
        NSFont(name: "IBMPlexMono-Regular", size: 17) ?? .monospacedSystemFont(ofSize: 17, weight: .regular)

    func makeNSView(context: Context) -> NoCopyTextField {
        let field = NoCopyTextField()
        field.isBordered = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.usesSingleLineMode = false
        field.maximumNumberOfLines = 0
        field.cell?.wraps = true
        field.cell?.isScrollable = false
        field.cell?.lineBreakMode = .byCharWrapping
        field.isAutomaticTextCompletionEnabled = false
        field.setAccessibilityLabel("Generated password")
        field.delegate = context.coordinator
        field.attributedStringValue = Self.coloured(text)
        context.coordinator.made = made
        return field
    }

    func updateNSView(_ field: NoCopyTextField, context: Context) {
        context.coordinator.typed = typed
        guard context.coordinator.made != made || field.currentEditor() == nil && field.stringValue != text else {
            return
        }
        context.coordinator.made = made
        field.abortEditing()
        field.attributedStringValue = Self.coloured(text)
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView field: NoCopyTextField, context: Context) -> CGSize? {
        let width = proposal.width ?? 280
        let height = field.cell?.cellSize(forBounds: NSRect(x: 0, y: 0, width: width, height: 10_000)).height ?? 24
        return CGSize(width: width, height: max(24, height))
    }

    func makeCoordinator() -> Coordinator { Coordinator(typed: typed) }

    /// `pwHtml`: digits and symbols in their colours, 0.02 em apart.
    static func coloured(_ text: String) -> NSAttributedString {
        let ink = NSColor(named: "text", bundle: appBundle) ?? .labelColor
        let digit = NSColor(named: "digit", bundle: appBundle) ?? ink
        let symbol = NSColor(named: "symbol", bundle: appBundle) ?? ink
        let lines = NSMutableParagraphStyle()
        lines.lineBreakMode = .byCharWrapping
        lines.minimumLineHeight = 24
        lines.maximumLineHeight = 24
        let out = NSMutableAttributedString()
        for char in text {
            let color =
                char.isASCII && char.isNumber
                ? digit : (char.isASCII && char.isLetter) || char.isWhitespace ? ink : symbol
            out.append(
                NSAttributedString(
                    string: String(char),
                    attributes: [.font: font, .foregroundColor: color, .kern: 0.34, .paragraphStyle: lines]))
        }
        return out
    }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var typed: (String) -> Void
        var made = 0

        init(typed: @escaping (String) -> Void) { self.typed = typed }

        func controlTextDidChange(_ note: Notification) {
            guard let field = note.object as? NSTextField else { return }
            typed(field.stringValue)
            // Colour the text being typed in the field editor too.
            if let editor = field.currentEditor() as? NSTextView, let storage = editor.textStorage {
                let selection = editor.selectedRanges
                storage.setAttributedString(GeneratedField.coloured(field.stringValue))
                editor.selectedRanges = selection
            }
        }
    }
}
