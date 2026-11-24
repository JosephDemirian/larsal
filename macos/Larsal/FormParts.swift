import SwiftUI

// More of the mockup's form parts (app.css `.segc`, `.step`, `.selx`, `.pill`,
// `.mini`, `.icongrid`, `.swatches`, `.link`).

/// `.segc`: a segmented control.
struct Segments: View {
    let items: [String]
    let selected: Int
    var mono = false
    let choose: (Int) -> Void

    var body: some View {
        HStack(spacing: 0) {
            ForEach(items.indices, id: \.self) { index in
                let isOn = index == selected
                Button {
                    choose(index)
                } label: {
                    Text(verbatim: items[index])
                        .font(mono ? .mono(13, .medium) : .sans(13, .medium))
                        .foregroundStyle(isOn ? Tok.text : Tok.muted)
                        .padding(.horizontal, 12)
                        .frame(height: 28)
                        .background {
                            if isOn {
                                RoundedRectangle(cornerRadius: 6).fill(Tok.pressed)
                                    .shadow(color: .black.opacity(0.12), radius: 1, y: 1)
                            }
                        }
                        .contentShape(Rectangle())
                }
                .buttonStyle(Bare())
                .accessibilityAddTraits(isOn ? .isSelected : [])
            }
        }
        .padding(2)
        .background(Tok.active, in: RoundedRectangle(cornerRadius: 8))
    }
}

/// `.step`: a number with Less and More.
struct StepBox: View {
    let value: String
    let less: () -> Void
    let more: () -> Void

    var body: some View {
        HStack(spacing: 0) {
            Text(verbatim: value).font(.sans(13)).num().padding(.horizontal, 10).frame(
                minWidth: 52, alignment: .trailing)
            stepButton("minus", "Less", less)
            stepButton("plus", "More", more)
        }
        .frame(height: 30)
        .background(Tok.field, in: RoundedRectangle(cornerRadius: 7))
        .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Tok.control))
        .clipShape(RoundedRectangle(cornerRadius: 7))
    }

    private func stepButton(_ glyph: String, _ label: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            // Not hidden: a hidden label keeps the button from the focus (AT-K06).
            Glyph(name: glyph, size: 12).accessibilityHidden(false).foregroundStyle(Tok.muted).frame(
                width: 26, height: 30
            ).contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .overlay(alignment: .leading) { Rectangle().fill(Tok.control).frame(width: 1) }
        .accessibilityLabel(Text(verbatim: label))
    }
}

/// `.selx`: a 30-point pop-up look with the caret.
struct SelectBox<Lead: View>: View {
    let title: String
    @ViewBuilder let lead: Lead

    var body: some View {
        HStack(spacing: 8) {
            lead
            Text(verbatim: title)
            Glyph(name: "caret-up-down", size: 12).foregroundStyle(Tok.muted)
        }
        .font(.sans(13))
        .padding(.leading, 11)
        .padding(.trailing, 9)
        .frame(height: 30)
        .background(Tok.field, in: RoundedRectangle(cornerRadius: 7))
        .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Tok.control))
    }
}

extension SelectBox where Lead == EmptyView {
    init(title: String) { self.init(title: title) { EmptyView() } }
}

/// `.pill`: a small rounded label.
struct Pill: View {
    /// `.pos`, `.neu`, and the reports' `.neg` and `.warn` (E5-S7).
    enum Kind { case positive, neutral, negative, warning }
    let text: String
    var glyph: String?
    var kind = Kind.neutral

    var body: some View {
        let (fill, ink): (Color, Color) =
            switch kind {
            case .positive: (Tok.posBg, Tok.posInk)
            case .neutral: (Tok.chipBg, Tok.chipInk)
            case .negative: (Tok.negBg, Tok.negInk)
            case .warning: (Tok.warnBg, Tok.warnInk)
            }
        HStack(spacing: 4) {
            if let glyph { Glyph(name: glyph, size: 12, fill: true) }
            Text(verbatim: text)
        }
        .font(.sans(12, .medium))
        .lineLimit(1)
        .foregroundStyle(ink)
        .padding(.horizontal, 8)
        .frame(height: 22)
        .background(fill, in: Capsule())
    }
}

/// `.panel.tbl-p` with a `.mini` table: a header row (12 muted) and body
/// rows 10 inside, ruled between.
struct MiniTable: View {
    /// Column titles; `nil` draws no header.
    let header: [MiniColumn]?
    let rows: [[AnyView]]
    let columns: [MiniColumn]
    /// The tallest cell's height: 32 where small buttons sit on a text line
    /// (CSS inline boxes), else the content's.
    var cellHeight: CGFloat = 0

    var body: some View {
        VStack(spacing: 0) {
            if let header {
                HStack(spacing: 0) {
                    ForEach(header.indices, id: \.self) { index in
                        cell(
                            Text(verbatim: header[index].title).font(.sans(12)).foregroundStyle(Tok.muted).frame(
                                height: 20),
                            columns[index])
                    }
                }
                .padding(.bottom, 8)
            }
            ForEach(rows.indices, id: \.self) { row in
                HStack(spacing: 0) {
                    ForEach(rows[row].indices, id: \.self) { index in
                        cell(rows[row][index], columns[index]).frame(minHeight: cellHeight).padding(.vertical, 10)
                    }
                }
                .frame(minHeight: 40)
                .overlay(alignment: .top) {
                    if row > 0 { Rectangle().fill(Tok.rule).frame(height: 1) }
                }
            }
        }
        .font(.sans(13))
        .padding(.horizontal, 7)
        .padding(.top, 7)
        .padding(.bottom, 3)
        .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
    }

    private func cell(_ content: some View, _ column: MiniColumn) -> some View {
        content
            .lineLimit(1)
            .padding(.horizontal, 10)
            .frame(width: column.width, alignment: column.trailing ? .trailing : .leading)
            .frame(maxWidth: column.width == nil ? .infinity : nil, alignment: column.trailing ? .trailing : .leading)
    }
}

/// One `.mini` column: a fixed width or the rest, left or right.
struct MiniColumn {
    var title = ""
    var width: CGFloat?
    var trailing = false
}

/// The `.icongrid` button: a 44-point square glyph, outlined in the accent
/// when chosen.
struct IconChoice: View {
    let glyph: String
    let isOn: Bool
    var size: CGFloat = 44
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            // Hidden from VoiceOver, the label would keep the button from the
            // focus (AT-K06); the button's name is what is read.
            Glyph(name: glyph, size: 20)
                .accessibilityHidden(false)
                .foregroundStyle(isOn ? Tok.accent : Tok.muted)
                .frame(width: size, height: size)
                .background(isOn ? Tok.accentSoft : hover ? Tok.hover : .clear, in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(isOn ? Tok.accent : .clear))
                .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .onHover { hover = $0 }
        .accessibilityLabel(Text(verbatim: glyph))
        .accessibilityAddTraits(isOn ? .isSelected : [])
    }
}

/// A `.swatches` button: a 24-point colour square, ringed when chosen.
struct SwatchChoice: View {
    let name: String
    let isOn: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            RoundedRectangle(cornerRadius: 7)
                .fill(Tok.tileColor(name))
                .frame(width: 24, height: 24)
                .background {
                    if isOn {
                        RoundedRectangle(cornerRadius: 11).strokeBorder(Tok.tileColor(name), lineWidth: 2).padding(-4)
                    }
                }
        }
        .buttonStyle(Bare())
        .accessibilityLabel(Text(verbatim: name))
        .accessibilityAddTraits(isOn ? .isSelected : [])
    }
}

/// A `.link` button: accent, medium.
struct LinkButton: View {
    let title: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(verbatim: title).font(.sans(12, .medium)).foregroundStyle(Tok.accent)
        }
        .buttonStyle(Bare())
    }
}
