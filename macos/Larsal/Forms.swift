import SwiftUI

// The mockup's form parts (app.css "forms", "editor", `.srow`, `.choice`,
// `.mini`), shared by the editor and the dialogs (E5-S5).

/// `.lab`: 13/18 medium, 6 above its control; `small` in muted regular.
struct Lab: View {
    let title: String
    var small: String?

    var body: some View {
        (Text(verbatim: title).font(.sans(13, .medium))
            + Text(verbatim: small.map { " " + $0 } ?? "").font(.sans(12)).foregroundColor(Tok.muted))
            .num()
            .frame(height: 18, alignment: .leading)
            .padding(.bottom, 6)
    }
}

/// `.help`: 12/16 muted, 6 below.
struct Help: View {
    let text: String

    var body: some View {
        Text(verbatim: text).font(.sans(12)).foregroundStyle(Tok.muted).lineBox(12, 16).padding(.top, 6)
    }
}

/// `.inp`: a 36-point box (`.inp.off` dims to 55 %); the accent ring shows
/// while a field inside has focus.
struct InputBox<Content: View>: View {
    var focused = false
    var off = false
    var gap: CGFloat = 8
    @ViewBuilder let content: Content

    var body: some View {
        HStack(spacing: gap) { content }
            .font(.sans(14))
            .padding(.leading, 13)
            .padding(.trailing, 7)
            .frame(height: 36)
            .background(Tok.field, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(focused ? Tok.accent : Tok.control))
            .background(RoundedRectangle(cornerRadius: 11).fill(focused ? Tok.accentSoft : .clear).padding(-3))
            .opacity(off ? 0.55 : 1)
    }
}

/// A plain text field inside `.inp`: vault text, its placeholder muted.
struct PlainField: View {
    let prompt: String
    @Binding var text: String
    var mono = false
    var label: String?
    var focus: FocusState<Bool>.Binding?

    var body: some View {
        let field = TextField(
            "", text: $text, prompt: Text(verbatim: prompt).foregroundStyle(Tok.muted)
        )
        .textFieldStyle(.plain)
        .font(mono ? .mono(14) : .sans(14))
        .foregroundStyle(Tok.text)
        .autocorrectionDisabled()
        .accessibilityLabel(Text(verbatim: label ?? prompt))
        if let focus {
            field.focused(focus)
        } else {
            field
        }
    }
}

/// `.chip` with its remove cross (`.x`).
struct Chip: View {
    let text: String
    var remove: (() -> Void)?

    var body: some View {
        HStack(spacing: 4) {
            Text(verbatim: text)
            if let remove {
                // `.chip .x`: the glyph keeps `.ph`'s 16 points.
                Button(action: remove) {
                    // A label hidden from VoiceOver keeps a button from the
                    // focus (AT-K06); the button's name is what is read.
                    Glyph(name: "x", size: 16).accessibilityHidden(false).opacity(0.6)
                }
                .buttonStyle(Bare())
                .accessibilityLabel(Text(verbatim: "Remove " + text))
            }
        }
        .font(.sans(12))
        .foregroundStyle(Tok.chipInk)
        .padding(.horizontal, 8)
        .frame(height: 22)
        .background(Tok.chipBg, in: RoundedRectangle(cornerRadius: 5))
    }
}

/// `.rb`: an 18-point radio mark.
struct RadioMark: View {
    let isOn: Bool

    var body: some View {
        Circle()
            .fill(Tok.field)
            .overlay(Circle().strokeBorder(isOn ? Tok.accent : Tok.control, lineWidth: isOn ? 5 : 1.5))
            .frame(width: 18, height: 18)
            .accessibilityHidden(true)
    }
}

/// `.cb`: an 18-point check box mark.
struct CheckMark: View {
    let isOn: Bool

    var body: some View {
        RoundedRectangle(cornerRadius: 5)
            .fill(isOn ? Tok.accent : Tok.field)
            .overlay(RoundedRectangle(cornerRadius: 5).strokeBorder(isOn ? Tok.accent : Tok.control, lineWidth: 1.5))
            .overlay {
                if isOn { Glyph(name: "check", size: 12).foregroundStyle(.white) }
            }
            .frame(width: 18, height: 18)
            .accessibilityHidden(true)
    }
}

/// `.chkrow`: a check box with its words and an optional second line.
struct CheckRow: View {
    let title: String
    var detail: String?
    @Binding var isOn: Bool

    var body: some View {
        Button {
            isOn.toggle()
        } label: {
            HStack(alignment: .top, spacing: 10) {
                CheckMark(isOn: isOn).padding(.top, 1)
                VStack(alignment: .leading, spacing: 0) {
                    Text(verbatim: title).frame(minHeight: 20, alignment: .leading)
                    if let detail {
                        Text(verbatim: detail).font(.sans(12)).foregroundStyle(Tok.muted).frame(height: 16)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .accessibilityLabel(Text(verbatim: title))
        .accessibilityValue(Text(verbatim: isOn ? "on" : "off"))
        .accessibilityAddTraits(isOn ? .isSelected : [])
    }
}

/// `.choice`: a bordered option with a radio mark; the chosen one is
/// outlined in the accent on its soft fill.
struct Choice: View {
    let isOn: Bool
    let title: String
    var note: String?
    var mono = false
    /// A control under the title (the custom sequence, the attachment).
    var extra: AnyView?
    /// The picture on the right (the logo, the group's tile).
    var trailing: AnyView?
    let action: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            RadioMark(isOn: isOn).padding(.top, 1)
            VStack(alignment: .leading, spacing: 0) {
                Text(verbatim: title).font(.sans(14, .medium)).frame(height: 20, alignment: .leading)
                if let note { ChoiceNote(text: note, mono: mono) }
                extra
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            trailing
        }
        // 14 inside the 1-point border.
        .padding(15)
        .background(isOn ? Tok.accentSoft : .clear, in: RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10).strokeBorder(isOn ? Tok.accent : Tok.border, lineWidth: isOn ? 2 : 1)
        )
        .contentShape(Rectangle())
        // A control inside keeps its clicks; the rest of the box chooses.
        .onTapGesture(perform: action)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text(verbatim: title))
        .accessibilityAddTraits(isOn ? [.isButton, .isSelected] : .isButton)
        .accessibilityAction(.default, action)
        // The keyboard reaches it and Space chooses it (AT-K06).
        .focusable()
        .onKeyPress(.space) {
            action()
            return .handled
        }
    }
}

/// `.choice small`: 13/18 muted, 2 below the title.
struct ChoiceNote: View {
    let text: String
    var mono = false

    var body: some View {
        Text(verbatim: text)
            .font(mono ? .mono(13) : .sans(13))
            .foregroundStyle(Tok.muted)
            .lineBox(13, 18)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 2)
    }
}

/// `.srow`: words on the left, a control on the right, at least 46 tall.
struct SRow<Control: View>: View {
    let title: String
    var detail: String?
    @ViewBuilder let control: Control

    var body: some View {
        HStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: title).frame(minHeight: 20, alignment: .leading)
                if let detail {
                    // 16-point lines (IBM Plex's own line is 15 at 12).
                    Text(verbatim: detail).font(.sans(12)).foregroundStyle(Tok.muted)
                        .lineSpacing(1).padding(.vertical, 0.5)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            control
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(minHeight: 46)
        .accessibilityElement(children: .contain)
    }
}

/// `.grp .box`: rows on the raised fill (dark: with a border), ruled
/// between.
struct RowBox: View {
    let rows: [AnyView]
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(spacing: 0) {
            // `.srow + .srow`: a 1-point rule above each later row.
            ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                row.padding(.top, index > 0 ? 1 : 0).overlay(alignment: .top) {
                    if index > 0 { Rectangle().fill(Tok.srowRule).frame(height: 1) }
                }
            }
        }
        // Dark: a 1-point border outside the rows, as CSS's border box.
        .padding(scheme == .dark ? 1 : 0)
        .background(Tok.raised, in: RoundedRectangle(cornerRadius: 10))
        .overlay {
            if scheme == .dark { RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border) }
        }
    }
}

/// A `.sw` switch with its accessible name.
struct Switch: View {
    let label: String
    @Binding var isOn: Bool

    var body: some View {
        Toggle(isOn: $isOn) { Text(verbatim: label) }
            .toggleStyle(SwitchStyle())
            .accessibilityLabel(Text(verbatim: label))
    }
}
