import AppCore
import SwiftUI

/// The mockup's sheet (`main.sheet`): the title row, the tabs, then the
/// entry table and the detail rail; or the new, empty vault.
struct SheetView: View {
    let model: VaultModel
    /// S-VIEW-04: the detail rail shows (View > Hide Details).
    var details = true

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if model.empty {
                EmptyVaultView(model: model)
            } else {
                titleRow.shareBanner(model)  // INT-08.20
                tabsRow.padding(.top, 18)
                HStack(alignment: .top, spacing: 24) {
                    EntryTable(model: model).shareLabel(model)  // INT-08.24
                    if details { RailView(model: model).frame(width: 368) }
                }
                .padding(.top, 16)
            }
        }
        .padding(.horizontal, 25)
        .padding(.top, 23)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Tok.surface, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Tok.border))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var bin: Bool { model.place == .bin }

    /// `.trow`: the title, the count line, and the actions.
    private var titleRow: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: model.title)
                    .font(.sans(22, .semibold))
                    .tracking(-0.22)
                    .frame(height: 28)
                    .accessibilityAddTraits(.isHeader)
                subtitle.font(.sans(14)).num().foregroundStyle(Tok.muted).frame(height: 20)
            }
            Spacer(minLength: 0)
            if bin {
                Button(action: model.askEmptyBin) {
                    BtnLabel(glyph: "trash", title: "Empty Recycle Bin")
                }
                .buttonStyle(Btn(size: .large))
                .disabled((model.sidebar?.bin ?? 0) == 0)
            } else {
                // `.trow .acts`: 8 apart.
                HStack(spacing: 8) {
                    Button(action: model.toggleGenerator) { BtnLabel(glyph: "password", title: "Generator") }
                        .buttonStyle(Btn(size: .large))
                        .keyboardShortcut("g", modifiers: [.option, .command])
                    Button {
                        model.newEntry()
                    } label: {
                        BtnLabel(glyph: "plus", title: "New Entry")
                    }
                    .buttonStyle(Btn(kind: .primary, size: .large))
                }
            }
        }
    }

    private var subtitle: Text {
        let count = Formats.count(model.placeRows.count, "entry", "entries")
        if bin { return Text(verbatim: count + " · you can restore them until you empty the bin") }
        let bad = model.attention
        guard bad > 0 else { return Text(verbatim: count) }
        return Text(verbatim: count + " · ")
            + Text(verbatim: "\(bad) need attention").font(.sans(14, .medium)).foregroundColor(Tok.negative)
    }

    /// `.tabsrow`: the tabs and the sort button.
    private var tabsRow: some View {
        HStack(alignment: .bottom, spacing: 0) {
            HStack(spacing: 24) {
                if bin {
                    TabButton(title: "Deleted entries", count: nil, alert: false, selected: true) {}
                } else {
                    ForEach(VaultModel.Tab.allCases, id: \.self) { tab in
                        let count = model.count(tab)
                        TabButton(
                            title: tab.rawValue, count: count, alert: tab == .attention && count > 0,
                            selected: model.tab == tab
                        ) { model.chooseTab(tab) }
                    }
                }
            }
            .accessibilityElement(children: .contain)
            Spacer(minLength: 0)
            Button {
                model.overlay = model.overlay == .sort ? nil : .sort
            } label: {
                BtnLabel(glyph: "sort-descending", title: model.sort.rawValue)
            }
            .buttonStyle(Btn(kind: .ghost, size: .small))
            .accessibilityLabel(Text(verbatim: "Sort by " + model.sort.rawValue))
            .padding(.bottom, 6)
        }
        .overlay(alignment: .bottom) { Rectangle().fill(Tok.border).frame(height: 1) }
    }
}

/// `.tab`: a 38-point tab with its count; the selected one is underlined.
struct TabButton: View {
    let title: String
    let count: Int?
    let alert: Bool
    let selected: Bool
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Text(verbatim: title).font(.sans(14, selected ? .medium : .regular))
                if let count {
                    Text(verbatim: "\(count)")
                        .font(.sans(12, alert ? .semibold : .regular))
                        .num()
                        .foregroundStyle(alert ? Tok.negative : Tok.muted)
                }
            }
            .foregroundStyle(selected || hover ? Tok.text : Tok.muted)
            .frame(height: 38)
            .overlay(alignment: .bottom) {
                if selected {
                    RoundedRectangle(cornerRadius: 2).fill(Tok.text).frame(height: 2)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .onHover { hover = $0 }
        .accessibilityAddTraits(selected ? [.isSelected, .isButton] : .isButton)
    }
}

/// The mockup's `.tbl`: the column heads, month headers and rows.
struct EntryTable: View {
    let model: VaultModel
    /// The list has keyboard focus: the selected row shows the mockup's
    /// focus outline (`.win :focus-visible`).
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 0) {
            head
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(model.sections) { section in
                            if let title = section.title {
                                Text(verbatim: title)
                                    .font(.sans(12, .semibold))
                                    .foregroundStyle(Tok.muted)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .frame(height: 16)
                                    .padding(.horizontal, 10)
                                    .padding(.top, 14)
                                    .padding(.bottom, 6)
                                    .accessibilityAddTraits(.isHeader)
                            }
                            ForEach(Array(section.rows.enumerated()), id: \.element.id) { index, row in
                                let previous = index > 0 ? section.rows[index - 1].id : nil
                                EntryRowView(
                                    row: row, code: model.codes[row.id]?.code, selected: row.id == model.selection,
                                    rule: index > 0 && previous != model.selection,
                                    focused: focused && row.id == model.selection
                                ) { model.select(row.id) }
                                .contextMenu { EntryContextMenu(model: model, row: row) }
                                .id(row.id)
                                .onAppear { if row.hasTotp { model.rowAppeared(row.id) } }
                                .onDisappear { model.rowDisappeared(row.id) }
                            }
                        }
                        if model.rows.isEmpty { empty }
                    }
                    .padding(.bottom, 24)
                }
                .scrollIndicators(.never)
                .onChange(of: model.selection) { _, id in
                    if let id { proxy.scrollTo(id) }
                }
            }
            .focusable()
            .focused($focused)
            .onKeyPress(.upArrow) {
                model.move(-1)
                return .handled
            }
            .onKeyPress(.downArrow) {
                model.move(1)
                return .handled
            }
            .entryKeys(model)
            .accessibilityLabel(Text(verbatim: "Entries"))
        }
        .frame(maxWidth: .infinity)
    }

    private var head: some View {
        // The live codes' seconds left (FEA-04.14), else this second's.
        let left = Int(model.codes.values.first?.secondsLeft ?? UInt32(30 - Int(Date().timeIntervalSince1970) % 30))
        return Columns {
            Text(verbatim: "Name")
        } code: {
            HStack(spacing: 6) {
                Text(verbatim: "Code")
                Capsule()
                    .fill(Tok.active)
                    .frame(width: 28, height: 4)
                    .overlay(alignment: .leading) {
                        Capsule().fill(Tok.accent).frame(width: 28 * CGFloat(left) / 30)
                    }
                    .accessibilityHidden(true)
                Text(verbatim: "\(left) s").num()
            }
        } password: {
            Text(verbatim: "Password")
        } modified: {
            Text(verbatim: model.place == .bin ? "Deleted" : "Modified")
        }
        .font(.sans(12))
        .foregroundStyle(Tok.muted)
        .frame(height: 32)
    }

    /// `.empty`: the list keeps its frame (FEA-01).
    private var empty: some View {
        Group {
            if model.searching {
                // Tab and VoiceOver reach and press it too (AT-K06, APP-08.25).
                (Text(verbatim: "No entries match “\(model.search)”. Try fewer words, or ")
                    + Text(verbatim: "clear the search").font(.sans(14, .medium)).foregroundColor(Tok.accent)
                    + Text(verbatim: "."))
                    .focusable().accessibilityAction { model.setSearch("") }
            } else if model.tab == .attention {
                Text(verbatim: "Every password here is strong, unique and current.")
            } else {
                Text(verbatim: "No entries here yet.")
            }
        }
        .font(.sans(14)).foregroundStyle(Tok.muted).lineBox(14, 20)
        .frame(maxWidth: .infinity, alignment: .leading).padding(21)
        .overlay(
            RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.control, style: StrokeStyle(lineWidth: 1, dash: [3]))
        )
        .contentShape(Rectangle())
        .onTapGesture { if model.searching { model.setSearch("") } }
        .accessibilityAddTraits(model.searching ? .isButton : [])
        .accessibilityHint(model.searching ? Text(verbatim: "Clears the search") : Text(verbatim: ""))
        .padding(.vertical, 8)
    }
}

/// The table's four columns (`.cols`): name, 104, 108 and 76 points, 16
/// apart, 10 points in.
struct Columns<Name: View, Code: View, Password: View, Modified: View>: View {
    @ViewBuilder let name: Name
    @ViewBuilder let code: Code
    @ViewBuilder let password: Password
    @ViewBuilder let modified: Modified

    var body: some View {
        HStack(spacing: 16) {
            name.frame(maxWidth: .infinity, alignment: .leading)
            code.frame(width: 104, alignment: .leading)
            password.frame(width: 108, alignment: .leading)
            modified.frame(width: 76, alignment: .trailing)
        }
        .padding(.horizontal, 10)
    }
}

/// One row (`.row`): logo, title and subtitle, code, strength, date.
struct EntryRowView: View {
    let row: EntryRow
    let code: String?
    let selected: Bool
    /// The hairline above the row (`.row + .row::before`).
    let rule: Bool
    /// `.win :focus-visible`: a 2-point accent outline 1 point out, radius 6.
    var focused = false
    let action: () -> Void
    @State private var hover = false
    @Environment(\.maskUserNames) private var maskUser

    var body: some View {
        Button(action: action) {
            Columns {
                identity
            } code: {
                if row.hasTotp, let code {
                    Text(verbatim: Codes.shown(code)).font(.mono(14, .medium)).tracking(0.28)
                } else {
                    Text(verbatim: "—").foregroundStyle(Tok.muted)
                }
            } password: {
                Strength(row: row)
            } modified: {
                Text(verbatim: Formats.modified(row.deleted ?? row.modified)).font(.sans(13)).num().foregroundStyle(
                    Tok.muted)
            }
            .font(.sans(14))
            .foregroundStyle(Tok.text)
            .frame(height: 56)
            .background(selected ? Tok.active : hover ? Tok.hover : .clear, in: .rect(cornerRadius: focused ? 6 : 10))
            .overlay(alignment: .top) {
                if rule && !selected && !hover {
                    Rectangle().fill(Tok.rule).frame(height: 1).padding(.leading, 54).padding(.trailing, 10)
                }
            }
            .overlay {
                if focused {
                    RoundedRectangle(cornerRadius: 8).stroke(Tok.accent, lineWidth: 2).padding(-2)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .onHover { hover = $0 }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private var identity: some View {
        HStack(spacing: 12) {
            EntryLogo(title: row.title, host: row.host, icon: row.icon, custom: row.customIcon)
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 4) {
                    Text(verbatim: row.title).font(.sans(14, .medium)).lineLimit(1)
                    if row.favorite {
                        Glyph(name: "star", fill: true).foregroundStyle(Tok.orange).accessibilityLabel("Favorite")
                    }
                }
                .frame(height: 20)
                HStack(spacing: 6) {
                    row.secondLine(maskUser: maskUser)
                    if row.passkey {
                        Glyph(name: "fingerprint", size: 12)
                        Text(verbatim: "passkey")
                    }
                }
                .font(.sans(13))
                .foregroundStyle(Tok.muted)
                .lineLimit(1)
                .frame(height: 18)
            }
            // VoiceOver reads the title first, then the logo's brand.
            .accessibilitySortPriority(1)
        }
    }
}

/// `.hl`: the strength word and the four-part meter (FEA-05.4, FEA-05.9).
struct Strength: View {
    let row: EntryRow

    var body: some View {
        let rating = row.rating
        let ink: Color = rating?.expired == true ? Tok.warning : rating?.attention == true ? Tok.negative : Tok.muted
        VStack(alignment: .leading, spacing: 5) {
            Text(verbatim: word)
                .font(.sans(12, rating?.attention == true ? .medium : .regular))
                .foregroundStyle(ink)
                .frame(height: 14)
            if let rating {
                HStack(spacing: 2) {
                    ForEach(0..<4, id: \.self) { index in
                        let lit = index < Int(rating.segments)
                        RoundedRectangle(cornerRadius: 2)
                            .fill(lit ? color(rating) : Tok.active)
                            .frame(width: 14, height: 3)
                    }
                }
                .accessibilityHidden(true)
            }
        }
    }

    private var word: String {
        if let rating = row.rating { return rating.word }
        if row.hasPassword { return "" }
        return row.passkey && row.kind != .card ? "Passkey only" : "—"
    }

    private func color(_ rating: Rating) -> Color {
        if rating.expired { return Tok.orange }
        if rating.attention { return Tok.negative }
        return Tok.muted.opacity(0.7)
    }
}
