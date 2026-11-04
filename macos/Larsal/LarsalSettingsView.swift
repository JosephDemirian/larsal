import AppKit
import LarsalCore
import SwiftUI

/// The settings window (mockup `settingsWin`, section `settings`, APP-01):
/// the nav with its search field, then the page in its raised box. Option A
/// draws no OK and Cancel: closing the window is OK, Escape is Cancel
/// (`LarsalSettingsWindow`).
struct LarsalSettingsView: View {
    let model: LarsalSettingsModel
    /// Closes the window without storing (Escape).
    var cancel: () -> Void = {}

    var body: some View {
        HStack(spacing: 0) {
            LarsalSettingsNav(model: model).frame(width: 232)
            LarsalSettingsBody(model: model)
                .padding(.vertical, 8)
                .padding(.trailing, 8)
        }
        .font(.sans(14))
        .foregroundStyle(Tok.text)
        .frame(minWidth: 760, minHeight: 520)
        .background(Tok.ground)
        .onExitCommand {
            model.cancel()
            cancel()
        }
    }
}

/// `.snav`: the window buttons' row, the search field and the pages.
struct LarsalSettingsNav: View {
    @Bindable var model: LarsalSettingsModel
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // `.lights`: the window's own buttons sit here (2 + 12 + 18).
            Color.clear.frame(height: 32)
            search.padding(.bottom, 14)
            ForEach(model.visiblePages) { page in
                SidebarItem(
                    title: page.title, current: model.page == page,
                    lead: AnyView(Tile(color: Tok.tileColor(page.tile.color), glyph: page.tile.glyph))
                ) {
                    EmptyView()
                } action: {
                    model.go(page)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.top, 16)
        .padding(.horizontal, 10)
        .padding(.bottom, 12)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text(verbatim: "Settings pages"))
    }

    /// `.search`, full width.
    private var search: some View {
        HStack(spacing: 8) {
            Glyph(name: "magnifying-glass").foregroundStyle(Tok.muted)
            TextField("", text: $model.query, prompt: Text(verbatim: "Search settings…").foregroundStyle(Tok.muted))
                .textFieldStyle(.plain)
                // The input's own 2-point side padding.
                .padding(.leading, 2)
                .font(.sans(14))
                .foregroundStyle(Tok.text)
                .autocorrectionDisabled()
                .focused($focused)
                .accessibilityLabel(Text(verbatim: "Search settings"))
        }
        // 11 inside the 1-point border.
        .padding(.leading, 12)
        .padding(.trailing, 9)
        .frame(height: 32)
        .background(Tok.field, in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(focused ? Tok.accent : Tok.border))
        .background(RoundedRectangle(cornerRadius: 11).fill(focused ? Tok.accentSoft : .clear).padding(-3))
    }
}

/// `.sbody`: the page's head and its scrolling content.
struct LarsalSettingsBody: View {
    let model: LarsalSettingsModel

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                arrow("caret-left", "Back", enabled: model.canGoBack, action: model.goBack)
                arrow("caret-right", "Forward", enabled: model.canGoForward, action: model.goForward)
                Text(verbatim: model.page.title).font(.sans(15, .semibold))
                    .accessibilityAddTraits(.isHeader)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 20)
            .frame(height: 52)
            .overlay(alignment: .bottom) { Rectangle().fill(Tok.rule).frame(height: 1) }
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if let error = model.error { LarsalSettingsErrorNotice(text: error).padding(.bottom, 20) }
                    LarsalSettingsPageView(model: model)
                }
                .padding(.top, 20)
                .padding(.horizontal, 24)
                .padding(.bottom, 32)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .scrollIndicators(.never)
        }
        // The 1-point border is inside the box, as CSS's border box.
        .padding(1)
        .background(Tok.surface, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Tok.border))
    }

    /// The head's back and forward arrows (`.shead .ph`, muted).
    private func arrow(_ glyph: String, _ label: String, enabled: Bool, action: @escaping () -> Void) -> some View {
        // Not hidden: a hidden label keeps the button from the focus (AT-K06).
        Button(action: action) { Glyph(name: glyph).accessibilityHidden(false).foregroundStyle(Tok.muted) }
            .buttonStyle(Bare())
            .disabled(!enabled)
            .help(label)
            .accessibilityLabel(Text(verbatim: label))
    }
}

/// `.notice` (negative): the settings file cannot be written (APP-01.12).
struct LarsalSettingsErrorNotice: View {
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Glyph(name: "warning").padding(.top, 1)
            Text(verbatim: text).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .font(.sans(13))
        .lineSpacing(1)
        .foregroundStyle(Tok.negInk)
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(Tok.negBg, in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
    }
}

/// One page of `SETP`.
struct LarsalSettingsPageView: View {
    let model: LarsalSettingsModel

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            switch model.page {
            case .general: LarsalSettingsGeneralPage(model: model)
            case .security: LarsalSettingsSecurityPage(model: model)
            case .autoType: LarsalSettingsAutoTypePage(model: model)
            case .browser: LarsalSettingsBrowserPage(model: model)
            case .ssh: LarsalSettingsSshPage(model: model)
            case .share: LarsalSettingsSharePage(model: model)
            case .keys: LarsalSettingsShortcutsPage(model: model)
            }
        }
    }
}

// MARK: Parts

/// `.grp`: an optional `h4`, then the rows in their box.
struct LarsalSettingsGroup: View {
    let title: String?
    let rows: [AnyView]

    init(_ title: String? = nil, @LarsalSettingsRowsBuilder rows: () -> [AnyView]) {
        self.title = title
        self.rows = rows()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let title {
                Text(verbatim: title).font(.sans(13, .semibold)).frame(height: 18)
                    .padding(.leading, 2).padding(.bottom, 8)
                    .accessibilityAddTraits(.isHeader)
            }
            LarsalSettingsBox(rows: rows)
        }
    }
}

/// `.grp .box` (as `RowBox`), with `.srow + .srow`'s rule inside the later
/// rows' 46-point minimum, as CSS's border box draws it.
struct LarsalSettingsBox: View {
    let rows: [AnyView]
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                row.environment(\.larsalSettingsRule, index > 0).overlay(alignment: .top) {
                    if index > 0 { Rectangle().fill(Tok.srowRule).frame(height: 1) }
                }
            }
        }
        .padding(scheme == .dark ? 1 : 0)
        .background(Tok.raised, in: RoundedRectangle(cornerRadius: 10))
        .overlay {
            if scheme == .dark { RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border) }
        }
    }
}

extension EnvironmentValues {
    /// The row has the 1-point rule above it (`.srow + .srow`).
    @Entry var larsalSettingsRule = false
}

@resultBuilder
enum LarsalSettingsRowsBuilder {
    static func buildExpression(_ row: some View) -> [AnyView] { [AnyView(row)] }
    static func buildExpression(_ rows: [AnyView]) -> [AnyView] { rows }
    static func buildBlock(_ parts: [AnyView]...) -> [AnyView] { parts.flatMap { $0 } }
    static func buildOptional(_ part: [AnyView]?) -> [AnyView] { part ?? [] }
    static func buildEither(first part: [AnyView]) -> [AnyView] { part }
    static func buildEither(second part: [AnyView]) -> [AnyView] { part }
    static func buildArray(_ parts: [[AnyView]]) -> [AnyView] { parts.flatMap { $0 } }
}

/// `.srow`: the words (and the `.d` line) left, the controls right, 8
/// apart; `.srow.sub` is indented to 32.
struct LarsalSettingsRow<Control: View, Title: View, Detail: View>: View {
    let title: Title
    let detail: Detail?
    var sub = false
    @ViewBuilder let control: Control
    @Environment(\.larsalSettingsRule) private var rule

    var body: some View {
        HStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 1) {
                title.frame(minHeight: 20, alignment: .leading)
                if let detail {
                    // 16-point lines (IBM Plex's own line is 15 at 12).
                    detail.font(.sans(12)).foregroundStyle(Tok.muted)
                        .lineSpacing(1).padding(.vertical, 0.5)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: 8) { control }
        }
        .padding(.leading, sub ? 32 : 14)
        .padding(.trailing, 14)
        .padding(.vertical, 10)
        .padding(.top, rule ? 1 : 0)
        .frame(minHeight: 46)
        .accessibilityElement(children: .contain)
    }
}

extension LarsalSettingsRow where Title == Text, Detail == Text {
    init(
        _ title: String, _ detail: String? = nil, mono: Bool = false, sub: Bool = false,
        @ViewBuilder control: () -> Control
    ) {
        self.title = Text(verbatim: title)
        self.detail = detail.map { Text(verbatim: $0).font(mono ? .mono(12) : .sans(12)) }
        self.sub = sub
        self.control = control()
    }
}

/// A `.sw` bound to a stored setting; disabled per APP-01.5.
struct LarsalSettingsSwitch: View {
    let model: LarsalSettingsModel
    let key: String
    let label: String

    var body: some View {
        Switch(label: label, isOn: model.binding(key)).disabled(model.isDisabled(key))
    }
}

/// `.step` over a stored number: `step` per press within `range`, shown
/// with its unit.
struct LarsalSettingsStepper: View {
    let model: LarsalSettingsModel
    let key: String
    let range: ClosedRange<Int64>
    var step: Int64 = 1
    var show: (Int64) -> String = { "\($0)" }
    /// The stored value per shown step (minutes stored as seconds).
    var scale: Int64 = 1

    var body: some View {
        let value = model.number(key)
        StepBox(value: show(value)) {
            model.setNumber(key, max(range.lowerBound, (value - step * scale) / scale * scale))
        } more: {
            model.setNumber(key, min(range.upperBound, (value + step * scale) / scale * scale))
        }
        .disabled(model.isDisabled(key))
        .accessibilityElement(children: .contain)
        .accessibilityValue(Text(verbatim: show(value)))
    }
}

/// `.selx` that opens its choices.
struct LarsalSettingsSelect: View {
    let label: String
    let title: String
    let choices: [String]
    let chosen: Int?
    var disabled = false
    let choose: (Int) -> Void
    @State private var open = false

    var body: some View {
        Button {
            open.toggle()
        } label: {
            SelectBox(title: title)
        }
        .buttonStyle(Bare())
        .disabled(disabled)
        .accessibilityLabel(Text(verbatim: label + ", " + title))
        .popover(isPresented: $open, arrowEdge: .bottom) {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(choices.indices, id: \.self) { index in
                    MenuItem(lead: .check(index == chosen), title: choices[index]) {
                        choose(index)
                        open = false
                    }
                }
            }
            .padding(6)
            .frame(minWidth: 180)
        }
    }
}

/// The coloured sample of S-UI-07 (`.pw`, mono 12): digits and symbols in
/// their tokens, letters in the line's colour.
func larsalSettingsSample(_ text: String) -> Text {
    text.reduce(Text(verbatim: "")) { line, char in
        let piece = Text(verbatim: String(char))
        if char.isASCII, char.isNumber { return line + piece.foregroundColor(Tok.digit) }
        if char.isASCII, char.isLetter { return line + piece }
        return line + piece.foregroundColor(Tok.symbol)
    }
}

/// When the controls of later stories come (`.later`).
enum LarsalSettingsWaits {
    static let updates = "Update checks come with Larsal's release feed (E14). Nothing is sent until then."
    static let touchID = Later.touchID
    static let autoType = "Changing the shortcut comes with Auto-Type (E8)."
    static let opera = "Opera waits for a check of the folder it reads (V-INT01-1)."
    static let socket = "Choosing a socket and a provider waits for the SSH page's new frames (W-05)."
}
