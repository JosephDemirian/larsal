import AppKit
import LarsalCore
import SwiftUI

/// The picker's list, search, highlight and keys (INT-05.26 to INT-05.29).
/// Rows hold no secret; a choice goes to Rust as a row position.
@MainActor
@Observable
final class AutoTypePicker {
    let target: FrontWindow
    /// The unlocked vaults when it opened.
    let unlocked: Set<UInt64>
    private(set) var rows: [AutoTypeRow]
    private(set) var highlight: Int
    /// S-VIEW-06 when it opened (APP-01.23, LD-219 (1)).
    var maskUserNames = false
    /// FEA-01 over every unlocked vault, as the user types (INT-05.27).
    var search = "" {
        didSet {
            guard search != oldValue else { return }
            show(session.autotypeRows(search: search, utcOffset: AutoType.offset))
        }
    }
    @ObservationIgnored private let session: Session
    @ObservationIgnored private let done: (AutoTypeChosen?) -> Void

    init(
        session: Session, target: FrontWindow, list: AutoTypeList, unlocked: Set<UInt64>,
        done: @escaping (AutoTypeChosen?) -> Void
    ) {
        self.session = session
        self.target = target
        self.unlocked = unlocked
        self.done = done
        rows = list.rows
        highlight = Int(list.highlight)
    }

    /// MI05-40.
    var header: String {
        target.title.isEmpty ? "Type into \(target.appName)" : "Type into “\(target.title)”"
    }

    func move(by step: Int) {
        guard !rows.isEmpty else { return }
        highlight = min(max(highlight + step, 0), rows.count - 1)
    }

    /// A type action on `row` (the highlighted one by default).
    func choose(_ action: AutoTypeAction, row: Int? = nil) {
        guard !rows.isEmpty else { return }
        let index = UInt32(row ?? highlight)
        done(session.autotypeChoose(index: index, action: action, utcOffset: AutoType.offset))
    }

    /// ⇧⌘1 to ⇧⌘4: copy (APP-03 `copy.autotype_*`), then close untyped.
    func copy(_ field: String) {
        guard rows.indices.contains(highlight) else { return }
        let row = rows[highlight]
        _ =
            field == "Code"
            ? try? session.copyCode(vault: row.vault, entry: row.entry)
            : try? session.copyField(vault: row.vault, entry: row.entry, field: field)
        cancel()
    }

    /// Escape clears the search, then closes the picker.
    func escape() {
        if search.isEmpty { cancel() } else { search = "" }
    }

    /// Closes without typing.
    func cancel() {
        session.autotypeClose()
        done(nil)
    }

    /// INT-05.29's keys in the search field; true when handled.
    func press(_ key: KeyEquivalent, _ modifiers: SwiftUI.EventModifiers) -> Bool {
        let mods = modifiers.intersection([.command, .shift, .option, .control])
        switch (key.character, mods) {
        case (KeyEquivalent.upArrow.character, []): move(by: -1)
        case (KeyEquivalent.downArrow.character, []): move(by: 1)
        case (KeyEquivalent.pageUp.character, []): move(by: -5)
        case (KeyEquivalent.pageDown.character, []): move(by: 5)
        case (KeyEquivalent.return.character, []): choose(.login)
        case (KeyEquivalent.return.character, .shift): choose(.password)
        case (KeyEquivalent.escape.character, []): escape()
        default: return false
        }
        return true
    }

    /// ⌘1 to ⌘5 type, ⇧⌘1 to ⇧⌘4 copy (INT-05.29); the view matches the
    /// keys as menus do, on any keyboard layout.
    func command(_ digit: Int, shift: Bool) {
        guard (1...(shift ? 4 : 5)).contains(digit) else { return }
        if shift {
            copy(["UserName", "Password", "Code", "URL"][digit - 1])
        } else {
            choose([.username, .password, .code, .url, .keyCodes][digit - 1])
        }
    }

    private func show(_ list: AutoTypeList) {
        rows = list.rows
        highlight = Int(list.highlight)
    }
}

/// The Auto-Type picker (frame `menubar-auto-type-picker`, INT-05.26): the
/// header, the search field with the focus, one row per (entry, sequence)
/// and the hint line. Not drawn until the owner's mockup changes (W-06,
/// D-INT05-16 (3), (4), R05-6): the app name line, the small line's
/// sequence and vault additions, the empty list text and the row menu.
struct AutoTypePickerView: View {
    let model: AutoTypePicker
    @FocusState private var focused: Bool
    @Environment(\.colorScheme) private var scheme

    /// Rows shown before the list scrolls.
    private static let visible = 6
    /// `text` with each ⏎ in the system font, as the mockup's font stack
    /// falls back to it (IBM Plex has no such glyph).
    static func keys(_ text: String) -> Text {
        var out = AttributedString()
        for (index, part) in text.split(separator: "⏎", omittingEmptySubsequences: false).enumerated() {
            if index > 0 {
                var ret = AttributedString("⏎")
                ret.font = .system(size: 12)
                out += ret
            }
            out += AttributedString(part)
        }
        return Text(out)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Glyph(name: "keyboard")
                Text(verbatim: model.header).font(.sans(14, .semibold)).lineLimit(1).truncationMode(.middle)
                    .accessibilityAddTraits(.isHeader)
            }
            .frame(height: 20)
            .padding(.bottom, 12)
            search
            list.padding(.top, 8)
            Self.keys("↑↓ to choose · ⏎ types username, password and code · ⇧⏎ types the password only")
                .font(.sans(12))
                .foregroundStyle(Tok.muted)
                .lineBox(12, 16)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 8)
        }
        .padding(16)
        .frame(width: 480)
        .background(Tok.dialog, in: RoundedRectangle(cornerRadius: 12))
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text(verbatim: model.header))
        .background {
            // `--pop-shadow` and its hairline ring, as `.dlg` (DialogCard).
            let dark = scheme == .dark
            BoxShadow(radius: 12, drop: dark ? 16 : 12, blur: dark ? 40 : 32, alpha: dark ? 0.6 : 0.16)
            RoundedRectangle(cornerRadius: 13)
                .strokeBorder(dark ? Color.white.opacity(0.08) : Color.black.opacity(0.06))
                .padding(-1)
        }
        .background { shortcuts }
        .environment(\.maskUserNames, model.maskUserNames)
        .onAppear { focused = true }
    }

    /// `.search`, full width; the keyboard focus (INT-05.26).
    private var search: some View {
        HStack(spacing: 8) {
            Glyph(name: "magnifying-glass").foregroundStyle(Tok.muted)
            TextField(
                "", text: Binding(get: { model.search }, set: { model.search = $0 }),
                prompt: Text(verbatim: "Search all entries…").foregroundStyle(Tok.muted)
            )
            .textFieldStyle(.plain)
            .padding(.leading, 2)
            .font(.sans(14))
            .foregroundStyle(Tok.text)
            .autocorrectionDisabled()
            .focused($focused)
            .accessibilityLabel(Text(verbatim: "Search all entries"))
            .onKeyPress(phases: [.down, .repeat]) { model.press($0.key, $0.modifiers) ? .handled : .ignored }
        }
        .padding(.leading, 12)
        .padding(.trailing, 9)
        .frame(height: 32)
        .background(Tok.field, in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(focused ? Tok.accent : Tok.border))
        .background(RoundedRectangle(cornerRadius: 11).fill(focused ? Tok.accentSoft : .clear).padding(-3))
    }

    @ViewBuilder private var list: some View {
        let rows = VStack(spacing: 0) {
            ForEach(Array(model.rows.enumerated()), id: \.offset) { index, row in
                AutoTypeRowView(row: row, highlighted: index == model.highlight) {
                    model.choose(.login, row: index)
                }
                .id(index)
            }
        }
        if model.rows.count > Self.visible {
            ScrollViewReader { proxy in
                ScrollView { rows }
                    .frame(height: CGFloat(Self.visible) * 60)
                    .onChange(of: model.highlight) { proxy.scrollTo(model.highlight) }
            }
        } else {
            rows
        }
    }

    /// ⌘1 to ⌘5 and ⇧⌘1 to ⇧⌘4 (INT-05.29), matched as menu keys are.
    private var shortcuts: some View {
        ZStack {
            ForEach(1...5, id: \.self) { digit in
                let key = KeyEquivalent(Character(String(digit)))
                Button("") { model.command(digit, shift: false) }.keyboardShortcut(key, modifiers: .command)
                if digit < 5 {
                    Button("") { model.command(digit, shift: true) }
                        .keyboardShortcut(key, modifiers: [.command, .shift])
                }
            }
        }
        .opacity(0)
        .accessibilityHidden(true)
    }
}

/// `.rec` as the picker draws it: the logo, the title in bold, the user
/// name, and MI05-42 on the highlighted row.
private struct AutoTypeRowView: View {
    let row: AutoTypeRow
    let highlighted: Bool
    let type: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            EntryLogo(title: row.title, host: row.host, icon: row.icon, custom: row.customIcon)
            VStack(alignment: .leading, spacing: 0) {
                // MOD-09.14: an expired entry is struck through.
                Text(verbatim: row.title).font(.sans(14, .medium)).strikethrough(row.expired).frame(height: 20)
                // S-VIEW-06 (LD-219 (1)): the mask, read "hidden".
                MaskedUser(user: row.username).font(.sans(12)).foregroundStyle(Tok.muted).frame(height: 20)
            }
            .lineLimit(1)
            .accessibilitySortPriority(1)
            Spacer(minLength: 0)
            if highlighted {
                AutoTypePickerView.keys("Type login ⏎").font(.sans(12)).foregroundStyle(Tok.muted)
            }
        }
        .foregroundStyle(Tok.text)
        .padding(10)
        .background(highlighted ? Tok.active : .clear, in: RoundedRectangle(cornerRadius: 10))
        .contentShape(Rectangle())
        .onTapGesture(count: 2, perform: type)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(highlighted ? [.isButton, .isSelected] : .isButton)
        .accessibilityValue(Text(verbatim: row.expired ? "Expired" : ""))
        .accessibilityAction(named: Text(verbatim: "Type login"), type)
    }
}

/// The picker's floating panel (D-INT05-3): it takes the keyboard without
/// making Larsal active, floats over other windows on the screen in front,
/// near its top, and is left out of screen captures (APP-10.3). Never in a
/// hidden launch (AGENTS.md rule 10).
final class AutoTypePanel: NSPanel {
    override var canBecomeKey: Bool { true }

    private static var shown: AutoTypePanel?

    /// `AutoType`'s presenter: shows `picker`, or hides with `nil`.
    static func present(_ picker: AutoTypePicker?) {
        shown?.orderOut(nil)
        shown = nil
        guard let picker, !launchHidden(), let screen = NSScreen.main else { return }
        // Room for six rows and the card's shadow; the clear rest lets
        // clicks through. ponytail: a fixed size, no resizing per list.
        let size = CGSize(width: 560, height: 600)
        let host = NSHostingView(
            rootView: AutoTypePickerView(model: picker).padding(40).frame(
                width: size.width, height: size.height, alignment: .top))
        let panel = AutoTypePanel(
            contentRect: NSRect(
                x: screen.visibleFrame.midX - size.width / 2, y: screen.visibleFrame.maxY - size.height - 40,
                width: size.width, height: size.height),
            styleMask: [.nonactivatingPanel, .borderless], backing: .buffered, defer: false)
        panel.contentView = host
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = false
        panel.level = .floating
        // APP-10.1: protected before it shows, unless capture is allowed.
        ScreenProtection.shared.adopt(panel)
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.isReleasedWhenClosed = false
        panel.makeKeyAndOrderFront(nil)
        shown = panel
    }
}

/// The unlock panel of INT-05.25 step 5 (APP-06.27): a small window centred
/// on the active screen with M06-40 over the unlock form and Cancel left of
/// Unlock; showing it makes Larsal active, the main window stays as it is.
/// Never in a hidden launch (AGENTS.md rule 10).
enum AutoTypeUnlockPanel {
    private static var shown: AutoTypePanel?

    /// The panel's content: the shared unlock form without the switcher
    /// and the footer.
    static func view(_ model: AutoTypeUnlock) -> some View {
        UnlockView(model: model.form, purpose: AutoTypeUnlock.purpose, cancel: model.cancel)
            .frame(width: 446)
            .fixedSize(horizontal: false, vertical: true)
    }

    /// `AutoType`'s presenter: shows `model`, or hides with `nil`.
    static func present(_ model: AutoTypeUnlock?) {
        shown?.orderOut(nil)
        shown = nil
        guard let model, !launchHidden() else { return }
        let host = NSHostingView(rootView: view(model))
        // The picker panel's class: listed as adopted before shown (APP-10.3).
        let panel = AutoTypePanel(
            contentRect: NSRect(origin: .zero, size: host.fittingSize), styleMask: [.titled], backing: .buffered,
            defer: false)
        panel.contentView = host
        panel.title = "Unlock \(model.form.vault.name)"
        panel.level = .floating
        panel.isReleasedWhenClosed = false
        // APP-10.1: protected before it shows, unless capture is allowed.
        ScreenProtection.shared.adopt(panel)
        panel.center()
        NSApp.activate()
        panel.makeKeyAndOrderFront(nil)
        shown = panel
    }
}
