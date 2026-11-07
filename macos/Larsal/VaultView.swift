import LarsalCore
import SwiftUI

/// The main window of an unlocked vault (E5-S4, mockup `shell`): the top bar
/// and the sidebar share the ground; the sheet sits inset 8 points right and
/// bottom; menus are drawn over the window.
struct VaultView: View {
    let model: VaultModel
    let window: MainWindowModel

    var body: some View {
        // S-VIEW-03 and S-VIEW-04 (View menu, APP-08.8).
        let sidebarHidden = !window.view.sidebar
        ZStack(alignment: .topLeading) {
            VStack(spacing: 0) {
                TopBar(model: model, window: window, sidebarHidden: sidebarHidden)
                    .zIndex(1)
                HStack(spacing: 0) {
                    if !sidebarHidden {
                        SidebarView(model: model, window: window).frame(width: 248)
                    }
                    Group {
                        if let editor = model.editor {
                            EditorScreen(model: model, editor: editor)
                        } else if let group = model.sharing.editor {
                            GroupEditorScreen(model: model, editor: group)
                        } else if let reports = model.reports {
                            ReportsView(model: model, reports: reports)
                        } else {
                            SheetView(model: model, details: window.view.details)
                        }
                    }
                    .padding(.leading, sidebarHidden ? 8 : 0)
                    .padding(.trailing, 8)
                    .padding(.bottom, 8)
                }
            }
            overlays
        }
        .overlay(alignment: .top) {
            if let dialog = model.dialog {
                // `.scrim`: the window dims; the sheet drops below the top bar.
                ZStack(alignment: .top) {
                    Tok.scrim.contentShape(Rectangle()).accessibilityHidden(true)
                        .onTapGesture { if case .qrCode(let popup) = dialog { popup.scrimClicked() } }
                    DialogView(model: model, dialog: dialog).id(dialog).padding(.top, 52)
                }
                .onExitCommand { if case .qrCode(let popup) = dialog { popup.escape() } else { model.dialog = nil } }
            }
        }
        .overlay(alignment: .bottom) {
            VStack(spacing: 8) {
                KeyChangeNotice(model: model, window: window)  // MOD-13.10 (F-074)
                // APP-05.30: in the notice's place while the file downloads.
                if model.downloading { ToastView(toast: model.downloadingToast) }
                if let toast = model.toast { ToastView(toast: toast) }
            }
            .padding(.bottom, 20)
        }
        .background(Tok.ground)
        // S-VIEW-06 (APP-01.23): the list rows and the detail read it.
        .environment(\.maskUserNames, window.view.maskUserNames)
        .environment(\.colourPasswords, window.view.colourPasswords)
        .environment(\.detailOptions, window.view.detail)  // F-082, F-084
        .onAppear { model.enter() }
        .onDisappear { model.leave() }
        .onChange(of: model.toast) { _, toast in
            // The mockup's `role="status"`: read out, focus stays put.
            if let toast { AccessibilityNotification.Announcement(toast.spoken).post() }
        }
        .onChange(of: model.downloading) { _, shown in
            if shown { AccessibilityNotification.Announcement(model.downloadingToast.spoken).post() }
        }
    }

    @ViewBuilder
    private var overlays: some View {
        if window.vaultMenu {
            MenuLayer(
                close: { window.vaultMenu = false },
                menu: {
                    VaultMenu(window: window).padding(.leading, 12).padding(.top, 112)
                })
        } else if let overlay = model.overlay {
            MenuLayer(
                close: { model.overlay = nil },
                menu: {
                    Group {
                        switch overlay {
                        case .more: MoreMenu(model: model).padding(.top, 186).padding(.trailing, 20)
                        case .sort: SortMenu(model: model).padding(.top, 132).padding(.trailing, 22)
                        case .generator(let generator):
                            // `.floatp` under the toolbar button (mockup `overlay === 'gen'`).
                            GeneratorPanel(model: generator, vault: model).padding(.top, 118).padding(.trailing, 166)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .topTrailing)
                })
        }
    }
}

/// The mockup's `.tb`: the window buttons' room and the sidebar button,
/// the search box, and Lock.
struct TopBar: View {
    let model: VaultModel
    let window: MainWindowModel
    let sidebarHidden: Bool

    var body: some View {
        HStack(spacing: 0) {
            HStack(spacing: 0) {
                Spacer()
                IconButton(
                    glyph: "sidebar-simple", label: sidebarHidden ? "Show sidebar (⌃⌘S)" : "Hide sidebar (⌃⌘S)"
                ) { window.view.set("ui.show_groups", sidebarHidden, window.session) }
                .padding(.trailing, 10)
            }
            .frame(width: 248)
            SearchBox(model: model)
                .frame(maxWidth: 520)
                .frame(maxWidth: .infinity)
            Button {
                window.lock(model.vault.id)
            } label: {
                BtnLabel(glyph: "lock-simple", title: "Lock", keys: "⌘L")
            }
            .buttonStyle(Btn())
            .padding(.leading, 12)
        }
        .padding(.trailing, 12)
        .frame(height: 52)
    }
}

/// The mockup's `.search` with its tips (FEA-01).
struct SearchBox: View {
    let model: VaultModel
    @FocusState private var focused: Bool
    @Environment(\.colorScheme) private var scheme
    private var clearer: SearchClearTimer { model.searchClearer }  // APP-01.27

    static let tips: [(String, String)] = [
        ("is:weak", "Weak, reused or expired passwords"), ("is:expired", "Entries past their expiry date"),
        ("group:Work", "Entries in a group and its subgroups"), ("url:github", "Only the website field"),
        ("tag:2fa", "Entries with a tag"), ("-amazon", "Leave out entries with this word"),
        ("\"exact words\"", "Match the words in this order"),
    ]

    var body: some View {
        let lit = focused
        HStack(spacing: 8) {
            Glyph(name: "magnifying-glass").foregroundStyle(Tok.muted)
            TextField(
                "",
                text: Binding(
                    get: { model.search },
                    set: { text in
                        if !text.isEmpty { model.closeReports() }  // a search shows the list
                        model.setSearch(text)
                    }),
                prompt: Text(verbatim: "Search \(model.vault.name)…").foregroundStyle(Tok.muted)
            )
            .textFieldStyle(.plain)
            .font(.sans(14))
            .foregroundStyle(Tok.text)
            .autocorrectionDisabled()
            .focused($focused)
            .accessibilityLabel(Text(verbatim: "Search entries"))
            .onKeyPress(.escape) {
                model.setSearch("")
                return .handled
            }
            // APP-08.14: ↑ and ↓ move the list's selection while typing.
            .onKeyPress(keys: [.upArrow, .downArrow]) { press in
                model.move(press.key == .upArrow ? -1 : 1)
                return .handled
            }
            if let notice = model.notice {
                Glyph(name: "warning").foregroundStyle(Tok.warning).help(Text(verbatim: notice))
            }
            if model.search.isEmpty {
                Kbd(keys: "⌘F")
            } else {
                IconButton(glyph: "x-circle", label: "Clear search", size: 28) { model.setSearch("") }
            }
        }
        .padding(.leading, 11)
        .padding(.trailing, 8)
        .frame(height: 32)
        .background(Tok.field, in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(lit ? Tok.accent : Tok.border))
        .background(RoundedRectangle(cornerRadius: 11).fill(lit ? Tok.accentSoft : .clear).padding(-3))
        .overlay(alignment: .top) {
            if (focused || model.tips) && model.search.isEmpty {
                // `.tips`: 40 below the box's 1-point border, inside it.
                tipsPanel.padding(.horizontal, 1).offset(y: 41)
            }
        }
        .background {
            Button("") { focused = true }
                .keyboardShortcut("f", modifiers: .command)
                .opacity(0)
                .accessibilityHidden(true)
        }
        // Edit > Find… and the menu bar icon's Search Entries… (APP-08.4).
        .onReceive(NotificationCenter.default.publisher(for: .larsalFind)) { _ in focused = true }
        .onChange(of: focused) {
            model.tips = focused
            clearer.focus(focused, model)
        }
        // APP-01.27: a new selection restarts the countdown from full.
        .onChange(of: model.selection) { if clearer.running { clearer.focus(false, model) } }
    }

    /// The mockup's `.tips`.
    private var tipsPanel: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(verbatim: "Search tips")
                .font(.sans(12, .semibold))
                .foregroundStyle(Tok.muted)
                .frame(height: 20)
                .padding(.leading, 8)
                .padding(.top, 4)
                .padding(.bottom, 6)
                .accessibilityAddTraits(.isHeader)
            ForEach(Self.tips, id: \.0) { tip in
                TipRow(query: tip.0, meaning: tip.1) { model.setSearch(tip.0) }
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Tok.menu, in: RoundedRectangle(cornerRadius: 10))
        .popShadow(scheme)
        .fixedSize(horizontal: false, vertical: true)
    }
}

/// One search tip (`.tips .ti`): the query in mono, then its meaning.
private struct TipRow: View {
    let query: String
    let meaning: String
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Text(verbatim: query).font(.mono(13)).foregroundStyle(Tok.accent).frame(
                    width: 132, height: 20, alignment: .leading)
                Text(verbatim: meaning).font(.sans(13)).foregroundStyle(Tok.muted)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 7)
            .background(hover ? Tok.hover : .clear, in: RoundedRectangle(cornerRadius: 6))
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .onHover { hover = $0 }
        .accessibilityLabel(Text(verbatim: query + ", " + meaning))
    }
}
