import AppKit
import LarsalCore
import SwiftUI

/// The group editor (W-15, mockup `groupEd`): the entry editor's layout with
/// the group's six pages; E11-S5 builds the Sharing page only (INT-08.21),
/// the others are drawn and wait for their story.
struct GroupEditorScreen: View {
    let model: VaultModel
    let editor: ShareEditorModel

    static let pages = [
        ("Group", "folder-simple"), ("Icon", "image-square"), ("Auto-Type", "keyboard"),
        ("Browser", "globe-simple"), ("Sharing", "share-network"), ("Properties", "info"),
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            titleRow
            HStack(alignment: .top, spacing: 32) {
                nav.frame(width: 196)
                ScrollView {
                    SharingPage(model: model, editor: editor)
                        .padding(.trailing, 4)
                        .padding(.bottom, 32)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .scrollIndicators(.never)
                .accessibilityElement(children: .contain)
                .accessibilityLabel(Text(verbatim: "Sharing"))
            }
            .padding(.top, 20)
        }
        .padding(.horizontal, 25)
        .padding(.top, 23)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Tok.surface, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Tok.border))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .onExitCommand { model.cancelGroup() }
    }

    /// `.trow`: the group's tile with its badge, "Edit group", Cancel, Save.
    private var titleRow: some View {
        HStack(alignment: .top, spacing: 16) {
            ShareGroupTile(model: model, group: editor.view.group, large: true)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: "Edit group")
                    .font(.sans(22, .semibold))
                    .tracking(-0.22)
                    .frame(height: 28)
                    .accessibilityAddTraits(.isHeader)
                Text(verbatim: editor.subtitle).foregroundStyle(Tok.muted).frame(height: 20)
            }
            Spacer(minLength: 0)
            HStack(spacing: 8) {
                Button("Cancel") { model.cancelGroup() }
                    .buttonStyle(Btn(size: .large))
                Button {
                    model.saveGroup()
                } label: {
                    BtnLabel(title: "Save", keys: "⌘S")
                }
                .buttonStyle(Btn(kind: .primary, size: .large))
                .keyboardShortcut("s", modifiers: .command)
            }
        }
        .overlay(alignment: .bottomTrailing) {
            if let problem = editor.problem {
                Text(verbatim: problem).font(.sans(12)).foregroundStyle(Tok.negative).offset(y: 18)
            }
        }
    }

    /// `.ednav`: the six pages; Sharing is the current one.
    private var nav: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(Self.pages, id: \.0) { title, glyph in
                let current = title == "Sharing"
                let item = SidebarItem(
                    title: title, current: current,
                    lead: AnyView(Glyph(name: glyph).foregroundStyle(current ? Tok.text : Tok.muted))
                ) {
                    EmptyView()
                } action: {
                }
                if current { item } else { item.later(Later.groupPages) }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text(verbatim: "Group editor pages"))
    }
}

extension View {
    /// A `.help` line with its 6 above, at W-15's 22 points (F-214): SwiftUI
    /// sets IBM Plex 12 in a 15-point line, so `lineBox(12, 16)` leaves each
    /// one 0.6 short, and the rows under it rose 2 points.
    fileprivate func helpRow() -> some View { frame(minHeight: 22, alignment: .leading) }
}

/// The Sharing page (INT-08.21 to INT-08.23, INT-08.39; mockup `sharePage`).
struct SharingPage: View {
    let model: VaultModel
    let editor: ShareEditorModel
    @FocusState private var pathFocus: Bool
    @State private var passwordFocused = false
    @State private var editing = false

    static let modes: [ShareMode] = [.inactive, .import, .export, .synchronize]
    /// Each Type's line under the control.
    static let helps = [
        "This group is not shared.",
        "Reads changes from the file into this group. Larsal never writes the file.",
        "Writes this group to the file after every save of the vault. Larsal never reads the file.",
        "Reads changes from the file into this group, and writes this group to the file after every save of the "
            + "vault.",
    ]

    var body: some View {
        let view = editor.view
        let off = editor.off
        let mode = Self.modes.firstIndex(of: view.mode) ?? 0
        let lead =
            "A group of your vault, shared as a file. The people you share with open the file with its password, "
            + "from a group of their own vault."
        EdSection(title: "Sharing", lead: lead) {
            VStack(alignment: .leading, spacing: 16) {
                FieldCell(label: "Type") {
                    Segments(items: Self.modes.map(ShareLabelNotice.modeName), selected: mode) {
                        editor.change(.mode(mode: Self.modes[$0]))
                    }
                    .accessibilityElement(children: .contain)
                    .accessibilityLabel(Text(verbatim: "Type"))
                } help: {
                    Help(text: Self.helps[mode]).helpRow()
                }
                FieldCell(label: "Path") {
                    path(off)
                } help: {
                    if !off {
                        (Text(verbatim: "Full path: ") + Text(verbatim: view.fullPath).font(.mono(12)))
                            .font(.sans(12)).foregroundStyle(Tok.muted).lineBox(12, 16)
                            .fixedSize(horizontal: false, vertical: true).padding(.top, 6).helpRow()
                    }
                }
                if !off, let warning = view.warning { ShareWarningNotice(warning: warning, path: view.path) }
                FieldCell(label: "Share password") {
                    password(off)
                } help: {
                    if !off {
                        Help(text: "Give it to the people you share with. It opens the file, never your vault.")
                            .helpRow()
                    }
                }
                if !off, view.weak { ShareWarningNotice.weak }
            }
            let keep = SRow(
                title: "Keep group structure",
                detail: "Also shares the groups inside \(view.name), with their entries. "
                    + "Off: only the entries directly in \(view.name)."
            ) {
                Switch(
                    label: "Keep group structure",
                    isOn: Binding(get: { view.keepGroups }, set: { editor.change(.keep(on: $0)) }))
            }
            RowBox(rows: [AnyView(keep)])
                .disabled(off)
                .opacity(off ? 0.55 : 1)
                .padding(.top, 20)
            HStack(spacing: 8) {
                Button {
                    editor.change(.clear)
                } label: {
                    BtnLabel(glyph: "x-circle", title: "Clear")
                        .foregroundStyle(view.item ? Tok.negative : Tok.text)
                }
                .buttonStyle(Btn())
                .disabled(!view.item)
                .opacity(view.item ? 1 : 0.55)
                Text(
                    verbatim: "Removes the sharing settings from this group when you save. The file stays where it is."
                )
                .font(.sans(12)).foregroundStyle(Tok.muted).lineBox(12, 16)
            }
            .padding(.top, 16)
            Text(
                verbatim: "The file also holds this vault's list of deleted items (their ids and times, never "
                    + "names or contents), so people with the file can see when you deleted something, also "
                    + "outside this group."
            )
            .font(.sans(12)).foregroundStyle(Tok.muted).lineBox(12, 16)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 2)
            .padding(.top, 20)
        }
    }

    private func path(_ off: Bool) -> some View {
        InputBox(focused: pathFocus, off: off) {
            Glyph(name: "folder-simple").foregroundStyle(Tok.muted)
            PlainField(
                prompt: "Choose a file, or type a path",
                text: Binding(get: { off ? "" : editor.view.path }, set: { editor.change(.path(path: $0)) }),
                mono: true,
                label: "Path", focus: $pathFocus
            )
            Button("Browse…") { browse() }.buttonStyle(Btn(size: .small))
        }
        .disabled(off)
    }

    /// The share password: masked (secure input while focused, APP-10), or
    /// the Show value in the no-copy field; Show and the generator (FEA-02).
    private func password(_ off: Bool) -> some View {
        InputBox(focused: passwordFocused, off: off) {
            Glyph(name: "key").foregroundStyle(Tok.muted)
            if let shown = editor.shown, editing {
                EditorPasswordField(
                    text: Binding(get: { shown }, set: { editor.typed($0) }), focused: $passwordFocused,
                    label: "Share password", focusOnAppear: true)
            } else if let shown = editor.shown {
                EditorShownPassword(text: shown) { editing = true }
            } else {
                MaskedPasswordField(
                    dots: off ? 0 : min(Int(editor.view.passwordChars), 16), focused: $passwordFocused,
                    label: "Share password", empty: "Share password"
                ) { editor.typed($0) }
                .id(editor.applied)
            }
            IconButton(
                glyph: editor.shown == nil ? "eye" : "eye-slash",
                label: editor.shown == nil ? "Show password" : "Hide password", size: 28
            ) { editor.toggleShow() }
            // APP-08.14, APP-10.9: ⌃H shows or hides it, ⌃G opens the generator.
            .keyboardShortcut("h", modifiers: .control)
            IconButton(glyph: "password", label: "Open generator (⌥⌘G)", size: 28) {
                model.openGenerator(fromEditor: true)
            }
            .keyboardShortcut("g", modifiers: [.option, .command])
            .background {
                Button("") { model.openGenerator(fromEditor: true) }
                    .keyboardShortcut("g", modifiers: .control)
                    .opacity(0)
                    .focusable(false)
                    .accessibilityHidden(true)
            }
        }
        .disabled(off)
        .onChange(of: passwordFocused) { _, now in if !now { editing = false } }
        .onChange(of: editor.shown == nil) { _, hidden in if hidden { editing = false } }
        .capsLockNote(focused: passwordFocused)  // M06-37 (APP-06.6, F-207)
    }

    /// INT-08.22: an open-file chooser for Import, a save-file chooser for
    /// Export and Synchronize; a name without a container name gets
    /// `.larsalvault` (Rust's `share_chosen_path`).
    private func browse() {
        let save = editor.view.mode != .import
        guard let url = ShareEditorModel.choose(save, ShareEditorModel.lastFolder) else { return }
        ShareEditorModel.lastFolder = url.deletingLastPathComponent()
        editor.change(.path(path: shareChosenPath(path: url.path(percentEncoded: false))))
    }
}

extension ShareEditorModel {
    // The folder last used for shares (INT-08.22), kept for this run only;
    // S-STATE-06 stores it once that setting has its Swift call.
    static var lastFolder: URL?

    /// The chooser (never shown by tests, AGENTS.md rule 10): all files;
    /// the container filters wait (W-15 draws none).
    static var choose: (_ save: Bool, _ folder: URL?) -> URL? = { save, folder in
        let panel: NSSavePanel = save ? NSSavePanel() : NSOpenPanel()
        panel.directoryURL = folder
        panel.canCreateDirectories = true
        return panel.runModal() == .OK ? panel.url : nil
    }
}

/// The message slot under Path (INT-08.23) and MI08-23, in W-15's looks.
struct ShareWarningNotice: View {
    let warning: ShareWarning
    let path: String

    static let weak = Notice(glyph: "warning", fill: Tok.warnBg, ink: Tok.warnInk) {
        Text(verbatim: "The share password is empty or weak. Anyone who gets the share file may be able to open it.")
    }

    var body: some View {
        let mono = { (text: String) in Text(verbatim: text).font(.mono(13)) }
        let plain = { (text: String) in Text(verbatim: text) }
        switch warning {
        case .openVault:
            Notice(glyph: "warning-circle", fill: Tok.negBg, ink: Tok.negInk) {
                plain("This file cannot be used for sharing: it is the file of a vault open in Larsal.")
            }
        case .extension:
            Notice(glyph: "warning", fill: Tok.warnBg, ink: Tok.warnInk) {
                plain("Larsal cannot share this kind of file. Use a name that ends in ") + mono(".larsalvault")
                    + plain(" or ") + mono(".larsalshare") + plain(".")
            }
        case .otherExports:
            Notice(glyph: "warning-circle", fill: Tok.negBg, ink: Tok.negInk) {
                plain("Another group in this vault already exports to ") + mono(path) + plain(". Choose another file.")
            }
        case .otherImports:
            Notice(glyph: "warning", fill: Tok.warnBg, ink: Tok.warnInk) {
                plain("Another group in this vault already imports from ") + mono(path)
                    + plain(". While both do, neither is updated.")
            }
        case .importAndExport:
            Notice(glyph: "warning", fill: Tok.warnBg, ink: Tok.warnInk) {
                plain("One group in this vault exports to ") + mono(path) + plain(" and another imports from it.")
            }
        case .bothOff:
            info("Sharing is turned off. Turn on import or export in Larsal's settings, Shared groups.")
        case .exportOff: info("Export is turned off in Larsal's settings.")
        case .importOff: info("Import is turned off in Larsal's settings.")
        }
    }

    private func info(_ text: String) -> some View {
        Notice(glyph: "info", fill: Tok.raised, ink: Tok.text) { Text(verbatim: text) }
    }
}
