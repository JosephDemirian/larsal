import AppCore
import SwiftUI

/// The entry editor (E5-S5, mockup `editorView`): it takes the sheet; the
/// sidebar stays. Title row with Cancel and Save, the page list, and the
/// page. Vault text is plain text (AT-E01); the password shows only as the
/// user's Show (AT-E07).
struct EditorScreen: View {
    let model: VaultModel
    let editor: EditorModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            titleRow
            HStack(alignment: .top, spacing: 32) {
                nav.frame(width: 196)
                ScrollView {
                    VStack(alignment: .leading, spacing: 28) { page }
                        .padding(.trailing, 4)
                        .padding(.bottom, 32)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .scrollIndicators(.never)
                .accessibilityElement(children: .contain)
                .accessibilityLabel(Text(verbatim: editor.page.rawValue))
            }
            .padding(.top, 20)
        }
        // The sheet (`main.sheet`), as SheetView draws it.
        .padding(.horizontal, 25)
        .padding(.top, 23)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Tok.surface, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Tok.border))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .onExitCommand { model.cancelEditor() }
    }

    /// `.trow`: the logo, "Edit entry" and its line, Cancel and Save.
    private var titleRow: some View {
        let view = editor.view
        return HStack(alignment: .top, spacing: 16) {
            if view.new {
                Glyph(name: "plus", size: 20)
                    .foregroundStyle(Color(hsl: 200, 0.48, 0.30))
                    .frame(width: 48, height: 48)
                    .background(Color(hsl: 200, 0.72, 0.90), in: RoundedRectangle(cornerRadius: 12))
            } else {
                EntryLogo(title: view.title, host: view.host, icon: view.icon, custom: view.customIcon, size: .large)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: editor.title)
                    .font(.sans(22, .semibold))
                    .tracking(-0.22)
                    .frame(height: 28)
                    .accessibilityAddTraits(.isHeader)
                Text(verbatim: editor.subtitle).foregroundStyle(Tok.muted).frame(height: 20)
            }
            Spacer(minLength: 0)
            HStack(spacing: 8) {
                Button("Cancel") { model.cancelEditor() }
                    .buttonStyle(Btn(size: .large))
                Button {
                    model.saveEditor()
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

    /// `.ednav`: the eight pages, the counts of Advanced and History.
    private var nav: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(EditorModel.Page.allCases, id: \.self) { page in
                let current = editor.page == page
                SidebarItem(
                    title: page.rawValue, current: current,
                    lead: AnyView(Glyph(name: page.glyph).foregroundStyle(current ? Tok.text : Tok.muted))
                ) {
                    if let count = count(page) { Count(value: count) }
                } action: {
                    editor.page = page
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text(verbatim: "Editor pages"))
    }

    private func count(_ page: EditorModel.Page) -> UInt32? {
        let view = editor.view
        guard !view.new else { return nil }
        switch page {
        case .advanced: return UInt32(view.custom.count + view.attachments.count)
        case .history: return view.historyItems
        default: return nil
        }
    }

    @ViewBuilder
    private var page: some View {
        switch editor.page {
        case .entry: EntryPage(model: model, editor: editor)
        case .advanced: AdvancedPage(model: model, editor: editor)
        case .icon: IconPage(editor: editor)
        case .autoType: AutoTypePage(editor: editor)
        case .browser: BrowserPage(editor: editor)
        case .ssh: SshPage(editor: editor)
        case .properties: PropertiesPage(model: model, editor: editor)
        case .history: HistoryPage(model: model, editor: editor)
        }
    }
}

/// `.edsec`: a 15/20 heading 12 above its content, an optional `.lead`.
struct EdSection<Content: View>: View {
    var title: String?
    var lead: String?
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let title {
                Text(verbatim: title)
                    .font(.sans(15, .semibold))
                    .frame(height: 20)
                    .padding(.bottom, 12)
                    .accessibilityAddTraits(.isHeader)
            }
            if let lead {
                Text(verbatim: lead)
                    .font(.sans(13))
                    .foregroundStyle(Tok.muted)
                    .frame(minHeight: 20, alignment: .leading)
                    .padding(.top, -6)
                    .padding(.bottom, 14)
                    .fixedSize(horizontal: false, vertical: true)
            }
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// `.fgrid`: two equal columns 16 apart.
struct TwoColumns<Left: View, Right: View>: View {
    /// A fixed left width where the mockup's grid grows the left column
    /// with its content (the Browser page's chips).
    var leftWidth: CGFloat?
    @ViewBuilder let left: Left
    @ViewBuilder let right: Right

    var body: some View {
        EqualColumns(left: leftWidth) {
            left
            right
        }
    }
}

/// Two columns of exactly equal width, whatever their content (CSS
/// `grid-template-columns: 1fr 1fr` with a 16-point gap).
struct EqualColumns: Layout {
    var left: CGFloat?
    var spacing: CGFloat = 16

    private func widths(_ total: CGFloat) -> [CGFloat] {
        let first = left ?? max((total - spacing) / 2, 0)
        return [first, max(total - spacing - first, 0)]
    }

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? 0
        let columns = widths(width)
        let height = zip(subviews, columns).map { $0.sizeThatFits(ProposedViewSize(width: $1, height: nil)).height }
        return CGSize(width: width, height: height.max() ?? 0)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let columns = widths(bounds.width)
        var left = bounds.minX
        for (view, width) in zip(subviews, columns) {
            view.place(
                at: CGPoint(x: left, y: bounds.minY), anchor: .topLeading,
                proposal: ProposedViewSize(width: width, height: nil))
            left += width + spacing
        }
    }
}

/// A `.fgrid` cell: `.lab` over its control, an optional `.help`.
struct FieldCell<Control: View, HelpView: View>: View {
    let label: String
    var small: String?
    @ViewBuilder let control: Control
    @ViewBuilder let help: HelpView

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Lab(title: label, small: small)
            control
            help
        }
    }
}

extension FieldCell where HelpView == EmptyView {
    init(label: String, small: String? = nil, @ViewBuilder control: () -> Control) {
        self.init(label: label, small: small, control: control) { EmptyView() }
    }
}

/// The additional website rows in INT-03.2's order (INT-03.18).
struct WebsiteRows: View {
    let view: EditorView

    var body: some View {
        ForEach(Array(zip(view.urls, view.urlNotes).enumerated()), id: \.offset) { _, row in
            WebsiteRow(row: row.0, note: row.1).padding(.top, 6)
        }
    }
}

/// An additional website row, with INT-03.18's note when its value can
/// never fit a web page (MI03-01 to MI03-03).
struct WebsiteRow: View {
    let row: CustomFieldView
    let note: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            InputBox {
                Glyph(name: "globe-simple").foregroundStyle(Tok.muted)
                Text(verbatim: row.protected ? "••••••" : row.value)  // F-060
                    .lineLimit(1)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .accessibilityLabel(Text(verbatim: "Another website"))
            if !note.isEmpty {
                Text(verbatim: note).font(.sans(12)).foregroundStyle(Tok.warning)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
