import AppKit
import LarsalCore
import SwiftUI

/// The bridge's dialogs (INT-02.15): the Connect dialog (INT-02.4) and the
/// site access prompt (INT-02.18). Rust holds the line and every word;
/// titles and user names are plain text (AT-E01), never a protected value:
/// one Rust hides comes empty with its mark and shows the mask.
extension MainWindowModel {
    /// Reads the questions of Larsal's SSH agent and of the bridge.
    func refreshAsks() {
        refreshSsh()
        refreshBrowser()
    }

    /// Reads the bridge's dialog: a new one shows, an ended one (answered,
    /// timed out, its vault locked, its session gone) closes.
    func refreshBrowser() {
        let question = session.browserQuestion()
        if question?.id != browserAsk?.id {
            browserAsk = question
        }
    }

    /// The Connect dialog's answer: a name is Connect, `nil` is Deny.
    func answerBrowserConnect(_ name: String?) {
        guard let ask = browserAsk else { return }
        session.answerBrowserConnect(id: ask.id, name: name)
        browserAsk = nil
    }

    /// The site access prompt's answer (INT-02.18).
    func answerBrowserAccess(allow: Bool, checked: [Bool], remember: Bool) {
        guard let ask = browserAsk else { return }
        session.answerBrowserAccess(id: ask.id, allow: allow, checked: checked, remember: remember)
        browserAsk = nil
    }
}

/// Frame `dialogs-connect-a-browser`: the vault's text, the Name field,
/// MI02-01's four words (W-07: Option A does not draw them yet), Deny and
/// the primary Connect, disabled while the name is not valid; a taken name
/// shows MI02-02 under the field.
struct BrowserConnectDialog: View {
    let window: MainWindowModel
    let ask: BrowserQuestion
    @State private var name: String

    init(window: MainWindowModel, ask: BrowserQuestion) {
        self.window = window
        self.ask = ask
        _name = State(initialValue: ask.name)
    }

    var body: some View {
        let problem = window.session.browserNameProblem(vault: ask.vault, name: name)
        DialogCard(tint: "teal", glyph: "plugs-connected", title: ask.title, text: ask.text) {
            DialogBody {
                Lab(title: "Name")
                InputBox { PlainField(prompt: "", text: $name, label: "Name") }
                if let problem, !problem.isEmpty {
                    Help(text: problem).foregroundStyle(Tok.negative)
                }
                if !ask.words.isEmpty {
                    Text(verbatim: ask.words)
                        .font(.sans(13))
                        .foregroundStyle(Tok.muted)
                        .padding(.top, 8)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        } foot: {
            SheetButton(title: "Deny", cancel: true) { window.answerBrowserConnect(nil) }
            SheetButton(title: "Connect", kind: .primary) { window.answerBrowserConnect(name) }
                .disabled(problem != nil)
        }
    }
}

/// Frame `dialogs-browser-asks-for-an-entry`: the line of INT-02.19 (W-07:
/// Option A does not draw it yet), one row per entry in a panel, each
/// checked, "Remember for ‹P›" (unchecked; hidden for HTTP sign-in and
/// INT-02.19), Deny and the primary Allow Selected, disabled while no row
/// is checked. Escape is Deny. `checked` and `remember` set another first
/// state (Option A's frame).
struct BrowserAccessDialog: View {
    let window: MainWindowModel
    let ask: BrowserQuestion
    @State private var checked: [Bool]
    @State private var remember: Bool

    init(window: MainWindowModel, ask: BrowserQuestion, checked: [Bool]? = nil, remember: Bool = false) {
        self.window = window
        self.ask = ask
        _checked = State(initialValue: checked ?? Array(repeating: true, count: ask.rows.count))
        _remember = State(initialValue: remember)
    }

    var body: some View {
        DialogCard(tint: "teal", glyph: "globe-simple", title: ask.title, text: ask.text) {
            DialogBody {
                if let line = ask.line {
                    Text(verbatim: line)
                        .font(.sans(13))
                        .foregroundStyle(Tok.warning)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.bottom, 8)
                }
                // `.panel` (4 by 12 inside) of `.chkrow`s, a rule between them.
                VStack(spacing: 0) {
                    ForEach(Array(ask.rows.enumerated()), id: \.offset) { index, row in
                        BrowserAccessRow(row: row, isOn: $checked[index])
                            .padding(.top, index > 0 ? 1 : 0)
                            .overlay(alignment: .top) {
                                if index > 0 { Rectangle().fill(Tok.rule).frame(height: 1) }
                            }
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 4)
                .padding(1)
                .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
                if let label = ask.remember {
                    CheckRow(title: label, isOn: $remember)
                }
            }
        } foot: {
            SheetButton(title: "Deny", cancel: true) {
                window.answerBrowserAccess(allow: false, checked: checked, remember: remember)
            }
            SheetButton(title: "Allow Selected", kind: .primary) {
                window.answerBrowserAccess(allow: true, checked: checked, remember: remember)
            }
            .disabled(!checked.contains(true))
        }
    }
}

/// One entry of the site access prompt (Option A's row): the check box, the
/// entry's 24-point logo, its title and its user name. A value Rust hides
/// (INT-02.18, MOD-01.7) shows the mask, read "hidden" (APP-01.23); a user
/// name follows S-VIEW-06 as everywhere (LD-219 (1)).
struct BrowserAccessRow: View {
    let row: BrowserQuestionRow
    @Binding var isOn: Bool
    @Environment(\.maskUserNames) private var mask

    var body: some View {
        Button {
            isOn.toggle()
        } label: {
            HStack(spacing: 10) {
                CheckMark(isOn: isOn)
                EntryLogo(title: row.title, host: row.host, icon: row.icon, custom: row.customIcon, size: .tiny)
                VStack(alignment: .leading, spacing: 0) {
                    (row.titleHidden ? Masked.line() : Text(verbatim: row.title))
                        .font(.sans(14, .medium))
                        .frame(minHeight: 20, alignment: .leading)
                    if row.usernameHidden || !row.username.isEmpty {
                        Group {
                            if row.usernameHidden { Masked.line() } else { MaskedUser(user: row.username) }
                        }
                        .font(.sans(12))
                        .foregroundStyle(Tok.muted)
                        .frame(height: 16)
                    }
                }
                .lineLimit(1)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.vertical, 10)
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .accessibilityLabel(Text(verbatim: Self.spoken(row, mask: mask)))
        .accessibilityValue(Text(verbatim: isOn ? "on" : "off"))
        .accessibilityAddTraits(isOn ? .isSelected : [])
    }

    /// The title and the user name as VoiceOver reads them; `mask`: S-VIEW-06.
    static func spoken(_ row: BrowserQuestionRow, mask: Bool) -> String {
        let title = row.titleHidden ? Masked.spoken : row.title
        let user = row.usernameHidden || (mask && !row.username.isEmpty) ? Masked.spoken : row.username
        return [title, user].filter { !$0.isEmpty }.joined(separator: ", ")
    }
}

/// The bridge's dialog over the whole window, as SSH key use shows.
struct BrowserAskSheet: View {
    let window: MainWindowModel
    let ask: BrowserQuestion

    var body: some View {
        ZStack(alignment: .top) {
            Tok.scrim.contentShape(Rectangle()).accessibilityHidden(true)
            Group {
                if ask.kind == "connect" {
                    BrowserConnectDialog(window: window, ask: ask)
                } else {
                    BrowserAccessDialog(window: window, ask: ask)
                }
            }
            .id(ask.id)
            .padding(.top, 52)
        }
        .onExitCommand {
            if ask.kind == "connect" {
                window.answerBrowserConnect(nil)
            } else {
                window.answerBrowserAccess(allow: false, checked: [], remember: false)
            }
        }
    }
}
