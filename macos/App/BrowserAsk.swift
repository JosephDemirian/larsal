import AppCore
import AppKit
import SwiftUI

/// The bridge's dialogs (INT-02.15): the Connect dialog (INT-02.4) and the
/// site access prompt (INT-02.18). Rust holds the line and every word;
/// titles and user names are plain text (AT-E01), never a password.
extension MainWindowModel {
    /// Reads the questions of App's SSH agent and of the bridge.
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
/// MI02-01's four words, Deny and the primary Connect, disabled while the
/// name is not valid; a taken name shows MI02-02 under the field.
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
        DialogCard(tint: "blue", glyph: "globe", title: ask.title, text: ask.text) {
            VStack(alignment: .leading, spacing: 6) {
                Text(verbatim: "Name").font(.sans(13, .medium))
                InputBox { PlainField(prompt: "", text: $name, label: "Name") }
                if let problem, !problem.isEmpty {
                    Text(verbatim: problem).font(.sans(12)).foregroundStyle(Tok.negative)
                }
                Text(verbatim: ask.words)
                    .font(.sans(13))
                    .foregroundStyle(Tok.muted)
                    .padding(.top, 8)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.top, 16)
        } foot: {
            SheetButton(title: "Deny", cancel: true) { window.answerBrowserConnect(nil) }
            SheetButton(title: "Connect", kind: .primary) { window.answerBrowserConnect(name) }
                .disabled(problem != nil)
        }
    }
}

/// Frame `dialogs-browser-asks-for-an-entry`: the line of INT-02.19, one
/// checked row per entry, "Remember for ‹P›" (hidden for HTTP sign-in and
/// INT-02.19), Deny and the primary Allow Selected, disabled while no row
/// is checked. Escape is Deny.
struct BrowserAccessDialog: View {
    let window: MainWindowModel
    let ask: BrowserQuestion
    @State private var checked: [Bool]
    @State private var remember = false

    init(window: MainWindowModel, ask: BrowserQuestion) {
        self.window = window
        self.ask = ask
        _checked = State(initialValue: Array(repeating: true, count: ask.rows.count))
    }

    var body: some View {
        DialogCard(tint: "blue", glyph: "globe", title: ask.title, text: ask.text) {
            VStack(alignment: .leading, spacing: 8) {
                if let line = ask.line {
                    Text(verbatim: line)
                        .font(.sans(13))
                        .foregroundStyle(Tok.warning)
                        .fixedSize(horizontal: false, vertical: true)
                }
                ForEach(Array(ask.rows.enumerated()), id: \.offset) { index, row in
                    CheckRow(title: row.title, detail: row.username.isEmpty ? nil : row.username, isOn: $checked[index])
                }
                if let label = ask.remember {
                    CheckRow(title: label, isOn: $remember).padding(.top, 6)
                }
            }
            .padding(.top, 16)
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
