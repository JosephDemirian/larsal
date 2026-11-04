import AppKit
import LarsalCore
import SwiftUI

/// The question of Larsal's SSH agent while it shows (INT-06.34): its words
/// from Rust, never a key or the data to sign (AGENTS rule 4).
struct SshAsk: Equatable {
    let question: SshQuestion
    /// When it showed: R06-6 counts from here.
    let shown: Date

    /// R06-6: the question comes up without any action in Larsal, often while
    /// the user types in a terminal, so a key press (Return or Space) chooses
    /// Allow Once only after it has shown for a second. A click, Escape and
    /// Deny act at once.
    func takes(allow: Bool, byKey: Bool, at now: Date) -> Bool {
        !(allow && byKey && now.timeIntervalSince(shown) < 1)
    }

    /// The button was chosen from the keyboard (Return, Space), not a click.
    static func byKey(_ event: NSEvent?) -> Bool { event?.type == .keyDown }
}

extension MainWindowModel {
    /// Reads Larsal's agent's question: a new one shows from now, an ended one
    /// (answered, 60 s without an answer, its vault locked) closes.
    func refreshSsh() {
        let question = session.sshQuestion()
        if question?.id != sshAsk?.question.id {
            sshAsk = question.map { SshAsk(question: $0, shown: Clock.now()) }
        }
    }

    /// The dialog's answer to Rust (INT-06.34); `true` is Allow Once. A key
    /// press on Allow Once within the first second does nothing (R06-6).
    func answerSsh(allow: Bool, byKey: Bool, at now: Date = Clock.now()) {
        guard let ask = sshAsk, ask.takes(allow: allow, byKey: byKey, at: now) else { return }
        session.answerSshQuestion(id: ask.question.id, allow: allow)
        sshAsk = nil
    }

    /// A button's answer from the event that chose it. A held Return or
    /// Space repeats its key press; the repeats choose nothing at any time,
    /// so a held key never allows a signature (LD-213 (3), R06-6's aim).
    /// `isARepeat` is read on key events only (AppKit raises otherwise).
    func answerSsh(allow: Bool, from event: NSEvent?, at now: Date = Clock.now()) {
        guard !(SshAsk.byKey(event) && event?.isARepeat == true) else { return }
        answerSsh(allow: allow, byKey: SshAsk.byKey(event), at: now)
    }
}

/// Frame `dialogs-ssh-key-use` (mockup.js `sshConfirm`): the graphite
/// terminal tile, MI06-29 and MI06-30 (or MI06-31), Deny and the primary
/// Allow Once. Escape is Deny.
struct SshKeyUseDialog: View {
    let window: MainWindowModel
    let ask: SshAsk

    var body: some View {
        DialogCard(tint: "graphite", glyph: "terminal-window", title: ask.question.heading, text: ask.question.text) {
            SheetButton(title: "Deny", cancel: true) {
                window.answerSsh(allow: false, from: NSApplication.shared.currentEvent)
            }
            SheetButton(title: "Allow Once", kind: .primary) {
                window.answerSsh(allow: true, from: NSApplication.shared.currentEvent)
            }
        }
    }
}

/// The question over the whole window, whatever it shows: the window dims
/// and the sheet drops below the top bar, as a vault's dialogs do.
struct SshKeyUseSheet: View {
    let window: MainWindowModel
    let ask: SshAsk

    var body: some View {
        ZStack(alignment: .top) {
            Tok.scrim.contentShape(Rectangle()).accessibilityHidden(true)
            SshKeyUseDialog(window: window, ask: ask).padding(.top, 52)
        }
        .onExitCommand { window.answerSsh(allow: false, byKey: true) }
    }
}
