import AppKit
import LarsalCore
import SwiftUI

/// Encrypt File and Decrypt File (FIL-02): the e22-s1 frames of
/// design/option-a/proposals.html, one `DialogCard` each, over the window's
/// scrim as the other window questions.
struct FileSheet: View {
    let flow: FileFlow

    var body: some View {
        ZStack(alignment: .top) {
            Tok.scrim.contentShape(Rectangle()).accessibilityHidden(true)
            FileDialog(flow: flow).padding(.top, 52)
        }
        .onExitCommand { flow.cancel() }
    }
}

/// The frame of the flow's screen.
struct FileDialog: View {
    let flow: FileFlow
    /// FIL-02.16: Reduce Motion leaves the same static bar and text.
    var reduceMotion = false

    var body: some View {
        switch flow.screen {
        case .entry: FileEntryFrame(flow: flow)
        case .encrypt: FileEncryptFrame(flow: flow)
        case .manual: FileManualFrame(flow: flow)
        case .recipients: FileRecipientsFrame(flow: flow)
        case .key: FileKeyFrame(flow: flow)
        case .decrypt: FileDecryptFrame(flow: flow)
        case .progress: FileProgressFrame(flow: flow)
        case .complete: FileCompleteFrame(flow: flow)
        case .error: FileErrorFrame(flow: flow)
        case .collision: FileCollisionFrame(flow: flow)
        case .cleanup: FileCleanupFrame(flow: flow)
        case .locked: FileLockedFrame(flow: flow)
        case .weakFile: FileWeakFrame(flow: flow)
        case .unprotectedFile: FileUnprotectedFrame(flow: flow)
        }
    }
}

// MARK: Parts (the frame's e22Field, e22Note, e22File, e22Destination, e22Button)

/// `e22Button`: a `btn lg`, with the frame's focus ring on the one that
/// has the focus first.
struct FileButton: View {
    let title: String
    var primary = false
    var focus = false
    var role: Role = .none
    let action: () -> Void

    enum Role { case none, cancel, main }

    var body: some View {
        let button = Button(title, action: action)
            .buttonStyle(Btn(kind: primary ? .primary : .plain, size: .large))
            .overlay {
                if focus {
                    RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.accent, lineWidth: 2).padding(-4)
                        .accessibilityHidden(true)
                }
            }
        switch role {
        case .cancel: button.keyboardShortcut(.cancelAction)
        case .main: button.keyboardShortcut(.defaultAction)
        case .none: button
        }
    }
}

/// `e22Field`: a label, a read-only box, and its help.
struct FileField: View {
    let label: String
    let value: String
    var secret = false
    var mono = false
    var help: String?
    var eye: (shown: Bool, toggle: () -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Lab(title: label)
            InputBox {
                if eye != nil, !secret {
                    // A secret shown in clear: the no-copy field (APP-03.19, S2-01).
                    NoCopyValue(text: value, label: label).frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    Text(verbatim: secret ? String(repeating: "•", count: max(value.count, 9)) : value)
                        .font(mono ? .mono(14) : .sans(14))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityLabel(Text(verbatim: label))
                        .accessibilityValue(Text(verbatim: secret ? "hidden" : value))
                }
                if let eye {
                    IconButton(
                        glyph: eye.shown ? "eye-slash" : "eye", label: eye.shown ? "Hide passphrase" : "Show passphrase"
                    ) {
                        eye.toggle()
                    }
                }
            }
            if let help { Help(text: help) }
        }
    }
}

/// A typed secret: AppKit's secure field (secure input while focused). Each
/// change goes to `typed`, which sends it to Rust; Swift keeps no copy (S2-04).
struct FileSecret: View {
    let label: String
    var help: String?
    let typed: (String) -> Void
    @State private var focused = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Lab(title: label)
            InputBox(focused: focused) {
                SecretField(shown: nil, label: label, turn: 0, focused: $focused, typed: typed)
            }
            if let help { Help(text: help) }
        }
    }
}

/// `e22Note`: 16 above, help type.
struct FileNote: View {
    let text: String

    var body: some View {
        Text(verbatim: text).font(.sans(12)).foregroundStyle(Tok.muted).lineBox(12, 16)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 16)
    }
}

/// `e22File`: the source, its size, and that the original stays.
struct FileSourcePanel: View {
    let flow: FileFlow

    var body: some View {
        HStack(spacing: 12) {
            Tile(color: Tok.tileColor("cyan"), glyph: "file-image", size: 32)
            VStack(alignment: .leading, spacing: 0) {
                Text(verbatim: flow.sourceLabel).font(.sans(14, .semibold))
                Text(verbatim: "\(flow.sizeLabel) · original stays where it is").font(.sans(12))
                    .foregroundStyle(Tok.muted).num().lineBox(12, 16)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
        .padding(.bottom, 18)
        .accessibilityElement(children: .combine)
    }
}

/// `e22Destination`: Save as, its folder, Choose Destination….
struct FileDestination: View {
    let flow: FileFlow

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            FileField(
                label: "Save as", value: flow.name,
                help: "\(flow.folder?.lastPathComponent ?? "") · use a new file name")
            FileButton(title: "Choose Destination…") { flow.chooseDestination() }.padding(.top, 12)
        }
    }
}

/// The inline words of a refusal (busy, input, an invalid key).
struct FileNotice: View {
    let flow: FileFlow

    var body: some View {
        if let notice = flow.notice {
            HStack(alignment: .top, spacing: 10) {
                Glyph(name: "warning-circle")
                Text(verbatim: notice).fixedSize(horizontal: false, vertical: true)
            }
            .font(.sans(13))
            .foregroundStyle(Tok.negInk)
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Tok.negBg, in: RoundedRectangle(cornerRadius: 10))
            .padding(.top, 16)
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.updatesFrequently)
        }
    }
}

/// `.notice.warn`.
struct FileWarn: View {
    let lines: [String]

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Glyph(name: "warning").padding(.top, 1)
            VStack(alignment: .leading, spacing: 0) {
                ForEach(lines, id: \.self) { Text(verbatim: $0) }
            }
            .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .font(.sans(13))
        .lineSpacing(2)
        .foregroundStyle(Tok.warnInk)
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(Tok.warnBg, in: RoundedRectangle(cornerRadius: 10))
        .padding(.top, 18)
        .accessibilityElement(children: .combine)
    }
}

/// MSG-FILE-LIMITS.
let fileLimits =
    "No server is contacted. Anyone with this encrypted file can test passphrase guesses. "
    + "Names, sizes and dates may still be visible."
/// FIL-02.11: what a readable file is, after it is saved.
let readableSaved = "The saved file is not encrypted. It stays on disk after Larsal locks. No other app was opened."
/// FIL-02.22 for recipients: no passphrase to guess, and no proof of sender.
let recipientLimits =
    "No server is contacted. Names, sizes and dates may still be visible. This does not prove who sent the file."

/// A secret shown read-only in clear: Larsal's no-copy field, neither editable
/// nor selectable, so no copy, cut, drag or Services request takes it out
/// (APP-03.19, FIL-02.3, S2-01).
struct NoCopyValue: NSViewRepresentable {
    let text: String
    let label: String

    func makeNSView(context: Context) -> NoCopyTextField {
        let field = NoCopyTextField()
        field.isEditable = false
        field.isSelectable = false
        field.isBordered = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.usesSingleLineMode = true
        field.cell?.lineBreakMode = .byTruncatingMiddle
        field.font =
            NSFont(name: "IBMPlexMono-Regular", size: 14) ?? .monospacedSystemFont(ofSize: 14, weight: .regular)
        field.setAccessibilityLabel(label)
        field.stringValue = text
        return field
    }

    func updateNSView(_ field: NoCopyTextField, context: Context) {
        if field.stringValue != text { field.stringValue = text }
    }
}

/// FIL-03.12's advisory estimate, in MSG-FILE-SPACE's words; nothing is refused.
struct FileSpace: View {
    let flow: FileFlow

    var body: some View {
        if flow.spaceShort { FileWarn(lines: [spaceWords]) }
    }
}

/// MSG-FILE-SPACE.
let spaceWords = "There is not enough free space. Free some space or choose another disk."
