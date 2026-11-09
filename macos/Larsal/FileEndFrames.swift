import LarsalCore
import SwiftUI

// The e22-s1 frames of decrypting, the work and its ends (FIL-02.10 to FIL-02.14).

struct FileDecryptFrame: View {
    @Bindable var flow: FileFlow

    var body: some View {
        DialogCard(
            tint: "cyan", glyph: "lock-open", title: "Decrypt File",
            text: "Save a readable file from Larsal or another compatible tool.", wide: true
        ) {
            DialogBody {
                VStack(alignment: .leading, spacing: 0) {
                    Text(verbatim: flow.sourceLabel).font(.sans(14, .semibold))
                    Text(verbatim: "Native password and X25519 files · binary or armored").font(.sans(12))
                        .foregroundStyle(Tok.muted).lineBox(12, 16)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 14)
                .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
                .padding(.bottom, 18)
                Segments(items: ["Passphrase", "File Key"], selected: flow.credential == .passphrase ? 0 : 1) {
                    flow.credential = $0 == 0 ? .passphrase : .fileKey
                }
                .accessibilityElement(children: .contain)
                .accessibilityLabel(Text(verbatim: "Credential mode"))
                if let entry = flow.entry {
                    FileField(label: "From your vault", value: entry.title).padding(.top, 16)
                } else {
                    FileSecret(
                        label: flow.credential == .passphrase ? "Passphrase" : "Key file passphrase",
                        help: flow.credential == .fileKey ? flow.keyFile?.lastPathComponent : nil
                    ) { flow.type(.decrypt, $0) }
                    .padding(.top, 16)
                }
                HStack(spacing: 0) {
                    Menu("Choose from Vault…") {
                        ForEach(flow.choices(), id: \.entry) { choice in
                            Button(choice.title) { flow.choose(choice) }
                        }
                    }
                    .menuStyle(.button)
                    .buttonStyle(Btn(size: .large))
                    .fixedSize()
                    .disabled(flow.vault == nil)
                    FileButton(title: "Choose Key File…") { flow.chooseKeyFile() }
                }
                .padding(.top, 12)
                .padding(.bottom, 16)
                FileDestination(flow: flow)
                FileSpace(flow: flow)
                FileNotice(flow: flow)
                FileNote(
                    text:
                        "The saved file is not encrypted. Keep it somewhere private. "
                        + "This does not prove who sent the file."
                )
            }
        } foot: {
            FileButton(title: "Cancel", role: .cancel) { flow.cancel() }
            FileButton(title: "Save Readable File", primary: true, focus: true, role: .main) { flow.decrypt() }
        }
    }
}

struct FileProgressFrame: View {
    let flow: FileFlow

    var body: some View {
        let step = flow.progress?.step ?? .preparing
        let decrypting = [.preparing, .checking, .saving].contains(step)
        DialogCard(
            tint: "cyan", glyph: "shield-check", title: flow.revoked ? "Stopping" : flow.stepTitle,
            text: decrypting
                ? "Nothing readable is saved until the first whole-file check finishes."
                : "Your original file stays where it is.",
            wide: true
        ) {
            DialogBody {
                GeometryReader { box in
                    ZStack(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 8).fill(Tok.border)
                        RoundedRectangle(cornerRadius: 8).fill(Tok.accent)
                            .frame(width: box.size.width * (flow.fraction ?? 0))
                    }
                }
                .frame(height: 8)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .accessibilityElement()
                .accessibilityLabel(Text(verbatim: flow.stepTitle))
                .accessibilityValue(Text(verbatim: flow.fraction.map { "\(Int($0 * 100)) percent" } ?? flow.countLine))
                Help(text: flow.countLine).num()
                    .accessibilityAddTraits(.updatesFrequently)
                VStack(alignment: .leading, spacing: 0) {
                    let steps: [FileStep] =
                        decrypting ? [.preparing, .checking, .saving] : [.savingPassphrase, .encrypting]
                    let current = steps.firstIndex(of: step) ?? 0
                    ForEach(Array(steps.enumerated()), id: \.offset) { index, each in
                        let words = FileFlow.title(of: each)
                        if index < current {
                            Text(verbatim: "✓ " + words).padding(.bottom, 8)
                        } else if index == current {
                            Text(verbatim: words).font(.sans(14, .semibold))
                        } else if index == current + 1 {
                            Help(text: "Next: " + words).padding(.top, 2)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 14)
                .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
                .padding(.top, 18)
                FileNote(
                    text:
                        "Cancel stops this operation. "
                        + "A passphrase check already running may need to finish before cleanup."
                )
            }
        } foot: {
            FileButton(title: "Cancel", focus: true, role: .cancel) { flow.cancel() }.disabled(flow.revoked)
        }
    }
}

struct FileCompleteFrame: View {
    let flow: FileFlow

    var body: some View {
        let readable = flow.readable
        DialogCard(
            tint: "teal", glyph: "check-circle", title: readable ? "Readable file saved" : "Encrypted file saved",
            text: readable ? "Your encrypted source is unchanged." : "Your original file stays where it is.",
            wide: true
        ) {
            DialogBody {
                FileField(label: "Saved to", value: flow.savedTo)
                FileNote(
                    text: readable
                        ? readableSaved
                        : (flow.mode == .recipients ? recipientLimits : fileLimits) + " No other app was opened.")
            }
        } foot: {
            FileButton(title: "Done", primary: true, focus: true, role: .main) { flow.close() }
        }
    }
}

struct FileErrorFrame: View {
    let flow: FileFlow

    var body: some View {
        let decrypt = flow.readable
        DialogCard(
            tint: "orange", glyph: "warning-circle", title: flow.failureTitle, text: flow.failureBody, wide: true
        ) {
            DialogBody {
                if flow.savedKey {
                    FileNote(text: "The passphrase is saved in your vault. No encrypted file was completed.")
                }
                FileNote(
                    text: decrypt
                        ? "No readable file was saved. Supported modes: native password and X25519; binary or armored."
                        : "No encrypted file was saved.")
            }
        } foot: {
            FileButton(title: "Cancel", focus: true, role: .cancel) { flow.close() }
            FileButton(title: "Try Again", primary: true) { flow.screen = decrypt ? .decrypt : .encrypt }
        }
    }
}

struct FileCollisionFrame: View {
    let flow: FileFlow

    var body: some View {
        DialogCard(
            tint: "orange", glyph: "files", title: "Choose a different name",
            text: "A file already exists with this name. Choose a different name.", wide: true
        ) {
            DialogBody {
                FileField(label: "Existing name", value: flow.name)
                if flow.savedKey {
                    FileNote(text: "The passphrase is saved in your vault. No encrypted file was completed.")
                }
                FileNote(text: "The existing file has not been changed. Your source is unchanged.")
            }
        } foot: {
            FileButton(title: "Cancel", focus: true, role: .cancel) { flow.close() }
            FileButton(title: "Choose Another Name…", primary: true) { flow.chooseAnotherName() }
        }
    }
}

struct FileCleanupFrame: View {
    let flow: FileFlow

    var body: some View {
        DialogCard(
            tint: "orange", glyph: "warning", title: "Check the destination",
            text: flow.failureTitle.isEmpty
                ? "Larsal could not remove an incomplete file. It may contain readable data. "
                    + "Check the destination before you leave."
                : flow.failureText,
            wide: true
        ) {
            DialogBody {
                FileField(label: "Chosen destination", value: flow.destinationLabel)
                FileNote(
                    text:
                        "The source is unchanged. "
                        + "Saved copies and disk backups cannot be recalled or securely erased by Larsal."
                )
            }
        } foot: {
            FileButton(title: "Done", primary: true, focus: true, role: .main) { flow.close() }
        }
    }
}

struct FileLockedFrame: View {
    let flow: FileFlow

    var body: some View {
        DialogCard(
            tint: "teal", glyph: "lock", title: "Unlock to save a passphrase",
            text: "The default encrypts with a new passphrase and saves it as a protected entry first.", wide: true
        ) {
            DialogBody {
                FileNote(
                    text:
                        "Unlock a writable vault, or explicitly choose your own passphrase or public recipients. "
                        + "No file has been written."
                )
            }
        } foot: {
            FileButton(title: "Cancel", focus: true, role: .cancel) { flow.cancel() }
            FileButton(title: "Unlock Vault…", primary: true) { flow.cancel() }
        }
    }
}

struct FileWeakFrame: View {
    let flow: FileFlow

    var body: some View {
        DialogCard(
            tint: "orange", glyph: "warning", title: "This file uses a low passphrase work factor",
            text: "Only save its contents if you trust the file.", wide: true
        ) {
            DialogBody {
                FileNote(text: "The saved file is not encrypted. Keep it somewhere private.")
            }
        } foot: {
            // MSG-FILE-WEAK: Cancel is the default.
            FileButton(title: "Cancel", focus: true, role: .main) { flow.answerWeak(save: false) }
            FileButton(title: "Save Readable File") { flow.answerWeak(save: true) }
        }
    }
}

/// MSG-FILE-UNPROTECTED's warned consent (E22-S4, C1-06): the chosen disk cannot
/// keep the readable file private; nothing is written until Save Readable File.
/// Words proposed for FIL-03; frame `e22-s1-unprotected` (DRAFT).
struct FileUnprotectedFrame: View {
    let flow: FileFlow

    var body: some View {
        DialogCard(
            tint: "orange", glyph: "warning", title: "This disk cannot keep a decrypted file private",
            text: "Anyone who can use this disk may be able to read the saved file.", wide: true
        ) {
            DialogBody {
                FileNote(text: "The saved file is not encrypted. Choose another folder unless you trust this disk.")
            }
        } foot: {
            // Cancel is the default; Return never confirms the warning.
            FileButton(title: "Cancel", focus: true, role: .main) { flow.answerWeak(save: false) }
            FileButton(title: "Save Readable File") { flow.answerWeak(save: true) }
        }
    }
}
