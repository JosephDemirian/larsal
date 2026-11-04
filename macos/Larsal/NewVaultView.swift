import AppKit
import LarsalCore
import SwiftUI

/// The new vault wizard window (mockup `wizard()`, 720 × 720): the top bar
/// with its title, the sheet with the step bar, the step and the buttons.
/// Behaviour from APP-07; the card's words where they differ.
struct NewVaultView: View {
    let model: NewVaultModel

    var body: some View {
        VStack(spacing: 0) {
            // `.wtop`: 52 tall; the window buttons sit on its left.
            Text(verbatim: "New Vault")
                .font(.sans(14, .semibold))
                .frame(maxWidth: .infinity)
                .frame(height: 52)
                .accessibilityAddTraits(.isHeader)
            VStack(spacing: 0) {
                StepBar(step: model.step)
                ScrollView(.vertical) {
                    Group {
                        switch model.step {
                        case .name: NameStep(model: model)
                        case .encryption: EncryptionStep(model: model)
                        case .password: PasswordStep(model: model).disabled(model.creating)
                        }
                    }
                    .padding(.horizontal, 28)
                    .padding(.vertical, 24)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .scrollIndicators(.never)
                .frame(maxHeight: .infinity)
                WizardFoot(model: model)
            }
            .background(Tok.surface, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Tok.border))
            .padding([.horizontal, .bottom], 8)
        }
        .font(.sans(14))
        .foregroundStyle(Tok.text)
        .background(Tok.ground)
        .overlay { WizardSheet(model: model) }
        .onExitCommand { if model.sheet == nil { model.cancel() } }
        .background(WindowChromeView())
    }
}

/// `.steps`: three bars, the done and current ones in the accent; M07-02's
/// step counter is read with it.
private struct StepBar: View {
    let step: NewVaultModel.Step

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            ForEach(NewVaultModel.Step.allCases, id: \.self) { item in
                VStack(alignment: .leading, spacing: 8) {
                    Capsule().fill(item.rawValue <= step.rawValue ? Tok.accent : Tok.active).frame(height: 4)
                    Text(verbatim: item.label)
                        .font(.sans(12, item == step ? .medium : .regular))
                        .foregroundStyle(item == step ? Tok.text : Tok.muted)
                        .frame(height: 20)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.horizontal, 28)
        .padding(.top, 21)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: "Step \(step.rawValue + 1) of 3, \(step.label)"))
    }
}

/// `.wbody h2` and the line under it.
private struct StepHead: View {
    let title: String
    let line: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(verbatim: title).font(.sans(20, .semibold)).frame(height: 26).accessibilityAddTraits(.isHeader)
            Text(verbatim: line).foregroundStyle(Tok.muted).lineBox(14, 20)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.bottom, 22)
    }
}

// MARK: Step 1

private struct NameStep: View {
    @Bindable var model: NewVaultModel
    @FocusState private var nameFocused: Bool
    @FocusState private var descriptionFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            StepHead(
                title: "Name your vault",
                line: "The name shows in the vault list. Name and description stay editable in Vault Settings.")
            VStack(alignment: .leading, spacing: 16) {
                VStack(alignment: .leading, spacing: 0) {
                    Lab(title: "Name")
                    InputBox(focused: nameFocused) {
                        PlainField(prompt: "", text: $model.name, label: "Name", focus: $nameFocused)
                            .onSubmit(model.primary)
                    }
                }
                VStack(alignment: .leading, spacing: 0) {
                    Lab(title: "Description", small: "· optional")
                    TextField(
                        "", text: $model.description, prompt: Text(verbatim: "Optional").foregroundStyle(Tok.muted),
                        axis: .vertical
                    )
                    .textFieldStyle(.plain)
                    .lineLimit(3...)
                    .focused($descriptionFocused)
                    .accessibilityLabel(Text(verbatim: "Description"))
                    .padding(.horizontal, 13)
                    .padding(.vertical, 11)
                    .frame(minHeight: 80, alignment: .topLeading)
                    .background(Tok.field, in: RoundedRectangle(cornerRadius: 8))
                    .overlay(
                        RoundedRectangle(cornerRadius: 8).strokeBorder(descriptionFocused ? Tok.accent : Tok.control)
                    )
                    // CSS: the inline textarea sits on a line box 5 taller.
                    .padding(.bottom, 5)
                }
                VStack(alignment: .leading, spacing: 0) {
                    Lab(title: "Save in")
                    InputBox {
                        Glyph(name: "folder-simple").foregroundStyle(Tok.muted)
                        Text(verbatim: model.folderText).lineLimit(1).truncationMode(.middle)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .accessibilityLabel(Text(verbatim: "Save in, " + model.folderText))
                        Button("Change…", action: model.changeFolder).buttonStyle(Btn(size: .small))
                    }
                    Help(text: model.fileName + ". A synced folder keeps it on your other Macs.")
                }
            }
        }
        .onAppear {
            nameFocused = true
            // APP-07.5: all selected, so typing replaces "Passwords".
            Task { NSApp?.sendAction(#selector(NSText.selectAll(_:)), to: nil, from: nil) }
        }
    }
}

// MARK: Step 2

private struct EncryptionStep: View {
    let model: NewVaultModel

    var body: some View {
        let custom = !model.recommended
        VStack(alignment: .leading, spacing: 0) {
            StepHead(
                title: "Encryption",
                line: "Choose how long an unlock takes. A longer unlock makes your password harder to guess. "
                    + "Vault Settings › Security can change it at any time."
            )
            VStack(spacing: 8) {
                Choice(
                    isOn: model.recommended, title: "Recommended",
                    note: "AES-256 with Argon2id. About 1 second to unlock on this Mac, and very slow to guess on "
                        + "other hardware."
                ) { model.choose(recommended: true) }
                Choice(
                    isOn: custom, title: "Custom", note: "Choose the cipher, memory and unlock time yourself."
                ) { model.choose(recommended: false) }
            }
            EncryptionRows(
                choice: model.choice, editable: custom, memoryNote: custom ? model.memoryNote : nil,
                set: model.setCustom
            )
            .opacity(custom ? 1 : 0.6)
            .padding(.top, 20)
            // M07-08 while measuring; its line is kept, so nothing moves.
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text(verbatim: "Measuring this Mac…").font(.sans(13)).foregroundStyle(Tok.muted)
            }
            .frame(height: 20)
            .padding(.top, 12)
            .opacity(model.measuring ? 1 : 0)
            .accessibilityHidden(!model.measuring)
        }
    }
}

// MARK: Step 3

private struct PasswordStep: View {
    let model: NewVaultModel
    @State private var passwordFocused = false
    @State private var repeatFocused = false

    var body: some View {
        let rating = model.rating
        VStack(alignment: .leading, spacing: 0) {
            StepHead(
                title: "Password and keys", line: "Choose what opens this vault. Only you should know it or have it.")
            VStack(alignment: .leading, spacing: 0) {
                Lab(title: "Password", small: rating.map { "· \($0.level), about \($0.bits) bits" })
                BigInput(focused: passwordFocused, bad: false) {
                    SecretField(
                        shown: model.shownPassword, dots: model.passwordLength, label: "Password",
                        turn: model.fieldTurn, focused: $passwordFocused, typed: model.passwordTyped)
                    IconButton(
                        glyph: model.shownPassword == nil ? "eye" : "eye-slash",
                        label: model.shownPassword == nil ? "Show password" : "Hide password",
                        action: model.toggleShow
                    )
                    .keyboardShortcut("h", modifiers: .control)
                    IconButton(glyph: "password", label: "Generate password", action: model.generate)
                        .keyboardShortcut("g", modifiers: .control)
                }
                .capsLockNote(focused: passwordFocused)  // APP-07.11: "Password" only
                Meter(rating: rating).padding(.top, 8)
            }
            VStack(alignment: .leading, spacing: 0) {
                Lab(title: "Verify password")
                BigInput(focused: repeatFocused, bad: model.mismatch) {
                    SecretField(
                        shown: model.shownRepeat, dots: model.repeatLength, label: "Verify password",
                        turn: model.fieldTurn, focused: $repeatFocused, typed: model.repeatTyped)
                    if model.match == true {
                        Glyph(name: "check-circle", size: 18, fill: true).foregroundStyle(Tok.positive)
                            .padding(.trailing, 6)
                            .accessibilityHidden(false)
                            .accessibilityLabel(Text(verbatim: "The passwords match"))
                    }
                }
            }
            // M07-20, a live region in the gap under the field: nothing moves.
            .overlay(alignment: .bottomLeading) {
                if model.mismatch {
                    Text(verbatim: "The two passwords are different.")
                        .font(.sans(12)).foregroundStyle(Tok.negative).frame(height: 16)
                        .offset(y: 18)
                        .accessibilityAddTraits(.updatesFrequently)
                }
            }
            .padding(.top, 16)
            VStack(alignment: .leading, spacing: 0) {
                (Text(verbatim: "More protection").font(.sans(13, .semibold))
                    + Text(verbatim: " · optional").font(.sans(12)).foregroundColor(Tok.muted))
                    .frame(height: 18)
                    .padding(.leading, 2)
                    .padding(.bottom, 8)
                RowBox(rows: [
                    AnyView(keyFileRow),
                    AnyView(WizardKeyRow(model: model)),
                    AnyView(
                        MarkRow(title: "Touch ID", detail: "Unlock with your finger after the first time.") {
                            Glyph(name: "fingerprint")
                        } control: {
                            Switch(label: "Touch ID", isOn: .constant(true)).later(Later.touchID)
                        }),
                ])
            }
            .padding(.top, 20)
        }
        .onAppear { passwordFocused = true }
        .onChange(of: model.focusRepeat) {
            if model.focusRepeat {
                repeatFocused = true
                model.focusRepeat = false
            }
        }
    }

    /// The key file part (M07-12): its words, or M07-27 (red) or M07-28
    /// (grey) in their place, a live region.
    private var keyFileRow: some View {
        let note =
            "Keep this file exactly as it is, and keep a copy somewhere safe: the vault opens only with this file, "
            + "unchanged."
        return MarkRow(
            title: model.keyFile.map { "Key file · " + $0.name } ?? "Key file",
            detail: model.keyFileProblem ?? model.keyFile?.note ?? note,
            bad: model.keyFileProblem != nil
        ) {
            Glyph(name: "file-lock")
        } control: {
            Button("New Key File…", action: model.askCreateKeyFile).buttonStyle(Btn(size: .small))
            Button("Choose Key File…", action: model.pickKeyFile).buttonStyle(Btn(size: .small))
            if model.keyFile != nil {
                Button("Remove", action: model.removeKeyFile).buttonStyle(Btn(size: .small))
            }
        }
    }
}

// MARK: The foot and the sheets

/// `.wfoot`: Cancel on the left, Back and the primary button on the right.
private struct WizardFoot: View {
    let model: NewVaultModel

    var body: some View {
        HStack(spacing: 8) {
            Button("Cancel", action: model.cancel).buttonStyle(Btn(size: .large))
                .disabled(model.creating)
            Spacer(minLength: 0)
            if model.creating {
                // M07-15 while the vault is written.
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    // M06-35 while the new key's challenge waits (APP-07.17).
                    Text(verbatim: KeyTouch.shared.waits ? KeyTouch.words : "Creating the vault…")
                        .font(.sans(13)).foregroundStyle(Tok.muted)
                }
                .accessibilityElement(children: .combine)
                .accessibilityAddTraits(.updatesFrequently)
            }
            if model.step != .name {
                Button("Back", action: model.back).buttonStyle(Btn(size: .large)).disabled(model.creating)
            }
            Button(model.step == .password ? "Create Vault" : "Continue", action: model.primary)
                .buttonStyle(Btn(kind: .primary, size: .large))
                .defaultAction(model.sheet == nil)
                .disabled(!model.canContinue)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
        .overlay(alignment: .top) { Rectangle().fill(Tok.rule).frame(height: 1) }
    }
}

/// The wizard's sheets (mockup `.scrim .dlg`): questions, notices and
/// "Create a key file".
private struct WizardSheet: View {
    let model: NewVaultModel

    var body: some View {
        if let sheet = model.sheet {
            ZStack(alignment: .top) {
                Tok.scrim.contentShape(Rectangle()).accessibilityHidden(true)
                Group {
                    switch sheet {
                    case .question(let question, let then):
                        QuestionCard(question: question) {
                            model.sheet = nil
                        } yes: {
                            model.answer(question, then: then)
                        }
                    case .notice(_, let text):
                        NoticeCard(text: text) { model.sheet = nil }
                    case .createKeyFile:
                        CreateKeyFileCard(
                            fileName: model.keyFilePath.lastPathComponent, change: model.changeKeyFilePath,
                            cancel: { model.sheet = nil }, create: model.createKeyFile)
                    }
                }
                .padding(.top, 52)
            }
            .onExitCommand { model.sheet = nil }
        }
    }
}

/// `.inp.lg`: 44 tall, radius 10, 15-point text; the accent ring with focus,
/// the negative one for M07-20 (`.inp.bad`).
private struct BigInput<Content: View>: View {
    let focused: Bool
    let bad: Bool
    @ViewBuilder let content: Content

    var body: some View {
        let edge = bad ? Tok.negative : focused ? Tok.accent : Tok.control
        HStack(spacing: 8) { content }
            .font(.sans(15))
            .padding(.leading, 13)
            .padding(.trailing, 7)
            .frame(height: 44)
            .background(Tok.field, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(edge))
            .background(
                RoundedRectangle(cornerRadius: 13).fill(bad ? Tok.negBg : focused ? Tok.accentSoft : .clear)
                    .padding(-3))
    }
}
