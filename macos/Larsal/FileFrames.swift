import LarsalCore
import SwiftUI

// The e22-s1 frames of the start of a file operation (FIL-02.1 to FIL-02.9).

struct FileEntryFrame: View {
    let flow: FileFlow

    var body: some View {
        DialogCard(
            tint: "cyan", glyph: "file-lock", title: "Encrypt or decrypt a file",
            text: "Keep a file private, wherever you take it."
        ) {
            DialogBody {
                VStack(spacing: 0) {
                    Glyph(name: "file-arrow-up")
                    Text(verbatim: "Drop one file here to encrypt it").font(.sans(16, .semibold)).lineBox(16, 22)
                        .padding(.top, 12).padding(.bottom, 8)
                    Text(verbatim: "Images and other files · no folders or links").font(.sans(12))
                        .foregroundStyle(Tok.muted).lineBox(12, 16).padding(.top, 6)
                    FileButton(title: "Choose File to Encrypt…", primary: true, focus: true, role: .main) {
                        flow.chooseSource(encrypt: true)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding(24)
                .background(Tok.surface, in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border, style: StrokeStyle(dash: [3, 3])))
                .dropDestination(for: URL.self) { urls, _ in
                    flow.dropped(urls)
                    return flow.notice == nil
                }
                .accessibilityElement(children: .contain)
                .accessibilityLabel(Text(verbatim: "Encrypt a File drop target"))
                FileButton(title: "Choose File to Decrypt…") { flow.chooseSource(encrypt: false) }.padding(.top, 16)
                FileNotice(flow: flow)
                FileNote(text: "Also in File ▸ Encrypt File… and Decrypt File…")
            }
        } foot: {
            FileButton(title: "Close", role: .cancel) { flow.cancel() }
        }
    }
}

struct FileEncryptFrame: View {
    @Bindable var flow: FileFlow

    var body: some View {
        DialogCard(
            tint: "cyan", glyph: "file-lock", title: "Encrypt File",
            text: "Make an encrypted copy. Your original file stays where it is.", wide: true
        ) {
            DialogBody {
                FileSourcePanel(flow: flow)
                Segments(items: ["Passphrase", "Recipients"], selected: 0) { index in
                    if index == 1 { flow.leaveEncrypt(to: .recipients) }
                }
                // A group with its own name; each segment keeps its own (FIL-02.15).
                .accessibilityElement(children: .contain)
                .accessibilityLabel(Text(verbatim: "Encryption mode"))
                if let reuse = flow.reuse {
                    // FIL-02.6: the saved entry, chosen and shown; never a new generation by itself.
                    FileField(
                        label: "Saved passphrase", value: reuse.title,
                        help: "Saved in your vault · used again for this file"
                    )
                    .padding(.top, 18)
                    FileButton(title: "Use a New Passphrase") { flow.newPassphrase() }.padding(.top, 12)
                } else {
                    FileField(
                        label: "Generated passphrase", value: flow.shown ?? "", secret: flow.shown == nil,
                        mono: flow.shown != nil, help: "10 random words · saved as a protected entry before encryption",
                        eye: (flow.shown != nil, { flow.toggleShow() })
                    )
                    .padding(.top, 18)
                }
                FileButton(title: "Choose My Own Passphrase…") { flow.leaveEncrypt(to: .manual) }.padding(.top, 12)
                Help(text: flow.placeLine)
                FileDestination(flow: flow)
                FileSpace(flow: flow)
                FileNotice(flow: flow)
                FileNote(text: fileLimits)
            }
        } foot: {
            FileButton(title: "Cancel", role: .cancel) { flow.cancel() }
            FileButton(title: "Encrypt File", primary: true, focus: true, role: .main) { flow.encrypt() }
        }
    }
}

struct FileManualFrame: View {
    @Bindable var flow: FileFlow

    var body: some View {
        let weak = flow.manualWeak
        DialogCard(
            tint: "orange", glyph: "key", title: "Use your own passphrase",
            text: "Choose a long, unique passphrase. Anyone with the encrypted file can test guesses.", wide: true
        ) {
            DialogBody {
                Grid(horizontalSpacing: 16, verticalSpacing: 16) {
                    GridRow {
                        FileSecret(label: "Passphrase") { flow.type(.passphrase, $0) }
                        FileSecret(label: "Repeat passphrase") { flow.type(.repeated, $0) }
                    }
                }
                if weak || !flow.saveManual {
                    FileWarn(
                        lines: (weak ? ["This passphrase may be easy to guess."] : [])
                            + ["Losing this passphrase means losing this file."])
                }
                CheckRow(
                    title: "Save as a protected entry in \(flow.vault?.name ?? "your vault")", isOn: $flow.saveManual
                )
                .disabled(flow.vault == nil)
                .padding(.top, 16)
                FileNotice(flow: flow)
            }
        } foot: {
            if weak {
                // FIL-01.7: Cancel is the default; Return never confirms a weak value.
                FileButton(title: "Cancel", focus: true, role: .main) { flow.cancel() }
                FileButton(title: "Use Anyway") { flow.useAnyway() }
            } else {
                FileButton(title: "Cancel", role: .cancel) { flow.cancel() }
                FileButton(title: "Encrypt File", primary: true, focus: true, role: .main) { flow.encrypt() }
                    .disabled(!flow.hasPassphrase || !flow.hasRepeat)
            }
        }
    }
}

struct FileRecipientsFrame: View {
    @Bindable var flow: FileFlow
    @State private var adding = false

    var body: some View {
        DialogCard(
            tint: "cyan", glyph: "users", title: "Encrypt for recipients",
            text: "Check each complete public key with its owner before sending the file.", wide: true
        ) {
            DialogBody {
                FileSourcePanel(flow: flow)
                ForEach(Array(flow.recipients.enumerated()), id: \.element) { index, key in
                    FileField(
                        label: "Recipient · \(index + 1)", value: key,
                        help: "Public key · review the full value, not only the label"
                    )
                    .padding(.bottom, 12)
                }
                if adding || flow.recipients.isEmpty {
                    VStack(alignment: .leading, spacing: 0) {
                        Lab(title: "New recipient")
                        InputBox {
                            PlainField(prompt: "age1…", text: $flow.recipientDraft, mono: true, label: "New recipient")
                                .onSubmit {
                                    flow.addRecipient()
                                    adding = flow.notice != nil
                                }
                        }
                    }
                    .padding(.bottom, 12)
                }
                HStack(spacing: 0) {
                    FileButton(title: "Add Recipient…") {
                        if adding, !flow.recipientDraft.isEmpty { flow.addRecipient() }
                        adding = flow.notice != nil || !adding
                    }
                    Menu("Add My File Key…") {
                        ForEach(flow.myFileKeys(), id: \.entry) { mine in
                            Button(mine.title) { flow.addMine(mine) }
                        }
                        Divider()
                        Button("Create File Key…") { flow.screen = .key }
                    }
                    .menuStyle(.button)
                    .buttonStyle(Btn(size: .large))
                    .fixedSize()
                }
                CheckRow(title: "I checked this key with its owner.", isOn: $flow.checkedWithOwner).padding(.top, 16)
                CheckRow(title: "I understand I may not be able to decrypt this file.", isOn: $flow.mayNotDecrypt)
                    .padding(.top, 10)
                FileNotice(flow: flow)
                FileNote(
                    text:
                        "These public keys do not protect against a future quantum computer. "
                        + "This does not prove who sent the file."
                )
            }
        } foot: {
            FileButton(title: "Cancel", role: .cancel) { flow.cancel() }
            FileButton(title: "Encrypt File", primary: true, focus: true, role: .main) { flow.encrypt() }
                .disabled(!flow.recipientsReady)
        }
    }
}

struct FileKeyFrame: View {
    @Bindable var flow: FileFlow

    var body: some View {
        DialogCard(
            tint: "teal", glyph: "key", title: "Create a file key",
            text: "Keep the private key protected in your vault. Give only the public key to other people.", wide: true
        ) {
            DialogBody {
                VStack(alignment: .leading, spacing: 0) {
                    Lab(title: "Entry title")
                    InputBox { PlainField(prompt: "My file key", text: $flow.keyTitle, label: "Entry title") }
                }
                FileField(label: "Save in", value: flow.vault?.name ?? "").padding(.top, 16)
                FileNotice(flow: flow)
                FileNote(
                    text:
                        "The public recipient will be available after your vault saves. "
                        + "The private key is saved as a protected field in your vault."
                )
            }
        } foot: {
            FileButton(title: "Cancel", role: .cancel) { flow.screen = .recipients }
            FileButton(title: "Create File Key", primary: true, focus: true, role: .main) {
                Task { await flow.createKey() }
            }
            .disabled(flow.keyTitle.isEmpty || flow.vault == nil)
        }
    }
}
