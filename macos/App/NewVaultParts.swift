import AppCore
import AppKit
import SwiftUI

// The parts the new vault wizard shares with the vault settings (APP-07.20):
// the encryption rows, a mark row, the meter and the sheets' cards.

/// The encryption rows of the wizard's step 2 and the Security page
/// (APP-07.20): Cipher, Key derivation, Unlock time, Memory and, when
/// editable, Parallel threads; read only, the values as text.
struct EncryptionRows: View {
    let choice: EncryptionChoice
    let editable: Bool
    var kdfNote: String?
    var memoryNote: String?
    var timeLabel = "Unlock time"
    var timeNote: String?
    var showLanes = false
    let set: ((inout EncryptionChoice) -> Void) -> Void

    static let ciphers: [(CipherChoice, String)] = [
        (.aes256, "AES-256"), (.twofish256, "Twofish-256"), (.chaCha20, "ChaCha20"),
    ]
    static let kdfs: [(KdfChoice, String)] = [(.argon2id, "Argon2id"), (.argon2d, "Argon2d"), (.aesKdf, "AES-KDF")]

    var body: some View {
        let argon = choice.kdf != .aesKdf
        var rows: [AnyView] = [
            AnyView(
                SRow(title: "Cipher") {
                    ChoicePicker(
                        title: "Cipher", items: Self.ciphers, selected: choice.cipher, enabled: editable,
                        choose: { pick in set { $0.cipher = pick } })
                }),
            AnyView(
                SRow(title: "Key derivation", detail: kdfNote) {
                    ChoicePicker(
                        title: "Key derivation", items: Self.kdfs, selected: choice.kdf, enabled: editable,
                        choose: { pick in set { $0.kdf = pick } })
                }),
            AnyView(
                SRow(title: timeLabel, detail: timeNote) {
                    HStack(spacing: 8) {
                        if editable {
                            RangeSlider(
                                label: timeLabel, value: Int(choice.unlockMs / 100), range: 1...50
                            ) { tenths in set { $0.unlockMs = UInt32(tenths) * 100 } }
                            .padding(.horizontal, 2)
                            .frame(width: 160)
                        }
                        Text(verbatim: Formats.seconds(choice.unlockMs)).num()
                            .accessibilityLabel(Text(verbatim: timeLabel + ", " + Formats.seconds(choice.unlockMs)))
                            .frame(minWidth: 44, alignment: .trailing)
                    }
                }),
        ]
        if argon {
            rows.append(
                AnyView(
                    SRow(title: "Memory", detail: memoryNote) {
                        if editable {
                            StepBox(
                                value: "\(choice.memoryMib) MiB",
                                less: { set { $0.memoryMib = max(1, $0.memoryMib / 2) } },
                                more: { set { $0.memoryMib = min(1_048_576, $0.memoryMib * 2) } })
                        } else {
                            Text(verbatim: "\(choice.memoryMib) MiB").num()
                        }
                    }
                    .foregroundStyle(Tok.text)))
            if showLanes || editable {
                rows.append(
                    AnyView(
                        SRow(title: "Parallel threads") {
                            StepBox(
                                value: "\(choice.lanes)",
                                less: { set { $0.lanes = max(1, $0.lanes - 1) } },
                                more: { set { $0.lanes = min(128, $0.lanes + 1) } }
                            )
                            .disabled(!editable)
                        }))
            }
        }
        return RowBox(rows: rows)
    }
}

/// A `.selx` that opens its choices.
struct ChoicePicker<Item: Hashable>: View {
    let title: String
    let items: [(Item, String)]
    let selected: Item
    let enabled: Bool
    let choose: (Item) -> Void
    @State private var open = false

    var body: some View {
        let name = items.first { $0.0 == selected }?.1 ?? ""
        Button {
            open.toggle()
        } label: {
            SelectBox(title: name)
        }
        .buttonStyle(Bare())
        .disabled(!enabled)
        .accessibilityLabel(Text(verbatim: title))
        .accessibilityValue(Text(verbatim: name))
        .popover(isPresented: $open, arrowEdge: .bottom) {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(items, id: \.0) { item in
                    MenuItem(lead: .check(item.0 == selected), title: item.1) {
                        open = false
                        choose(item.0)
                    }
                }
            }
            .padding(6)
            .frame(minWidth: 180)
        }
    }
}

/// `.srow` with a 16-point mark 8 before its title (mockup `inline-flex
/// gap 8`); the second line starts under the mark.
struct MarkRow<Mark: View, Control: View>: View {
    let title: String
    var detail: String?
    var bad = false
    @ViewBuilder let mark: Mark
    @ViewBuilder let control: Control

    var body: some View {
        HStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 8) {
                    mark.frame(width: 16, height: 16)
                    Text(verbatim: title).frame(height: 20, alignment: .leading)
                }
                // CSS: the inline-flex title sits on a line box 2.5 taller.
                .padding(.bottom, 2.5)
                if let detail {
                    Text(verbatim: detail).font(.sans(12)).foregroundStyle(bad ? Tok.negative : Tok.muted)
                        .lineSpacing(1).padding(.vertical, 0.5)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityAddTraits(bad ? .updatesFrequently : [])
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: 8) { control }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(minHeight: 46)
        .accessibilityElement(children: .contain)
    }
}

/// A brand's logo as the mockup's `brandSvg(name, 16)`, named for VoiceOver.
struct BrandMark: View {
    let brand: String
    var size: CGFloat = 16

    var body: some View {
        Image("brand-" + brand, bundle: appBundle).resizable().frame(width: size, height: size)
            .accessibilityElement()
            .accessibilityLabel(Text(verbatim: Brands.titles[brand] ?? brand))
            .accessibilityAddTraits(.isImage)
    }
}

/// The strength bar under the password (FEA-05.7): its share of 128 bits.
struct Meter: View {
    let rating: Rating?

    var body: some View {
        Capsule()
            .fill(Tok.active)
            .frame(height: 3)
            .overlay(alignment: .leading) {
                GeometryReader { box in
                    Capsule()
                        .fill(color)
                        .frame(width: box.size.width * min(1, CGFloat(rating?.bits ?? 0) / 128))
                }
            }
            .clipShape(Capsule())
            .accessibilityHidden(true)
    }

    private var color: Color {
        guard let rating else { return Tok.positive }
        return rating.segments >= 3 ? Tok.positive : rating.segments == 2 ? Tok.warning : Tok.negative
    }
}

/// A question with Cancel as the default (mockup `weakMaster`'s look):
/// the yes on the left, Cancel the primary button on the right.
struct QuestionCard: View {
    let question: Question
    let cancel: () -> Void
    let yes: () -> Void

    var body: some View {
        DialogCard(
            tint: "orange", glyph: "warning", title: question.message,
            text: question.details.isEmpty ? nil : question.details
        ) {
            Button(question.confirm, action: yes).buttonStyle(Btn(size: .large))
                .frame(maxWidth: .infinity, alignment: .leading)
            Button("Cancel", action: cancel).buttonStyle(Btn(kind: .primary, size: .large))
                .keyboardShortcut(.defaultAction)
        }
    }
}

/// A refusal or failure with OK (the card's alerts).
struct NoticeCard: View {
    let text: String
    let done: () -> Void

    var body: some View {
        DialogCard(tint: "red", glyph: "warning-circle", title: text) {
            SheetButton(title: "OK", kind: .primary, action: done)
        }
    }
}

/// mockup `keyFile` (dialogs-create-key-file), APP-07.13's words for the
/// file name; the wizard's and the vault settings' (APP-07.20).
struct CreateKeyFileCard: View {
    let fileName: String
    let change: () -> Void
    let cancel: () -> Void
    let create: () -> Void

    var body: some View {
        DialogCard(
            tint: "blue", glyph: "file-lock", title: "Create a key file",
            text: "A key file is a second secret. Keep a copy somewhere safe: without it the vault does not open."
        ) {
            DialogBody {
                Lab(title: "Save as")
                InputBox {
                    Glyph(name: "file-lock").foregroundStyle(Tok.muted)
                    Text(verbatim: fileName).font(.mono(14)).lineLimit(1)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityLabel(Text(verbatim: "Save as, " + fileName))
                    Button("Change…", action: change).buttonStyle(Btn(size: .small))
                }
                Help(text: "Do not keep it next to the vault in the same synced folder.")
            }
        } foot: {
            SheetButton(title: "Cancel", cancel: true, action: cancel)
            SheetButton(title: "Create Key File", kind: .primary, action: create)
        }
    }
}

extension View {
    /// Return presses this button, unless a sheet over it has its own.
    @ViewBuilder func defaultAction(_ enabled: Bool) -> some View {
        if enabled { keyboardShortcut(.defaultAction) } else { self }
    }
}

extension Formats {
    /// The unlock time: "1.0 s" (mockup).
    static func seconds(_ millis: UInt32) -> String { String(format: "%.1f s", Double(millis) / 1000) }
}
