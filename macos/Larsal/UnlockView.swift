import AppKit
import LarsalCore
import SwiftUI

/// The unlock screen (APP-06, E5-S3; mockup `lockedWindow`): the vault
/// switcher, then the sheet with the vault tile, the form and the footer.
/// Touch ID (E6-S3) is drawn and disabled; security keys: UnlockKeys.swift.
struct UnlockView: View {
    @Bindable var model: UnlockModel
    /// The main window; `nil` in the unlock panel (APP-06.27), which has no
    /// switcher and no footer.
    var window: MainWindowModel?
    /// APP-06.27: the panel's purpose line (M06-40) and its Cancel.
    var purpose: String?
    var cancel: (() -> Void)?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @FocusState private var focus: Field?
    /// The shown password field (after Show) has focus; an AppKit field
    /// reports it itself.
    @State private var shownFocus = false

    enum Field { case password, keyFile, touch }

    var body: some View {
        ZStack(alignment: .topLeading) {
            VStack(spacing: 0) {
                if window != nil { switcher }
                VStack(spacing: 0) {
                    card
                        .frame(width: 380)
                        .modifier(Shake(count: CGFloat(model.shakes)))
                        .animation(reduceMotion ? nil : .linear(duration: 0.35), value: model.shakes)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                    if let window { LockFoot(model: model, window: window) } else { Color.clear.frame(height: 23) }
                }
                .padding(.horizontal, 25)
                .padding(.top, 23)
                .background(Tok.surface, in: RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Tok.border))
                .padding([.horizontal, .bottom], 8)
            }
            if let window, window.vaultMenu {
                MenuLayer(
                    close: { window.vaultMenu = false },
                    menu: {
                        VaultMenu(window: window).padding(.leading, 140).padding(.top, 48)
                    })
            }
        }
        .background(Tok.ground)
        .foregroundStyle(Tok.text)
        .onAppear {
            if model.touchForm { focus = .touch } else { focusPassword() }
        }
        .onChange(of: model.message) { _, found in
            // APP-06.17: key file problems take the focus to UL-KEY.
            if let found, !model.working {
                if found.aboutKeyFile { focus = .keyFile } else { focusPassword() }
            }
        }
        .alert(
            model.question?.message ?? "",
            isPresented: Binding(get: { model.question != nil }, set: { if !$0 { model.question = nil } }),
            presenting: model.question
        ) { _ in
            Button("Unlock") { model.answer(unlock: true) }
            Button("Cancel", role: .cancel) { model.answer(unlock: false) }
        } message: { question in
            Text(verbatim: question.details)
        }
    }

    /// UL-SWITCH: the ghost button 96 points right of the window buttons.
    private var switcher: some View {
        HStack(spacing: 0) {
            Button {
                window?.vaultMenu.toggle()
            } label: {
                HStack(spacing: 6) {
                    Tile(color: model.vault.tileColor, glyph: model.vault.tileGlyph)
                    Text(verbatim: model.vault.name).font(.sans(14, .semibold))
                    Glyph(name: "caret-up-down")
                }
            }
            .buttonStyle(Btn(kind: .ghost))
            .accessibilityLabel(Text(verbatim: "Switch vault"))
            .accessibilityValue(Text(verbatim: model.vault.name))
            Spacer()
        }
        .padding(.leading, 182)
        .frame(height: 52)
    }

    private var card: some View {
        VStack(spacing: 0) {
            if let purpose {
                Text(verbatim: purpose).font(.sans(13)).foregroundStyle(Tok.muted).padding(.bottom, 16)
            }
            Tile(color: model.vault.tileColor, glyph: model.vault.tileGlyph, size: 64)
            Text(verbatim: "Unlock \(model.vault.name)")
                .font(.sans(22, .semibold))
                .frame(height: 28)
                .padding(.top, 18)
                .accessibilityAddTraits(.isHeader)
            Text(verbatim: model.vault.path)
                .font(.sans(13))
                .foregroundStyle(Tok.muted)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(height: 20)
                .padding(.top, 4)
            if model.touchForm { touchForm } else { passwordForm }
        }
        .disabled(model.working)
    }

    /// UL-TOUCH (APP-04.9): drawn now; quick unlock comes with E6-S3.
    private var touchForm: some View {
        VStack(spacing: 0) {
            Button {
            } label: {
                Glyph(name: "fingerprint", size: 40)
                    .foregroundStyle(Tok.pink)
                    .frame(width: 76, height: 76)
                    .background(Tok.raised, in: Circle())
                    .overlay(Circle().strokeBorder(Tok.border))
            }
            .buttonStyle(Bare())
            .focused($focus, equals: .touch)
            .accessibilityLabel(Text(verbatim: "Unlock with Touch ID"))
            .later(Later.touchID)
            .padding(.top, 28)
            Text(verbatim: "Touch ID or enter your Mac password to unlock")
                .font(.sans(14))
                .foregroundStyle(Tok.muted)
                .frame(height: 20)
                .padding(.top, 14)
            Button {
                model.touchForm = false
                focusPassword()
            } label: {
                BtnLabel(glyph: "key", title: "Use password instead")
            }
            .buttonStyle(Btn(size: .huge, wide: true))
            .padding(.top, 28)
        }
        .onExitCommand {
            model.touchForm = false
            focusPassword()
        }
    }

    private var passwordForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 0) {
                Text(verbatim: "Password").font(.sans(13, .medium)).frame(height: 18).padding(.bottom, 6)
                // M06-37 (APP-06.6), never over UL-ERR.
                passwordField.capsLockNote(focused: passwordFocused, error: model.message != nil)
                errorLine
                if model.touchWaits && model.working {
                    // M06-35 (APP-06.15): grey, in UL-ERR's place.
                    Text(verbatim: "Waiting for a touch on the security key…")
                        .font(.sans(13)).foregroundStyle(Tok.muted).padding(.top, 8)
                        .accessibilityAddTraits(.updatesFrequently)
                }
                if model.downloading {
                    // MSG-DISK-DOWNLOADING (APP-05.30): grey, under the form.
                    Text(verbatim: "Still downloading. “\(model.fileName)” opens when the download ends.")
                        .font(.sans(13)).foregroundStyle(Tok.muted).padding(.top, 8)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityAddTraits(.updatesFrequently)
                }
            }
            UnlockExtra(model: model, focus: $focus)
            unlockRow
            HStack(spacing: 20) {
                Button {
                } label: {
                    HStack(spacing: 6) {
                        Glyph(name: "fingerprint")
                        Text(verbatim: "Use Touch ID")
                    }
                    .font(.sans(13))
                    .foregroundStyle(Tok.muted)
                    .frame(height: 20)
                }
                .buttonStyle(Bare())
                .later(Later.touchID)
            }
            .frame(maxWidth: .infinity)
            .padding(.top, 4)
        }
        .padding(.top, 24)
    }

    /// UL-PW: a secure field (APP-06.5, APP-10.9).
    private var passwordField: some View {
        let bad = model.message != nil && !(model.message?.aboutKeyFile ?? false)
        let lit = passwordFocused
        return HStack(spacing: 8) {
            Glyph(name: "key").foregroundStyle(Tok.muted)
            if model.reveal {
                // APP-03.19: shown in clear, still no Copy or Cut.
                ShownPasswordField(text: $model.password, focused: $shownFocus) { model.unlock() }
            } else {
                SecureField("", text: $model.password, prompt: prompt)
                    .textFieldStyle(.plain)
                    .font(.sans(15))
                    .autocorrectionDisabled()
                    .focused($focus, equals: .password)
                    .onSubmit { model.unlock() }
                    .accessibilityLabel(Text(verbatim: "Password"))
            }
            IconButton(
                glyph: model.reveal ? "eye-slash" : "eye", label: model.reveal ? "Hide password" : "Show password"
            ) {
                let had = passwordFocused
                model.reveal.toggle()
                if had { focusPassword() }
            }
            // APP-08.14: ⌃H shows or hides the text.
            .keyboardShortcut("h", modifiers: .control)
        }
        .padding(.leading, 12)
        .padding(.trailing, 6)
        .frame(height: 44)
        .background(Tok.field, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(bad ? Tok.negative : lit ? Tok.accent : Tok.control))
        .background(
            RoundedRectangle(cornerRadius: 13).fill(bad ? Tok.negBg : lit ? Tok.accentSoft : .clear).padding(-3)
        )
    }

    private var prompt: Text { Text(verbatim: "Password").foregroundStyle(Tok.muted) }

    /// The password field has focus: the secure field, or the shown one.
    private var passwordFocused: Bool { model.reveal ? shownFocus : focus == .password }

    /// Focus to the password, in whichever field shows it.
    private func focusPassword() {
        focus = model.reveal ? nil : .password
        shownFocus = model.reveal
    }

    /// UL-ERR (APP-06.17 to APP-06.20), a live region.
    @ViewBuilder
    private var errorLine: some View {
        if let found = model.message {
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .top, spacing: 6) {
                    Glyph(name: "warning-circle").padding(.top, 1)
                    // UL-ERR is a live region (APP-06.29); the icon is not read.
                    Text(verbatim: found.text).lineBox(13, 18).fixedSize(horizontal: false, vertical: true)
                        .accessibilityAddTraits(.updatesFrequently)
                }
                if let detail = found.detail {
                    Text(verbatim: detail).font(.sans(12)).opacity(0.8).padding(.leading, 22)
                }
                if found.blankPassword {
                    Button("Unlock with a blank password") { model.unlock(blank: true) }
                        .buttonStyle(Bare())
                        .font(.sans(13, .medium))
                        .foregroundStyle(Tok.accent)
                        .padding(.leading, 22)
                }
                if found.import {
                    Button("Import…") {}.buttonStyle(Btn(size: .small)).later(Later.importer).padding(.leading, 22)
                }
            }
            .font(.sans(13))
            .foregroundStyle(Tok.negative)
            .padding(.top, 8)
        }
    }
}

extension UnlockView {
    /// Unlock; the unlock panel's Cancel left of it is Escape (APP-06.27, APP-06.28).
    fileprivate var unlockRow: some View {
        HStack(spacing: 8) {
            if let cancel {
                Button("Cancel", action: cancel).buttonStyle(Btn(size: .huge)).keyboardShortcut(.cancelAction)
            }
            Button {
                model.unlock()
            } label: {
                Text(verbatim: model.working ? "Unlocking…" : "Unlock")
            }
            .buttonStyle(Btn(kind: .primary, size: .huge, wide: true))
        }
    }
}

/// The mockup's shake (APP-06.17): two swings of 6 points per count.
struct Shake: GeometryEffect {
    var count: CGFloat
    var animatableData: CGFloat {
        get { count }
        set { count = newValue }
    }

    func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(translationX: 6 * sin(count * .pi * 4), y: 0))
    }
}

/// `.extra`: the key file row (UL-KEY) and the security key row (UL-HW).
private struct UnlockExtra: View {
    let model: UnlockModel
    var focus: FocusState<UnlockView.Field?>.Binding

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Glyph(name: "file-lock")
                VStack(alignment: .leading, spacing: 0) {
                    Text(verbatim: "Key file").frame(height: 20)
                    Text(verbatim: model.keyFileText ?? "No key file")
                        .font(.sans(12))
                        .foregroundStyle(Tok.muted)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(height: 20)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                Button("Browse…") { model.chooseKeyFile() }
                    .buttonStyle(Btn(size: .small))
                    .focused(focus, equals: .keyFile)
                    .onDeleteCommand { model.removeKeyFile() }
                    .accessibilityLabel(Text(verbatim: "Key file"))
                    .accessibilityValue(Text(verbatim: model.keyFileText ?? "No key file"))
                    .accessibilityHint(Text(verbatim: "Browse…"))
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .contentShape(Rectangle())
            .contextMenu {
                if !model.keyFile.isEmpty {
                    Button("Remove Key File") { model.removeKeyFile() }
                }
            }
            .dropDestination(for: URL.self) { urls, _ in
                guard let path = FileOpen.paths(urls).first else { return false }
                model.useKeyFile(path)
                return true
            }
            SecurityKeyRow(model: model)
        }
        .font(.sans(13))
        .padding(1)
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
    }

}

/// `.lockfoot`: when it locked, and the other vaults.
private struct LockFoot: View {
    let model: UnlockModel
    let window: MainWindowModel

    var body: some View {
        let others = window.vaults.filter { $0.id != model.vault.id }
        return HStack(spacing: 0) {
            if let lockedAt = model.vault.lockedAt {
                Text(verbatim: "Locked at \(Formats.time(lockedAt))").num()
            }
            Spacer()
            if !others.isEmpty {
                Text(verbatim: "Other vaults: ")
                ForEach(Array(others.enumerated()), id: \.element.id) { index, vault in
                    Text(verbatim: (index > 0 ? " · " : "") + vault.name + (vault.locked ? " " : ""))
                    if vault.locked {
                        Glyph(name: "lock-simple").accessibilityLabel(Text(verbatim: "locked"))
                    }
                }
            }
        }
        .font(.sans(12))
        .foregroundStyle(Tok.muted)
        .frame(height: 20)
        .padding(.top, 15)
        .padding(.bottom, 16)
        .overlay(alignment: .top) { Rectangle().fill(Tok.rule).frame(height: 1) }
    }
}
