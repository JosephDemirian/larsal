import LarsalCore
import SwiftUI

/// The main window: the welcome view while no vault is open, the unlock
/// screen of the shown vault while it is locked (E5-S3), or its main window
/// (E5-S4). Option A look (design/option-a/mockup.html).
struct MainWindow: View {
    let model: MainWindowModel

    var body: some View {
        ZStack(alignment: .bottom) {
            if let unlock = model.unlock {
                UnlockView(model: unlock, window: model)
                    .id(unlock.vault.id)
            } else if let keyChange = model.keyChange {
                KeyChangeView(model: keyChange).id(keyChange.vault.id)
            } else if let main = model.main {
                VaultView(model: main, window: model)
                    .id(main.vault.id)
            } else {
                WelcomeView(window: model)
            }
            if let banner = model.banner {
                bannerView(banner)
            }
        }
        .overlay(alignment: .top) {
            if let ask = model.sshAsk {
                SshKeyUseSheet(window: model, ask: ask)
            } else if let ask = model.browserAsk {
                BrowserAskSheet(window: model, ask: ask)
            }
        }
        .font(.sans(14))
        .foregroundStyle(Tok.text)
        .ignoresSafeArea()
        .frame(minWidth: 860, minHeight: 540)
        .background(Tok.ground)
        .background(WindowChromeView(main: true))
    }

    /// M09-07 and other open errors, as the mockup's `.toast`.
    private func bannerView(_ text: String) -> some View {
        HStack(spacing: 8) {
            Glyph(name: "warning")
            Text(verbatim: text).lineLimit(2)
            Button {
                model.banner = nil
            } label: {
                Glyph(name: "x", size: 12)
            }
            .buttonStyle(Bare())
            .help("Dismiss")
            .accessibilityLabel(Text(verbatim: "Dismiss"))
        }
        .font(.sans(13))
        .foregroundStyle(Tok.onPrimary)
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(Tok.primary, in: RoundedRectangle(cornerRadius: 10))
        .shadow(color: .black.opacity(0.25), radius: 15, y: 10)
        .padding(.bottom, 20)
        .accessibilityElement(children: .contain)
        .accessibilityAddTraits(.updatesFrequently)
    }
}
