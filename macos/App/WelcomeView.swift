import AppCore
import SwiftUI

/// The start view with no vault open (mockup `welcomeWin`): App, the three
/// ways in, and the recent vaults; a vault file dropped here opens.
struct WelcomeView: View {
    let window: MainWindowModel
    @State private var dropping = false

    var body: some View {
        HStack(spacing: 0) {
            left.frame(width: 300)
            recent
                .padding(.top, 8)
                .padding([.trailing, .bottom], 8)
        }
        .background(Tok.ground)
    }

    private var left: some View {
        VStack(alignment: .leading, spacing: 0) {
            Tile(color: Tok.tileColor("teal"), glyph: "keyhole", size: 64).padding(.top, 52)
            Text(verbatim: "App").font(.sans(24, .semibold)).frame(height: 30).padding(.top, 16).padding(.bottom, 4)
                .accessibilityAddTraits(.isHeader)
            Text(verbatim: "Your passwords, in a file you own.").foregroundStyle(Tok.muted).frame(height: 20)
            VStack(spacing: 6) {
                action("plus", "blue", "New vault", "An encrypted file for your passwords") {
                    AuxWindows.newVault(window)
                }
                action("folder-open", "orange", "Open vault…", "A vault file on this Mac or a synced folder") {
                    window.chooseVault()
                }
                action("download-simple", "green", "Import…", "From CSV or another password manager") {}
                    .later(Later.importer)
            }
            .padding(.top, 28)
            Spacer(minLength: 0)
            Text(verbatim: "Version \(AppCore.coreVersion()) · open source · GPL-3.0")
                .font(.sans(12))
                .num()
                .foregroundStyle(Tok.muted)
                .frame(height: 20)
        }
        .padding(.horizontal, 28)
        .padding(.top, 52)
        .padding(.bottom, 28)
        .frame(maxHeight: .infinity, alignment: .top)
    }

    private func action(
        _ glyph: String, _ color: String, _ title: String, _ detail: String, run: @escaping () -> Void
    ) -> some View {
        WelcomeAction(glyph: glyph, color: color, title: title, detail: detail, action: run)
    }

    private var recent: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(verbatim: "Recent vaults").font(.sans(15, .semibold)).frame(height: 20).padding(.bottom, 12)
                .accessibilityAddTraits(.isHeader)
            ForEach(window.recents) { item in
                RecentRow(item: item) { Task { await window.open(item.path) } }
            }
            Spacer(minLength: 0)
            Text(verbatim: "Drag a vault file here to open it.").font(.sans(12)).foregroundStyle(Tok.muted).frame(
                height: 16)
        }
        .padding(25)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Tok.surface, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(dropping ? Tok.accent : Tok.border))
        .dropDestination(for: URL.self) { urls, _ in
            let paths = FileOpen.droppedVaults(urls)
            window.open(paths)
            return !paths.isEmpty
        } isTargeted: {
            dropping = $0
        }
    }
}

/// `.wel .act`.
private struct WelcomeAction: View {
    let glyph: String
    let color: String
    let title: String
    let detail: String
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Tile(color: Tok.tileColor(color), glyph: glyph, size: 32)
                VStack(alignment: .leading, spacing: 0) {
                    Text(verbatim: title).font(.sans(14, .medium)).frame(height: 20)
                    Text(verbatim: detail).font(.sans(12)).foregroundStyle(Tok.muted).lineBox(12, 16).fixedSize(
                        horizontal: false, vertical: true)
                }
                // The left column is 300 wide: 28 + 10 on each side, then
                // the 32-point tile and 12 apart.
                .frame(width: 180, alignment: .leading)
            }
            .foregroundStyle(Tok.text)
            .padding(10)
            .background(hover ? Tok.active : .clear, in: RoundedRectangle(cornerRadius: 10))
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .onHover { hover = $0 }
    }
}

/// `.rec`: a recent vault with its tile, path and when it was opened.
private struct RecentRow: View {
    let item: MainWindowModel.Recent
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Tile(
                    color: VaultLooks.color(item.look.colour, hue: 0), glyph: VaultLooks.glyph(item.look.icon), size: 32
                )
                VStack(alignment: .leading, spacing: 0) {
                    Text(verbatim: item.look.name).font(.sans(14, .medium)).frame(height: 20)
                    Text(verbatim: item.look.path).font(.sans(12)).foregroundStyle(Tok.muted).lineLimit(1).frame(
                        height: 20)
                }
                Spacer(minLength: 0)
                Text(verbatim: Formats.modified(Int64(item.opened.timeIntervalSince1970)))
                    .font(.sans(12))
                    .num()
                    .foregroundStyle(Tok.muted)
            }
            .foregroundStyle(Tok.text)
            .padding(10)
            .background(hover ? Tok.hover : .clear, in: RoundedRectangle(cornerRadius: 10))
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
        .onHover { hover = $0 }
    }
}

/// The new, empty vault (mockup `emptyVault`, first run after the wizard).
struct EmptyVaultView: View {
    let model: VaultModel

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 16) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: "All entries").font(.sans(22, .semibold)).tracking(-0.22).frame(height: 28)
                        .accessibilityAddTraits(.isHeader)
                    Text(verbatim: model.vault.fileName + " · " + Formats.created(model.sidebar?.created ?? 0))
                        .foregroundStyle(Tok.muted)
                        .frame(height: 20)
                }
                Spacer(minLength: 0)
                Button {
                } label: {
                    BtnLabel(glyph: "plus", title: "New Entry")
                }
                .buttonStyle(Btn(kind: .primary, size: .large))
                .later(Later.editor)
            }
            Spacer(minLength: 0)
            VStack(spacing: 0) {
                Tile(color: model.vault.tileColor, glyph: model.vault.tileGlyph, size: 64)
                Text(verbatim: "\(model.vault.name) is ready")
                    .font(.sans(20, .semibold))
                    .frame(height: 20)
                    .padding(.top, 18)
                    .padding(.bottom, 6)
                Text(verbatim: Self.ready)
                    .foregroundStyle(Tok.muted)
                    .lineBox(14, 20)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.bottom, 24)
                HStack(alignment: .top, spacing: 12) {
                    option(["plus", "blue", "New entry", "A login, card or note", ""]) { model.newEntry() }
                    option(["download-simple", "green", "Import", "CSV and other managers", Later.importer]) {}
                    option(["folder-simple", "orange", "New group", "Sort entries like folders", ""]) {
                        model.dialog = .newGroup(name: "")
                    }
                }
                .fixedSize(horizontal: false, vertical: true)
            }
            .frame(width: 520)
            Spacer(minLength: 0)
        }
    }

    private static let ready =
        "The vault is saved and encrypted. Add your first entry, or bring passwords over from another app."

    /// Glyph, tile colour, title, detail and the later story's hint (empty
    /// when it works) of one choice.
    private func option(_ item: [String], action: @escaping () -> Void) -> AnyView {
        let button = optionButton(item[0], item[1], item[2], item[3], action)
        return item[4].isEmpty ? AnyView(button) : AnyView(button.later(item[4]))
    }

    private func optionButton(
        _ glyph: String, _ color: String, _ title: String, _ detail: String, _ action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 0) {
                Tile(color: Tok.tileColor(color), glyph: glyph, size: 32)
                Text(verbatim: title).font(.sans(15, .semibold)).frame(height: 20).padding(.top, 10).padding(.bottom, 4)
                Text(verbatim: detail).font(.sans(13)).foregroundStyle(Tok.muted).lineBox(13, 18).fixedSize(
                    horizontal: false, vertical: true)
            }
            .foregroundStyle(Tok.text)
            .padding(19)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Tok.border))
            .contentShape(Rectangle())
        }
        .buttonStyle(Bare())
    }
}
