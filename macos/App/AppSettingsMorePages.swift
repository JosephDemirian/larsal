import AppCore
import AppKit
import SwiftUI

struct AppSettingsAutoTypePage: View {
    let model: AppSettingsModel

    var body: some View {
        accessNotice
            .onAppear { model.recheckAccess() }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                model.recheckAccess()
            }
        AppSettingsGroup("Shortcut") {
            AppSettingsRow("Type the login for the window in front") {
                Text(verbatim: model.text("autotype.global_shortcut"))
                    .font(.sans(13))
                    .foregroundStyle(Tok.muted)
                    .padding(.horizontal, 10)
                    .frame(height: 26)
                    .background(Tok.raised, in: RoundedRectangle(cornerRadius: 5))
                Button {
                } label: {
                    Text(verbatim: "Change")
                }
                .buttonStyle(Btn(size: .small))
                .later(AppSettingsWaits.autoType)
            }
        }
        AppSettingsGroup("Matching") {
            AppSettingsRow("Match by window title") {
                AppSettingsSwitch(model: model, key: "autotype.match_title", label: "Title")
            }
            AppSettingsRow("Match by website address in the title") {
                AppSettingsSwitch(model: model, key: "autotype.match_url", label: "URL")
            }
            AppSettingsRow("Always ask which entry to type") {
                AppSettingsSwitch(model: model, key: "autotype.always_ask", label: "Ask")
            }
            AppSettingsRow("Skip expired entries") {
                AppSettingsSwitch(model: model, key: "autotype.hide_expired", label: "Expired")
            }
            AppSettingsRow("Lock again after typing") {
                AppSettingsSwitch(model: model, key: "lock.relock_after_autotype", label: "Relock")
            }
        }
        AppSettingsGroup("Timing") {
            AppSettingsRow("Wait before typing") {
                AppSettingsStepper(model: model, key: "autotype.start_delay_ms", range: 100...10_000, step: 100) {
                    "\($0) ms"
                }
            }
            AppSettingsRow("Pause between keys") {
                AppSettingsStepper(model: model, key: "autotype.key_delay_ms", range: 0...500, step: 5) { "\($0) ms" }
            }
            AppSettingsRow("Do not type the same login again within") {
                AppSettingsStepper(model: model, key: "autotype.retype_seconds", range: 0...60) { "\($0) s" }
            }
        }
    }

    /// `.notice.neu` with its link (INT-05.35): MI05-31 with the
    /// Accessibility permission, MI05-32 without it.
    private var accessNotice: some View {
        let granted = model.accessibility
        var words = AttributedString(granted ? "Accessibility access is on." : "Accessibility access is off.")
        words.font = .sans(13, .semibold)
        var rest = AttributedString(
            granted
                ? " macOS lets App type into other apps. " : " App can't type into other apps until you turn it on. ")
        rest.font = .sans(13)
        var link = AttributedString("Open Privacy & Security")
        link.font = .sans(13, .medium)
        link.foregroundColor = Tok.accent
        link.link = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
        return HStack(alignment: .top, spacing: 10) {
            Glyph(name: granted ? "check-circle" : "warning-circle").padding(.top, 1)
            Text(words + rest + link).lineBox(13, 18).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .tint(Tok.accent)
        .foregroundStyle(Tok.text)
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(Tok.raised, in: RoundedRectangle(cornerRadius: 10))
        .padding(.bottom, -4)  // `.notice` margin-bottom 20 within the page's 24 gap
    }
}

struct AppSettingsBrowserPage: View {
    let model: AppSettingsModel

    /// The frame's six browsers (INT-01.8); Edge waits for W-07.
    static let browsers: [(brand: String, name: String)] = [
        ("safari", "Safari"), ("googlechrome", "Chrome"), ("firefoxbrowser", "Firefox"), ("brave", "Brave"),
        ("vivaldi", "Vivaldi"), ("opera", "Opera"),
    ]

    var body: some View {
        AppSettingsGroup {
            AppSettingsRow(
                "Let browsers use App", "Fill sign-ins, one-time codes and passkeys through the App extension."
            ) {
                AppSettingsSwitch(model: model, key: "browser.enabled", label: "Browser")
            }
        }
        // MI01-02, MI01-05, MI01-06 (INT-01.6, INT-01.11).
        ForEach(model.browserNotes, id: \.self) { AppSettingsErrorNotice(text: $0) }
        AppSettingsGroup("Browsers") {
            for browser in Self.browsers {
                AppSettingsRow(title: logoTitle(browser.brand, browser.name), detail: detail(browser.brand)) {
                    browserSwitch(browser.brand, browser.name)
                }
            }
        }
        AppSettingsGroup("When a browser asks") {
            AppSettingsRow("Show a notification") {
                AppSettingsSwitch(model: model, key: "browser.notify", label: "Notify")
            }
            AppSettingsRow("Ask to unlock a locked vault") {
                AppSettingsSwitch(model: model, key: "browser.unlock_on_request", label: "Unlock")
            }
            AppSettingsRow("Offer only the best matches") {
                AppSettingsSwitch(model: model, key: "browser.best_match_only", label: "Best")
            }
            AppSettingsRow("Search every open vault") {
                AppSettingsSwitch(model: model, key: "browser.search_all_vaults", label: "All vaults")
            }
            AppSettingsRow("Never ask before giving access", "Not recommended: any site that matches gets the entry.") {
                AppSettingsSwitch(model: model, key: "browser.never_ask_access", label: "Never ask")
            }
            AppSettingsRow("Allow passkeys on localhost", "For web developers.") {
                AppSettingsSwitch(model: model, key: "browser.passkeys_localhost", label: "Localhost")
            }
        }
        AppSettingsGroup("Advanced") {
            // LD-167: the card's words over the mockup's "Use a custom proxy location".
            AppSettingsRow("Use my own proxy program") {
                AppSettingsSwitch(model: model, key: "browser.custom_proxy", label: "Proxy")
            }
            AppSettingsRow("Rewrite the browser setup files at start") {
                AppSettingsSwitch(model: model, key: "browser.rewrite_manifests", label: "Rewrite")
            }
        }
    }

    /// Safari: S-BRW-02, disabled without a team id (INT-01.15); the others:
    /// on = App's setup file is in that browser's folder (INT-01.8), written
    /// or removed on OK (APP-01.30).
    @ViewBuilder
    private func browserSwitch(_ brand: String, _ name: String) -> some View {
        if brand == "safari" {
            AppSettingsSwitch(model: model, key: "browser.safari", label: name)
        } else if AppSettingsModel.browserNames[brand] == nil {
            Switch(label: name, isOn: .constant(false)).later(AppSettingsWaits.opera)
        } else {
            Switch(
                label: name,
                isOn: Binding(get: { model.browsersOn.contains(brand) }, set: { model.setBrowser(brand, $0) })
            )
            .disabled(model.isDisabled("browser.manifests"))
        }
    }

    /// MI01-04 under Safari while the switch is disabled (INT-01.15).
    private func detail(_ brand: String) -> Text? {
        guard brand == "safari", !model.safariAllowed, let note = model.safariNote else { return nil }
        return Text(verbatim: note)
    }

    /// The row's title: the `.logo` (26, radius 7, mark 15) and the name.
    private func logoTitle(_ brand: String, _ name: String) -> some View {
        HStack(spacing: 10) {
            Image("brand-" + brand, bundle: appBundle)
                .resizable()
                .frame(width: 15, height: 15)
                .frame(width: 26, height: 26)
                .background(Tok.tile, in: RoundedRectangle(cornerRadius: 7))
                .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Tok.border))
                .accessibilityElement()
                .accessibilityLabel(Text(verbatim: Brands.titles[brand] ?? name))
                .accessibilityAddTraits(.isImage)
            Text(verbatim: name)
        }
    }
}

struct AppSettingsSshPage: View {
    let model: AppSettingsModel

    var body: some View {
        AppSettingsGroup {
            AppSettingsRow("Work with the SSH agent", "Adds keys from entries to the system agent.") {
                AppSettingsSwitch(model: model, key: "ssh.enabled", label: "SSH")
            }
        }
        AppSettingsGroup("Agent") {
            if let status = model.sshStatus {
                // APP-01.31: the socket in use, and whether the agent answers.
                let detail = status.connected ? status.socket : status.message ?? status.socket
                AppSettingsRow("Status", detail, mono: status.connected) {
                    if status.connected {
                        Pill(text: "Connected", glyph: "check-circle", kind: .positive)
                    } else {
                        Pill(text: "Not connected", glyph: "warning-circle", kind: .warning)
                    }
                }
            }
            AppSettingsRow("Use a different socket") {
                Switch(
                    label: "Socket",
                    isOn: Binding(get: { !model.text("ssh.socket_override").isEmpty }, set: { _ in })
                )
                .later(AppSettingsWaits.socket)
            }
            AppSettingsRow("Security key provider", "For sk-ed25519 keys on a hardware key.") {
                let provider = model.text("ssh.sk_provider_override")
                // Shown only: choosing one waits for W-05 (the socket switch says so).
                SelectBox(title: provider.isEmpty ? "Built-in" : provider)
            }
        }
    }
}

/// INT-08.26 (W-15 `appShares`): the three switches for every vault on this
/// Mac; no signer, fingerprint or Generate (D-INT08-1 option b only).
struct AppSettingsSharePage: View {
    let model: AppSettingsModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            AppSettingsGroup {
                AppSettingsRow("Allow import", "Shared groups read the changes other people make to their files.") {
                    AppSettingsSwitch(model: model, key: "share.import", label: "Allow import")
                }
                AppSettingsRow("Allow export", "Shared groups write their files each time a vault is saved.") {
                    AppSettingsSwitch(model: model, key: "share.export", label: "Allow export")
                }
                AppSettingsRow("Hide sync success messages", "Problems still show.") {
                    AppSettingsSwitch(model: model, key: "share.quiet", label: "Hide sync success messages")
                }
            }
            Text(
                verbatim: "A shared group is a group of your vault, shared as a file. Set one up on the Sharing page "
                    + "of the group's editor. These switches apply to every vault on this Mac."
            )
            .font(.sans(12)).foregroundStyle(Tok.muted).lineBox(12, 16)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 2)
            .padding(.top, 10)
        }
    }
}

struct AppSettingsShortcutsPage: View {
    let model: AppSettingsModel

    var body: some View {
        ForEach(AppSettingsShortcuts.groups, id: \.title) { group in
            AppSettingsGroup(group.title) {
                for item in group.items {
                    AppSettingsRow(item.title) {
                        // `.kbd`; the text keeps its own box for VoiceOver.
                        HStack(spacing: 0) { Text(verbatim: item.keys).font(.sans(12)).foregroundStyle(Tok.muted) }
                            .padding(.horizontal, 6)
                            .frame(height: 20)
                            .background(Tok.raised, in: RoundedRectangle(cornerRadius: 5))
                    }
                }
            }
        }
    }
}
