import AppKit
import LarsalCore
import SwiftUI

struct LarsalSettingsAutoTypePage: View {
    let model: LarsalSettingsModel

    var body: some View {
        accessNotice
            .onAppear { model.recheckAccess() }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                model.recheckAccess()
            }
        LarsalSettingsGroup("Shortcut") {
            LarsalSettingsRow("Type the login for the window in front") {
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
                .later(LarsalSettingsWaits.autoType)
            }
        }
        LarsalSettingsGroup("Matching") {
            LarsalSettingsRow("Match by window title") {
                LarsalSettingsSwitch(model: model, key: "autotype.match_title", label: "Title")
            }
            LarsalSettingsRow("Match by website address in the title") {
                LarsalSettingsSwitch(model: model, key: "autotype.match_url", label: "URL")
            }
            LarsalSettingsRow("Always ask which entry to type") {
                LarsalSettingsSwitch(model: model, key: "autotype.always_ask", label: "Ask")
            }
            LarsalSettingsRow("Skip expired entries") {
                LarsalSettingsSwitch(model: model, key: "autotype.hide_expired", label: "Expired")
            }
            LarsalSettingsRow("Lock again after typing") {
                LarsalSettingsSwitch(model: model, key: "lock.relock_after_autotype", label: "Relock")
            }
        }
        LarsalSettingsGroup("Timing") {
            LarsalSettingsRow("Wait before typing") {
                LarsalSettingsStepper(model: model, key: "autotype.start_delay_ms", range: 100...10_000, step: 100) {
                    "\($0) ms"
                }
            }
            LarsalSettingsRow("Pause between keys") {
                LarsalSettingsStepper(model: model, key: "autotype.key_delay_ms", range: 0...500, step: 5) {
                    "\($0) ms"
                }
            }
            LarsalSettingsRow("Do not type the same login again within") {
                LarsalSettingsStepper(model: model, key: "autotype.retype_seconds", range: 0...60) { "\($0) s" }
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
                ? " macOS lets Larsal type into other apps. "
                : " Larsal can't type into other apps until you turn it on. ")
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

struct LarsalSettingsBrowserPage: View {
    let model: LarsalSettingsModel

    /// The frame's six browsers (INT-01.8); Edge waits for W-07.
    static let browsers: [(brand: String, name: String)] = [
        ("safari", "Safari"), ("googlechrome", "Chrome"), ("firefoxbrowser", "Firefox"), ("brave", "Brave"),
        ("vivaldi", "Vivaldi"), ("opera", "Opera"),
    ]

    var body: some View {
        LarsalSettingsGroup {
            LarsalSettingsRow(
                "Let browsers use Larsal", "Fill sign-ins, one-time codes and passkeys through the Larsal extension."
            ) {
                LarsalSettingsSwitch(model: model, key: "browser.enabled", label: "Browser")
            }
        }
        // MI01-02, MI01-05, MI01-06 (INT-01.6, INT-01.11).
        ForEach(model.browserNotes, id: \.self) { LarsalSettingsErrorNotice(text: $0) }
        LarsalSettingsGroup("Browsers") {
            for browser in Self.browsers {
                LarsalSettingsRow(title: logoTitle(browser.brand, browser.name), detail: detail(browser.brand)) {
                    browserSwitch(browser.brand, browser.name)
                }
            }
        }
        LarsalSettingsGroup("When a browser asks") {
            LarsalSettingsRow("Show a notification") {
                LarsalSettingsSwitch(model: model, key: "browser.notify", label: "Notify")
            }
            LarsalSettingsRow("Ask to unlock a locked vault") {
                LarsalSettingsSwitch(model: model, key: "browser.unlock_on_request", label: "Unlock")
            }
            LarsalSettingsRow("Offer only the best matches") {
                LarsalSettingsSwitch(model: model, key: "browser.best_match_only", label: "Best")
            }
            LarsalSettingsRow("Search every open vault") {
                LarsalSettingsSwitch(model: model, key: "browser.search_all_vaults", label: "All vaults")
            }
            LarsalSettingsRow(
                "Never ask before giving access", "Not recommended: any site that matches gets the entry."
            ) {
                LarsalSettingsSwitch(model: model, key: "browser.never_ask_access", label: "Never ask")
            }
            LarsalSettingsRow("Allow passkeys on localhost", "For web developers.") {
                LarsalSettingsSwitch(model: model, key: "browser.passkeys_localhost", label: "Localhost")
            }
        }
        LarsalSettingsGroup("Advanced") {
            // LD-167: the card's words over the mockup's "Use a custom proxy location".
            LarsalSettingsRow("Use my own proxy program") {
                LarsalSettingsSwitch(model: model, key: "browser.custom_proxy", label: "Proxy")
            }
            LarsalSettingsRow("Rewrite the browser setup files at start") {
                LarsalSettingsSwitch(model: model, key: "browser.rewrite_manifests", label: "Rewrite")
            }
        }
    }

    /// Safari: S-BRW-02, disabled without a team id (INT-01.15); the others:
    /// on = Larsal's setup file is in that browser's folder (INT-01.8), written
    /// or removed on OK (APP-01.30).
    @ViewBuilder
    private func browserSwitch(_ brand: String, _ name: String) -> some View {
        if brand == "safari" {
            LarsalSettingsSwitch(model: model, key: "browser.safari", label: name)
        } else if LarsalSettingsModel.browserNames[brand] == nil {
            Switch(label: name, isOn: .constant(false)).later(LarsalSettingsWaits.opera)
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

struct LarsalSettingsSshPage: View {
    let model: LarsalSettingsModel

    var body: some View {
        LarsalSettingsGroup {
            LarsalSettingsRow("Work with the SSH agent", "Adds keys from entries to the system agent.") {
                LarsalSettingsSwitch(model: model, key: "ssh.enabled", label: "SSH")
            }
        }
        LarsalSettingsGroup("Agent") {
            if let status = model.sshStatus {
                // APP-01.31: the socket in use, and whether the agent answers.
                let detail = status.connected ? status.socket : status.message ?? status.socket
                LarsalSettingsRow("Status", detail, mono: status.connected) {
                    if status.connected {
                        Pill(text: "Connected", glyph: "check-circle", kind: .positive)
                    } else {
                        Pill(text: "Not connected", glyph: "warning-circle", kind: .warning)
                    }
                }
            }
            LarsalSettingsRow("Use a different socket") {
                Switch(
                    label: "Socket",
                    isOn: Binding(get: { !model.text("ssh.socket_override").isEmpty }, set: { _ in })
                )
                .later(LarsalSettingsWaits.socket)
            }
            LarsalSettingsRow("Security key provider", "For sk-ed25519 keys on a hardware key.") {
                let provider = model.text("ssh.sk_provider_override")
                // Shown only: choosing one waits for W-05 (the socket switch says so).
                SelectBox(title: provider.isEmpty ? "Built-in" : provider)
            }
        }
    }
}

/// INT-08.26 (W-15 `appShares`): the three switches for every vault on this
/// Mac; no signer, fingerprint or Generate (D-INT08-1 option b only).
struct LarsalSettingsSharePage: View {
    let model: LarsalSettingsModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            LarsalSettingsGroup {
                LarsalSettingsRow("Allow import", "Shared groups read the changes other people make to their files.") {
                    LarsalSettingsSwitch(model: model, key: "share.import", label: "Allow import")
                }
                LarsalSettingsRow("Allow export", "Shared groups write their files each time a vault is saved.") {
                    LarsalSettingsSwitch(model: model, key: "share.export", label: "Allow export")
                }
                LarsalSettingsRow("Hide sync success messages", "Problems still show.") {
                    LarsalSettingsSwitch(model: model, key: "share.quiet", label: "Hide sync success messages")
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

struct LarsalSettingsShortcutsPage: View {
    let model: LarsalSettingsModel

    var body: some View {
        ForEach(LarsalSettingsShortcuts.groups, id: \.title) { group in
            LarsalSettingsGroup(group.title) {
                for item in group.items {
                    LarsalSettingsRow(item.title) {
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
