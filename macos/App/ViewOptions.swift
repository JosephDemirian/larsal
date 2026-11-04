import AppCore
import AppKit
import Observation
import SwiftUI

/// The View menu's settings (APP-08.8, APP-08.24): S-VIEW-01 and S-VIEW-03
/// to S-VIEW-07, read from the settings store and stored at once when the
/// menu changes one. Screen capture is not stored (APP-10.4).
@Observable
final class ViewOptions {
    /// S-VIEW-01: auto, light or dark.
    private(set) var theme = "auto"
    /// S-VIEW-03, S-VIEW-04.
    private(set) var sidebar = true
    private(set) var details = true
    /// S-VIEW-05.
    private(set) var keepOnTop = false
    /// S-VIEW-06, S-VIEW-07 (APP-01.23).
    private(set) var maskUserNames = false
    private(set) var maskPasswords = true
    /// S-UI-07 (APP-01.24, LD-212 (5)): a shown password's digits and
    /// symbols in colour.
    private(set) var colourPasswords = true
    /// S-CONV-01, S-CONV-04, S-CONV-05 (APP-01.23).
    private(set) var detail = DetailOptions()

    /// Reads the stored values (at start and after the settings' OK).
    func load(_ store: AppSettingsStore) {
        theme = store.text(key: "ui.theme")
        sidebar = store.flag(key: "ui.show_groups")
        details = store.flag(key: "ui.show_preview")
        keepOnTop = store.flag(key: "window.always_on_top")
        maskUserNames = store.flag(key: "display.hide_usernames")
        maskPasswords = store.flag(key: "display.hide_passwords")
        colourPasswords = store.flag(key: "display.color_passwords")
        detail = DetailOptions(
            hideNotes: store.flag(key: "display.hide_notes"),
            hideCodes: store.flag(key: "display.hide_totp_in_preview"),
            dotsForEmpty: store.flag(key: "display.dots_for_empty"))
        WindowRules.shared.keepOnTop(keepOnTop)
    }

    func set(_ key: String, _ value: Bool, _ session: Session) {
        store(AppSetting(key: key, value: .flag(on: value)), session)
    }

    func setTheme(_ theme: String, _ session: Session) {
        store(AppSetting(key: "ui.theme", value: .text(text: theme)), session)
        Appearance.apply(session.settings())
    }

    /// A store that cannot be written keeps the old value (APP-01.12).
    private func store(_ setting: AppSetting, _ session: Session) {
        try? session.saveSettings(changes: [setting])
        load(session.settings())
    }
}

extension EnvironmentValues {
    /// S-VIEW-06 (APP-01.23, LD-219 (1)): every user name App draws is
    /// masked; set by the vault's view from `ViewOptions.maskUserNames`.
    @Entry var maskUserNames = false
    /// S-UI-07 (APP-01.24, LD-212 (5)): the detail colours a shown
    /// password's digits and symbols; set by the vault's view.
    @Entry var colourPasswords = true
    /// S-CONV-01, S-CONV-04, S-CONV-05 for the detail pane and the editor;
    /// set by the vault's view from `ViewOptions.detail`.
    @Entry var detailOptions = DetailOptions()
}

/// What the detail pane and the editor hide (APP-01.23, F-082, F-084): the
/// notes behind Show (S-CONV-05), the live code until its button (S-CONV-04),
/// and an empty password drawn as a filled one (S-CONV-01).
struct DetailOptions: Equatable {
    var hideNotes = false
    var hideCodes = false
    var dotsForEmpty = false
}

/// APP-01.23: masked text is six U+25CF; VoiceOver reads it as "hidden"
/// (APP-08.25).
enum Masked {
    static let text = "●●●●●●"
    static let spoken = "hidden"

    /// The mask, after "`site` · " when there is a site, read
    /// "<site>, hidden".
    static func line(site: String? = nil, more: String = "") -> Text {
        Text(verbatim: (site.map { $0 + " · " } ?? "") + text + more)
            .accessibilityLabel(Text(verbatim: site.map { $0 + ", " + spoken } ?? spoken))
    }
}

/// A user name wherever App draws one (LD-219 (1)): the mask while S-VIEW-06
/// is on and the user did not choose Show, else the text; an empty one
/// stays empty (APP-01.23).
struct MaskedUser: View {
    let user: String
    var site: String?
    var shown = false
    @Environment(\.maskUserNames) private var mask

    var body: some View {
        if mask && !shown && !user.isEmpty {
            Masked.line(site: site)
        } else {
            Text(verbatim: (site.map { $0 + " · " } ?? "") + user)
        }
    }
}

extension EntryRow {
    /// The second line holds the user name, not the URL's host shown for
    /// none (LD-214 (7)). ponytail: the row has no user name flag, so a
    /// custom field in its place counts too and a user name equal to the
    /// host does not; a flag from Rust if that matters.
    var subtitleIsUser: Bool { !subtitle.isEmpty && subtitle != host }

    /// The list row's second line: the user name, else the URL's host, else
    /// the first plain custom field; "—" for none. S-VIEW-06 masks the user
    /// name (APP-01.23), read as "hidden".
    func secondLine(maskUser: Bool) -> Text {
        let more = passkey ? " ·" : ""
        if maskUser && subtitleIsUser { return Masked.line(more: more) }
        let first = subtitle.isEmpty ? host : subtitle
        return Text(verbatim: (first.isEmpty ? "—" : first) + more)
    }
}
