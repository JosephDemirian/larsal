import AppCore
import AppKit
import SwiftUI

struct AppSettingsGeneralPage: View {
    let model: AppSettingsModel

    /// S-START-12: the days the choice offers (0 = expired entries only).
    static let days: [Int64] = [0, 1, 3, 7, 14, 30, 90]

    static func within(_ days: Int64) -> String {
        days == 0 ? "Expired only" : days == 1 ? "Within 1 day" : "Within \(days) days"
    }

    var body: some View {
        AppSettingsGroup("Startup") {
            AppSettingsRow("Open App at login") {
                Switch(label: "Login", isOn: Binding(get: { model.loginOn }, set: { model.loginOn = $0 }))
                    .disabled(!model.loginEditable)
            }
            AppSettingsRow("Reopen the last vaults at start") {
                AppSettingsSwitch(model: model, key: "recent.reopen_at_start", label: "Reopen")
            }
            AppSettingsRow("Remember recent vaults", "Also remembers which key file each one used.") {
                AppSettingsStepper(model: model, key: "recent.count", range: 1...25)
                AppSettingsSwitch(model: model, key: "recent.remember", label: "Recent")
            }
            AppSettingsRow("Show entries that expire soon after unlocking") {
                let days = model.number("expiry.notice_days")
                AppSettingsSelect(
                    label: "Expiry days", title: Self.within(days), choices: Self.days.map(Self.within),
                    chosen: Self.days.firstIndex(of: days), disabled: model.isDisabled("expiry.notice_days")
                ) { model.setNumber("expiry.notice_days", Self.days[$0]) }
                AppSettingsSwitch(model: model, key: "expiry.notice_on_unlock", label: "Expiry")
            }
            // Card words over the mockup's "once a day" (APP-01.19: weekly).
            AppSettingsRow("Check for updates", "Asks GitHub once a week. Nothing else leaves this Mac.") {
                AppSettingsSwitch(model: model, key: "update.check", label: "Updates").later(AppSettingsWaits.updates)
            }
            AppSettingsRow("Include beta versions", sub: true) {
                AppSettingsSwitch(model: model, key: "update.include_beta", label: "Beta").later(
                    AppSettingsWaits.updates)
            }
        }
        AppSettingsGroup("Saving") {
            // LD-167: the card's words over the mockup's "Save after every change".
            AppSettingsRow("Save changes as you make them") {
                AppSettingsSwitch(model: model, key: "save.after_every_change", label: "Autosave")
            }
            AppSettingsRow("Save when locking") {
                AppSettingsSwitch(model: model, key: "save.on_lock", label: "Save on lock")
            }
            AppSettingsRow("Reload the vault when another app changes it", "Merges your unsaved changes first.") {
                AppSettingsSwitch(model: model, key: "save.reload_on_change", label: "Reload")
            }
            AppSettingsRow("Keep a backup before saving", model.text("backup.pattern"), mono: true) {
                AppSettingsSwitch(model: model, key: "backup.enabled", label: "Backup")
            }
            AppSettingsRow("Safe saving", "Writes a temporary file, then replaces the vault in one step.") {
                saveMethod
            }
        }
        AppSettingsGroup("Entries") {
            AppSettingsRow("Ask before moving to the Recycle Bin") {
                AppSettingsSwitch(model: model, key: "entry.confirm_recycle", label: "Confirm")
            }
            AppSettingsRow("Make a password for every new entry") {
                AppSettingsSwitch(model: model, key: "entry.autogen_password", label: "Autogen")
            }
            AppSettingsRow("Double-clicking a row copies") {
                let copies = model.flag("list.copy_on_double_click")
                AppSettingsSelect(
                    label: "Double-click", title: copies ? "Password" : "Nothing", choices: ["Password", "Nothing"],
                    chosen: copies ? 0 : 1
                ) { model.setFlag("list.copy_on_double_click", $0 == 0) }
            }
            AppSettingsRow("Hide App after copying") {
                let mode = model.text("window.hide_on_copy.mode")
                AppSettingsSelect(
                    label: "Hide by", title: mode == "background" ? "Move behind other windows" : "Minimize",
                    choices: ["Minimize", "Move behind other windows"], chosen: mode == "background" ? 1 : 0,
                    disabled: model.isDisabled("window.hide_on_copy.mode")
                ) { model.setText("window.hide_on_copy.mode", $0 == 0 ? "minimize" : "background") }
                AppSettingsSwitch(model: model, key: "window.hide_on_copy", label: "Hide")
            }
        }
        AppSettingsGroup("Look") {
            AppSettingsRow("Appearance") {
                let themes = ["auto", "light", "dark"]
                let selected = themes.firstIndex(of: model.text("ui.theme")) ?? 0
                Segments(items: ["System", "Light", "Dark"], selected: selected) {
                    model.setText("ui.theme", themes[$0])
                }
            }
            AppSettingsRow(
                title: Text(verbatim: "Colour digits and symbols in passwords"),
                detail: appSettingsSample("x9!Lq#4vT").font(.mono(12)).kerning(0.24)
            ) {
                AppSettingsSwitch(model: model, key: "display.color_passwords", label: "Colour")
            }
            AppSettingsRow("Monospace font in notes") {
                AppSettingsSwitch(model: model, key: "display.monospace_notes", label: "Mono notes")
            }
            AppSettingsRow("Show App in the menu bar") {
                let colourful = model.text("menubar_icon.style") == "colorful"
                AppSettingsSelect(
                    label: "Menu bar icon", title: colourful ? "Colourful icon" : "Monochrome icon",
                    choices: ["Monochrome icon", "Colourful icon"], chosen: colourful ? 1 : 0,
                    disabled: model.isDisabled("menubar_icon.style")
                ) { model.setText("menubar_icon.style", $0 == 0 ? "monochrome" : "colorful") }
                AppSettingsSwitch(model: model, key: "menubar_icon.show", label: "Menu bar")
            }
            AppSettingsRow("Closing the window keeps App running") {
                AppSettingsSwitch(model: model, key: "window.close_hides", label: "Hide on close")
            }
        }
    }

    /// S-FILE-07 and S-FILE-08 as one choice (APP-05: safe, `temp_move`,
    /// `direct`).
    private var saveMethod: some View {
        let alternative = model.flag("save.alternative")
        let mode = model.number("save.alternative.mode")
        let chosen = !alternative ? 0 : mode == 1 ? 2 : 1
        let titles = ["Through a temporary file", "Temporary file moved into place", "Straight into the vault file"]
        return AppSettingsSelect(label: "Safe saving", title: titles[chosen], choices: titles, chosen: chosen) {
            model.setFlag("save.alternative", $0 != 0)
            if $0 != 0 { model.setNumber("save.alternative.mode", $0 == 2 ? 1 : 0) }
        }
    }
}

struct AppSettingsSecurityPage: View {
    let model: AppSettingsModel

    /// Seconds as the steppers show them.
    static func seconds(_ value: Int64) -> String { "\(value) s" }
    static func minutes(_ value: Int64) -> String { value % 60 == 0 ? "\(value / 60) min" : "\(value) s" }

    var body: some View {
        AppSettingsGroup("Timeouts") {
            AppSettingsRow("Clear the clipboard after", "Copied passwords and codes disappear from the clipboard.") {
                AppSettingsStepper(
                    model: model, key: "clipboard.clear.seconds", range: 1...999, step: 5, show: Self.seconds)
                AppSettingsSwitch(model: model, key: "clipboard.clear.enabled", label: "Clipboard")
            }
            AppSettingsRow("Lock after no use for") {
                AppSettingsStepper(
                    model: model, key: "lock.idle.seconds", range: 60...43_200, show: Self.minutes, scale: 60)
                AppSettingsSwitch(model: model, key: "lock.idle.enabled", label: "Idle lock")
            }
            AppSettingsRow("Clear the search after") {
                AppSettingsStepper(model: model, key: "search.clear_after_minutes", range: 1...1_440) { "\($0) min" }
                AppSettingsSwitch(model: model, key: "search.clear_when_idle", label: "Clear search")
            }
        }
        AppSettingsGroup("Locking") {
            AppSettingsRow(
                "Unlock with Touch ID",
                "Your vault key stays in the Secure Enclave keychain until App quits or 8 hours pass."
            ) {
                AppSettingsSwitch(model: model, key: "quick_unlock.enabled", label: "Touch ID").later(
                    AppSettingsWaits.touchID)
            }
            AppSettingsRow("Lock when the screen locks") {
                AppSettingsSwitch(model: model, key: "lock.on_screen_lock", label: "Screen lock")
            }
            AppSettingsRow("Lock when you switch user") {
                AppSettingsSwitch(model: model, key: "lock.on_user_switch", label: "User switch")
            }
            AppSettingsRow("Lock when the window is minimized") {
                AppSettingsSwitch(model: model, key: "lock.on_minimize", label: "Minimize")
            }
        }
        AppSettingsGroup("Showing secrets") {
            AppSettingsRow("Hide passwords in the editor") {
                AppSettingsSwitch(model: model, key: "display.hide_password_in_editor", label: "Editor")
            }
            AppSettingsRow("Hide passwords in the detail pane") {
                AppSettingsSwitch(model: model, key: "display.hide_password_in_preview", label: "Preview")
            }
            AppSettingsRow("Hide one-time codes in the detail pane") {
                AppSettingsSwitch(model: model, key: "display.hide_totp_in_preview", label: "Codes")
            }
            AppSettingsRow("Hide notes") { AppSettingsSwitch(model: model, key: "display.hide_notes", label: "Notes") }
            AppSettingsRow("Show dots for empty passwords") {
                AppSettingsSwitch(model: model, key: "display.dots_for_empty", label: "Dots")
            }
        }
        AppSettingsGroup("Privacy") {
            // APP-10: allowing capture is for this run only, never stored.
            AppSettingsRow(
                "Let other apps record App's windows",
                "Screen sharing and screenshots show App as a blank window while this is off."
            ) {
                // The View menu's Permit Screen Capture (APP-10.4): for this
                // run, at once, outside OK and Cancel.
                Switch(
                    label: "Capture",
                    isOn: Binding(get: { ScreenProtection.shared.allowed }, set: { ScreenProtection.shared.allow($0) }))
            }
        }
    }
}
