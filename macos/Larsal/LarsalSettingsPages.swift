import AppKit
import LarsalCore
import SwiftUI

struct LarsalSettingsGeneralPage: View {
    let model: LarsalSettingsModel

    /// S-START-12: the days the choice offers (0 = expired entries only).
    static let days: [Int64] = [0, 1, 3, 7, 14, 30, 90]

    static func within(_ days: Int64) -> String {
        days == 0 ? "Expired only" : days == 1 ? "Within 1 day" : "Within \(days) days"
    }

    var body: some View {
        LarsalSettingsGroup("Startup") {
            LarsalSettingsRow("Open Larsal at login") {
                Switch(label: "Login", isOn: Binding(get: { model.loginOn }, set: { model.loginOn = $0 }))
                    .disabled(!model.loginEditable)
            }
            LarsalSettingsRow("Reopen the last vaults at start") {
                LarsalSettingsSwitch(model: model, key: "recent.reopen_at_start", label: "Reopen")
            }
            LarsalSettingsRow("Remember recent vaults", "Also remembers which key file each one used.") {
                LarsalSettingsStepper(model: model, key: "recent.count", range: 1...25)
                LarsalSettingsSwitch(model: model, key: "recent.remember", label: "Recent")
            }
            LarsalSettingsRow("Show entries that expire soon after unlocking") {
                let days = model.number("expiry.notice_days")
                LarsalSettingsSelect(
                    label: "Expiry days", title: Self.within(days), choices: Self.days.map(Self.within),
                    chosen: Self.days.firstIndex(of: days), disabled: model.isDisabled("expiry.notice_days")
                ) { model.setNumber("expiry.notice_days", Self.days[$0]) }
                LarsalSettingsSwitch(model: model, key: "expiry.notice_on_unlock", label: "Expiry")
            }
            // Card words over the mockup's "once a day" (APP-01.19: weekly).
            LarsalSettingsRow("Check for updates", "Asks GitHub once a week. Nothing else leaves this Mac.") {
                LarsalSettingsSwitch(model: model, key: "update.check", label: "Updates").later(
                    LarsalSettingsWaits.updates)
            }
            LarsalSettingsRow("Include beta versions", sub: true) {
                LarsalSettingsSwitch(model: model, key: "update.include_beta", label: "Beta").later(
                    LarsalSettingsWaits.updates)
            }
        }
        LarsalSettingsGroup("Saving") {
            // LD-167: the card's words over the mockup's "Save after every change".
            LarsalSettingsRow("Save changes as you make them") {
                LarsalSettingsSwitch(model: model, key: "save.after_every_change", label: "Autosave")
            }
            LarsalSettingsRow("Save when locking") {
                LarsalSettingsSwitch(model: model, key: "save.on_lock", label: "Save on lock")
            }
            LarsalSettingsRow("Reload the vault when another app changes it", "Merges your unsaved changes first.") {
                LarsalSettingsSwitch(model: model, key: "save.reload_on_change", label: "Reload")
            }
            LarsalSettingsRow("Keep a backup before saving", model.text("backup.pattern"), mono: true) {
                LarsalSettingsSwitch(model: model, key: "backup.enabled", label: "Backup")
            }
            LarsalSettingsRow("Safe saving", "Writes a temporary file, then replaces the vault in one step.") {
                saveMethod
            }
        }
        LarsalSettingsGroup("Entries") {
            LarsalSettingsRow("Ask before moving to the Recycle Bin") {
                LarsalSettingsSwitch(model: model, key: "entry.confirm_recycle", label: "Confirm")
            }
            LarsalSettingsRow("Make a password for every new entry") {
                LarsalSettingsSwitch(model: model, key: "entry.autogen_password", label: "Autogen")
            }
            LarsalSettingsRow("Double-clicking a row copies") {
                let copies = model.flag("list.copy_on_double_click")
                LarsalSettingsSelect(
                    label: "Double-click", title: copies ? "Password" : "Nothing", choices: ["Password", "Nothing"],
                    chosen: copies ? 0 : 1
                ) { model.setFlag("list.copy_on_double_click", $0 == 0) }
            }
            LarsalSettingsRow("Hide Larsal after copying") {
                let mode = model.text("window.hide_on_copy.mode")
                LarsalSettingsSelect(
                    label: "Hide by", title: mode == "background" ? "Move behind other windows" : "Minimize",
                    choices: ["Minimize", "Move behind other windows"], chosen: mode == "background" ? 1 : 0,
                    disabled: model.isDisabled("window.hide_on_copy.mode")
                ) { model.setText("window.hide_on_copy.mode", $0 == 0 ? "minimize" : "background") }
                LarsalSettingsSwitch(model: model, key: "window.hide_on_copy", label: "Hide")
            }
        }
        LarsalSettingsGroup("Look") {
            LarsalSettingsRow("Appearance") {
                let themes = ["auto", "light", "dark"]
                let selected = themes.firstIndex(of: model.text("ui.theme")) ?? 0
                Segments(items: ["System", "Light", "Dark"], selected: selected) {
                    model.setText("ui.theme", themes[$0])
                }
            }
            LarsalSettingsRow(
                title: Text(verbatim: "Colour digits and symbols in passwords"),
                detail: larsalSettingsSample("x9!Lq#4vT").font(.mono(12)).kerning(0.24)
            ) {
                LarsalSettingsSwitch(model: model, key: "display.color_passwords", label: "Colour")
            }
            LarsalSettingsRow("Monospace font in notes") {
                LarsalSettingsSwitch(model: model, key: "display.monospace_notes", label: "Mono notes")
            }
            LarsalSettingsRow("Show Larsal in the menu bar") {
                let colourful = model.text("menubar_icon.style") == "colorful"
                LarsalSettingsSelect(
                    label: "Menu bar icon", title: colourful ? "Colourful icon" : "Monochrome icon",
                    choices: ["Monochrome icon", "Colourful icon"], chosen: colourful ? 1 : 0,
                    disabled: model.isDisabled("menubar_icon.style")
                ) { model.setText("menubar_icon.style", $0 == 0 ? "monochrome" : "colorful") }
                LarsalSettingsSwitch(model: model, key: "menubar_icon.show", label: "Menu bar")
            }
            LarsalSettingsRow("Closing the window keeps Larsal running") {
                LarsalSettingsSwitch(model: model, key: "window.close_hides", label: "Hide on close")
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
        return LarsalSettingsSelect(label: "Safe saving", title: titles[chosen], choices: titles, chosen: chosen) {
            model.setFlag("save.alternative", $0 != 0)
            if $0 != 0 { model.setNumber("save.alternative.mode", $0 == 2 ? 1 : 0) }
        }
    }
}

struct LarsalSettingsSecurityPage: View {
    let model: LarsalSettingsModel

    /// Seconds as the steppers show them.
    static func seconds(_ value: Int64) -> String { "\(value) s" }
    static func minutes(_ value: Int64) -> String { value % 60 == 0 ? "\(value / 60) min" : "\(value) s" }

    var body: some View {
        LarsalSettingsGroup("Timeouts") {
            LarsalSettingsRow("Clear the clipboard after", "Copied passwords and codes disappear from the clipboard.") {
                LarsalSettingsStepper(
                    model: model, key: "clipboard.clear.seconds", range: 1...999, step: 5, show: Self.seconds)
                LarsalSettingsSwitch(model: model, key: "clipboard.clear.enabled", label: "Clipboard")
            }
            LarsalSettingsRow("Lock after no use for") {
                LarsalSettingsStepper(
                    model: model, key: "lock.idle.seconds", range: 60...43_200, show: Self.minutes, scale: 60)
                LarsalSettingsSwitch(model: model, key: "lock.idle.enabled", label: "Idle lock")
            }
            LarsalSettingsRow("Clear the search after") {
                LarsalSettingsStepper(model: model, key: "search.clear_after_minutes", range: 1...1_440) { "\($0) min" }
                LarsalSettingsSwitch(model: model, key: "search.clear_when_idle", label: "Clear search")
            }
        }
        LarsalSettingsGroup("Locking") {
            LarsalSettingsRow(
                "Unlock with Touch ID",
                "Your vault key stays in the Secure Enclave keychain until Larsal quits or 8 hours pass."
            ) {
                LarsalSettingsSwitch(model: model, key: "quick_unlock.enabled", label: "Touch ID").later(
                    LarsalSettingsWaits.touchID)
            }
            LarsalSettingsRow("Lock when the screen locks") {
                LarsalSettingsSwitch(model: model, key: "lock.on_screen_lock", label: "Screen lock")
            }
            LarsalSettingsRow("Lock when you switch user") {
                LarsalSettingsSwitch(model: model, key: "lock.on_user_switch", label: "User switch")
            }
            LarsalSettingsRow("Lock when the window is minimized") {
                LarsalSettingsSwitch(model: model, key: "lock.on_minimize", label: "Minimize")
            }
        }
        LarsalSettingsGroup("Showing secrets") {
            LarsalSettingsRow("Hide passwords in the editor") {
                LarsalSettingsSwitch(model: model, key: "display.hide_password_in_editor", label: "Editor")
            }
            LarsalSettingsRow("Hide passwords in the detail pane") {
                LarsalSettingsSwitch(model: model, key: "display.hide_password_in_preview", label: "Preview")
            }
            LarsalSettingsRow("Hide one-time codes in the detail pane") {
                LarsalSettingsSwitch(model: model, key: "display.hide_totp_in_preview", label: "Codes")
            }
            LarsalSettingsRow("Hide notes") {
                LarsalSettingsSwitch(model: model, key: "display.hide_notes", label: "Notes")
            }
            LarsalSettingsRow("Show dots for empty passwords") {
                LarsalSettingsSwitch(model: model, key: "display.dots_for_empty", label: "Dots")
            }
        }
        LarsalSettingsGroup("Privacy") {
            // APP-10: allowing capture is for this run only, never stored.
            LarsalSettingsRow(
                "Let other apps record Larsal's windows",
                "Screen sharing and screenshots show Larsal as a blank window while this is off."
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
