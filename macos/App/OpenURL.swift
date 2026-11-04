import AppCore
import AppKit

/// The open-URL action (MOD-08.31, F-080): Rust resolves the URL and picks
/// its kind; a command asks MSG-08-2 here, and only a URL without any
/// protected value comes back to the system opener.
extension VaultModel {
    /// Opens the selected entry's URL.
    func openURL() {
        guard let id = detail?.id else { return }
        openURL(entry: id)
    }

    func openURL(entry: String) {
        let session = session
        let vault = vault.id
        Task {
            let action = await Task.detached { try? session.openUrl(vault: vault, entry: entry) }.value
            switch action {
            case .open(let url):
                if let url = URL(string: url) { NSWorkspace.shared.open(url) }
            case .ask(let message, let command, let remember, let clock):
                ask(message, command: command, clock: clock, remember: remember, entry: entry)
            case .refused(let message):
                notify(Toast(glyph: "warning", text: message))
            case .done, .nothing, nil:
                break
            }
        }
    }

    /// MSG-08-2: Yes or No (default No), with "Remember my choice" only when
    /// Rust offers it (F-071); never in a hidden launch (AGENTS.md rule 10).
    private func ask(_ message: String, command: String, clock: Int64, remember offered: Bool, entry: String) {
        guard !launchHidden() else { return }
        let box = ScreenProtection.shared.alert()
        box.messageText = message
        box.informativeText = command
        box.addButton(withTitle: "No")
        box.addButton(withTitle: "Yes")
        box.showsSuppressionButton = offered
        box.suppressionButton?.title = "Remember my choice"
        guard box.runModal() == .alertSecondButtonReturn else { return }
        let remember = offered && box.suppressionButton?.state == .on
        // F-128: false only when the command no longer reads as shown on the question's clock
        // (a sync changed it): ask again.
        let ran = try? session.runUrlCommand(
            vault: vault.id, entry: entry, command: command, at: clock, remember: remember)
        if ran == false { openURL(entry: entry) }
    }
}

/// Website icons on request (MOD-06.11, APP-01.21, F-094): Rust downloads,
/// decodes and sets them; Swift sees a count and a notice.
extension VaultModel {
    /// "Fetch Site Icon" for the selected entry; off the main thread.
    func fetchSiteIcon() {
        guard let id = detail?.id else { return }
        fetchSiteIcons([id], select: id)
    }

    /// "Fetch Site Icons for Group…" (APP-08 `action.download_group_icons`,
    /// MOD-06.11's bulk download): every live entry of the group and its
    /// subgroups, `view` being the group's list.
    func fetchSiteIcons(in view: ListView) {
        guard let rows = try? session.list(vault: vault.id, view: view).rows, !rows.isEmpty else { return }
        fetchSiteIcons(rows.map(\.id), select: nil)
    }

    /// `select`: the entry selected after a change, else the selection then.
    private func fetchSiteIcons(_ ids: [String], select: String?) {
        let session = session
        let vault = vault.id
        Task {
            let result = await Task.detached {
                Result { try session.fetchSiteIcons(vault: vault, entries: ids) }
            }.value
            switch result {
            case .success(let fetched):
                if fetched.set > 0 { afterChange(select: select ?? selection) }
                notify(Toast(glyph: fetched.set > 0 ? "check" : "warning", text: fetched.message))
            case .failure(let error):
                notify(Toast(glyph: "warning", text: message(error)))
            }
        }
    }
}
