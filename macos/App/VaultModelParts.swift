import AppCore

/// The vault view's list tabs and sort keys, and what shows once after an
/// unlock (MOD-09.7, MOD-13.10) or follows a change of screen (APP-01.27).
extension VaultModel {
    /// The list's tabs (mockup `TABS`).
    enum Tab: String, CaseIterable {
        case all = "All"
        case codes = "Two-step codes"
        case passkeys = "Passkeys"
        case attention = "Needs attention"

        func keeps(_ row: EntryRow) -> Bool {
            switch self {
            case .all: true
            case .codes: row.hasTotp
            case .passkeys: row.passkey
            case .attention: row.rating?.attention == true
            }
        }
    }

    /// The sort menu's keys.
    enum Sort: String, CaseIterable {
        case modified = "Modified"
        case title = "Title"
        case created = "Created"
    }

    /// Once after the unlock (MOD-09.7, APP-01.18, MOD-13.10, F-077,
    /// F-074): the expiry notice's search in the search field, titled; the
    /// key change notice.
    func afterUnlock(_ after: AfterUnlock) {
        keyChangeNotice = after.keyChange
        // APP-05.26: at unlock the rollback guard only warns.
        if let notice = after.diskNotice { notify(Toast(glyph: "warning", text: notice)) }
        if let search = after.expirySearch, let title = after.expiryTitle {
            expiryTitle = (search, title)
            setSearch(search)
        }
    }

    /// APP-01.27, F-083: a change of screen (the editor or the reports open
    /// or close) restarts a running search clear countdown from full.
    func screenChanged() {
        if searchClearer.running { searchClearer.focus(false, self) }
    }
}
