import Foundation
import LarsalCore
import Observation
import os

/// View data of the main window for one unlocked vault (E5-S4). It holds
/// views without secrets from Rust; the only secrets are the values the user
/// asked for with Show (`shown`) and the live one-time codes on screen. Both
/// are dropped on Hide, on entry change and on lock (AT-E07).
@Observable
final class VaultModel {
    /// A sidebar place (mockup `LIB`, groups, tags, the bin).
    enum Place: Hashable {
        case all, favorites, codes, passkeys, bin
        case group(String)
        case tag(String)
    }

    /// Rows under one month header (none for the title sort).
    struct Section: Identifiable {
        let id: Int
        let title: String?
        let rows: [EntryRow]
    }

    let session: Session
    let vault: VaultInfo
    private(set) var sidebar: Sidebar?
    private(set) var place = Place.all
    private(set) var tab = Tab.all
    private(set) var search = ""
    private(set) var sort = Sort.modified
    private(set) var ascending = false
    /// The place's rows, for the title, the counts and the tabs.
    private(set) var placeRows: [EntryRow] = []
    /// The rows on screen: the place or the search, the tab, sorted.
    private(set) var rows: [EntryRow] = []
    private(set) var sections: [Section] = []
    private(set) var notice: String?
    private(set) var selection: String?
    private(set) var detail: EntryDetail?
    /// Show values by field name (AT-E07; allowed crossings: LD-220 (1)).
    private(set) var shown: [String: String] = [:]
    @ObservationIgnored private var showTurn = 0  // moves on select and leave: a late Show is dropped
    /// Live codes by entry id, for the rows and the detail (FEA-04.14).
    private(set) var codes: [String: TotpView] = [:]
    /// The copy notice (APP-03.21): a label and seconds, never the value.
    var toast: Toast?
    /// APP-05.30: the vault file is still downloading (`MSG-DISK-DOWNLOADING`).
    var downloading = false
    /// MOD-13.10 (F-074): the recommended key change, until Later or Change Now.
    var keyChangeNotice: String?
    /// MOD-09.7 (F-077): the expiry notice's search and its title.
    var expiryTitle: (search: String, title: String)?
    var overlay: Overlay? { didSet { if case .generator(let old) = oldValue, overlay != oldValue { closed(old) } } }
    /// The entry editor, while it takes the sheet (E5-S5).
    var editor: EditorModel? {
        didSet {
            if editor == nil, oldValue != nil { diskResume() }
            if (editor == nil) != (oldValue == nil) { screenChanged() }
        }
    }
    /// The shared groups' badges, label, banner and group editor (E11-S5).
    let sharing = VaultSharing()
    /// The Reports screen, while it takes the sheet (E5-S7).
    var reports: ReportsModel? { didSet { if (reports == nil) != (oldValue == nil) { screenChanged() } } }
    /// APP-01.27 (S-TIME-05): the search field's clear countdown.
    @ObservationIgnored let searchClearer = SearchClearTimer()
    /// The sheet dropped from the window top (mockup `.scrim .dlg`).
    var dialog: Dialog? { didSet { if dialog == nil, oldValue != nil { diskResume() } } }
    /// The footer's save state (APP-05): unsaved changes, last save.
    var saveStatus: SaveStatus?
    /// S-ENTRY-02 "Ask before moving to the Recycle Bin", off (MOD-04.3).
    var askBeforeBin = false
    /// APP-05: S-FILE-01, the save window and the disk watch (Saving.swift).
    @ObservationIgnored let disk = DiskState()
    @ObservationIgnored var saving: Task<Void, Never>?
    /// What runs after the unsaved-changes question (LD-199 (2)).
    @ObservationIgnored var afterLeave: (() -> Void)?
    var tagsOpen = false
    /// The search tips show (focus in an empty search field).
    var tips = false
    /// The last list update, Rust call to sorted sections (FEA-01.34).
    private(set) var lastUpdate: Duration = .zero
    private var ticker: Task<Void, Never>?
    var rating: Task<Void, Never>?
    /// The worker that rates, cancelled with `rating` (`leave`).
    var ratingWorker: Task<Bool, Never>?
    private var searchRows: [EntryRow]?
    /// All Entries rows by id: a search maps its hits onto them (FEA-01.34).
    @ObservationIgnored private var allRows: [String: EntryRow] = [:]
    /// Rows on screen with a one-time code: only they get codes.
    @ObservationIgnored private var onScreen: Set<String> = []
    @ObservationIgnored private var tickQueued = false
    @ObservationIgnored var toastTimer: Task<Void, Never>?

    init(session: Session, vault: VaultInfo) {
        self.session = session
        self.vault = vault
        sidebar = try? session.sidebar(vault: vault.id)
        reload()
    }

    var searching: Bool { !search.trimmingCharacters(in: .whitespaces).isEmpty }
    /// No entry and no group yet (mockup `emptyVault`).
    var empty: Bool { sidebar.map { $0.all == 0 && $0.groups.isEmpty && ($0.bin ?? 0) == 0 } ?? false }

    var title: String {
        if let expiryTitle, search == expiryTitle.search { return expiryTitle.title }  // MSG-09-1, MSG-09-2
        return switch place {
        case .all: "All entries"
        case .favorites: "Favorites"
        case .codes: "One-time codes"
        case .passkeys: "Passkeys"
        case .bin: "Recycle Bin"
        case .tag(let name): "#" + name
        case .group(let id): sidebar?.groups.first { $0.id == id }?.name ?? ""
        }
    }

    /// Entries of the place that need attention (FEA-05.15).
    var attention: Int { placeRows.filter { $0.rating?.attention == true }.count }

    func count(_ tab: Tab) -> Int { placeRows.filter(tab.keeps).count }

    /// FEA-01.27: choosing a place ends the search; the tab goes back to All.
    func choose(_ newPlace: Place) {
        closeReports()
        place = newPlace
        tab = .all
        search = ""
        overlay = nil
        reload()
    }

    func chooseTab(_ newTab: Tab) {
        tab = newTab
        arrange()
    }

    /// FEA-01.25: the search runs at once on each change; blank text ends it.
    func setSearch(_ text: String) {
        guard text != search else { return }
        search = text
        reload(place: false)
    }

    func setSort(_ key: Sort) {
        if key != sort {
            sort = key
            ascending = key == .title
        }
        overlay = nil
        arrange()
    }

    func setAscending(_ value: Bool) {
        ascending = value
        overlay = nil
        arrange()
    }

    /// Runs the place and the search, and keeps the selection when it is
    /// still a row; else the first row is selected (FEA-01.26).
    func reload(place reloadPlace: Bool = true) {
        let start = ContinuousClock.now
        if reloadPlace {
            placeRows = (try? session.list(vault: vault.id, view: listView))?.rows ?? []
            if place == .all { allRows = Dictionary(placeRows.map { ($0.id, $0) }) { first, _ in first } }
        }
        searchRows = nil
        notice = nil
        if searching {
            if allRows.isEmpty {
                let all = (try? session.list(vault: vault.id, view: .all))?.rows ?? []
                allRows = Dictionary(all.map { ($0.id, $0) }) { first, _ in first }
            }
            let wait = sidebar?.attention == nil ? searchWaitsForRatings(query: search) : nil  // LD-137 (4), LD-139
            let hits = wait == nil ? (try? session.search(vault: vault.id, query: search)) : nil  // FEA-01.20
            searchRows = hits?.ids.compactMap { allRows[$0] } ?? []
            notice = wait ?? hits?.notice
        }
        arrange()
        if reloadPlace { reloadShares() }  // INT-08.24: the place's label
        lastUpdate = ContinuousClock.now - start
        if searching {
            let micros = Int(lastUpdate / .microseconds(1))
            Logger.app.notice("Search updated the list in \(micros) µs")  // a number, no vault data
        }
    }

    private var listView: ListView {
        switch place {
        case .all: .all
        case .favorites: .favorites
        case .codes: .codes
        case .passkeys: .passkeys
        case .bin: .bin
        case .group(let id): .group(id: id)
        case .tag(let name): .tag(name: name)
        }
    }

    /// Filters by tab, sorts, and makes the month sections.
    private func arrange() {
        let rising = ascending
        let date: (EntryRow) -> Int64 = { [sort] row in sort == .created ? row.created : row.deleted ?? row.modified }
        let kept = (searchRows ?? placeRows).filter(tab.keeps)
        // Sorted by key and index: moving whole rows is slow in a debug build.
        var order = Array(kept.indices)
        if sort == .title {
            order.sort { ordered(kept[$0].title, kept[$1].title, ascending: rising) }
        } else {
            let keys = kept.map(date)
            order.sort { rising ? keys[$0] < keys[$1] : keys[$0] > keys[$1] }
        }
        rows = order.map { kept[$0] }
        sections = sort == .title ? [Section(id: 0, title: nil, rows: rows)] : months(date)
        if !rows.contains(where: { $0.id == selection }) {
            select(rows.first?.id)
        }
    }

    /// Month sections: one calendar look-up per month, not per row.
    private func months(_ date: (EntryRow) -> Int64) -> [Section] {
        var out: [Section] = []
        var batch: [EntryRow] = []
        var month: DateInterval?
        for row in rows {
            let when = Formats.date(date(row))
            if month?.contains(when) != true {
                if let first = batch.first {
                    out.append(Section(id: out.count, title: Formats.month(date(first)), rows: batch))
                }
                batch = []
                month = Formats.monthOf(date(row))
            }
            batch.append(row)
        }
        if let first = batch.first {
            out.append(Section(id: out.count, title: Formats.month(date(first)), rows: batch))
        }
        return out
    }

    /// Selects an entry; the shown values of the old one are dropped.
    func select(_ id: String?) {
        guard id != selection || detail == nil else { return }
        shown = [:]
        showTurn += 1
        selection = id
        overlay = nil
        detail = id.flatMap { try? session.entry(vault: vault.id, entry: $0) }
        tick()
    }

    /// This vault's screen goes away (another vault is shown, the window
    /// closes): the shown values and the live codes are dropped and the
    /// timers stop (AT-E07).
    func leave() {
        showTurn += 1
        ticker?.cancel()
        ticker = nil
        rating?.cancel()
        rating = nil
        ratingWorker?.cancel()
        ratingWorker = nil
        toastTimer?.cancel()
        toastTimer = nil
        toast = nil
        shown = [:]
        codes = [:]
        editor?.pause()  // LD-199 (2): the draft stays in Rust, shown values go
        sharing.editor?.hide()
        closeReports()  // FEA-06.12: closing the reports stops the breach check
        (dialog, overlay) = (nil, nil)  // the generator's value goes too (D-02-5)
    }

    /// This vault's screen shows: the live codes run again, and the
    /// passwords are rated off the screen thread (FEA-05.9, LD-137).
    func enter() {
        editor?.resume()
        guard ticker == nil else { return }
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                self?.tick()
                try? await Task.sleep(for: .seconds(1))
            }
        }
        rateAll()
    }

    /// Rates every password in small steps on a worker, then reloads.
    func rateAll() {
        guard rating == nil, sidebar?.attention == nil else { return }
        let session = session
        let id = vault.id
        let offset = Int32(TimeZone.current.secondsFromGMT())
        let worker = Task.detached {
            while !Task.isCancelled {
                guard let done = try? session.rate(vault: id, max: 25, utcOffset: offset) else { return false }
                if done { return true }
            }
            return false
        }
        ratingWorker = worker
        rating = Task { [weak self] in
            let done = await worker.value
            guard done, !Task.isCancelled else { return }
            self?.rated()
        }
    }

    /// Ratings are in: the counts, the words and the meters show.
    func rated() {
        sidebar = try? session.sidebar(vault: vault.id)
        allRows = [:]
        reload()
        if let selection { detail = try? session.entry(vault: vault.id, entry: selection) }
    }
}

/// Finder-like text order in either direction; equal texts are never
/// ordered, so the sort stays a strict weak order.
private func ordered(_ first: String, _ second: String, ascending: Bool) -> Bool {
    let order = first.localizedStandardCompare(second)
    return ascending ? order == .orderedAscending : order == .orderedDescending
}

extension VaultModel {
    /// Drops every view and shown value: on lock and close.
    func clear() {
        leave()
        editor?.close()  // a lock or close: Rust dropped the draft and its copies
        (editor, sharing.editor) = (nil, nil)
        afterLeave = nil
        detail = nil
        selection = nil
        search = ""
        placeRows = []
        allRows = [:]
        onScreen = []
        searchRows = nil
        rows = []
        sections = []
        sidebar = nil
    }

    /// Moves the selection up or down the list (arrow keys).
    func move(_ step: Int) {
        let index = rows.firstIndex { $0.id == selection }.map { min(max($0 + step, 0), rows.count - 1) } ?? 0
        select(rows.indices.contains(index) ? rows[index].id : nil)
    }

    /// FEA-04.14: the codes and seconds left, fetched once a second for the
    /// rows on screen and the entry shown (at most 200).
    func tick() {
        var ids = rows.filter { $0.hasTotp && onScreen.contains($0.id) }.map(\.id)
        if let selection, detail?.hasTotp == true, !ids.contains(selection) { ids.append(selection) }
        ids = Array(ids.prefix(200))
        guard !ids.isEmpty, let found = try? session.codes(vault: vault.id, entries: ids) else {
            codes = [:]
            return
        }
        var next: [String: TotpView] = [:]
        for (id, code) in zip(ids, found) {
            next[id] = code
        }
        codes = next
    }

    /// A row with a code came on screen: its code shows on the next turn.
    func rowAppeared(_ id: String) {
        onScreen.insert(id)
        guard codes[id] == nil, !tickQueued else { return }
        tickQueued = true
        Task { [weak self] in
            self?.tickQueued = false
            self?.tick()
        }
    }

    func rowDisappeared(_ id: String) { onScreen.remove(id) }

    /// Show and Hide (AT-E07: Hide drops the value).
    func toggleShow(_ field: String) async {
        guard let selection, shown[field] == nil else {
            shown[field] = nil
            return
        }
        let (session, id, turn) = (session, vault.id, showTurn)  // off the screen thread; LD-126 meter
        let value = await Task.detached { try? session.showField(vault: id, entry: selection, field: field) }.value
        if turn == showTurn, self.selection == selection { shown[field] = value }  // same vault, same entry
    }
}
