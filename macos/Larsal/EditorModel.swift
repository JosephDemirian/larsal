import Foundation
import LarsalCore
import Observation

/// View data of the entry editor (E5-S5, mockup `editorView`). The draft
/// lives in Rust; this holds its view without secrets apart from LD-220's
/// allowed crossings: the shown password (`shownPassword`), fetched with Show and dropped on
/// Hide, on leaving the editor and on lock (AT-E07); typed passwords go
/// straight to Rust.
@Observable
final class EditorModel {
    /// The editor's pages (mockup `ED_PAGES`).
    enum Page: String, CaseIterable {
        case entry = "Entry"
        case advanced = "Advanced"
        case icon = "Icon"
        case autoType = "Auto-Type"
        case browser = "Browser"
        case ssh = "SSH Agent"
        case properties = "Properties"
        case history = "History"

        var glyph: String {
            switch self {
            case .entry: "key"
            case .advanced: "list-bullets"
            case .icon: "image-square"
            case .autoType: "keyboard"
            case .browser: "globe-simple"
            case .ssh: "terminal-window"
            case .properties: "info"
            case .history: "clock-counter-clockwise"
            }
        }
    }

    let session: Session
    let vault: VaultInfo
    /// Show as QR Code of a draft field (FEA-10.3): the vault's pop-up.
    @ObservationIgnored var showQr: (String) -> Void = { _ in }
    private(set) var view: EditorView
    var page = Page.entry
    /// The password as shown in the field (Show; LD-220 (1)).
    private(set) var shownPassword: String?
    /// The password's strength, rated in Rust off the screen thread after
    /// typing pauses (FEA-05.7, LD-137).
    private(set) var rating: Rating?
    /// The draft's live one-time code (FEA-04.14).
    private(set) var code: TotpView?
    /// A refusal from Rust, in plain words (no value).
    var problem: String?
    /// Protected values shown with Show, by name: custom and standard fields.
    private(set) var shownFields: [String: String] = [:]
    /// Uses of a generated password (E5-S6): the masked field starts anew.
    private(set) var applied = 0
    /// Files waiting to be added, with the questions already answered.
    @ObservationIgnored var pending: [PendingFile] = []
    @ObservationIgnored private var rater: Task<Void, Never>?
    @ObservationIgnored private var ticker: Task<Void, Never>?

    init(session: Session, vault: VaultInfo, view: EditorView) {
        self.session = session
        self.vault = vault
        self.view = view
        // LD-199 (1), S-CONV-02 (on by default): the password opens masked;
        // its value reaches Swift only after Show (rule 4).
        rate(after: .zero)
        startTicker()
    }

    var title: String { view.new ? "New entry" : "Edit entry" }

    /// "GitHub · Work", or "In Work · Personal" for a new entry.
    var subtitle: String {
        view.new ? "In \(view.groupName) · \(vault.name)" : "\(view.title) · \(view.groupName)"
    }

    /// Re-reads the draft's view after a change.
    func refresh() {
        if let next = try? session.editor(vault: vault.id) { view = next }
    }

    /// Runs one draft change; a refusal shows its reason.
    func run(_ change: () throws -> Void) {
        do {
            try change()
            problem = nil
        } catch {
            problem = message(error)
        }
        refresh()
    }

    /// A symbol and a colour become the entry's custom icon (LD-192 (1)):
    /// the tile is drawn here, Rust stores the PNG.
    func chooseSymbol(_ glyph: String, _ color: String) {
        guard let png = SymbolIcon.png(glyph, color) else {
            problem = "The icon could not be made."
            return
        }
        run {
            let icon = try session.addCustomIcon(vault: vault.id, png: png, name: SymbolIcon.name(glyph, color))
            try session.setCustomIcon(vault: vault.id, icon: icon)
        }
    }

    func set(_ field: EditText, _ value: String) {
        run { try session.setText(vault: vault.id, field: field, value: value) }
        // A protected field the user types in shows what was typed (F-060,
        // LD-207): it came from the keyboard, not from Rust.
        if view.protected.contains(field) { shownFields[field.name] = value }
    }

    /// The password field changed: the text goes to Rust; the field keeps
    /// what it shows, nothing else here does.
    func passwordTyped(_ text: String) {
        shownPassword = text
        maskedTyped(text)
    }

    /// The masked field changed: the text goes to Rust; Swift keeps none
    /// (the secure field holds what it shows).
    func maskedTyped(_ text: String) {
        run { _ = try session.setPassword(vault: vault.id, value: text) }
        rate(after: .milliseconds(300))
    }

    /// The generator's value became the draft's password in Rust (E5-S6):
    /// the field shows it as it showed the old one, clear or masked.
    func generated() {
        refresh()
        if shownPassword != nil { shownPassword = (try? session.draftPassword(vault: vault.id)) ?? "" }
        applied += 1
        rate(after: .zero)
    }

    /// Show and Hide of the password field (AT-E07: Hide drops the value).
    func toggleShowPassword() {
        if shownPassword == nil {
            shownPassword = (try? session.draftPassword(vault: vault.id)) ?? ""
        } else {
            shownPassword = nil
        }
    }

    func toggleShowField(_ name: String) {
        if shownFields[name] != nil {
            shownFields[name] = nil
        } else {
            shownFields[name] = try? session.showDraftField(vault: vault.id, name: name)
        }
    }

    /// Rates the draft's password on a worker once typing has paused.
    private func rate(after pause: Duration) {
        rater?.cancel()
        let session = session
        let id = vault.id
        rater = Task { [weak self] in
            if pause > .zero { try? await Task.sleep(for: pause) }
            guard !Task.isCancelled else { return }
            let next = await Task.detached { try? session.rateDraft(vault: id) }.value
            guard !Task.isCancelled else { return }
            self?.rating = next ?? nil
        }
    }

    /// The live code, once a second, while the draft has settings.
    private func startTicker() {
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                self?.tick()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func tick() {
        code = view.totp == nil ? nil : (try? session.draftCode(vault: vault.id)) ?? nil
    }

    /// The vault goes out of view with the editor open: the shown values
    /// go and the timers stop; the draft stays in Rust (AT-E07).
    func pause() {
        rater?.cancel()
        ticker?.cancel()
        ticker = nil
        shownPassword = nil
        shownFields = [:]
        code = nil
    }

    /// The vault shows again: the live code runs again.
    func resume() {
        if ticker == nil { startTicker() }
    }

    /// The editor goes away: timers stop and the shown values go (AT-E07).
    func close() {
        rater?.cancel()
        ticker?.cancel()
        shownPassword = nil
        shownFields = [:]
        code = nil
    }

    /// A file to add and the questions it passed (MOD-05.5).
    struct PendingFile {
        let url: URL
        var overwrite = false
        var big = false
    }

    /// Adds waiting files until one needs a question (MOD-05.5: a same
    /// name, then more than 5 MiB); returns that question, or nil.
    func nextFile() async -> VaultModel.Dialog? {
        while let item = pending.first {
            let name = item.url.lastPathComponent
            let path = item.url.path(percentEncoded: false)
            if !item.overwrite, view.attachments.contains(where: { $0.name == name }) {
                return .overwriteAttachment(name: name)
            }
            let size = (try? item.url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
            if !item.big, size > 5_242_880 {
                return .bigFile(name: name, megabytes: String(format: "%.1f", Double(size) / 1_048_576))
            }
            pending.removeFirst()
            // Read off the screen thread: a file may be large or slow.
            let (session, id) = (session, vault.id)
            let done = await Task.detached { Result { try session.attachFile(vault: id, path: path) } }.value
            run { try done.get() }
        }
        return nil
    }

    /// The answer to the first waiting file's question.
    func answer(_ yes: Bool, overwrite: Bool) {
        guard !pending.isEmpty else { return }
        if !yes {
            pending.removeFirst()
        } else if overwrite {
            pending[0].overwrite = true
        } else {
            pending[0].big = true
        }
    }

    /// The Discard sheet's sentence from the draft's changes (MOD-03.11
    /// labels): "You changed the password and the tags."
    var changeSentence: String {
        let words = view.changed.map { label -> String in
            switch label {
            case "URL": "the website"
            case "Custom attributes": "the custom fields"
            case "Expiration": "the expiry"
            default: "the " + label.lowercased()
            }
        }
        guard let last = words.last else { return "" }
        let head = words.dropLast().joined(separator: ", ")
        return "You changed " + (head.isEmpty ? last : head + " and " + last) + "."
    }
}
