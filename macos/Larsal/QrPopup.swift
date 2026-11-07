import AppKit
import LarsalCore
import Observation
import SwiftUI
import UniformTypeIdentifiers

/// The card's literal words (FEA-10 actions and messages).
nonisolated enum QrText {
    static let title = "Show as QR Code"
    static let field = "Show Field as QR Code"
    static let join = "Show Wi-Fi Join Code"
    static let exposure = "Anyone who sees this code can read its contents."
    static let capture = "Screenshots and recordings may include this code."
    static let size = "Make this window larger to show the QR code."
    static let failed = "The QR code could not be made."
    static let saveTitle = "Save a readable QR image?"
    static let shareTitle = "Share a readable QR image?"
    static let warning =
        "This image is not encrypted. Anyone with it can read the password or other contents. "
        + "Saved or shared copies can remain after this window closes or the vault locks."
    static let shareLimit =
        "The system or browser and the app you choose may keep files or clipboard copies, even if you later "
        + "cancel. Larsal cannot erase or recall those copies."
    static let shareUnavailable = "Sharing an image is not available here. You can save the image instead."
    static let saveFailed = "The QR image could not be saved."
    static let shareFailed = "The QR image could not be shared."

    static func closing(_ seconds: Int) -> String {
        seconds == 1 ? "1 second until this window closes" : "\(seconds) seconds until this window closes"
    }
}

/// What a pop-up shows; Rust makes the matrix from this and nothing else.
nonisolated enum QrRequest: Hashable, Sendable {
    /// A saved field, as its Show gives it (FEA-10.3).
    case field(entry: String, name: String)
    /// A field of the open draft, literal.
    case draft(name: String)
    /// A Wi-Fi entry's join text (FEA-10.4).
    case wifi(entry: String)

    func make(_ session: Session, _ vault: UInt64) throws -> QrShown {
        switch self {
        case .field(let entry, let name): try session.qrShowField(vault: vault, entry: entry, field: name)
        case .draft(let name): try session.qrShowDraft(vault: vault, field: name)
        case .wifi(let entry): try session.qrShowWifi(vault: vault, entry: entry)
        }
    }
}

/// FEA-10.12's size and pitch: pure, so every version and scale is testable.
nonisolated struct QrLayout: Equatable, Sendable {
    let modules: Int
    let scale: CGFloat

    /// Whole physical pixels per module: 296 pt when it can, at least 3.
    var pitch: Int { max(3, Int((296 * scale / CGFloat(modules)).rounded(.down))) }
    var points: CGFloat { CGFloat(modules * pitch) / scale }
    /// The dialog's outer width: 22 + panel + 22, and never below 460.
    var outer: CGFloat { max(460, points + 44) }
    /// The panel's left edge in the 22-point content, on a whole pixel.
    var leading: CGFloat { (((outer - 44 - points) / 2) * scale).rounded() / scale }
}

/// One stop of the dialog's Tab cycle (FEA-10.13).
nonisolated enum QrStop: Hashable, Sendable {
    case save, share, done, cancel, confirm
}

/// One Show as QR Code pop-up (FEA-10.11 to .19). It holds the matrix, never
/// the text. `revoke` is the one way out and takes everything with it; each
/// paint and export step asks `live` first.
@Observable
final class QrPopup: Hashable {
    enum Stage: Equatable {
        case waiting, code
        case warning(QrExport)
        /// A confirmed save panel or share destination has the action.
        case exporting
        case refused(String)
        case closed
    }

    private(set) var stage = Stage.waiting
    private(set) var symbol: Qr?
    /// The chrome stopped moving: the code may paint (FEA-10.11).
    private(set) var settled = false
    /// The first complete code was painted: the 44 seconds run.
    private(set) var seconds: Int?
    /// The whole dialog does not fit its bounds (MSG-QR-SIZE).
    var sizeRefused = false
    /// Where keyboard focus is; the ring follows it (FEA-10.13).
    var focus = QrStop.done
    let purpose: String

    @ObservationIgnored private weak var model: VaultModel?
    @ObservationIgnored let request: QrRequest
    @ObservationIgnored private let session: Session
    @ObservationIgnored private let vault: UInt64
    @ObservationIgnored private let now: () -> ContinuousClock.Instant
    @ObservationIgnored private var ticket: UInt64?
    /// The live ticket number, no secret (tests ask Rust about it).
    var liveTicket: UInt64? { ticket }
    @ObservationIgnored private var consent: UInt64?
    @ObservationIgnored private var deadline: ContinuousClock.Instant?
    /// A code not yet painted (the motion, MSG-QR-SIZE) has no deadline of its
    /// own, so it is held at most this long.
    @ObservationIgnored private var holdUntil: ContinuousClock.Instant?
    /// A chosen share service takes the app's focus once (FEA-10.15).
    @ObservationIgnored private var handedOff = false
    @ObservationIgnored private var ticker: Task<Void, Never>?
    @ObservationIgnored private var watch: QrWatch?
    /// Closes the system UI an export has open.
    @ObservationIgnored private var cancelExport: (() -> Void)?
    /// FEA-10.13: what had the focus. AppKit holds it only for a text control;
    /// any other control’s focus is SwiftUI’s, and AppKit sees just the hosting view.
    @ObservationIgnored private weak var invoker: NSView?
    @ObservationIgnored private var invokerButton: Namespace.ID?

    init(model: VaultModel, request: QrRequest, purpose: String, now: @escaping () -> ContinuousClock.Instant) {
        self.model = model
        self.request = request
        self.purpose = purpose
        self.now = now
        session = model.session
        vault = model.vault.id
        invoker = (VaultModel.qrWindow()?.firstResponder as? NSText).map { ($0.delegate as? NSView) ?? $0 }
        invokerButton = QrFocus.shared.held
        watch = QrWatch(centers: VaultModel.qrCenters, window: VaultModel.qrWindow) { [weak self] kind in
            self?.signal(kind)
        }
        Self.opened.add(self)
    }

    /// Every pop-up not yet closed, for the window's own hide paths.
    private static let opened = NSHashTable<QrPopup>.weakObjects()

    /// The vault's window is about to leave the screen (FEA-10.15): before the
    /// system acts, so no code goes into a Dock tile or the way out.
    static func revokeAll(leaving window: NSWindow?) {
        guard let window, window === VaultModel.qrWindow() else { return }
        for popup in opened.allObjects { popup.revoke() }
        QrWatch.flush(window)
    }

    nonisolated static func == (lhs: QrPopup, rhs: QrPopup) -> Bool { lhs === rhs }
    nonisolated func hash(into hasher: inout Hasher) { hasher.combine(ObjectIdentifier(self)) }

    /// Asks Rust off the screen thread; a late answer is dropped (FEA-10.14).
    func start() {
        let (session, vault, request) = (session, vault, request)
        Task { [weak self] in
            let result = await Task.detached { Result { try request.make(session, vault) } }.value
            if let self {
                self.received(result)
            } else if case .success(let shown) = result {
                session.qrRelease(vault: vault, ticket: shown.ticket)
            }
        }
    }

    func received(_ result: Result<QrShown, Error>) {
        switch result {
        case .success(let shown):
            guard stage == .waiting else { return session.qrRelease(vault: vault, ticket: shown.ticket) }
            ticket = shown.ticket
            guard Self.valid(shown.symbol) else {
                session.qrRelease(vault: vault, ticket: shown.ticket)
                ticket = nil
                stage = .refused(QrText.failed)
                return
            }
            symbol = shown.symbol
            stage = .code
            holdUntil = now() + .seconds(44)
            ticker = Task { [weak self] in
                while let wait = self?.tick() { try? await Task.sleep(for: wait) }
            }
        case .failure(let error):
            guard stage == .waiting else { return }
            stage = .refused(message(error))
        }
    }

    /// SR-13: N is 29 to 185 in steps of 4, N² cells of 0 or 1, and the
    /// four-module quiet zone is white.
    nonisolated static func valid(_ symbol: Qr) -> Bool {
        let side = Int(symbol.size)
        guard (29...185).contains(side), (side - 29) % 4 == 0, symbol.modules.count == side * side else { return false }
        for (index, cell) in symbol.modules.enumerated() {
            let (row, column) = (index / side, index % side)
            let quiet = min(row, column) < 4 || max(row, column) >= side - 4
            if cell > 1 || (quiet && cell != 0) { return false }
        }
        return true
    }

    /// The motion ended, or Reduce Motion is on (FEA-10.11). Never restarts
    /// the deadline.
    func settle() { settled = true }

    /// The source, the deadline and the request all hold (FEA-10.14).
    func live() -> Bool {
        guard stage != .closed, let ticket else { return false }
        if let end = deadline ?? holdUntil, now() >= end { return false }
        return session.qrIsCurrent(vault: vault, ticket: ticket)
    }

    /// What the code view may paint now; asked before every repaint.
    func paintable() -> Qr? {
        guard stage == .code, settled, !sizeRefused, let symbol else { return nil }
        guard live() else {
            Task { [weak self] in self?.revoke() }
            return nil
        }
        return symbol
    }

    /// The first complete code is on screen: the 44 seconds start, once, and
    /// VoiceOver hears the dialog once (FEA-10.13).
    func painted() {
        guard deadline == nil else { return }
        deadline = now() + .seconds(44)
        seconds = 44
        let line = [QrText.title, purpose, QrText.exposure, QrText.capture, QrText.closing(44)]
        AccessibilityNotification.Announcement(line.joined(separator: ". ")).post()
    }

    /// One check; nil once closed. The next check falls on the next whole
    /// second of the count, read from elapsed time (FEA-10.14).
    @discardableResult
    func tick() -> Duration? {
        guard stage != .closed else { return nil }
        guard ticket == nil || live() else {
            revoke()
            return nil
        }
        guard let deadline else { return .seconds(1) }
        let left = deadline - now()
        let parts = left.components
        seconds = Int(parts.seconds) + (parts.attoseconds > 0 ? 1 : 0)
        // The rest of this second, so the count turns on time.
        return parts.attoseconds > 0 ? .nanoseconds(parts.attoseconds / 1_000_000_000) : .seconds(1)
    }

    /// FEA-10.15: revoke, but for what a confirmed system UI causes by itself:
    /// a panel covering the window, and the one blur of a chosen share service.
    /// Any other blur is the user going elsewhere.
    private func signal(_ kind: QrSignal) {
        if stage == .exporting {
            if kind == .covered { return }
            if kind == .blur, handedOff {
                handedOff = false
                return
            }
        }
        revoke()
    }

    /// Everything goes now: pixels, matrix, timers, watch, system UI and the
    /// ticket with any consent. No exit animation; nothing comes back.
    func revoke() {
        guard stage != .closed else { return }
        stage = .closed
        symbol = nil
        ticker?.cancel()
        ticker = nil
        watch = nil
        consent = nil
        let close = cancelExport
        cancelExport = nil
        close?()
        if let ticket { session.qrRelease(vault: vault, ticket: ticket) }
        ticket = nil
        if let model {
            if case .qrCode(let shown) = model.dialog, shown === self { model.dialog = nil }
            if model.qrPopup === self { model.qrPopup = nil }
        }
        restoreFocus()
    }

    /// FEA-10.13: back to the invoker if it still exists, else the entry list.
    /// A lock's unlock screen takes focus by itself (UnlockView).
    private func restoreFocus() {
        if let invoker, let window = invoker.window {
            window.makeFirstResponder(invoker)
        } else {
            QrFocus.shared.give(to: model, button: invokerButton)
        }
    }

    /// The dialog left the window (Done, Escape, a click outside, a lock).
    func dialogGone() {
        if stage != .exporting { revoke() }
    }

    /// Escape: a warning goes back, as its Cancel; the pop-up closes.
    func escape() {
        if case .warning = stage { cancelWarning() } else { revoke() }
    }

    /// A click on the dimmed window: a warning stays (FEA-10.13's trap).
    func scrimClicked() {
        if case .warning = stage { return }
        revoke()
    }

    /// Too long for the dialog's head: it wraps in its own scroll (FEA-10.13).
    var purposeIsLong: Bool { purpose.count > 80 }

    // MARK: Exports (FEA-10.16 to .19)

    var shareAvailable: Bool { !VaultModel.qrShareRoutes.isEmpty }
    var canExport: Bool { stage == .code && seconds != nil && !sizeRefused }

    /// Save Image… or Share…: the warning, every attempt.
    func ask(_ action: QrExport) {
        guard canExport, action == .save || shareAvailable else { return }
        guard live() else { return revoke() }
        stage = .warning(action)
        focus = .cancel
    }

    /// Cancel: back to the live pop-up, on the same deadline.
    func cancelWarning() {
        guard case .warning(let action) = stage else { return }
        guard live() else { return revoke() }
        stage = .code
        focus = action == .save ? .save : .share
    }

    /// The warning's confirmation: the one consent, then the pixels clear
    /// before any system UI starts. No way back to the pop-up from here.
    func confirm() {
        guard case .warning(let action) = stage, let ticket else { return }
        guard live(), let consent = try? session.qrConsent(vault: vault, ticket: ticket, action: action) else {
            return revoke()
        }
        self.consent = consent
        stage = .exporting
        symbol = nil
        model?.dialog = nil
        switch action {
        case .save: cancelExport = VaultModel.qrSavePanel { [weak self] url in self?.chosen(url) }
        case .share: share()
        }
    }

    /// The save panel answered: Rust writes after its own last check.
    private func chosen(_ url: URL?) {
        guard stage == .exporting else { return }
        cancelExport = nil
        guard let url, live(), let ticket, let consent else { return revoke() }
        let (session, vault, path) = (session, vault, url.path(percentEncoded: false))
        Task { [weak self] in
            let result = await Task.detached {
                Result { try session.qrSavePng(vault: vault, ticket: ticket, consent: consent, path: path) }
            }.value
            if case .failure = result { self?.model?.notify(.init(glyph: "warning", text: QrText.saveFailed)) }
            self?.revoke()
        }
    }

    /// FEA-10.18: an in-memory item whose bytes are made on request, live,
    /// with no file behind it. Rechecked right before the first system call.
    private func share() {
        let item = NSItemProvider()
        item.suggestedName = "Larsal QR"
        let png = UTType.png.identifier
        item.registerDataRepresentation(forTypeIdentifier: png, visibility: .all) { [weak self] send in
            Task { @MainActor in
                if let bytes = self?.shareBytes() {
                    send(bytes, nil)
                } else {
                    send(nil, CocoaError(.fileReadUnknown))
                }
            }
            return nil
        }
        guard live() else { return revoke() }
        cancelExport = VaultModel.qrSharePresenter(item) { [weak self] chosen in
            if chosen { self?.handedOff = true } else { self?.revoke() }
        }
    }

    /// A destination asks for the item: only inside the original deadline.
    private func shareBytes() -> Data? {
        guard stage == .exporting, live(), let ticket, let consent else {
            model?.notify(.init(glyph: "warning", text: QrText.shareFailed))
            revoke()
            return nil
        }
        return try? session.qrSharePng(vault: vault, ticket: ticket, consent: consent)
    }
}
