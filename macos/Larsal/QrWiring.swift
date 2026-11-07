import AppKit
import LarsalCore
import SwiftUI

/// FEA-10.15's system signals, by what a confirmed system UI may cause itself.
enum QrSignal {
    case hard, blur, covered
}

/// Watches them for one pop-up. Dock minimize and app hide also have their
/// "will" signal, heard before the system acts, with the pixels gone first.
final class QrWatch {
    // Touched on the main actor and in the last owner's deinit only.
    nonisolated(unsafe) private var tokens: [(NotificationCenter, any NSObjectProtocol)] = []
    nonisolated(unsafe) private var relay: (NotificationCenter, Relay)?

    init(centers: QrCenters, window: @escaping () -> NSWindow?, signal: @escaping @MainActor (QrSignal) -> Void) {
        let hard: [(NotificationCenter, Notification.Name)] = [
            (centers.local, NSApplication.didHideNotification),
            (centers.local, NSApplication.willTerminateNotification),
            (centers.workspace, NSWorkspace.willSleepNotification),
            (centers.workspace, NSWorkspace.screensDidSleepNotification),
            (centers.workspace, NSWorkspace.sessionDidResignActiveNotification),
        ]
        for (center, name) in hard { observe(center, name) { signal(.hard) } }
        observe(centers.local, NSApplication.willHideNotification) {
            signal(.hard)
            Self.flush(window())
        }
        observe(centers.local, NSApplication.didResignActiveNotification) { signal(.blur) }
        // Only the vault's own window counts; a settings window may come and go.
        let own: (AnyObject?) -> Bool = { $0 != nil && $0 === window() }
        for name in [NSWindow.didMiniaturizeNotification, NSWindow.willCloseNotification] {
            observeWindow(centers.local, name) { if own($0) { signal(.hard) } }
        }
        observeWindow(centers.local, NSWindow.willMiniaturizeNotification) {
            if own($0) {
                signal(.hard)
                Self.flush(window())
            }
        }
        observeWindow(centers.local, NSWindow.didChangeOcclusionStateNotification) {
            if own($0), window()?.occlusionState.contains(.visible) == false { signal(.covered) }
        }
        let locked = Relay { signal(.hard) }
        if let system = centers.distributed as? DistributedNotificationCenter {
            // As LockSignals: a plain observer is held back while Larsal is not
            // the front app, and an export can be open behind another app.
            system.addObserver(
                locked, selector: #selector(Relay.fire), name: LockSignals.screenIsLocked, object: nil,
                suspensionBehavior: .deliverImmediately)
        } else {
            centers.distributed.addObserver(
                locked, selector: #selector(Relay.fire), name: LockSignals.screenIsLocked, object: nil)
        }
        relay = (centers.distributed, locked)
    }

    /// The revoke's new state reaches the window's pixels now, not at the next
    /// turn of the run loop.
    @MainActor
    static func flush(_ window: NSWindow?) {
        window?.contentView?.layoutSubtreeIfNeeded()
        window?.displayIfNeeded()
        CATransaction.flush()
    }

    deinit {
        for (center, token) in tokens { center.removeObserver(token) }
        if let relay { relay.0.removeObserver(relay.1) }
    }

    private func observe(
        _ center: NotificationCenter, _ name: Notification.Name, _ body: @escaping @MainActor () -> Void
    ) {
        tokens.append((center, center.addObserver(forName: name, object: nil, queue: nil) { _ in onMain(body) }))
    }

    private func observeWindow(
        _ center: NotificationCenter, _ name: Notification.Name, _ body: @escaping @MainActor (AnyObject?) -> Void
    ) {
        let token = center.addObserver(forName: name, object: nil, queue: nil) { note in
            nonisolated(unsafe) let object = note.object as AnyObject?
            onMain { body(object) }
        }
        tokens.append((center, token))
    }
}

/// Where the watch listens; tests pass private centers and never post a real
/// system notification.
struct QrCenters {
    var workspace: NotificationCenter = NSWorkspace.shared.notificationCenter
    var distributed: NotificationCenter = DistributedNotificationCenter.default()
    var local: NotificationCenter = .default
}

extension VaultModel {
    /// FEA-10.17's panel, already warned: `Larsal QR.png` by default. Gives
    /// back what closes it. Never shown by tests (AGENTS.md rule 10).
    static var qrSavePanel: (@escaping (URL?) -> Void) -> () -> Void = { done in
        // ponytail: starts in the home folder, as the export panel does.
        let panel = NSSavePanel()
        panel.title = "Save Image"
        panel.nameFieldStringValue = "Larsal QR.png"
        panel.allowedContentTypes = [.png]
        panel.directoryURL = URL(fileURLWithPath: NSHomeDirectory())
        panel.canCreateDirectories = true
        panel.begin { answer in done(answer == .OK ? panel.url : nil) }
        return { panel.cancel(nil) }
    }

    /// FEA-10.18: the system services proved for an in-memory image without
    /// Copy, Print, automatic Save or staging. None is proved yet, so Share…
    /// stays unavailable (MSG-QR-SHARE-UNAVAILABLE, W-08). A name goes here
    /// only with its proof; a title never identifies a service.
    static var qrShareRoutes: [NSSharingService.Name] = []

    /// Offers `item` to the proved routes only. Gives back what closes the
    /// picker. Never shown by tests (AGENTS.md rule 10).
    static var qrSharePresenter: (NSItemProvider, @escaping (Bool) -> Void) -> () -> Void = { item, done in
        let picker = NSSharingServicePicker(items: [item])
        let policy = QrSharePolicy(routes: qrShareRoutes, done: done)
        picker.delegate = policy
        if let view = WindowRules.shared.window?.contentView {
            picker.show(relativeTo: .zero, of: view, preferredEdge: .minY)
        }
        return {
            picker.close()
            _ = policy
        }
    }

    static var qrCenters = QrCenters()
    static var qrWindow: () -> NSWindow? = { WindowRules.shared.window }
    static var qrClock: () -> ContinuousClock.Instant = { .now }

    /// FEA-10.2: the menu and its shortcut act in the active Larsal window, as
    /// `copyCommand` does: never while another of its windows is in front, or
    /// with the window in the Dock. No key window and a window at its place is
    /// the hidden launch, which never orders it in (AGENTS.md rule 10). Hidden
    /// to the icon Larsal is an accessory app, with no menu to reach this.
    private var qrInFront: Bool {
        let (key, main) = (WindowRules.shared.keyWindow(), Self.qrWindow())
        if let key { return key === main }
        return main?.isMiniaturized != true
    }

    /// Show as QR Code for a saved field; Password when no field is named.
    func showQr(field: String = "Password") {
        guard let selection else { return }
        openQr(.field(entry: selection, name: field), purpose: Self.qrPurpose(field))
    }

    /// Show as QR Code for a field of the open draft: its unsaved text.
    func showDraftQr(field: String) {
        openQr(.draft(name: field), purpose: Self.qrPurpose(field))
    }

    /// Show Wi-Fi Join Code.
    func showWifiJoin() {
        guard let selection else { return }
        openQr(.wifi(entry: selection), purpose: "Wi-Fi join code")
    }

    /// ⌃⌥⌘Q: the focused protected field, else the entry's Password; the
    /// editor shows its draft (FEA-10.2).
    func showQrFromKeys(focused: String?) {
        guard qrInFront else { return }
        if editor != nil {
            showDraftQr(field: focused ?? "Password")
        } else {
            showQr(field: focused ?? "Password")
        }
    }

    /// The Entry menu's Show Wi-Fi Join Code.
    func showWifiJoinFromMenu() {
        if qrInFront { showWifiJoin() }
    }

    /// Security holds a join: as the classifier's Wi-Fi entries, and the open
    /// networks it does not know (FEA-10.6).
    var canJoinWifi: Bool { detail.map(Self.joins) ?? false }

    /// The same for a row of the list (FEA-10.4), selected or not.
    func canJoinWifi(row: EntryRow) -> Bool {
        if row.kind == .wiFi { return true }
        if row.id == selection { return canJoinWifi }
        return (try? session.entry(vault: vault.id, entry: row.id)).map(Self.joins) ?? false
    }

    private static func joins(_ detail: EntryDetail) -> Bool {
        if detail.kind == .wiFi { return true }
        let security = detail.fields.first { $0.kind == .custom && $0.name == "Security" }
        return security.map { ["Open", "nopass"].contains($0.value) } ?? false
    }

    /// One pop-up per session: a new one destroys the old first (FEA-10.11).
    private func openQr(_ request: QrRequest, purpose: String) {
        qrPopup?.revoke()
        let popup = QrPopup(model: self, request: request, purpose: purpose, now: Self.qrClock)
        qrPopup = popup
        dialog = .qrCode(popup)
        popup.start()
    }

    /// MSG-QR-PURPOSE: the field's name as the screen calls it.
    private static func qrPurpose(_ field: String) -> String {
        field == "UserName" ? "Username" : field
    }

    /// A vault's `dialog` changed: the disk watch resumes, and a pop-up that
    /// left the window ends.
    func dialogChanged(from old: Dialog?) {
        if dialog == nil, old != nil { diskResume() }
        if case .qrCode(let popup) = old, dialog != old { popup.dialogGone() }
    }
}

/// FEA-10.18: offers only the proved routes, never what the system proposes.
final class QrSharePolicy: NSObject, NSSharingServicePickerDelegate {
    private let routes: [NSSharingService.Name]
    private let done: (Bool) -> Void

    /// `done` hears whether a service was chosen: its app may take the focus.
    init(routes: [NSSharingService.Name], done: @escaping (Bool) -> Void) {
        self.routes = routes
        self.done = done
    }

    func sharingServicePicker(
        _ picker: NSSharingServicePicker, sharingServicesForItems items: [Any],
        proposedSharingServices proposed: [NSSharingService]
    ) -> [NSSharingService] {
        routes.compactMap { NSSharingService(named: $0) }
    }

    func sharingServicePicker(_ picker: NSSharingServicePicker, didChoose service: NSSharingService?) {
        done(service != nil)
    }
}

/// The dialog's keyboard stops (FEA-10.13).
extension QrPopup {
    /// The stops Tab goes through: none outside the dialog, none disabled.
    var focusStops: [QrStop] {
        if case .warning = stage { return [.cancel, .confirm] }
        return canExport ? [.save] + (shareAvailable ? [.share] : []) + [.done] : [.done]
    }

    /// Tab and Shift-Tab, trapped in the dialog (FEA-10.13).
    func moveFocus(back: Bool = false) {
        let stops = focusStops
        let place = stops.firstIndex(of: focus) ?? stops.count - 1
        focus = stops[(place + (back ? stops.count - 1 : 1)) % stops.count]
    }

    /// Space on the focused stop.
    func activateFocus() {
        switch focus {
        case .save: ask(.save)
        case .share: ask(.share)
        case .done: revoke()
        case .cancel: cancelWarning()
        case .confirm: confirm()
        }
    }
}

/// What a vault model keeps for Show as QR Code.
struct QrHeld {
    /// The live request, on the window or in a save panel.
    var popup: QrPopup?
    /// The protected field the focus is in (`QrFocusReader`); its own window, never another.
    var field: String?
}

extension VaultModel {
    var qrPopup: QrPopup? {
        get { qrHeld.popup }
        set { qrHeld.popup = newValue }
    }
}

/// Where SwiftUI holds the focus and AppKit cannot see it. FEA-10.13: the QR
/// button that has it, and the turn a closed pop-up gives: to that button if it
/// is still there, otherwise to the entry list.
@MainActor
@Observable
final class QrFocus {
    static let shared = QrFocus()
    private(set) var turn = 0
    private(set) weak var model: VaultModel?
    /// The button whose turn it is; none is the list’s.
    private(set) var button: Namespace.ID?
    @ObservationIgnored var held: Namespace.ID?
    @ObservationIgnored var there: Set<Namespace.ID> = []

    func isListTurn(of model: VaultModel) -> Bool { self.model === model && button == nil }

    func give(to model: VaultModel?, button: Namespace.ID? = nil) {
        self.model = model
        self.button = button.flatMap { there.contains($0) ? $0 : nil }
        turn += 1
    }
}
