import Foundation
import LarsalCore
import Observation

/// One vault screen's shared groups (E11-S5, INT-08.20 to INT-08.24,
/// INT-08.31): the badges, the label under the entry list, the last pass's
/// banner and the group editor. Views without secrets from Rust.
@Observable
final class VaultSharing {
    /// The badge of each share group by id: `true` is "Share active".
    var marks: [String: Bool] = [:]
    /// The label of the group on screen (`nil`: none).
    var label: ShareLabel?
    /// INT-08.20: the last pass's banner, until Close.
    var banner: ShareBanner?
    /// The group editor, while it takes the sheet (INT-08.21).
    var editor: ShareEditorModel?
}

/// The group editor's Sharing page (INT-08.21). The draft is in Rust; the
/// share password crosses only as the Show the user asked for (LD-220).
@Observable
final class ShareEditorModel {
    let session: Session
    let vault: UInt64
    /// "Household · Personal".
    let subtitle: String
    private(set) var view: ShareEditView
    /// The Show value; dropped on Hide, on leave and with the editor.
    private(set) var shown: String?
    /// Why the last change or Save was refused.
    var problem: String?
    /// Moves when Rust takes a password from elsewhere (the generator): the
    /// masked field starts again with the new length.
    private(set) var applied = 0

    init(session: Session, vault: UInt64, view: ShareEditView, subtitle: String) {
        self.session = session
        self.vault = vault
        self.view = view
        self.subtitle = subtitle
    }

    var off: Bool { view.mode == .inactive }

    func change(_ change: ShareChange) {
        run { try session.shareEditChange(vault: vault, change: change) }
    }

    /// The masked or shown field's text goes to Rust at once.
    func typed(_ text: String) {
        run { try session.shareEditPassword(vault: vault, value: text) }
        if shown != nil { shown = text }
    }

    /// Use password (FEA-02): Rust moves the generator's value in.
    func generated() throws {
        view = try session.shareEditGenerated(vault: vault)
        if shown != nil { shown = try? session.shareEditShow(vault: vault) }
        applied += 1
    }

    /// Show and Hide (rule 4: Hide drops the value).
    func toggleShow() {
        shown = shown == nil ? try? session.shareEditShow(vault: vault) : nil
    }

    func hide() { shown = nil }

    private func run(_ call: () throws -> ShareEditView) {
        do {
            view = try call()
            problem = nil
        } catch {
            problem = message(error)
        }
    }
}

extension VaultModel {
    /// Edit Group… (APP-08.7): the group editor takes the sheet, on its
    /// Sharing page (the only page E11-S5 builds).
    func editGroup(_ id: String) {
        overlay = nil
        closeReports()
        do {
            let view = try session.shareEdit(vault: vault.id, group: id)
            sharing.editor = ShareEditorModel(
                session: session, vault: vault.id, view: view, subtitle: view.name + " · " + self.vault.name)
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
    }

    /// Save (⌘S): Rust writes the share item and approves it (INT-08.31);
    /// the vault saves as after any change (APP-05).
    func saveGroup() {
        guard let editor = sharing.editor else { return }
        do {
            try session.shareEditSave(vault: vault.id)
        } catch {
            editor.problem = message(error)
            return
        }
        editor.hide()
        sharing.editor = nil
        afterChange(select: selection)
        shareRefresh()
        diskResume()  // LD-310 (7): a change on disk waited for the editor
    }

    /// Cancel and Escape: the draft goes.
    func cancelGroup() {
        sharing.editor?.hide()
        try? session.shareEditCancel(vault: vault.id)
        sharing.editor = nil
        diskResume()  // LD-310 (7)
    }

    /// After a share pass, a settings change or Approve: the banner, the
    /// watches, the badges and the label (MainWindowModel.refresh).
    func shareRefresh() {
        takeShareNews()
        watchShares()
        if let banner = disk.shareBanner {
            sharing.banner = banner
            disk.shareBanner = nil
        }
        reloadShares()
    }

    /// The badges and the label of the group on screen (INT-08.24).
    func reloadShares() {
        let marks = (try? session.shareMarks(vault: vault.id)) ?? []
        sharing.marks = Dictionary(marks.map { ($0.group, $0.active) }) { first, _ in first }
        if case .group(let id) = place, let label = try? session.shareLabel(vault: vault.id, group: id) {
            sharing.label = label
        } else {
            sharing.label = nil
        }
    }

    /// The Approve sheet's Approve (INT-08.31): the record is stored on this
    /// Mac and the share runs at once.
    func approveShare(_ label: ShareLabel) {
        dialog = nil
        do {
            try session.approveShareShown(
                vault: vault.id, group: label.group, mode: label.mode, fullPath: label.fullPath)
        } catch {
            notify(Toast(glyph: "warning", text: message(error)))
        }
        shareRefresh()
    }
}
